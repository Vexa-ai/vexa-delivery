#!/usr/bin/env python3
"""vexa_subscriber — manage credentials on the Vexa channel registry.

The channel registry runs on a STANDALONE Docker host, off the product cluster
(RUNBOOK § 5.1, 2026-08-25): a cluster outage must not kill the mechanism that
restores the cluster. The old in-cluster deployment — namespace
``channel-registry``, Secret ``registry-htpasswd``, two Deployments — is a
scaled-to-0 rollback path and is NOT served by this tool. Patching that Secret
changes nothing the live registry reads, which is exactly how a rotation can
print a credential that authenticates nowhere and report success.

    python3 publisher/vexa_subscriber.py list
    python3 publisher/vexa_subscriber.py add pilot
    python3 publisher/vexa_subscriber.py add pilot --park --station pilot ...
    python3 publisher/vexa_subscriber.py revoke pilot

WHERE that host is, is site configuration and not repository content
(ADR-0009 § 4). Every coordinate is read from the environment, and a missing one
refuses and names itself rather than defaulting into somebody else's estate:

* ``CHANNEL_REGISTRY_SSH`` — the ssh target that operates the stack.
* ``CHANNEL_ROOT`` — where the stack lives on that host: compose file,
  ``htpasswd``, ``env``.
* ``CHANNEL_EDGE_URL`` — the edge's own origin, where a minted credential is
  PROVEN before it is printed.

None of the three has a default, and all three are resolved BEFORE the mint: a
rotation is destructive, and discovering the edge URL unset after the htpasswd
was rewritten would leave an account with no working credential and nothing
printed. Copy ``config/channel.example.env`` to ``config/channel.env``
(gitignored) and source it.

Two files under ``$CHANNEL_ROOT`` hold the credential state, and a rotation must
touch BOTH or it half-works (RUNBOOK § 5.4):

* ``htpasswd`` — raw bcrypt lines, consumed by registry:3. This is the read
  path: every request the registry sees is checked here.
* ``env`` — consumed by Caddy via ``{env.*}``. ``PUBLISHER_BCRYPT`` gates all
  mutating verbs; ``SUB_<NAME>_BCRYPT`` gates a subscriber's station-write path;
  ``EDGE_READER_BASIC`` is the base64 ``user:pass`` the edge presents upstream
  on the anonymous signature-read path. **Values in this file are
  docker-compose-escaped: every ``$`` doubled.** A raw bcrypt hash written here
  is silently truncated by compose interpolation and breaks the gate it was
  meant to open — the 57-of-60-character scar in RUNBOOK § 5.3.

After a write, ``docker compose up -d --force-recreate``: a plain
``docker restart`` re-runs the container with its ORIGINAL environment and does
NOT re-read ``env_file``.

``--park`` changes the DELIVERY leg and nothing else. It shares this same host
path — the same mint, the same rotation, the same two files — and stdout still
carries the credential once so the operator can vault it. What it adds is a
second line: a six-digit claim code, printed ``123 456`` and read aloud on a
call, against which the subscriber's own cluster fetches the credential from the
channel edge and writes it into a Secret. The credential never travels in mail,
chat, a ticket or a document, and nobody on their side ever sees it. See
``onboarding/credential-delivery.md`` and ``edge/claim/README.md``.

Two things it deliberately does NOT do:

* it never writes the password anywhere — not to a file, not to a log, not to
  the process title, not to a remote command line. ``add`` prints it once to
  stdout and forgets it; file contents and the credential under proof move over
  stdin only. Vault it in the operator's secrets vault immediately, and deliver
  it to the subscriber by claim code (``--park``), or age-encrypted to a key
  they already control (see ``onboarding/credential-delivery.md``). A parked
  credential is sealed to the EDGE's key: this tool encrypts and cannot decrypt
  what it just wrote. **``edge-signature-reader`` is the one exception and it is
  structural**: the edge must PRESENT that credential upstream rather than merely
  check it, so its value lands base64 in ``$CHANNEL_ROOT/env`` (mode 0600) by
  construction. That is why the account is edge-held and never given to anyone;
* it never grants station-write to a NEW subscriber by itself. That is one
  ``basic_auth`` line in the host's Caddyfile plus one ``SUB_<NAME>_BCRYPT``
  entry — a decision, not a default. This tool maintains the env entry once it
  exists; adding the Caddyfile line is a deliberate manual edit.

Host access is plain SSH: the tool shells out to ``ssh`` rather than taking a
dependency on a transport library, and moves file contents over stdin.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import string
import subprocess
import sys
import tempfile

# The park format has ONE definition and it lives with the service that reads
# it (edge/claim/vexa_claim.py). Importing it across the tree beats keeping a
# second copy here: a format with two definitions drifts silently, and the
# drift surfaces on the one call where somebody is reading a code aloud.
sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent / "edge" / "claim")
)
import vexa_claim  # noqa: E402

# vexa_stations is imported lazily inside the park path only. It needs PyYAML,
# and `list`/`add`/`revoke` — the verbs an operator runs during an incident —
# stay runnable on a host with nothing but the standard library.

# The account whose credential also unlocks the edge write gate.
PUBLISHER_ACCOUNT = "publisher"
PUBLISHER_ENV_KEY = "PUBLISHER_BCRYPT"

# Edge-held account the Caddy edge presents upstream on the anonymous
# signature-read path. Never given to a subscriber.
EDGE_READER_ACCOUNT = "edge-signature-reader"
EDGE_READER_ENV_KEY = "EDGE_READER_BASIC"

# Password alphabet: unambiguous, shell-safe, no quoting hazards. 32 chars of
# this is ~165 bits. "No quoting hazards" is load-bearing twice over now: the
# value also travels through a curl config file on stdin during the proof.
PASSWORD_ALPHABET = string.ascii_letters + string.digits
PASSWORD_LENGTH = 32

# Registry usernames end up in URLs, logs and env keys; keep them boring.
NAME_ALPHABET = set(string.ascii_lowercase + string.digits + "-")


class SubscriberError(Exception):
    """Anything the operator caused and can fix."""


# --------------------------------------------------------------------------
# Site configuration. ADR-0009 § 4: an operator's host address, filesystem root
# and edge URL are configuration, not repository content.
# --------------------------------------------------------------------------


def env_or_flag(flag_value: "str | None", env_name: str, what: str) -> str:
    """A missing input refuses and names the variable, the way publish.sh does.

    Silently defaulting one of these would mean operating the wrong host,
    parking to the wrong edge or sealing to the wrong key — and all three fail
    at the customer rather than here.
    """
    value = flag_value or os.environ.get(env_name)
    if not value:
        raise SubscriberError(
            f"{what} is not set: pass the flag or set ${env_name} "
            "(see config/channel.example.env)"
        )
    return value


def site_var(env_name: str, what: str) -> str:
    """A site coordinate: no flag, no default, and a refusal that names it."""
    value = os.environ.get(env_name)
    if not value:
        raise SubscriberError(
            f"{what} is not set: set ${env_name} — copy config/channel.example.env "
            "to config/channel.env and `set -a; source config/channel.env; set +a`"
        )
    return value


def channel_ssh() -> str:
    return site_var("CHANNEL_REGISTRY_SSH", "the channel host's ssh target")


def channel_root() -> str:
    return site_var("CHANNEL_ROOT",
                    "the stack's root directory on the channel host").rstrip("/")


def htpasswd_path() -> str:
    return f"{channel_root()}/htpasswd"


def env_path() -> str:
    return f"{channel_root()}/env"


def edge_url() -> str:
    return site_var("CHANNEL_EDGE_URL",
                    "the channel edge's own origin URL").rstrip("/")


def site_preflight() -> None:
    """Resolve every site coordinate before anything is read or written.

    ``add`` rotates and ``revoke`` removes; both are destructive on their first
    write. A coordinate read only at its point of use — the edge URL, consulted
    after the recreate — would refuse AFTER the htpasswd was rewritten, leaving
    an account with no working credential and nothing printed. So all three are
    demanded up front, the way ``park_preflight`` demands its inputs.
    """
    channel_ssh()
    channel_root()
    edge_url()


# --------------------------------------------------------------------------
# Pure htpasswd / env handling. No I/O, no host, no randomness — this half is
# what most of the unit tests cover.
# --------------------------------------------------------------------------


def validate_name(name: str) -> str:
    """Reject names that would be ambiguous in an htpasswd file or a URL."""
    if not name:
        raise SubscriberError("account name is empty")
    if not set(name) <= NAME_ALPHABET:
        raise SubscriberError(
            f"account name {name!r} must be lowercase letters, digits and '-' only"
        )
    if name.startswith("-") or name.endswith("-"):
        raise SubscriberError(f"account name {name!r} must not start or end with '-'")
    return name


def parse_htpasswd(text: str) -> "dict[str, str]":
    """Parse an htpasswd file into ``{user: hash}``.

    Blank lines and ``#`` comments are dropped. A duplicate user is an error
    rather than a last-one-wins, because which one the registry honours is not
    something we want to be guessing about during an incident.
    """
    entries: "dict[str, str]" = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise SubscriberError(f"htpasswd line {lineno} has no ':' separator")
        user, _, digest = line.partition(":")
        user = user.strip()
        digest = digest.strip()
        if not user or not digest:
            raise SubscriberError(f"htpasswd line {lineno} has an empty user or hash")
        if user in entries:
            raise SubscriberError(f"htpasswd has duplicate entries for {user!r}")
        entries[user] = digest
    return entries


def render_htpasswd(entries: "dict[str, str]") -> str:
    """Serialise ``{user: hash}`` back to an htpasswd file.

    Sorted, one trailing newline: the output is a pure function of the mapping,
    so re-adding an unchanged account produces a byte-identical file and no
    spurious recreate.
    """
    if not entries:
        return ""
    return "".join(f"{user}:{entries[user]}\n" for user in sorted(entries))


def add_entry(text: str, name: str, digest: str) -> str:
    """Return the htpasswd text with ``name`` set to ``digest`` (upsert)."""
    entries = parse_htpasswd(text)
    entries[validate_name(name)] = digest
    return render_htpasswd(entries)


def remove_entry(text: str, name: str) -> str:
    """Return the htpasswd text without ``name``. Absent is an error."""
    entries = parse_htpasswd(text)
    validate_name(name)
    if name not in entries:
        raise SubscriberError(f"no account named {name!r} in the registry htpasswd")
    del entries[name]
    return render_htpasswd(entries)


def compose_escape(value: str) -> str:
    """Escape a value for ``$CHANNEL_ROOT/env``: compose interpolates ``$``.

    Docker Compose v5 interpolates ``$`` inside ``env_file`` values, and once
    ate three characters of a bcrypt hash — 57 instead of 60 — breaking exactly
    one account while the others kept working (RUNBOOK § 5.3). Every literal
    ``$`` must therefore travel as ``$$``.
    """
    return value.replace("$", "$$")


def sub_env_key(name: str) -> str:
    """The env key Caddy reads for ``name``'s station-write hash.

    ``pilot`` -> ``SUB_PILOT_BCRYPT``. Hyphens become underscores because env
    keys cannot carry ``-``.
    """
    return "SUB_" + validate_name(name).upper().replace("-", "_") + "_BCRYPT"


def set_env_value(text: str, key: str, value: str) -> str:
    """Return the env-file text with ``key``'s value replaced.

    Everything else — ordering, comments, unrelated keys — is preserved
    byte-for-byte. A missing key is an error, not an append: this file's shape
    is contractual with the host's Caddyfile, and a key we expected but did not
    find means the host no longer looks the way this tool believes it does.
    """
    lines = text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.split("=", 1)[0].strip() == key]
    if not hits:
        raise SubscriberError(
            f"the channel env file ($CHANNEL_ROOT/env) has no {key!r} line — the "
            "host layout differs from what this tool expects; inspect it before "
            "rotating"
        )
    if len(hits) > 1:
        raise SubscriberError(
            f"the channel env file ($CHANNEL_ROOT/env) has duplicate {key!r} lines"
        )
    i = hits[0]
    newline = "\n" if lines[i].endswith("\n") else ""
    lines[i] = f"{key}={value}{newline}"
    return "".join(lines)


def env_has_key(text: str, key: str) -> bool:
    return any(line.split("=", 1)[0].strip() == key for line in text.splitlines())


def generate_password(length: int = PASSWORD_LENGTH) -> str:
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


# `htpasswd -n` prints "<name>:<hash>" to stdout instead of writing a file, so
# it needs a name it will never use; `-i` reads the password from stdin. We
# strip the prefix back off and keep only the hash. Named rather than written
# inline: a bare quoted token sitting next to the word "htpasswd" reads as a
# hardcoded credential to a scanner, and a red security check on every push is
# a real cost for a value that is discarded two lines later.
STUB_NAME = "unused"


def bcrypt_hash(password: str) -> str:
    """bcrypt the password.

    Prefers the ``bcrypt`` module; falls back to the ``htpasswd`` binary
    (present on macOS and in every apache2-utils install), fed over stdin with
    ``-i`` so the password never enters an argv. registry:3 accepts bcrypt only
    — MD5/crypt/SHA1 htpasswd hashes are rejected at startup, so there is no
    weaker fallback to take.
    """
    try:
        import bcrypt  # type: ignore
    except ImportError:
        pass
    else:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        out = subprocess.run(
            ["htpasswd", "-nBi", STUB_NAME],
            input=password,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except FileNotFoundError:
        raise SubscriberError(
            "need bcrypt hashing: `pip install bcrypt`, or install apache2-utils "
            "so the `htpasswd` binary is on PATH"
        ) from None
    except subprocess.CalledProcessError as exc:
        raise SubscriberError(f"htpasswd failed: {exc.stderr.strip()}") from None

    line = out.strip()
    prefix = STUB_NAME + ":"
    if not line.startswith(prefix):
        # Never echo the output: on a bad flag combination it can be the line
        # we were trying not to produce.
        raise SubscriberError("unexpected htpasswd output shape")
    return line[len(prefix):]


def is_bcrypt(digest: str) -> bool:
    """registry:3 only honours bcrypt; anything else is a silent lockout."""
    return digest.startswith(("$2a$", "$2b$", "$2y$"))


# --------------------------------------------------------------------------
# Host I/O — plain SSH to the standalone Docker host. File contents move over
# stdin/stdout only; nothing credential-shaped ever reaches a remote argv.
# --------------------------------------------------------------------------


def ssh_run(command: str, stdin: "str | None" = None, *,
            target: "str | None" = None) -> str:
    """The ONE SSH shell-out. Dials `$CHANNEL_REGISTRY_SSH` unless `target`
    names another login — the park leg passes the host half of
    `$CHANNEL_CLAIM_SPOOL_SSH`, which is its own setting and is dialled as
    itself even where it is the same machine."""
    target = target or channel_ssh()
    cmd = ["ssh", "-o", "BatchMode=yes", target, command]
    try:
        proc = subprocess.run(
            cmd, input=stdin, capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        raise SubscriberError("ssh not found on PATH") from None
    except subprocess.CalledProcessError as exc:
        raise SubscriberError(
            f"ssh {target} {command.split()[0]!r} failed:\n{exc.stderr.strip()}"
        ) from None
    return proc.stdout


def read_host_file(path: str) -> str:
    return ssh_run(f"cat {shlex.quote(path)}")


def write_host_file(path: str, content: str) -> None:
    """Atomically replace ``path`` on the host, mode 0600, content via stdin."""
    q = shlex.quote(path)
    ssh_run(
        f"umask 077 && cat > {q}.tmp && chmod 600 {q}.tmp && mv {q}.tmp {q}",
        stdin=content,
    )


def recreate_stack() -> None:
    """Recreate the compose stack so env_file changes are picked up.

    ``docker restart`` re-runs the same container with its ORIGINAL
    environment — env_file is read at container creation. Recreate, or the
    rotation silently does not reach Caddy.
    """
    ssh_run(f"cd {shlex.quote(channel_root())} && "
            f"docker compose up -d --force-recreate")


def http_status(url: str, *, credential: "str | None" = None) -> str:
    """The status code the edge answers with, as a string.

    A credential travels in a curl config on stdin (``-K -``) and never in
    argv, which is world-readable in ``/proc`` and in ``ps`` for the life of
    the process — the same promise ``gates/check-secret-argv.py`` enforces for
    the kit's shell scripts.
    """
    argv = ["curl", "-sS", "--max-time", "15", "-o", "/dev/null",
            "-w", "%{http_code}"]
    config = None
    if credential is not None:
        argv += ["-K", "-"]
        config = f'user = "{credential}"\n'
    argv.append(url)
    try:
        proc = subprocess.run(argv, input=config, capture_output=True,
                              text=True, check=True)
    except FileNotFoundError:
        raise SubscriberError("curl not found on PATH") from None
    except subprocess.CalledProcessError as exc:
        raise SubscriberError(f"{url} could not be reached: "
                              f"{exc.stderr.strip()}") from None
    return proc.stdout.strip()


def verify_healthz() -> None:
    """The edge answers /healthz unauthenticated once the stack is back."""
    url = f"{edge_url()}/healthz"
    try:
        subprocess.run(
            ["curl", "-fsS", "--max-time", "10",
             "--retry", "6", "--retry-delay", "5", "--retry-all-errors",
             "-o", "/dev/null", url],
            capture_output=True, text=True, check=True,
        )
    except FileNotFoundError:
        raise SubscriberError("curl not found on PATH") from None
    except subprocess.CalledProcessError as exc:
        raise SubscriberError(
            f"the stack was recreated but {url} did not come back: "
            f"{exc.stderr.strip()}"
        ) from None


def verify_credential(name: str, password: str) -> None:
    """Prove the credential works, AND that the gate it works against is shut.

    Two requests, and the negative one is not decoration. A registry whose auth
    is off answers 200 to anything, so the positive request alone cannot tell
    *this credential authenticates* from *nothing here checks*. 200 with it and
    401 without it are the pair that says the credential is real, and between
    them they would have caught the failure this whole change exists to stop —
    a rotation that edited a dark path and reported success.

    Not optional: a credential that half-works deserves more suspicion than one
    that does not work at all (RUNBOOK § 5.3).
    """
    url = f"{edge_url()}/v2/"
    with_it = http_status(url, credential=f"{name}:{password}")
    if with_it != "200":
        raise SubscriberError(
            f"the freshly minted credential for {name!r} did NOT authenticate "
            f"against {url} (HTTP {with_it}) — the rotation is broken, do not "
            f"deliver this password"
        )
    without = http_status(url)
    if without != "401":
        raise SubscriberError(
            f"{url} answered HTTP {without} with NO credential, where 401 was "
            f"expected — the credential for {name!r} cannot be said to have "
            f"been proven, because the gate it was proven against is open. "
            f"Do not deliver this password; inspect the edge first"
        )


# --------------------------------------------------------------------------
# Parking. The credential is sealed to the EDGE's key before it leaves this
# process, so nothing between here and the edge — the temp file, scp, the
# spool, a backup of the spool — carries anything openable by its holder.
# --------------------------------------------------------------------------


def split_scp_target(target: str) -> "tuple[str, str]":
    """`user@host:/path` into what `ssh` dials and the path on that host.

    The same string `scp` takes, split at its first colon, so the operator sets
    ONE value (`$CHANNEL_CLAIM_SPOOL_SSH`) and both the copy and the chown that
    follows it land on the same host. An IPv6 literal arrives bracketed for
    scp's sake and `ssh` wants it bare.
    """
    text = target.rstrip("/")
    if text.startswith("["):
        host, sep, path = text[1:].partition("]:")
    else:
        host, sep, path = text.partition(":")
    if not sep or not host or not path.startswith("/"):
        raise SubscriberError(
            f"--park-ssh {target!r} is not an scp target: expected "
            "user@host:/absolute/path/to/spool (see config/channel.example.env)"
        )
    return host, path


def remote_spool_owner(target: str) -> str:
    """`uid:gid` of the spool directory on the edge host, checked BEFORE the mint.

    The park is copied by `scp` as the SSH user — root, on the standalone host —
    and lands `root:root 0600`. The service is `USER 65532` (edge/claim/
    Dockerfile), correctly not root, so a park left owned by root is one it
    cannot open: the code gets read aloud against a file the edge answers with
    the uniform 403, which says nothing. Observed exactly so on the live edge
    on 2026-09-06 (receipt, finding 4), when the deploy note's `chown` covered
    the DIRECTORY and nothing covered the file.

    So the file takes the owner of the spool it lands in — the one fact the
    deploy already decided — and this reads that owner up front, where a spool
    that is missing, unreachable, or itself still root-owned refuses before
    anything is rotated. A root-owned spool is refused outright: with the
    shipped image every park into it would be unreadable, and the fix is one
    line on the edge host. `stat -c` is GNU coreutils, which the edge host has
    by being a Linux Docker host.
    """
    host, path = split_scp_target(target)
    quoted = shlex.quote(path)
    # One remote command, exit 0 either way, so that "ssh failed" (a non-zero
    # exit, quoted from stderr) and "no such directory" (this sentinel) are
    # told apart instead of both reading as a failed login.
    out = ssh_run(
        f"test -d {quoted} && stat -c %u:%g {quoted} || echo no-such-directory",
        target=host,
    ).strip()
    if not re.fullmatch(r"[0-9]+:[0-9]+", out):
        raise SubscriberError(
            f"the spool {path} on {host} is not a directory (or `stat -c` is not "
            f"GNU stat there): got {out!r}. Create it on the edge host — "
            "edge/claim/README.md § Deploy, step 1. Nothing was minted."
        )
    if out.startswith("0:"):
        raise SubscriberError(
            f"the spool {path} on {host} is owned by root. The claim edge runs as "
            "uid 65532 (edge/claim/Dockerfile) and cannot read a park that lands "
            "in a root-owned spool — the code would be read aloud against a file "
            f"the service cannot open. On the edge host: chown 65532:65532 {path} "
            "(edge/claim/README.md § Deploy, step 1). Nothing was minted."
        )
    return out


def adopt_spool_owner(path: pathlib.Path) -> "str | None":
    """Give a locally written park the owner of the spool it landed in.

    The local transport has the same shape of failure one level down: a
    publisher running as root on the edge host itself, writing into the
    service's 65532-owned spool, leaves a root-owned file the service cannot
    read. Only root can hand a file to another uid, so this is best effort —
    a publisher that is not root keeps its own file, which is the right answer
    for a synced directory (the far end re-owns it) and is said aloud for a
    shared mount rather than left to fail at the call.

    Returns a warning line, or None when the owner already matches.
    """
    want = path.parent.stat()
    have = path.stat()
    if (have.st_uid, have.st_gid) == (want.st_uid, want.st_gid):
        return None
    try:
        os.chown(path, want.st_uid, want.st_gid)
    except PermissionError:
        return (
            f"park is owned by uid {have.st_uid} inside a spool owned by uid "
            f"{want.st_uid}; the edge can read it only if it runs as uid "
            f"{have.st_uid} — otherwise chown {want.st_uid}:{want.st_gid} {path}"
        )
    return None


def deliver_park(record: dict, *, spool: "str | None", ssh: "str | None",
                 owner: "str | None" = None) -> str:
    """Put the park where the edge will read it. Local directory, or scp.

    Exactly one transport, chosen by the operator's site: a spool the publisher
    can write directly (a mount, a synced directory) or the standalone host over
    SSH, which is the transport § 5.4 already uses for this host. The local copy
    on the scp path is written 0600 into a 0700 temp directory and removed
    afterwards — it is ciphertext, but it is ciphertext with a fifteen-minute
    code beside it in somebody's terminal.

    ON THE SCP PATH THE COPY IS FOLLOWED BY A CHOWN, over the same SSH login, to
    `owner` — the spool directory's own `uid:gid`, read by `remote_spool_owner`
    (passed in from the preflight, or read here). `scp` writes as the SSH user,
    and a park owned by root in a spool the service owns as 65532 is a park the
    service cannot open (2026-09-06, finding 4). The mode is re-asserted to 0600
    in the same command rather than trusted to scp's protocol negotiation.
    Both steps happen before the code is printed, so the operator never reads
    six digits aloud against a file the edge cannot read.
    """
    name = f"{record['station']}.park.json"
    if spool:
        path = vexa_claim.write_park(pathlib.Path(spool).expanduser(), record)
        warning = adopt_spool_owner(path)
        if warning:
            print(f"# warning: {warning}", file=sys.stderr)
        return str(path)
    host, remote_dir = split_scp_target(ssh)
    owner = owner or remote_spool_owner(ssh)
    work = pathlib.Path(tempfile.mkdtemp(prefix="vexa-park-"))
    try:
        vexa_claim.write_park(work, record)
        target = f"{ssh.rstrip('/')}/{name}"
        try:
            subprocess.run(
                ["scp", "-q", str(work / name), target],
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError:
            raise SubscriberError("scp not found on PATH") from None
        except subprocess.CalledProcessError as exc:
            raise SubscriberError(f"scp to {target} failed:\n{exc.stderr.strip()}") from None
    finally:
        shutil.rmtree(work, ignore_errors=True)

    remote_file = shlex.quote(f"{remote_dir}/{name}")
    try:
        ssh_run(f"chown {owner} {remote_file} && chmod 600 {remote_file}", target=host)
    except SubscriberError as exc:
        raise SubscriberError(
            f"the park landed at {target} but is still owned by the SSH user, "
            f"and the edge cannot read it until it is the spool's: on {host}, "
            f"chown {owner} {remote_dir}/{name}. Do not read the code out until "
            f"that is done.\n{exc}"
        ) from None
    return f"{target} (owner {owner}, the spool's)"


def park_preflight(args: argparse.Namespace, account: str) -> dict:
    """Resolve and check every park input BEFORE the mint.

    This runs first because the mint is destructive: `add` rotates, so the old
    credential stops working the moment the Secret is written. Discovering a
    missing recipients file afterwards would leave the subscriber locked out
    with nothing parked and nothing printed — a self-inflicted outage caused by
    a typo in a path. Everything that can be checked without minting is checked
    here, including one round trip through `age`.

    ORDER: every refusal this function can reach on its own comes first, and the
    `age` round trip — the one check that spawns a process and needs a binary —
    comes last. Not a preference: with the probe earlier, a bad ledger path or a
    missing `--edge` was reported as "the `age` binary is not on PATH" on any
    host without it, which is every CI runner. Two tests caught exactly that.
    """
    import vexa_stations  # PyYAML; only this path needs it

    if not args.channel:
        raise SubscriberError(
            "--park needs --channel: the park is recorded in the stations ledger "
            "at channels/<channel>/stations/<station>/credential-events.yaml, and "
            "a park in no ledger is an unrecorded live credential"
        )
    if args.ttl < 60 or args.ttl > 3600:
        raise SubscriberError(
            f"--ttl {args.ttl} is outside 60..3600 seconds. The window IS the "
            "control here; a generous one makes the code a password with extra "
            "steps, and a 30-second one gets read aloud twice"
        )
    spool = args.park_out or os.environ.get("CHANNEL_CLAIM_SPOOL")
    ssh = args.park_ssh or os.environ.get("CHANNEL_CLAIM_SPOOL_SSH")
    if bool(spool) == bool(ssh):
        raise SubscriberError(
            "give exactly one park transport: --park-out (or $CHANNEL_CLAIM_SPOOL) "
            "for a spool this host can write, or --park-ssh (or "
            "$CHANNEL_CLAIM_SPOOL_SSH) for the standalone edge host"
        )
    recipients = env_or_flag(
        args.edge_recipient, "CHANNEL_CLAIM_EDGE_RECIPIENT",
        "the edge's age recipients file",
    )
    context = {
        "station": vexa_claim.validate_station(args.station or account),
        "recipients": recipients,
        "edge": env_or_flag(args.edge, "CHANNEL_CLAIM_EDGE", "the claim endpoint URL"),
        "spool": spool,
        "ssh": ssh,
        "spool_owner": None,
        "root": ledger_call(vexa_stations, vexa_stations.resolve_root, args.ledger),
        "channel": args.channel,
    }
    # The two checks that leave this host come last, cheapest first. The SSH
    # round trip proves the edge host answers, the spool exists, and who owns
    # it — the owner the park will be handed to after the copy — so a wrong
    # `$CHANNEL_CLAIM_SPOOL_SSH`, a spool nobody created, or a spool still owned
    # by root refuses HERE, with nothing rotated, rather than at the scp after
    # the subscriber's old credential has already stopped working.
    if ssh:
        context["spool_owner"] = remote_spool_owner(ssh)
    # LAST, and it is the expensive one: encrypt a throwaway to prove the key
    # works. A recipients file that is present but malformed fails here, on a
    # value nobody needs, instead of after the rotation.
    vexa_claim.age_encrypt(recipients, "park-preflight")
    return context


def ledger_call(module, func, *args, **kwargs):
    """Run a ledger reducer, reporting its refusals in this tool's own voice."""
    try:
        return func(*args, **kwargs)
    except module.LedgerError as exc:
        raise SubscriberError(f"stations ledger: {exc}") from None


def park_credential(ctx: dict, args: argparse.Namespace, *, account: str,
                    password: str, rotating: bool) -> None:
    """Seal, record, place, and print the code — in that order, deliberately.

    The ledger commit comes BEFORE the park lands, and the code is printed last.
    A park that exists in no ledger is an unrecorded live credential; a ledger
    row for a park that failed to write is a line somebody can read and correct.
    Printing last means the operator never reads a code aloud that the edge
    cannot serve.
    """
    import vexa_stations

    code = vexa_claim.generate_code()
    record = vexa_claim.build_park(
        station=ctx["station"],
        account=account,
        code=code,
        # The only line in this file that touches the password, and it hands it
        # straight to age. No branch here writes it anywhere else.
        ciphertext=vexa_claim.age_encrypt(
            ctx["recipients"], json.dumps({"username": account, "password": password})
        ),
        parked_by=args.parked_by or os.environ.get("USER") or "unknown",
        edge=ctx["edge"],
        ttl_seconds=args.ttl,
        rotation=rotating,
    )

    out = ledger_call(
        vexa_stations, vexa_stations.record_credential_events,
        ctx["root"], channel=ctx["channel"], station=ctx["station"],
        events=[vexa_stations.park_event(record)],
    )
    where = deliver_park(record, spool=ctx["spool"], ssh=ctx["ssh"],
                         owner=ctx.get("spool_owner"))

    for line in (
        f"# parked for station {ctx['station']!r}, claimable at {ctx['edge']}",
        f"#   park      {where}",
        f"#   ledger    {out['path']} ({out['commit'] or 'no change'})",
        f"#   expires   {record['expires_at']} ({args.ttl // 60} minutes), "
        f"{record['max_attempts']} attempts, one redemption",
        "# read the six digits on the second line below out on the call; they run:",
        f"#   ./kit/claim.sh --code <the six digits> --edge {ctx['edge']} "
        f"--station {ctx['station']} --namespace <their prod namespace>",
    ):
        print(line, file=sys.stderr)
    # Line 2 of stdout, grouped `123 456` for reading aloud. Line 1 is the
    # credential, unchanged; the code is digits and a space, so the two lines
    # can never be read as one another.
    print(vexa_claim.format_code(code))


# --------------------------------------------------------------------------
# Verbs.
# --------------------------------------------------------------------------


def account_scope(name: str, env_text: str) -> str:
    """What the account may do, read from the two files rather than assumed."""
    if name == PUBLISHER_ACCOUNT:
        return "push+pull"
    if name == EDGE_READER_ACCOUNT:
        return "edge-held"
    if env_has_key(env_text, sub_env_key(name)):
        return "pull+station"
    return "pull"


def cmd_list(args: argparse.Namespace) -> int:
    entries = parse_htpasswd(read_host_file(htpasswd_path()))
    if not entries:
        print("no accounts on the channel registry")
        return 0
    env_text = read_host_file(env_path())
    width = max(len(u) for u in entries)
    print(f"{'ACCOUNT'.ljust(width)}  SCOPE         HASH")
    for user in sorted(entries):
        kind = "bcrypt" if is_bcrypt(entries[user]) else "NOT-BCRYPT"
        print(f"{user.ljust(width)}  "
              f"{account_scope(user, env_text).ljust(12)}  {kind}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    name = validate_name(args.name)
    # Before the mint, because the mint rotates: see site_preflight and
    # park_preflight. Site first — it is the cheaper refusal.
    site_preflight()
    park_ctx = park_preflight(args, name) if args.park else None
    current = read_host_file(htpasswd_path())
    env_text = read_host_file(env_path())
    # Checked before anything is written, for the same reason park_preflight
    # runs before the mint: this is the cheap way to catch $CHANNEL_ROOT
    # pointing somewhere that is not the live stack.
    if not env_has_key(env_text, PUBLISHER_ENV_KEY):
        raise SubscriberError(
            f"{env_path()} has no {PUBLISHER_ENV_KEY!r} line — the Caddy edge "
            f"reads it as {{env.{PUBLISHER_ENV_KEY}}} and cannot start without "
            f"it. Check $CHANNEL_ROOT names the live stack before rotating"
        )
    rotating = name in parse_htpasswd(current)

    password = generate_password()
    digest = bcrypt_hash(password)
    new_htpasswd = add_entry(current, name, digest)

    # Which env key does this account's credential also live behind?
    new_env = env_text
    if name == PUBLISHER_ACCOUNT:
        # The edge write gate checks the same credential; keep the two halves
        # in lockstep or a publish starts failing at the proxy.
        new_env = set_env_value(new_env, PUBLISHER_ENV_KEY, compose_escape(digest))
    elif name == EDGE_READER_ACCOUNT:
        # The edge PRESENTS this one upstream on the anonymous signature-read
        # path, as base64 user:pass — so this key holds the value, not a hash
        # of it, and that is the one place a password legitimately lands in a
        # file. Rotating the htpasswd line without it leaves anonymous
        # signature reads answering 401 and Kyverno denying at admission.
        basic = base64.b64encode(f"{name}:{password}".encode()).decode()
        new_env = set_env_value(new_env, EDGE_READER_ENV_KEY, compose_escape(basic))
    elif env_has_key(env_text, sub_env_key(name)):
        # This subscriber has a station-write line in the host's Caddyfile; its
        # hash rides the env file.
        new_env = set_env_value(new_env, sub_env_key(name), compose_escape(digest))
    elif not rotating:
        print(
            f"# note: {name} is being minted pull-only. Station-write needs a "
            f"basic_auth line in $CHANNEL_ROOT/Caddyfile plus a "
            f"{sub_env_key(name)} env entry — a deliberate manual edit, then "
            f"rerun `add {name}` to populate it.",
            file=sys.stderr,
        )

    write_host_file(htpasswd_path(), new_htpasswd)
    if new_env != env_text:
        write_host_file(env_path(), new_env)
    recreate_stack()
    verify_healthz()
    # PROVE, then print. A credential that is printed before it is proven has
    # already been read aloud by the time anyone finds out it is dead.
    verify_credential(name, password)

    verb = "rotated" if rotating else "added"
    print(f"# {verb} {name} ({account_scope(name, new_env)}); live auth verified",
          file=sys.stderr)
    print("# vault it now in your secrets store ($CHANNEL_CREDENTIAL_VAULT)",
          file=sys.stderr)
    # The one and only time this value is ever emitted.
    print(f"{name}:{password}")
    if park_ctx:
        park_credential(park_ctx, args, account=name, password=password,
                        rotating=rotating)
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    name = validate_name(args.name)
    if name == PUBLISHER_ACCOUNT and not args.force:
        raise SubscriberError(
            "revoking 'publisher' breaks publishing and the edge write gate; "
            "pass --force if that is really what you want"
        )
    if name == EDGE_READER_ACCOUNT and not args.force:
        raise SubscriberError(
            "revoking 'edge-signature-reader' breaks anonymous signature "
            "verification for every consumer, Kyverno included; "
            "pass --force if that is really what you want"
        )
    site_preflight()
    current = read_host_file(htpasswd_path())
    write_host_file(htpasswd_path(), remove_entry(current, name))
    recreate_stack()
    verify_healthz()
    env_text = read_host_file(env_path())
    if name not in (PUBLISHER_ACCOUNT, EDGE_READER_ACCOUNT) and env_has_key(
        env_text, sub_env_key(name)
    ):
        # Left in place on purpose: the Caddyfile references {env.KEY}, and a
        # dangling reference is a Caddy-start risk. The hash is inert — the
        # registry rejects the account at the htpasswd — but removing the
        # Caddyfile line and the env entry together is the clean follow-up.
        print(
            f"# note: {sub_env_key(name)} still exists in {env_path()} and the "
            f"Caddyfile still lists {name}. The credential is dead (htpasswd "
            f"line removed); remove both together when tidying.",
            file=sys.stderr,
        )
    print(f"revoked {name}; the credential no longer authenticates")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vexa_subscriber",
        description=(
            "Manage credentials on the Vexa channel registry, which runs on a "
            "standalone Docker host. Host coordinates are site configuration: "
            "$CHANNEL_REGISTRY_SSH, $CHANNEL_ROOT and $CHANNEL_EDGE_URL, "
            "documented in config/channel.example.env."
        ),
    )
    sub = parser.add_subparsers(dest="verb", required=True)

    p_list = sub.add_parser("list", help="show accounts and their scope")
    p_list.set_defaults(func=cmd_list)

    p_add = sub.add_parser(
        "add", help="mint a credential for an account (also rotates an existing one)"
    )
    p_add.add_argument("name", help="account name, e.g. 'pilot'")
    park = p_add.add_argument_group(
        "claim-code delivery (--park)",
        "Seal the minted credential to the edge's key and park it under a "
        f"{vexa_claim.CODE_LENGTH}-digit code you read on a call. Line 1 of "
        "stdout is still the credential, to vault; line 2 is the six digits, "
        "grouped in threes for reading aloud.",
    )
    park.add_argument("--park", action="store_true",
                      help="park the credential for claiming at the channel edge")
    park.add_argument("--channel", help="channel the station belongs to "
                                        "(required with --park; the ledger path)")
    park.add_argument("--station", help="station the code is bound to "
                                        "(default: the account name)")
    park.add_argument("--edge", help="claim endpoint URL "
                                     "(default: $CHANNEL_CLAIM_EDGE)")
    park.add_argument("--edge-recipient",
                      help="age recipients file holding the EDGE's public key — "
                           "we encrypt to it and cannot decrypt what we wrote "
                           "(default: $CHANNEL_CLAIM_EDGE_RECIPIENT)")
    park.add_argument("--park-out", help="spool directory this host can write "
                                         "(default: $CHANNEL_CLAIM_SPOOL)")
    park.add_argument("--park-ssh", help="scp target for the edge host's spool, "
                                         "e.g. root@host:/srv/channel/claims "
                                         "(default: $CHANNEL_CLAIM_SPOOL_SSH)")
    park.add_argument("--ledger", help="checkout of the vexa-stations ledger "
                                       "(default: $VEXA_STATIONS_DIR)")
    park.add_argument("--ttl", type=int, default=vexa_claim.TTL_SECONDS,
                      metavar="SECONDS",
                      help=f"how long the code lives (default {vexa_claim.TTL_SECONDS})")
    park.add_argument("--parked-by", help="who parked it, for the ledger "
                                          "(default: $USER)")
    p_add.set_defaults(func=cmd_add)

    p_revoke = sub.add_parser("revoke", help="remove an account's credential")
    p_revoke.add_argument("name")
    p_revoke.add_argument(
        "--force",
        action="store_true",
        help="allow revoking the publisher or edge-signature-reader account",
    )
    p_revoke.set_defaults(func=cmd_revoke)

    return parser


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (SubscriberError, vexa_claim.ClaimError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
