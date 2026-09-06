#!/usr/bin/env python3
"""vexa_subscriber — manage credentials on the Vexa channel registry.

The channel registry (``channel.vexa.ai``, namespace ``channel-registry`` in the
production LKE cluster) authenticates with an htpasswd file held in the
``registry-htpasswd`` Secret. This tool is the ONLY supported way to change it:
it mints the password, writes the bcrypt line, patches the Secret and rolls the
Deployment(s) that consume it.

    python3 publisher/vexa_subscriber.py list
    python3 publisher/vexa_subscriber.py add pilot
    python3 publisher/vexa_subscriber.py add pilot --park --station pilot ...
    python3 publisher/vexa_subscriber.py revoke pilot

``--park`` changes the DELIVERY leg and nothing else. The mint is the same mint
and the rotation is the same rotation; stdout still carries the credential once
so the operator can vault it. What it adds is a second line — an eight-character
claim code, read aloud on a call — against which the subscriber's own cluster
fetches the credential from the channel edge and writes it into a Secret. The
credential never travels in mail, chat, a ticket or a document, and nobody on
their side ever sees it. See ``onboarding/credential-delivery.md`` and
``edge/claim/README.md``.

Two things it deliberately does NOT do:

* it never writes the password anywhere — not to a file, not to a log, not to
  the process title. ``add`` prints it once to stdout and forgets it. Vault it
  in the operator's secrets vault immediately, and deliver it to the subscriber
  by claim code (``--park``), or age-encrypted to a key they already control
  (see ``onboarding/credential-delivery.md``). A parked credential is sealed to
  the EDGE's key: this tool encrypts and cannot decrypt what it just wrote;
* it never grants write access to a subscriber. Registry htpasswd auth is
  all-or-nothing, so pushes are gated at the Caddy edge against the ``publisher``
  account instead. Adding the ``publisher`` account here therefore also rewrites
  the edge's ``publisherBcrypt`` key and rolls Caddy. See
  ``vexa-platform/cluster/channel-registry-ns/README.md`` § security model.

Cluster access comes from the ambient ``KUBECONFIG``; the tool shells out to
``kubectl`` rather than taking a dependency on a Kubernetes client library.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import secrets
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

NAMESPACE = "channel-registry"
SECRET_NAME = "registry-htpasswd"
HTPASSWD_KEY = "htpasswd"
PUBLISHER_BCRYPT_KEY = "publisherBcrypt"
REGISTRY_DEPLOYMENT = "channel-registry"
CADDY_DEPLOYMENT = "channel-registry-caddy"

# The account whose credential also unlocks the edge write gate.
PUBLISHER_ACCOUNT = "publisher"

# Password alphabet: unambiguous, shell-safe, no quoting hazards. 32 chars of
# this is ~165 bits.
PASSWORD_ALPHABET = string.ascii_letters + string.digits
PASSWORD_LENGTH = 32

# Registry usernames end up in URLs, logs and Secret keys; keep them boring.
NAME_ALPHABET = set(string.ascii_lowercase + string.digits + "-")


class SubscriberError(Exception):
    """Anything the operator caused and can fix."""


# --------------------------------------------------------------------------
# Pure htpasswd handling. No I/O, no cluster, no randomness — this half is what
# the unit tests cover.
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
    so re-adding an unchanged account produces a byte-identical Secret and no
    spurious rollout.
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


def generate_password(length: int = PASSWORD_LENGTH) -> str:
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


def bcrypt_hash(password: str) -> str:
    """bcrypt the password.

    Prefers the ``bcrypt`` module; falls back to the ``htpasswd`` binary, which
    is present on macOS and in every apache2-utils install. registry:3 accepts
    bcrypt only — MD5/crypt/SHA1 htpasswd hashes are rejected at startup, so
    there is no weaker fallback to take.
    """
    try:
        import bcrypt  # type: ignore
    except ImportError:
        pass
    else:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        out = subprocess.run(
            ["htpasswd", "-nbB", "x", password],
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
    if not line.startswith("x:"):
        raise SubscriberError(f"unexpected htpasswd output: {line!r}")
    return line.partition(":")[2]


def is_bcrypt(digest: str) -> bool:
    """registry:3 only honours bcrypt; anything else is a silent lockout."""
    return digest.startswith(("$2a$", "$2b$", "$2y$"))


# --------------------------------------------------------------------------
# Cluster I/O.
# --------------------------------------------------------------------------


def kubectl(*args: str, stdin: "str | None" = None) -> str:
    cmd = ["kubectl", "-n", NAMESPACE, *args]
    try:
        proc = subprocess.run(
            cmd, input=stdin, capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        raise SubscriberError("kubectl not found on PATH") from None
    except subprocess.CalledProcessError as exc:
        raise SubscriberError(
            f"kubectl {' '.join(args)} failed:\n{exc.stderr.strip()}"
        ) from None
    return proc.stdout


def read_secret() -> "dict[str, str]":
    """Return the Secret's data, base64-decoded. Missing Secret -> empty."""
    try:
        raw = kubectl("get", "secret", SECRET_NAME, "-o", "json")
    except SubscriberError as exc:
        if "NotFound" in str(exc):
            return {}
        raise
    data = json.loads(raw).get("data") or {}
    return {k: base64.b64decode(v).decode() for k, v in data.items()}


def write_secret(data: "dict[str, str]") -> None:
    """Replace the Secret with exactly ``data`` (create-or-replace)."""
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": SECRET_NAME,
            "namespace": NAMESPACE,
            "labels": {
                "app.kubernetes.io/name": "channel-registry",
                "app.kubernetes.io/component": "auth",
            },
        },
        "type": "Opaque",
        "stringData": data,
    }
    kubectl("apply", "-f", "-", stdin=json.dumps(manifest))


def roll(deployment: str) -> None:
    kubectl("rollout", "restart", f"deployment/{deployment}")


def wait_rollout(deployment: str, timeout: str = "120s") -> None:
    kubectl("rollout", "status", f"deployment/{deployment}", f"--timeout={timeout}")


# --------------------------------------------------------------------------
# Parking. The credential is sealed to the EDGE's key before it leaves this
# process, so nothing between here and the edge — the temp file, scp, the
# spool, a backup of the spool — carries anything openable by its holder.
# --------------------------------------------------------------------------


def env_or_flag(flag_value: "str | None", env_name: str, what: str) -> str:
    """A missing input refuses and names the variable, the way publish.sh does.

    Silently defaulting one of these would mean parking to the wrong edge or
    sealing to the wrong key, and both fail at the customer rather than here.
    """
    value = flag_value or os.environ.get(env_name)
    if not value:
        raise SubscriberError(
            f"{what} is not set: pass the flag or set ${env_name} "
            "(see config/channel.example.env)"
        )
    return value


def deliver_park(record: dict, *, spool: "str | None", ssh: "str | None") -> str:
    """Put the park where the edge will read it. Local directory, or scp.

    Exactly one transport, chosen by the operator's site: a spool the publisher
    can write directly (a mount, a synced directory) or the standalone host over
    SSH, which is the transport § 5.4 already uses for this host. The local copy
    on the scp path is written 0600 into a 0700 temp directory and removed
    afterwards — it is ciphertext, but it is ciphertext with a fifteen-minute
    code beside it in somebody's terminal.
    """
    name = f"{record['station']}.park.json"
    if spool:
        return str(vexa_claim.write_park(pathlib.Path(spool).expanduser(), record))
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
        return target
    finally:
        shutil.rmtree(work, ignore_errors=True)


def park_preflight(args: argparse.Namespace, account: str) -> dict:
    """Resolve and check every park input BEFORE the mint.

    This runs first because the mint is destructive: `add` rotates, so the old
    credential stops working the moment the Secret is written. Discovering a
    missing recipients file afterwards would leave the subscriber locked out
    with nothing parked and nothing printed — a self-inflicted outage caused by
    a typo in a path. Everything that can be checked without minting is checked
    here, including one round-trip through `age`.
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
    # Encrypt a throwaway now. A recipients file that is present but malformed
    # fails here, on a value nobody needs, instead of after the rotation.
    vexa_claim.age_encrypt(recipients, "park-preflight")
    return {
        "station": vexa_claim.validate_station(args.station or account),
        "recipients": recipients,
        "edge": env_or_flag(args.edge, "CHANNEL_CLAIM_EDGE", "the claim endpoint URL"),
        "spool": spool,
        "ssh": ssh,
        "root": ledger_call(vexa_stations, vexa_stations.resolve_root, args.ledger),
        "channel": args.channel,
    }


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
    where = deliver_park(record, spool=ctx["spool"], ssh=ctx["ssh"])

    for line in (
        f"# parked for station {ctx['station']!r}, claimable at {ctx['edge']}",
        f"#   park      {where}",
        f"#   ledger    {out['path']} ({out['commit'] or 'no change'})",
        f"#   expires   {record['expires_at']} ({args.ttl // 60} minutes), "
        f"{record['max_attempts']} attempts, one redemption",
        "# read the second line below on the call; they run:",
        f"#   ./kit/claim.sh --code <code> --edge {ctx['edge']} "
        f"--station {ctx['station']} --namespace <their prod namespace>",
    ):
        print(line, file=sys.stderr)
    # Line 2 of stdout. Line 1 is the credential, unchanged; the code's alphabet
    # holds no ':' so the two lines can never be read as one another.
    print(vexa_claim.format_code(code))


# --------------------------------------------------------------------------
# Verbs.
# --------------------------------------------------------------------------


def cmd_list(args: argparse.Namespace) -> int:
    data = read_secret()
    entries = parse_htpasswd(data.get(HTPASSWD_KEY, ""))
    if not entries:
        print("no accounts on the channel registry")
        return 0
    width = max(len(u) for u in entries)
    print(f"{'ACCOUNT'.ljust(width)}  SCOPE      HASH")
    for user in sorted(entries):
        scope = "push+pull" if user == PUBLISHER_ACCOUNT else "pull"
        kind = "bcrypt" if is_bcrypt(entries[user]) else "NOT-BCRYPT"
        print(f"{user.ljust(width)}  {scope.ljust(9)}  {kind}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    name = validate_name(args.name)
    # Before the mint, because the mint rotates: see park_preflight.
    park_ctx = park_preflight(args, name) if args.park else None
    data = read_secret()
    current = data.get(HTPASSWD_KEY, "")
    existing = parse_htpasswd(current)
    rotating = name in existing

    password = generate_password()
    digest = bcrypt_hash(password)
    data[HTPASSWD_KEY] = add_entry(current, name, digest)

    rolls = [REGISTRY_DEPLOYMENT]
    if name == PUBLISHER_ACCOUNT:
        # The edge write gate checks the same credential; keep the two halves
        # in lockstep or a publish starts failing at the proxy.
        data[PUBLISHER_BCRYPT_KEY] = digest
        rolls.append(CADDY_DEPLOYMENT)
    elif PUBLISHER_BCRYPT_KEY not in data:
        raise SubscriberError(
            f"Secret has no {PUBLISHER_BCRYPT_KEY!r} key — add the 'publisher' "
            "account first, otherwise the Caddy edge cannot start"
        )

    write_secret(data)
    for dep in rolls:
        roll(dep)
    for dep in rolls:
        wait_rollout(dep)

    verb = "rotated" if rotating else "added"
    scope = "push+pull" if name == PUBLISHER_ACCOUNT else "pull only"
    # The one and only time this value is ever emitted.
    print(f"# {verb} {name} on channel.vexa.ai ({scope})", file=sys.stderr)
    print("# vault it now in your secrets store ($CHANNEL_CREDENTIAL_VAULT)", file=sys.stderr)
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
    data = read_secret()
    data[HTPASSWD_KEY] = remove_entry(data.get(HTPASSWD_KEY, ""), name)
    write_secret(data)
    roll(REGISTRY_DEPLOYMENT)
    wait_rollout(REGISTRY_DEPLOYMENT)
    print(f"revoked {name}; the credential no longer authenticates")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vexa_subscriber",
        description="Manage credentials on the Vexa channel registry (channel.vexa.ai).",
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
        "Seal the minted credential to the edge's key and park it under an "
        f"{vexa_claim.CODE_LENGTH}-character code you read on a call. Line 1 of "
        "stdout is still the credential, to vault; line 2 is the code.",
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
        "--force", action="store_true", help="allow revoking the publisher account"
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
