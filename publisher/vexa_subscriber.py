#!/usr/bin/env python3
"""vexa_subscriber — manage credentials on the Vexa channel registry.

The channel registry (``channel.vexa.ai``, namespace ``channel-registry`` in the
production LKE cluster) authenticates with an htpasswd file held in the
``registry-htpasswd`` Secret. This tool is the ONLY supported way to change it:
it mints the password, writes the bcrypt line, patches the Secret and rolls the
Deployment(s) that consume it.

    python3 publisher/vexa_subscriber.py list
    python3 publisher/vexa_subscriber.py add pilot
    python3 publisher/vexa_subscriber.py revoke pilot

Two things it deliberately does NOT do:

* it never writes the password anywhere — not to a file, not to a log, not to
  the process title. ``add`` prints it once to stdout and forgets it. Vault it
  in the operator's secrets vault immediately, and deliver
  it to the subscriber age-encrypted to their SSH key (see
  ``onboarding/credential-delivery.md``);
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
import secrets
import string
import subprocess
import sys

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
    except SubscriberError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
