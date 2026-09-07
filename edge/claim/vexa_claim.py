#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa_claim — the park format and the claim state machine.

ONE definition, read by both ends. The publisher (`vexa_subscriber.py add
--park`) writes a park record; this service reads it. A format with two
definitions drifts silently and the drift only shows up on the one call where
somebody is reading a code aloud, so the module lives here — beside the service
that owns the spool — and `publisher/vexa_subscriber.py` imports it across the
tree rather than keeping a second copy.

WHAT IS SECRET, AND WHAT PROTECTS IT

  the credential   protected by the age envelope. The publisher encrypts to a
                   recipient whose private half exists only on the edge host,
                   so the ciphertext is inert everywhere it travels: in the
                   spool, in a backup, in transit, in this file's tests.
  the claim code   protected by TTL, one redemption, five failed attempts, and
                   rate limiting at the service. NOT by its digest.

A SIX-DIGIT CODE IS ONE OF A MILLION, AND THE COUNTING IS WHAT MAKES THAT SAFE.
Five failed attempts burn the park, so an online guesser gets five tries at
1,000,000: one in 200,000, once, before the park is dead and we have to place a
new one. The service adds a per-source limit and a per-park limit on top so that
renting more addresses buys no more guesses (`claim_edge.py`, and the arithmetic
in README.md). Digits are the point: the code is read down a phone line, in
whatever language the two people share, and `B`/`V`/`P` do not survive that.

THE DIGEST IS SALTED, AND AT SIX DIGITS THAT IS NOT OPTIONAL. `code_sha256` is
taken over `code_salt` and the code; the salt lives in the park file, which is
0600 on the edge host and deleted the moment the park goes terminal. A bare
SHA-256 of six digits is a million-candidate search — milliseconds — and the
digest is copied into the stations ledger, which is a git repository read by
more people, for longer, than the spool ever is. Unsalted, that row WOULD be the
code for as long as the park is live. Salted, it is what it is meant to be: a
commitment that binds an attempt to the park `add --park` wrote, and nothing an
offline reader can invert.

THE PARK IS PER STATION, AND THAT IS WHY THE BURN COUNTER MEANS ANYTHING.

A claim is `{code, station}`. The station is not secret — it is in the
subscriber's own onboarding pack — so it is the LOOKUP, and the code is the
SECRET compared against the park it finds. Count failures against the park the
station names and five of them burn it. Had the code been the lookup key
instead, a wrong code would have found no record, there would have been nothing
to count against, and the five-attempt burn would have been decoration: it
could only ever have fired on a caller who already had the right code.

Files in the spool, one writer each:

    <station>.park.json              publisher   immutable; holds the ciphertext
    <station>.<park_id>.state.json   the edge     attempts and terminal state
    attempts.ndjson                  the edge     every attempt, append-only

A new park mints a new `park_id`, so it gets a NEW state file rather than
resetting one this process does not own. The publisher never edits state and
the edge never edits a park — it only deletes it, on any terminal outcome, so
the ciphertext stops existing the moment the code dies. The identifying facts
are copied into the state file first, so the record survives the deletion.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import subprocess
import tempfile
import threading

SCHEMA_VERSION = 1

# DIGITS, because the code is said out loud on a call and digits are the one
# alphabet that survives a phone line in any language: no B/V/P confusion, no
# spelling alphabet to agree on first, no case to lose, and every listener
# already knows how to write them down. Six of ten: 1,000,000 codes. The
# confusable-character question that shapes an alphanumeric alphabet does not
# arise — there is nothing here to confuse with anything.
CODE_ALPHABET = "0123456789"
CODE_LENGTH = 6

# Fifteen minutes: long enough to finish the sentence "run this now while we are
# both on the call", short enough that a code overheard in a recording is dead
# before anyone transcribes it. The window is the point — a code with a generous
# TTL is a password with extra steps.
TTL_SECONDS = 15 * 60

# Five is the cap that makes a million enough. It is not a usability number: it
# is the numerator of the guesser's odds, 5/1,000,000, and every attempt from
# every source counts against the same park, so a distributed caller does not
# get a fresh five by changing address.
MAX_ATTEMPTS = 5

STATION_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")

# The station of an attempt whose body never parsed. Chosen because it can
# never BE a station name (STATION_RE requires a leading alphanumeric), so the
# ledger can route it aside instead of mistaking it for one — and it must be
# routed aside: one junk POST at the endpoint used to refuse a whole batch of
# real events, which would have blocked the return leg for as long as anyone
# was probing.
UNATTRIBUTED = "-"

LIVE = "live"
REDEEMED = "redeemed"
BURNED = "burned"
EXPIRED = "expired"

# Every refusal the service can emit. They are DISTINCT HERE and IDENTICAL ON
# THE WIRE: the operator's log needs to tell "expired" from "wrong code", and
# the caller must not, because which one it was is itself the oracle.
REFUSAL_NO_PARK = "no-park"
REFUSAL_WRONG_CODE = "wrong-code"
REFUSAL_EXPIRED = "expired"
REFUSAL_BURNED = "burned"
REFUSAL_SPENT = "spent"
REFUSAL_MALFORMED = "malformed"
REFUSAL_RATE_LIMITED = "rate-limited"
# One source over its limit vs. many sources converging on one station. Both are
# `403` on the wire; in the ledger they are different events, and the second is
# the one that says somebody brought more than one address.
REFUSAL_PARK_RATE_LIMITED = "park-rate-limited"


class ClaimError(Exception):
    """Anything the operator caused and can fix."""


class ClaimRefused(Exception):
    """A claim that will not be served. `reason` is for our log, never the wire."""

    def __init__(self, reason: str, *, burned: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.burned = burned


# --------------------------------------------------------------------------
# Codes. Pure; no I/O, no clock.
# --------------------------------------------------------------------------


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def stamp(when: datetime.datetime) -> str:
    return when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stamp(text: str) -> datetime.datetime:
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def generate_code(length: int = CODE_LENGTH) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))


def normalise_code(raw: str) -> str:
    """Drop the separators a human types, then refuse anything else.

    Spaces and hyphens come back because we PRINT the code grouped (`123 456`)
    and somebody will type it back with the space, or with a dash, or with
    neither. All three are the same code. Nothing else is repaired: a character
    outside the alphabet is not a near-miss to be guessed at, it is a code this
    system never issued.
    """
    if not isinstance(raw, str):
        raise ClaimError("claim code must be a string")
    text = re.sub(r"[\s\-]", "", raw)
    if len(text) != CODE_LENGTH or not set(text) <= set(CODE_ALPHABET):
        raise ClaimError(f"claim code must be {CODE_LENGTH} digits")
    return text


def format_code(code: str) -> str:
    """`123 456` — the shape a person reads aloud without losing their place.

    A space, not a dash: it is spoken, and "one two three, four five six" is
    what the space means. A dash invites somebody to type one, which is why
    `normalise_code` accepts that too.
    """
    half = len(code) // 2
    return f"{code[:half]} {code[half:]}"


def new_salt() -> str:
    """Per-park, 128 bits. It lives in the park file and nowhere else."""
    return secrets.token_hex(16)


def code_sha256(salt: str, code: str) -> str:
    """The verifier. SALTED — see the module docstring: a bare digest of six
    digits is a million-candidate search, and this value is copied into a git
    ledger that outlives the park by years."""
    return hashlib.sha256(f"{salt}:{normalise_code(code)}".encode()).hexdigest()


def codes_match(salt: str, code: str, digest: str) -> bool:
    """Constant-time. The comparison is over hex digests, so an early-exit
    memcmp would leak a prefix of the digest — and a prefix of the digest, for a
    caller who also holds the salt, is a prefix of the code."""
    return hmac.compare_digest(code_sha256(salt, code), digest)


def validate_station(name: str) -> str:
    """Station names index into the spool as filenames, and they arrive from the
    wire. `../../etc/shadow` is a station name until something says otherwise."""
    if not isinstance(name, str) or not STATION_RE.match(name):
        raise ClaimError(
            f"station name {name!r} must match {STATION_RE.pattern}"
        )
    return name


# --------------------------------------------------------------------------
# The age envelope. Both directions shell out to `age` rather than composing
# primitives here: the one thing this module must not do is invent a scheme.
# --------------------------------------------------------------------------


def have_age() -> bool:
    try:
        subprocess.run(["age", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return True


def _age(args: list[str], stdin: bytes) -> bytes:
    try:
        proc = subprocess.run(["age", *args], input=stdin, capture_output=True)
    except FileNotFoundError:
        raise ClaimError(
            "the `age` binary is not on PATH — brew install age / apt-get install age"
        ) from None
    if proc.returncode != 0:
        # age writes its diagnosis to stderr and never echoes the payload, so
        # this is safe to surface. Do not add the stdin to it.
        raise ClaimError(f"age failed: {proc.stderr.decode().strip()}")
    return proc.stdout


def age_encrypt(recipients_file: str, plaintext: str) -> str:
    """Armored ciphertext for the edge's recipients file.

    `-R` takes a file of recipients — the same shape `age -R github.keys` takes
    in onboarding/credential-delivery.md, so an operator who has done the
    age-encrypt handoff recognises this one.
    """
    path = pathlib.Path(recipients_file).expanduser()
    if not path.is_file():
        raise ClaimError(f"edge recipients file not found: {path}")
    if not path.read_text().strip():
        raise ClaimError(f"edge recipients file is empty: {path}")
    return _age(["-R", str(path), "-a"], plaintext.encode()).decode()


def age_decrypt(identity_file: str, armor: str) -> str:
    path = pathlib.Path(identity_file).expanduser()
    if not path.is_file():
        raise ClaimError(f"age identity file not found: {path}")
    return _age(["-d", "-i", str(path)], armor.encode()).decode()


def identity_is_private(identity_file: str) -> bool:
    """The edge's private half must not be group- or world-readable.

    Checked at startup rather than trusted: a 0644 identity on a host that also
    serves HTTP is the whole scheme undone, and it fails silently — everything
    works exactly as well as it does when the file is 0600.
    """
    mode = pathlib.Path(identity_file).expanduser().stat().st_mode
    return not mode & 0o077


# --------------------------------------------------------------------------
# The park record. Written by the publisher, never edited afterwards.
# --------------------------------------------------------------------------


def park_path(spool: pathlib.Path, station: str) -> pathlib.Path:
    return spool / f"{validate_station(station)}.park.json"


def state_path(spool: pathlib.Path, station: str, park_id: str) -> pathlib.Path:
    if not re.match(r"^[0-9a-f]{16}$", park_id):
        raise ClaimError(f"park_id {park_id!r} is not 16 hex characters")
    return spool / f"{validate_station(station)}.{park_id}.state.json"


def attempts_path(spool: pathlib.Path) -> pathlib.Path:
    return spool / "attempts.ndjson"


def build_park(
    *,
    station: str,
    account: str,
    code: str,
    ciphertext: str,
    parked_by: str,
    edge: str,
    now: "datetime.datetime | None" = None,
    ttl_seconds: int = TTL_SECONDS,
    max_attempts: int = MAX_ATTEMPTS,
    rotation: bool = False,
) -> dict:
    """The record, with the credential already sealed by the caller.

    `ciphertext` arrives encrypted. This function never sees a password and
    there is deliberately no parameter through which one could be passed —
    the sealing happens one layer up, where the recipients file is named.
    """
    if not ciphertext.startswith("-----BEGIN AGE ENCRYPTED FILE-----"):
        raise ClaimError(
            "park ciphertext is not an armored age file — refusing to write a "
            "park whose payload may be plaintext"
        )
    when = now or utcnow()
    salt = new_salt()
    return {
        "schema_version": SCHEMA_VERSION,
        "park_id": secrets.token_hex(8),
        "station": validate_station(station),
        "account": account,
        # The salt stays HERE. `new_state` and `vexa_stations.park_event` copy
        # the digest and not the salt, which is what keeps the ledger row from
        # being the code.
        "code_salt": salt,
        "code_sha256": code_sha256(salt, code),
        "parked_at": stamp(when),
        "expires_at": stamp(when + datetime.timedelta(seconds=ttl_seconds)),
        "ttl_seconds": ttl_seconds,
        "max_attempts": max_attempts,
        "parked_by": parked_by,
        "edge": edge,
        "rotation": rotation,
        "ciphertext": ciphertext,
    }


def write_park(spool: pathlib.Path, record: dict) -> pathlib.Path:
    """Write the park, superseding any park already live for that station.

    Superseding is the correct behaviour and not a race: parking again IS the
    rotation path (`add` rotates), and the new park's own `park_id` means the
    edge starts a fresh state file rather than inheriting a counter from a code
    that no longer exists.
    """
    spool.mkdir(parents=True, exist_ok=True)
    path = park_path(spool, record["station"])
    # 0600 before a byte lands. Writing then chmod-ing leaves a window in which
    # the ciphertext is world-readable, which is a smaller hole than it sounds
    # and still a hole nobody needs.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(record, fh, indent=1)
        fh.write("\n")
    return path


def read_json(path: pathlib.Path) -> "dict | None":
    """A record in the spool, None if there is none — and a ClaimError, never a
    bare exception, if there is one this process cannot open.

    A park that exists but cannot be read is OUR misconfiguration, not the
    caller's, so it must take the same path as a park sealed to a rotated key:
    `503`, an `error:` row in the attempts log, and no attempt spent. Before this
    was caught, a `PermissionError` escaped the handler and the connection was
    dropped without an answer — which, through Caddy, reached the subscriber as
    a `502`, and reached nobody's log at all. The way it happens in practice is
    a park delivered by `scp` as root into a spool owned by 65532 (2026-09-06
    receipt, finding 4); the message says so and names the fix.
    """
    if not path.is_file():
        return None
    try:
        text = path.read_text()
    except PermissionError:
        raise ClaimError(
            f"{path.name} exists but uid {os.getuid()} cannot read it: it was "
            "delivered with the wrong owner — on the edge host, chown it to the "
            "spool's owner (edge/claim/README.md § Deploy)"
        ) from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ClaimError(f"{path} is not readable JSON: {exc}") from None


def unreadable_parks(spool: pathlib.Path) -> "list[pathlib.Path]":
    """Every park in the spool this process cannot open. Deploy-time check."""
    found = []
    for park in sorted(spool.glob("*.park.json")):
        try:
            with open(park, "rb"):
                pass
        except PermissionError:
            found.append(park)
    return found


def write_state(spool: pathlib.Path, state: dict) -> pathlib.Path:
    path = state_path(spool, state["station"], state["park_id"])
    tmp = pathlib.Path(
        tempfile.mkstemp(dir=str(spool), prefix=".state-", suffix=".tmp")[1]
    )
    tmp.write_text(json.dumps(state, indent=1) + "\n")
    tmp.chmod(0o600)
    # Atomic: a crash mid-write must not leave a state file that reads as
    # `live` with a lost attempt count.
    tmp.replace(path)
    return path


def new_state(park: dict, now: datetime.datetime) -> dict:
    """The identifying facts are COPIED here, because the park file is deleted
    on any terminal outcome and this is what is left to read afterwards."""
    return {
        "schema_version": SCHEMA_VERSION,
        "park_id": park["park_id"],
        "station": park["station"],
        "account": park.get("account"),
        "code_sha256": park["code_sha256"],
        "parked_at": park["parked_at"],
        "expires_at": park["expires_at"],
        "max_attempts": park.get("max_attempts", MAX_ATTEMPTS),
        "state": LIVE,
        "attempts": 0,
        "first_seen_at": stamp(now),
        "terminal_at": None,
        "terminal_reason": None,
    }


def load_state(spool: pathlib.Path, park: dict, now: datetime.datetime) -> dict:
    return read_json(state_path(spool, park["station"], park["park_id"])) or new_state(
        park, now
    )


# --------------------------------------------------------------------------
# The state machine. `decrypt` is injected so the transitions can be tested
# without an age keypair — the transitions are the part that decides who gets
# a credential, and they must be provable in CI, where `age` is not installed.
# --------------------------------------------------------------------------


def terminate(
    spool: pathlib.Path, state: dict, outcome: str, reason: str, now: datetime.datetime
) -> dict:
    state["state"] = outcome
    state["terminal_at"] = stamp(now)
    state["terminal_reason"] = reason
    write_state(spool, state)
    # The ciphertext stops existing here. Not "is marked dead" — is removed.
    park_path(spool, state["station"]).unlink(missing_ok=True)
    return state


def redeem(
    spool: pathlib.Path,
    *,
    station: str,
    code: str,
    decrypt,
    now: "datetime.datetime | None" = None,
) -> dict:
    """Serve one claim, or raise ClaimRefused with the reason for OUR log.

    Order matters and is not arbitrary: expiry is checked before the code, so a
    caller who arrives late with the RIGHT code retires the park as `expired`
    rather than spending one of its five attempts on a code that was correct.
    """
    now = now or utcnow()
    station = validate_station(station)
    park = read_json(park_path(spool, station))
    if park is None:
        # Covers three cases the caller must not be able to tell apart: never
        # parked, already redeemed, already burned.
        raise ClaimRefused(REFUSAL_NO_PARK)

    state = load_state(spool, park, now)
    if state["state"] != LIVE:
        raise ClaimRefused(REFUSAL_SPENT)

    if now >= parse_stamp(park["expires_at"]):
        terminate(spool, state, EXPIRED, "ttl elapsed", now)
        raise ClaimRefused(REFUSAL_EXPIRED)

    salt = park.get("code_salt")
    if not salt:
        # A park with no salt cannot be verified against, and guessing that it
        # is an unsalted digest would be inventing a scheme. OUR problem, so it
        # takes the 503 path and leaves the park alone rather than burning a
        # code the caller may well have got right.
        raise ClaimError(
            f"park for station {station!r} carries no code_salt — it was written "
            "by an incompatible publisher; park again, which rotates"
        )

    try:
        matched = codes_match(salt, code, park["code_sha256"])
    except ClaimError:
        # A code outside the alphabet, of the wrong length, or not a string at
        # all CANNOT match, so it takes the same branch as a wrong one. It used
        # to escape as a ClaimError, which the service answered `503` while a
        # merely wrong code got `403` — a free oracle separating "malformed" from
        # "wrong", on the one value the whole design keeps secret. One branch,
        # one answer, and it costs an attempt like any other failed claim.
        matched = False
    if not matched:
        state["attempts"] += 1
        if state["attempts"] >= state["max_attempts"]:
            terminate(
                spool,
                state,
                BURNED,
                f"{state['attempts']} failed attempts",
                now,
            )
            raise ClaimRefused(REFUSAL_BURNED, burned=True)
        write_state(spool, state)
        raise ClaimRefused(REFUSAL_WRONG_CODE)

    # Decrypt BEFORE terminating. A decryption failure is our misconfiguration
    # — the wrong identity file, a park sealed to a rotated key — and burning
    # the subscriber's only code over our own mistake would make them wait for
    # a new one for no reason.
    credential = json.loads(decrypt(park["ciphertext"]))
    terminate(spool, state, REDEEMED, "claimed", now)
    return {
        "station": park["station"],
        "username": credential["username"],
        "password": credential["password"],
    }


_SEQ_LOCK = threading.Lock()
_SEQ: "dict[str, int]" = {}


def last_seq(path: pathlib.Path) -> int:
    """The highest `seq` already in a log, or 0. Read once per spool."""
    if not path.is_file():
        return 0
    highest = 0
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line).get("seq")
            except json.JSONDecodeError:
                continue
            if isinstance(value, int) and value > highest:
                highest = value
    return highest


def next_seq(spool: pathlib.Path) -> int:
    """The next attempt number for this spool. Monotonic, and it survives a
    restart by reading the log it is about to be appended to."""
    key = str(pathlib.Path(spool).resolve())
    with _SEQ_LOCK:
        seq = _SEQ.get(key)
        if seq is None:
            seq = last_seq(attempts_path(spool))
        seq += 1
        _SEQ[key] = seq
        return seq


def append_attempt(spool: pathlib.Path, event: dict) -> None:
    """One line per attempt, append-only, NEVER the value.

    This file is the edge's half of the ledger's return path: the operator
    copies it back and `vexa_stations.py record-credential` reduces it into
    `credential-events.yaml` beside the station's state.

    THE SEQUENCE IS STAMPED HERE, AND IT IS WHAT KEEPS THE COUNT. That reducer
    deduplicates on the whole event, which is what makes re-ingesting the same
    log a no-op with no cursor for anyone to maintain — but `ts` is
    second-resolution, so ten identical attempts inside one second were ten
    identical rows and the ledger kept ONE. A burst read exactly like a single
    request in the record that exists to show bursts (2026-09-07 rehearsal,
    finding 3: ten `no-park` attempts became one row while the spool kept all
    ten). One monotonic number per attempt makes the rows distinct without
    making re-ingest add anything: it is written into the log once, so a second
    copy of that log carries the same numbers.

    A sequence rather than a sub-second timestamp because it also shows what a
    finer clock would not: a GAP is a line that left this file. It is monotonic
    per spool and continues across a restart, because it is seeded from the log
    itself; if the log is rotated away it starts again, which is why the
    reducer still compares whole rows rather than trusting the number alone.
    """
    spool.mkdir(parents=True, exist_ok=True)
    path = attempts_path(spool)
    event = {**event, "seq": next_seq(spool)}
    with open(path, "a") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")


def attempt_event(
    *,
    station: str,
    outcome: str,
    source: str,
    now: "datetime.datetime | None" = None,
    park_id: "str | None" = None,
    code_sha256_hex: "str | None" = None,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "event": "claim",
        "ts": stamp(now or utcnow()),
        "station": station,
        "outcome": outcome,
        "source": source,
        "park_id": park_id,
        "code_sha256": code_sha256_hex,
    }
