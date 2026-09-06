#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""claim-edge — `POST /claim`, the one endpoint that hands over a credential.

It sits beside the channel registry on the same host and behind the same Caddy
edge, which is the whole point: a subscriber already allowed `channel.vexa.ai`
through their firewall to pull, and claiming a credential must not cost them a
second host (RUNBOOK § 5.2).

    POST /claim   {"code": "123 456", "station": "pilot"}
              ->  200 {"station": ..., "username": ..., "password": ...}
              ->  403 {"error": "refused"}          for every other case
    GET  /healthz -> 200 {"ok": true}

ONE REFUSAL, ALWAYS THE SAME. Wrong code, expired code, already redeemed,
burned, never parked, malformed, rate-limited: identical status, identical body,
and no timing branch worth measuring. Which one it was is itself the oracle — a
distinguishable "expired" tells a guesser that the station exists and that a
code was recently live, and a distinguishable "wrong code" turns the burn
counter into a progress bar. The distinction is kept for US, in the attempts log
and the operator's ledger, where it is the whole diagnostic value.

TWO LIMITS, AND THEY ANSWER DIFFERENT CALLERS. Per source: ten attempts a
minute, then a fifteen-minute cooling period — one address never gets a second
window inside a code's fifteen-minute life. Per park: twenty requests a minute
from everyone, so a caller who brings a hundred addresses does not thereby bring
a hundred budgets. Neither is the cap that makes a six-digit code safe; the
five-attempt burn is, at 5 in 1,000,000. These are what stop the burn from being
walked around. The arithmetic is written out in README.md.

WHAT IT NEVER DOES: log a credential, log a code, write either to disk, echo
either into an error, or keep a decrypted value beyond the response it is
serving. The attempts log carries station, outcome, source and time, and the
`code_sha256` of the park it was aimed at — never of the code that was offered,
because that hash IS the code to anyone willing to spend a minute searching.

DEPLOYMENT: see README.md in this directory. This service has NOT been deployed
by the change that introduced it — the live edge is founder-owned.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vexa_claim  # noqa: E402

# A claim body is two short strings. Anything larger is not a claim, and reading
# it into memory before deciding that is how a small service becomes a memory
# exhaustion target.
MAX_BODY = 4096

REFUSED_BODY = json.dumps({"error": "refused"}).encode()


# A source gets ten tries a minute and is then told to go away for fifteen —
# which is a code's entire life, so no address gets a second window against the
# same code. Ten is well above what a real delivery needs (one request, or a
# handful if the line drops) and well below what a guesser needs against a
# million: at this rate, and ignoring the burn that stops it much sooner, one
# address would need over two and a half years to walk the space once.
RATE_LIMIT = 10
RATE_WINDOW = 60
RATE_COOLDOWN = 15 * 60

# ...and a station absorbs at most twenty requests a minute from EVERYONE. The
# five-attempt burn is what actually caps guessing; this is what stops a caller
# with a hundred addresses from buying a hundred separate ten-per-minute
# budgets against one park, and it keeps the attempts log from being something
# anyone can inflate at will. A real delivery makes one request.
PARK_RATE_LIMIT = 20

# How many keys a limiter tracks before it drops the ones that went quiet.
MAX_TRACKED = 10000


class RateLimiter:
    """Sliding window with a cooling period. Deliberately the boring one.

    It guards the ONLINE guess, which is the only attack on the code that the
    design has to answer — the five-attempt burn already caps guesses against
    any one park, so this exists to stop a caller sweeping many stations, to
    make extra source addresses buy nothing, and to keep a broken client from
    spending a subscriber's five attempts in a retry loop before anyone can pick
    up the phone.

    `cooldown` is what makes the limit bite rather than merely shape traffic: a
    source that trips it is refused for that whole period instead of resuming at
    the limit as soon as the window slides. Zero means no cooling period, which
    is right for the per-park limiter — burning a station out of service for
    fifteen minutes is a denial of the delivery, and the park has its own,
    stricter cap in the burn counter.

    In memory, so it resets when the service restarts. That is a real limit and
    it is stated rather than papered over: a restart is a visible event on a
    host one person operates, not something an attacker can induce from here.
    """

    def __init__(self, limit: int, window: int, cooldown: int = 0):
        self.limit = limit
        self.window = window
        self.cooldown = cooldown
        self.hits: "dict[str, collections.deque]" = {}
        self.blocked: "dict[str, float]" = {}
        self.lock = threading.Lock()

    def allow(self, source: str, now: "float | None" = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            until = self.blocked.get(source)
            if until is not None:
                if now < until:
                    # Not extended by the requests it refuses: a stuck client
                    # would otherwise never come back, and the operator would be
                    # debugging a permanent block that no rule states.
                    return False
                del self.blocked[source]
                self.hits.pop(source, None)

            seen = self.hits.setdefault(source, collections.deque())
            while seen and now - seen[0] > self.window:
                seen.popleft()
            if len(seen) >= self.limit:
                if self.cooldown:
                    self.blocked[source] = now + self.cooldown
                    del self.hits[source]
                return False
            seen.append(now)
            if len(self.hits) + len(self.blocked) > MAX_TRACKED:
                self.sweep(now)
            return True

    def sweep(self, now: float) -> None:
        """Drop every key nothing has touched for a window. Caller holds the lock.

        Keys that stopped calling must not accumulate: an unbounded dict keyed
        on a value the caller controls is the same memory target MAX_BODY closes,
        one layer up — and the per-park limiter is keyed on a STATION NAME, which
        arrives from the wire, so a caller can mint as many distinct keys as it
        can send requests. Dropping only the keys whose deque is already empty
        would drop nothing: a deque is pruned when its own key is next used, so a
        key that is never used again stays non-empty forever. The test is the
        last hit, not the current length.
        """
        for key in [k for k, v in self.hits.items()
                    if not v or now - v[-1] > self.window]:
            del self.hits[key]
        for key in [k for k, v in self.blocked.items() if v <= now]:
            del self.blocked[key]


class Config:
    def __init__(self, spool: str, identity: str, *, rate_limit: int, rate_window: int,
                 trust_forwarded_for: bool, rate_cooldown: int = RATE_COOLDOWN,
                 park_rate_limit: int = PARK_RATE_LIMIT):
        self.spool = pathlib.Path(spool).expanduser()
        self.identity = str(pathlib.Path(identity).expanduser())
        self.limiter = RateLimiter(rate_limit, rate_window, rate_cooldown)
        # No cooling period, by the argument in RateLimiter's docstring.
        self.park_limiter = RateLimiter(park_rate_limit, rate_window)
        self.trust_forwarded_for = trust_forwarded_for

    @classmethod
    def from_env(cls, env=None) -> "Config":
        env = os.environ if env is None else env
        missing = [k for k in ("CLAIM_SPOOL", "CLAIM_IDENTITY") if not env.get(k)]
        if missing:
            raise vexa_claim.ClaimError(f"missing environment: {', '.join(missing)}")
        return cls(
            env["CLAIM_SPOOL"],
            env["CLAIM_IDENTITY"],
            rate_limit=int(env.get("CLAIM_RATE_LIMIT", str(RATE_LIMIT))),
            rate_window=int(env.get("CLAIM_RATE_WINDOW", str(RATE_WINDOW))),
            rate_cooldown=int(env.get("CLAIM_RATE_COOLDOWN", str(RATE_COOLDOWN))),
            park_rate_limit=int(env.get("CLAIM_PARK_RATE_LIMIT",
                                        str(PARK_RATE_LIMIT))),
            # OFF by default, and that default is the safe one. Behind Caddy the
            # real source is in X-Forwarded-For; reached directly, that header is
            # whatever the caller typed, so trusting it unconditionally would
            # give every guesser a fresh rate-limit bucket per request.
            trust_forwarded_for=env.get("CLAIM_TRUST_FORWARDED_FOR", "") == "1",
        )

    def check(self) -> None:
        if not pathlib.Path(self.identity).is_file():
            raise vexa_claim.ClaimError(f"age identity not found: {self.identity}")
        if not vexa_claim.identity_is_private(self.identity):
            raise vexa_claim.ClaimError(
                f"{self.identity} is group- or world-readable. chmod 600 it: on a "
                "host that also serves HTTP this is the whole scheme undone, and "
                "it fails silently — everything works exactly as well as it does "
                "when the file is correct."
            )
        if not vexa_claim.have_age():
            raise vexa_claim.ClaimError("the `age` binary is not on PATH")
        self.spool.mkdir(parents=True, exist_ok=True)

    def decrypt(self, armor: str) -> str:
        return vexa_claim.age_decrypt(self.identity, armor)


def serve_claim(config: Config, body: bytes, source: str) -> "tuple[int, bytes]":
    """One claim, start to finish. Pure enough to test without a socket."""
    station = None
    park_id = None
    park_hash = None
    try:
        if not config.limiter.allow(source):
            raise vexa_claim.ClaimRefused(vexa_claim.REFUSAL_RATE_LIMITED)
        try:
            payload = json.loads(body)
            station = vexa_claim.validate_station(payload["station"])
            code = payload["code"]
        except (json.JSONDecodeError, KeyError, TypeError, vexa_claim.ClaimError):
            raise vexa_claim.ClaimRefused(vexa_claim.REFUSAL_MALFORMED) from None

        # After the parse, because it is keyed on the station, and before the
        # state machine, because a request that never reaches the state machine
        # must not cost the subscriber one of their five attempts.
        if not config.park_limiter.allow(station):
            raise vexa_claim.ClaimRefused(vexa_claim.REFUSAL_PARK_RATE_LIMITED)

        park = vexa_claim.read_json(vexa_claim.park_path(config.spool, station))
        if park:
            park_id = park.get("park_id")
            park_hash = park.get("code_sha256")
        result = vexa_claim.redeem(
            config.spool, station=station, code=code, decrypt=config.decrypt
        )
    except vexa_claim.ClaimRefused as refusal:
        log_attempt(config, station, refusal.reason, source, park_id, park_hash)
        return HTTPStatus.FORBIDDEN, REFUSED_BODY
    except vexa_claim.ClaimError as exc:
        # OUR fault, not theirs: a park sealed to a rotated key, an unreadable
        # spool. `redeem` has already declined to burn the park over it, and the
        # caller is told to retry rather than that they got it wrong.
        log_attempt(config, station, f"error:{exc}", source, park_id, park_hash)
        return HTTPStatus.SERVICE_UNAVAILABLE, json.dumps(
            {"error": "unavailable"}
        ).encode()

    log_attempt(config, station, "claimed", source, park_id, park_hash)
    return HTTPStatus.OK, json.dumps(result).encode()


def log_attempt(config: Config, station, outcome, source, park_id, park_hash) -> None:
    vexa_claim.append_attempt(
        config.spool,
        vexa_claim.attempt_event(
            station=station or vexa_claim.UNATTRIBUTED,
            outcome=outcome,
            source=source,
            park_id=park_id,
            # The hash of the PARK, so the ledger can bind this attempt to the
            # row `add --park` wrote. Never a hash of what the caller offered.
            code_sha256_hex=park_hash,
        ),
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "vexa-claim-edge"
    sys_version = ""
    config: Config

    def _respond(self, status, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def source(self) -> str:
        if self.config.trust_forwarded_for:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()[:64]
        return self.client_address[0]

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        if self.path == "/healthz":
            self._respond(HTTPStatus.OK, json.dumps({"ok": True}).encode())
            return
        self._respond(HTTPStatus.NOT_FOUND, json.dumps({"error": "not found"}).encode())

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/claim":
            self._respond(HTTPStatus.NOT_FOUND,
                          json.dumps({"error": "not found"}).encode())
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._respond(HTTPStatus.FORBIDDEN, REFUSED_BODY)
            return
        status, body = serve_claim(self.config, self.rfile.read(length), self.source())
        self._respond(status, body)

    def log_message(self, fmt, *args) -> None:
        """Access logging goes to the attempts log, not here.

        The default handler prints the request line. A future maintainer adding
        the body to it — the obvious next step when debugging a 403 — would put
        a live claim code in the journal, so the line does not exist to extend.
        """
        sys.stderr.write(
            f"{self.address_string()} {self.command} {self.path.split('?')[0]}\n"
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="claim_edge",
        description="Serve POST /claim: hand a parked credential to the station "
                    "that names the right code, once.",
    )
    p.add_argument("--listen", default=os.environ.get("CLAIM_LISTEN", "127.0.0.1:8088"),
                   help="host:port to bind (default: $CLAIM_LISTEN or 127.0.0.1:8088; "
                        "TLS is Caddy's, upstream of this process)")
    p.add_argument("--check", action="store_true",
                   help="validate configuration and exit, serving nothing")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = Config.from_env()
        config.check()
    except vexa_claim.ClaimError as exc:
        print(f"claim-edge: {exc}", file=sys.stderr)
        return 2
    if args.check:
        print(f"claim-edge: config OK (spool {config.spool}, identity mode 600)")
        return 0

    host, _, port = args.listen.rpartition(":")
    Handler.config = config
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    print(f"claim-edge: listening on {args.listen}, spool {config.spool}",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
