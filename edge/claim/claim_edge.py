#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""claim-edge — `POST /claim`, the one endpoint that hands over a credential.

It sits beside the channel registry on the same host and behind the same Caddy
edge, which is the whole point: a subscriber already allowed `channel.vexa.ai`
through their firewall to pull, and claiming a credential must not cost them a
second host (RUNBOOK § 5.2).

    POST /claim   {"code": "ABCD-EFGH", "station": "pilot"}
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


class RateLimiter:
    """Fixed window per source. Deliberately the boring one.

    It guards the ONLINE guess, which is the only attack on the code that the
    design has to answer — the five-attempt burn already caps guesses against
    any one park, so this exists to stop a caller sweeping many stations, and to
    keep a broken client from spending a subscriber's five attempts in a retry
    loop before anyone can pick up the phone.

    In memory, so it resets when the service restarts. That is a real limit and
    it is stated rather than papered over: a restart is a visible event on a
    host one person operates, not something an attacker can induce from here.
    """

    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self.hits: "dict[str, collections.deque]" = {}
        self.lock = threading.Lock()

    def allow(self, source: str, now: "float | None" = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            seen = self.hits.setdefault(source, collections.deque())
            while seen and now - seen[0] > self.window:
                seen.popleft()
            if len(seen) >= self.limit:
                return False
            seen.append(now)
            # Sources that stopped calling must not accumulate: an unbounded
            # dict keyed on a value the caller controls is the same memory
            # target MAX_BODY closes, one layer up.
            if len(self.hits) > 10000:
                for key in [k for k, v in self.hits.items() if not v]:
                    del self.hits[key]
            return True


class Config:
    def __init__(self, spool: str, identity: str, *, rate_limit: int, rate_window: int,
                 trust_forwarded_for: bool):
        self.spool = pathlib.Path(spool).expanduser()
        self.identity = str(pathlib.Path(identity).expanduser())
        self.limiter = RateLimiter(rate_limit, rate_window)
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
            rate_limit=int(env.get("CLAIM_RATE_LIMIT", "20")),
            rate_window=int(env.get("CLAIM_RATE_WINDOW", "60")),
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
