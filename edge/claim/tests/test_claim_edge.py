# SPDX-License-Identifier: Apache-2.0
"""The claim edge over a real socket, against a fixture spool.

`test_claim.py` proves the transitions. This proves the SERVICE: that every
refusal is byte-identical on the wire, that the rate limiter fires, that the
attempts log gets the outcome the transition produced, and that nothing anywhere
in the response path or the log carries a credential or a code.

No age keypair: `decrypt` is injected into the Config the same way the state
machine takes it, so this runs in CI where the binary is absent. The one real
envelope is proved in test_claim.py.
"""

import contextlib
import datetime
import io
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import claim_edge as ce  # noqa: E402
import vexa_claim as vc  # noqa: E402


def stub_server(status, body=b"", headers=None):
    """Something that is NOT the claim service, answering on a real socket:
    the Caddy write gate (401), a registry's 404, a proxy with a dead upstream
    (502), a captive portal (200), a redirect."""

    class Stub(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST  # noqa: N815

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever,
                     kwargs={"poll_interval": 0.02}, daemon=True).start()
    return server


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

ARMOR = "-----BEGIN AGE ENCRYPTED FILE-----\nfixture\n-----END AGE ENCRYPTED FILE-----\n"
# The needle. A leak is a test failure rather than something a reviewer has to
# notice in a log they were skimming.
NEEDLE = "PW-FIXTURE-NEVER-REAL"
CREDENTIAL = {"username": "pilot", "password": NEEDLE}


class FixtureConfig(ce.Config):
    """The real Config with the age call replaced. Everything else — the spool,
    the limiter, the forwarded-for policy — is the production object."""

    def __init__(self, spool, **kw):
        # Both limits raised out of the way, so a test that is about something
        # else never trips one by accident. The limits get their own tests.
        kw.setdefault("rate_limit", 100)
        kw.setdefault("rate_window", 60)
        kw.setdefault("park_rate_limit", 100)
        kw.setdefault("trust_forwarded_for", False)
        super().__init__(str(spool), "/dev/null", **kw)

    def decrypt(self, armor):
        assert armor == ARMOR
        return json.dumps(CREDENTIAL)


class EdgeCase(unittest.TestCase):
    def setUp(self):
        self.spool = pathlib.Path(tempfile.mkdtemp(prefix="vexa-edge-"))
        self.config = FixtureConfig(self.spool)
        ce.Handler.config = self.config
        # The access line is real behaviour and stays in the service; here it
        # would put forty lines of noise into `make test` for no assertion.
        ce.Handler.log_message = lambda *a, **k: None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ce.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def park(self, code, station="pilot", **kw):
        record = vc.build_park(
            station=station, account="pilot", code=code, ciphertext=ARMOR,
            parked_by="tester", edge="https://channel.example/claim", **kw)
        vc.write_park(self.spool, record)
        return record

    def post(self, payload, path="/claim", headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + path, data=body, method="POST",
            headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def attempts(self):
        path = vc.attempts_path(self.spool)
        if not path.is_file():
            return []
        return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]

    # ------------------------------------------------------------------ paths

    def test_healthz(self):
        with urllib.request.urlopen(self.base + "/healthz") as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read()), {"ok": True})

    def test_only_claim_accepts_a_post(self):
        self.park("123456")
        status, _ = self.post({"code": "123456", "station": "pilot"}, path="/claims")
        self.assertEqual(status, 404)
        # ...and the park is untouched: a wrong path is not an attempt.
        self.assertTrue(vc.park_path(self.spool, "pilot").exists())

    # ----------------------------------------------------------------- claims

    def test_a_valid_claim_returns_the_credential_once(self):
        self.park("123456")
        status, body = self.post({"code": "123 456", "station": "pilot"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body),
                         {"station": "pilot", **CREDENTIAL})
        status, body = self.post({"code": "123456", "station": "pilot"})
        self.assertEqual(status, 403)
        self.assertNotIn(NEEDLE.encode(), body)

    def test_every_refusal_is_byte_identical(self):
        # The single most important property on the wire. A distinguishable
        # "expired" tells a guesser the station exists and a code was recently
        # live; a distinguishable "wrong code" turns the burn counter into a
        # progress bar.
        self.park("123456", station="pilot")
        self.park("654321", station="expired",
                  now=vc.utcnow() - datetime.timedelta(hours=1))
        responses = [
            self.post({"code": "222222", "station": "pilot"}),       # wrong code
            self.post({"code": "654321", "station": "expired"}),     # expired
            self.post({"code": "123456", "station": "absent"}),      # never parked
            self.post({"code": "123456", "station": "../etc"}),      # bad station
            self.post({"code": "!!!", "station": "pilot"}),            # bad code
            self.post({"code": 123456, "station": "pilot"}),         # code not a string
            self.post(b"{not json"),                                   # malformed
            self.post({"station": "pilot"}),                           # no code
        ]
        for status, body in responses:
            self.assertEqual(status, 403)
            self.assertEqual(body, ce.REFUSED_BODY)
        self.assertEqual(len({r for r in responses}), 1)

    def test_our_own_failure_is_503_and_not_a_refusal(self):
        # A park sealed to a rotated key is our misconfiguration. Answering 403
        # would tell the subscriber they got the code wrong and send them to
        # ask for another one, which would not help.
        self.park("123456")

        def broken(_armor):
            raise vc.ClaimError("no identity matched this file")

        self.config.decrypt = broken
        status, body = self.post({"code": "123456", "station": "pilot"})
        self.assertEqual(status, 503)
        self.assertNotIn(NEEDLE.encode(), body)
        # The park survives OUR mistake; the code is not spent.
        self.assertTrue(vc.park_path(self.spool, "pilot").exists())

    def test_five_wrong_attempts_burn_it_over_http(self):
        self.park("123456")
        for _ in range(5):
            self.assertEqual(self.post({"code": "222222", "station": "pilot"})[0], 403)
        self.assertEqual(self.post({"code": "123456", "station": "pilot"})[0], 403)
        outcomes = [a["outcome"] for a in self.attempts()]
        self.assertEqual(outcomes.count(vc.REFUSAL_WRONG_CODE), 4)
        self.assertIn(vc.REFUSAL_BURNED, outcomes)

    def test_an_oversized_body_is_refused_without_being_read(self):
        self.park("123456")
        status, body = self.post(b"x" * (ce.MAX_BODY + 1))
        self.assertEqual(status, 403)
        self.assertEqual(body, ce.REFUSED_BODY)
        self.assertTrue(vc.park_path(self.spool, "pilot").exists())

    @unittest.skipIf(os.geteuid() == 0, "root can read anything")
    def test_a_park_this_uid_cannot_read_is_503_and_costs_no_attempt(self):
        # The live edge's first park: `scp` as root into a spool owned by
        # 65532, `root:root 0600`, unreadable to `USER 65532` (2026-09-06
        # receipt, finding 4). On the wire it must be the same answer as a park
        # sealed to a rotated key — ours to fix, theirs to retry — and in the
        # log it must be a row that says which. It used to be neither: the
        # PermissionError escaped the handler, the connection dropped, and Caddy
        # turned that into a 502 with no row anywhere.
        self.park("123456")
        park = vc.park_path(self.spool, "pilot")
        park.chmod(0)
        # The park is redeemed — and deleted — at the end of this test.
        self.addCleanup(lambda: park.exists() and park.chmod(0o600))
        status, body = self.post({"code": "123456", "station": "pilot"})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"error": "unavailable"})
        self.assertNotIn(NEEDLE.encode(), body)
        self.assertTrue(park.exists())
        self.assertFalse(list(self.spool.glob("*.state.json")))
        (row,) = self.attempts()
        self.assertEqual(row["station"], "pilot")
        self.assertTrue(row["outcome"].startswith("error:"), row["outcome"])
        self.assertIn("owner", row["outcome"])
        self.assertNotIn("123456", row["outcome"])
        # ...and the right code, once the owner is fixed, still works: the
        # attempt above cost nothing.
        park.chmod(0o600)
        status, body = self.post({"code": "123456", "station": "pilot"})
        self.assertEqual(status, 200)

    # ------------------------------------------------------------------ probe

    def stub(self, status, body=b"", headers=None) -> str:
        server = stub_server(status, body, headers)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/claim"

    def test_probe_ok_when_the_route_reaches_this_spool(self):
        ok, lines = ce.probe(self.config, self.base + "/claim")
        self.assertTrue(ok, lines)
        self.assertIn("probe OK", lines[0])
        # One row, under a station no real station has, refused as malformed:
        # the probe carried no code, so nothing was compared and nothing spent.
        (row,) = self.attempts()
        self.assertTrue(row["station"].startswith(ce.PROBE_STATION_PREFIX))
        self.assertEqual(row["outcome"], vc.REFUSAL_MALFORMED)
        self.assertIsNone(row["park_id"])
        self.assertIn(row["station"], lines[0])
        self.assertIn("127.0.0.1", lines[1])

    def test_probe_never_touches_a_real_park(self):
        record = self.park("123456")
        ok, _ = ce.probe(self.config, self.base + "/claim")
        self.assertTrue(ok)
        self.assertTrue(vc.park_path(self.spool, "pilot").exists())
        self.assertFalse(
            vc.state_path(self.spool, "pilot", record["park_id"]).exists())
        self.assertEqual([a for a in self.attempts() if a["station"] == "pilot"], [])

    def test_probe_tells_this_service_from_another_one(self):
        # A 403 with the right body proves A claim service answered. The row in
        # THIS spool is what proves it was this one, through this route.
        other = FixtureConfig(pathlib.Path(tempfile.mkdtemp(prefix="vexa-other-")))
        ok, lines = ce.probe(other, self.base + "/claim")
        self.assertFalse(ok)
        self.assertIn("not in this spool", lines[0])

    def test_probe_names_the_write_gate(self):
        # 2026-09-06, finding 3: the stanza below `@write` and every claim a 401.
        url = self.stub(401, b"", {"WWW-Authenticate": 'Basic realm="Vexa channel registry"'})
        ok, lines = ce.probe(self.config, url)
        self.assertFalse(ok)
        self.assertIn("401", lines[0])
        self.assertIn("write gate", lines[0])
        self.assertIn("ABOVE", lines[1])
        self.assertEqual(self.attempts(), [])

    def test_probe_names_a_missing_route(self):
        ok, lines = ce.probe(self.config, self.stub(404, b"page not found\n"))
        self.assertFalse(ok)
        self.assertIn("no route", lines[0])

    def test_probe_names_a_loopback_that_is_not_this_hosts(self):
        # 2026-09-06, finding 2: `reverse_proxy 127.0.0.1:8088` from a Caddy
        # that is a container. Validates, starts, 502 on the call.
        ok, lines = ce.probe(self.config, self.stub(502))
        self.assertFalse(ok)
        self.assertIn("cannot reach this service", lines[0])
        self.assertIn("127.0.0.1:8088", lines[1])
        self.assertIn("compose.caddy-container.yaml", lines[1])

    def test_probe_refuses_a_200(self):
        ok, lines = ce.probe(self.config, self.stub(200, b"<html>welcome</html>"))
        self.assertFalse(ok)
        self.assertIn("something other than this service", lines[0])

    def test_probe_does_not_follow_a_redirect(self):
        url = self.stub(302, b"", {"Location": "http://sso.example.invalid/login"})
        ok, lines = ce.probe(self.config, url)
        self.assertFalse(ok)
        self.assertIn("redirected", lines[0])
        self.assertIn("sso.example.invalid", lines[0])

    def test_probe_reports_nothing_answering(self):
        ok, lines = ce.probe(self.config, f"http://127.0.0.1:{closed_port()}/claim",
                             timeout=2)
        self.assertFalse(ok)
        self.assertIn("nothing answered", lines[0])

    # ------------------------------------------------------------ rate limits

    def test_the_rate_limiter_fires_per_source(self):
        self.config.limiter = ce.RateLimiter(limit=3, window=60)
        self.park("123456")
        for _ in range(3):
            self.post({"code": "222222", "station": "pilot"})
        self.post({"code": "123456", "station": "pilot"})
        outcomes = [a["outcome"] for a in self.attempts()]
        self.assertIn(vc.REFUSAL_RATE_LIMITED, outcomes)
        # Rate limiting is not an attempt against the park: it never reached the
        # state machine, so it must not have cost the subscriber one of five.
        self.assertEqual(outcomes.count(vc.REFUSAL_WRONG_CODE), 3)

    def test_a_rate_limited_attempt_still_names_its_station(self):
        # `rate-limited` is the one outcome that means "one address hammered
        # THIS station", and it was the one outcome the station's own record
        # could not show: the limiter fires before the state machine, nothing
        # had read the body yet, so the event was written with station `-` and
        # `record-credential` dropped it as unattributed (2026-09-07 rehearsal).
        self.config.limiter = ce.RateLimiter(limit=2, window=60)
        record = self.park("123456")
        wire = [self.post({"code": "222222", "station": "pilot"}) for _ in range(4)]
        limited = [a for a in self.attempts()
                   if a["outcome"] == vc.REFUSAL_RATE_LIMITED]
        self.assertEqual(len(limited), 2)
        for event in limited:
            self.assertEqual(event["station"], "pilot")
            self.assertEqual(event["source"], "127.0.0.1")
            # The STATION, and no more. It was already in the body, so reading
            # it is free; the park id would be a disk read keyed on a name the
            # caller chose, on the one path whose whole job is to stop doing
            # work for a source that is hammering us. Attribution is by station,
            # and that is what the ledger needs.
            self.assertIsNone(event["park_id"])
            self.assertIsNone(event["code_sha256"])
        # THE WIRE IS UNCHANGED. Reading the station buys the record something;
        # it must buy the caller nothing.
        for status, body in wire:
            self.assertEqual(status, 403)
            self.assertEqual(body, ce.REFUSED_BODY)
        # And it still costs the park nothing — it never reached the state
        # machine, so it must not have spent one of the subscriber's five.
        self.assertEqual(
            vc.read_json(vc.state_path(self.spool, "pilot",
                                       record["park_id"]))["attempts"], 2)
        self.assertNotIn("222222", vc.attempts_path(self.spool).read_text())

    def test_a_rate_limited_body_that_names_no_station_stays_unattributed(self):
        # There is nothing to attribute it to, and inventing one would put an
        # attacker's string in a station's record.
        self.config.limiter = ce.RateLimiter(limit=1, window=60)
        self.post(b"{not json")
        self.post({"code": "123456", "station": "../etc"})
        self.assertEqual([a["station"] for a in self.attempts()],
                         [vc.UNATTRIBUTED, vc.UNATTRIBUTED])
        self.assertEqual([a["outcome"] for a in self.attempts()],
                         [vc.REFUSAL_MALFORMED, vc.REFUSAL_RATE_LIMITED])

    def test_rate_limit_window_expires(self):
        limiter = ce.RateLimiter(limit=2, window=60)
        self.assertTrue(limiter.allow("a", now=0))
        self.assertTrue(limiter.allow("a", now=1))
        self.assertFalse(limiter.allow("a", now=2))
        # A different source has its own bucket.
        self.assertTrue(limiter.allow("b", now=2))
        # ...and the window slides.
        self.assertTrue(limiter.allow("a", now=100))

    def test_the_shipped_numbers_are_the_ones_the_arithmetic_assumes(self):
        # README § The cryptography does the sum with these three. If they move,
        # that paragraph is wrong and this test is where you find out.
        self.assertEqual(ce.RATE_LIMIT, 10)
        self.assertEqual(ce.RATE_WINDOW, 60)
        self.assertEqual(ce.RATE_COOLDOWN, vc.TTL_SECONDS)
        self.assertEqual(ce.PARK_RATE_LIMIT, 20)

    def test_a_source_over_the_limit_is_cooled_off_for_a_whole_code_life(self):
        # The cooling period is what makes the limit bite. Without it a source
        # resumes at ten a minute the instant the window slides; with it, one
        # address gets ONE window inside a code's fifteen minutes.
        limiter = ce.RateLimiter(limit=ce.RATE_LIMIT, window=ce.RATE_WINDOW,
                                 cooldown=ce.RATE_COOLDOWN)
        for n in range(ce.RATE_LIMIT):
            self.assertTrue(limiter.allow("a", now=n))
        self.assertFalse(limiter.allow("a", now=11))
        # The window has long since slid; the cooling period has not.
        self.assertFalse(limiter.allow("a", now=ce.RATE_WINDOW + 30))
        self.assertFalse(limiter.allow("a", now=ce.RATE_COOLDOWN))
        # A code parked at t=0 is dead before this source is heard again.
        self.assertTrue(limiter.allow("a", now=ce.RATE_COOLDOWN + 11))
        # ...and it comes back with a full budget, not one request.
        self.assertTrue(limiter.allow("a", now=ce.RATE_COOLDOWN + 12))
        # Refused requests do not extend it: a stuck client would otherwise be
        # blocked forever by a rule nobody wrote down.
        other = ce.RateLimiter(limit=1, window=60, cooldown=100)
        self.assertTrue(other.allow("b", now=0))
        for t in range(1, 100):
            self.assertFalse(other.allow("b", now=t))
        self.assertTrue(other.allow("b", now=101))

    def test_a_limiter_does_not_grow_without_bound(self):
        # The per-park limiter is keyed on the STATION NAME, which comes from
        # the request body, so a caller can mint as many keys as it can send
        # requests. The sweep must drop keys by their last hit — dropping only
        # empty deques would drop nothing, because a deque is pruned when its
        # own key is next used and these keys are never used again.
        limiter = ce.RateLimiter(limit=5, window=60)
        for n in range(ce.MAX_TRACKED + 50):
            limiter.allow(f"station-{n}", now=0)
        # Inside one window they are all live, and the limiter is entitled to
        # hold them: what bounds this is the request rate, which the per-source
        # limit in front of it caps.
        self.assertEqual(len(limiter.hits), ce.MAX_TRACKED + 50)
        # One request a window later trips the sweep, and everything that went
        # quiet goes with it. No explicit call: the automatic path is the one
        # that has to work.
        limiter.allow("later", now=1000)
        self.assertEqual(list(limiter.hits), ["later"])

    def test_the_park_limit_counts_every_source_together(self):
        # The per-source limit is per source, so a caller with a hundred
        # addresses would otherwise buy a hundred budgets against one station.
        # This is the cap that makes extra addresses worth nothing.
        self.config.trust_forwarded_for = True
        self.config.park_limiter = ce.RateLimiter(limit=2, window=60)
        self.park("123456")
        for i in range(5):
            self.assertEqual(
                self.post({"code": "222222", "station": "pilot"},
                          headers={"X-Forwarded-For": f"198.51.100.{i}"})[0], 403)
        outcomes = [a["outcome"] for a in self.attempts()]
        self.assertEqual(outcomes.count(vc.REFUSAL_WRONG_CODE), 2)
        self.assertEqual(outcomes.count(vc.REFUSAL_PARK_RATE_LIMITED), 3)
        # Five distinct addresses, and the park has spent two of its five
        # attempts. It is still live.
        self.assertTrue(vc.park_path(self.spool, "pilot").exists())

    def test_one_station_over_the_park_limit_does_not_block_another(self):
        self.config.park_limiter = ce.RateLimiter(limit=1, window=60)
        self.park("123456", station="pilot")
        self.park("654321", station="second")
        self.post({"code": "222222", "station": "pilot"})
        self.assertEqual(self.post({"code": "222222", "station": "pilot"})[0], 403)
        status, body = self.post({"code": "654321", "station": "second"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["station"], "second")

    def test_forwarded_for_is_ignored_unless_configured(self):
        # OFF by default, and that default is the safe one: reached directly,
        # the header is whatever the caller typed, so trusting it would hand
        # every guesser a fresh rate-limit bucket per request.
        self.config.limiter = ce.RateLimiter(limit=2, window=60)
        self.park("123456")
        for i in range(4):
            self.post({"code": "222222", "station": "pilot"},
                      headers={"X-Forwarded-For": f"198.51.100.{i}"})
        self.assertIn(vc.REFUSAL_RATE_LIMITED,
                      [a["outcome"] for a in self.attempts()])
        self.assertEqual({a["source"] for a in self.attempts()}, {"127.0.0.1"})

    def test_forwarded_for_is_used_when_configured(self):
        self.config.trust_forwarded_for = True
        self.park("123456")
        self.post({"code": "222222", "station": "pilot"},
                  headers={"X-Forwarded-For": "198.51.100.9, 10.0.0.1"})
        self.assertEqual(self.attempts()[0]["source"], "198.51.100.9")

    # ------------------------------------------------------------------- logs

    def test_the_log_carries_the_outcome_the_source_and_no_secret(self):
        record = self.park("123456")
        self.post({"code": "222222", "station": "pilot"})
        self.post({"code": "123456", "station": "pilot"})
        events = self.attempts()
        self.assertEqual([e["outcome"] for e in events],
                         [vc.REFUSAL_WRONG_CODE, "claimed"])
        for event in events:
            self.assertEqual(event["station"], "pilot")
            self.assertEqual(event["source"], "127.0.0.1")
            self.assertEqual(event["park_id"], record["park_id"])
            # The hash of the PARK, so the ledger can bind this attempt to the
            # row `add --park` wrote. Never a hash of what the caller offered —
            # that hash IS the code to anyone willing to spend a minute.
            self.assertEqual(event["code_sha256"], record["code_sha256"])

        raw = vc.attempts_path(self.spool).read_text()
        self.assertNotIn(NEEDLE, raw)
        self.assertNotIn("123456", raw)
        self.assertNotIn("222222", raw)
        self.assertNotIn("BEGIN AGE", raw)

    def test_identical_attempts_in_one_second_are_distinct_events(self):
        # `ts` is second-resolution and the ledger deduplicates on the whole
        # event, so ten identical attempts inside one second used to reduce to
        # ONE row while the spool kept all ten — a burst reading exactly like a
        # single request in the record that exists to show bursts. The sequence
        # is what keeps the count (2026-09-07 rehearsal, finding 3).
        for _ in range(10):
            self.assertEqual(
                self.post({"code": "222222", "station": "absent"})[0], 403)
        events = self.attempts()
        self.assertEqual(len(events), 10)
        self.assertEqual({e["outcome"] for e in events}, {vc.REFUSAL_NO_PARK})
        self.assertEqual([e["seq"] for e in events], list(range(1, 11)))
        # Distinct as WHOLE EVENTS, which is what the reducer compares.
        self.assertEqual(
            len({json.dumps(e, sort_keys=True) for e in events}), 10)

    def test_the_sequence_survives_a_restart(self):
        # In-memory would be enough for one process and wrong across two: a
        # restarted edge would re-issue numbers a copied-back log already
        # carries. It is seeded from the log itself.
        self.post({"code": "222222", "station": "absent"})
        self.post({"code": "222222", "station": "absent"})
        vc._SEQ.clear()  # what a restart looks like from here
        self.post({"code": "222222", "station": "absent"})
        self.assertEqual([e["seq"] for e in self.attempts()], [1, 2, 3])

    def test_an_unparseable_body_is_logged_unattributed(self):
        # It names no station, so the ledger can route it aside instead of
        # refusing a whole batch of real events over it.
        self.post(b"{not json")
        self.assertEqual(self.attempts()[0]["station"], vc.UNATTRIBUTED)
        self.assertEqual(self.attempts()[0]["outcome"], vc.REFUSAL_MALFORMED)

    # ----------------------------------------------------------------- config

    def test_config_from_env_requires_both_paths(self):
        with self.assertRaises(vc.ClaimError):
            ce.Config.from_env({"CLAIM_SPOOL": "/tmp"})
        with self.assertRaises(vc.ClaimError):
            ce.Config.from_env({"CLAIM_IDENTITY": "/tmp/k"})
        config = ce.Config.from_env(
            {"CLAIM_SPOOL": str(self.spool), "CLAIM_IDENTITY": "/tmp/k",
             "CLAIM_RATE_LIMIT": "7", "CLAIM_RATE_WINDOW": "30",
             "CLAIM_RATE_COOLDOWN": "120", "CLAIM_PARK_RATE_LIMIT": "9"})
        self.assertEqual(config.limiter.limit, 7)
        self.assertEqual(config.limiter.window, 30)
        self.assertEqual(config.limiter.cooldown, 120)
        self.assertEqual(config.park_limiter.limit, 9)
        self.assertFalse(config.trust_forwarded_for)

    def test_the_defaults_are_the_shipped_numbers(self):
        # An operator who sets neither variable gets the limits the README
        # states, not whatever the class happened to default to.
        config = ce.Config.from_env(
            {"CLAIM_SPOOL": str(self.spool), "CLAIM_IDENTITY": "/tmp/k"})
        self.assertEqual(config.limiter.limit, ce.RATE_LIMIT)
        self.assertEqual(config.limiter.window, ce.RATE_WINDOW)
        self.assertEqual(config.limiter.cooldown, ce.RATE_COOLDOWN)
        self.assertEqual(config.park_limiter.limit, ce.PARK_RATE_LIMIT)
        # The per-park limiter has NO cooling period: locking a station out for
        # fifteen minutes is a denial of the delivery, and the park already has
        # a stricter cap of its own in the five-attempt burn.
        self.assertEqual(config.park_limiter.cooldown, 0)

    def test_a_group_readable_identity_refuses_to_start(self):
        identity = self.spool / "edge.key"
        identity.write_text("AGE-SECRET-KEY-NOT-A-REAL-KEY\n")
        identity.chmod(0o644)
        config = ce.Config(str(self.spool), str(identity), rate_limit=1,
                           rate_window=1, trust_forwarded_for=False)
        with self.assertRaises(vc.ClaimError) as caught:
            config.check()
        self.assertIn("readable", str(caught.exception))


class CheckCase(unittest.TestCase):
    """`--check` and `--probe` as the deploy runs them: through `main`, from
    the environment, with `age` stubbed present so this runs in CI too."""

    def setUp(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="vexa-check-"))
        self.spool = root / "spool"
        self.spool.mkdir()
        self.identity = root / "edge.key"
        self.identity.write_text("AGE-SECRET-KEY-NOT-A-REAL-KEY\n")
        self.identity.chmod(0o600)
        self.env = {"CLAIM_SPOOL": str(self.spool), "CLAIM_IDENTITY": str(self.identity)}
        patcher = unittest.mock.patch.object(vc, "have_age", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def main(self, argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch.dict(os.environ, env or self.env, clear=False), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if not (env or {}).get("CLAIM_PUBLIC_URL"):
                os.environ.pop("CLAIM_PUBLIC_URL", None)
            rc = ce.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def park(self, station="pilot"):
        record = vc.build_park(station=station, account="pilot", code="123456",
                               ciphertext=ARMOR, parked_by="t", edge="x")
        return vc.write_park(self.spool, record)

    def test_a_clean_spool_checks_clean(self):
        self.assertEqual(ce.Config.from_env(self.env).check(), [])
        rc, out, _ = self.main(["--check"])
        self.assertEqual(rc, 0)
        self.assertIn("config OK", out)

    @unittest.skipIf(os.geteuid() == 0, "root can write anywhere")
    def test_an_unwritable_spool_refuses(self):
        # The attempt counter and the attempts log live in the spool. Unwritable,
        # the five-attempt burn cannot be recorded — and before this check the
        # first attempt was a dropped connection, not a refusal at deploy time.
        self.spool.chmod(0o500)
        self.addCleanup(self.spool.chmod, 0o700)
        with self.assertRaises(vc.ClaimError) as caught:
            ce.Config.from_env(self.env).check()
        self.assertIn("not writable", str(caught.exception))
        self.assertIn("chown", str(caught.exception))
        rc, _, err = self.main(["--check"])
        self.assertEqual(rc, 2)
        self.assertIn("not writable", err)

    @unittest.skipIf(os.geteuid() == 0, "root can read anything")
    def test_a_park_this_uid_cannot_read_is_named_and_check_refuses(self):
        park = self.park()
        park.chmod(0)
        self.addCleanup(park.chmod, 0o600)
        self.assertEqual(ce.Config.from_env(self.env).check(), [park])
        rc, _, err = self.main(["--check"])
        self.assertEqual(rc, 2)
        self.assertIn("pilot.park.json", err)
        self.assertIn("chown", err)
        # Readable again: clean.
        park.chmod(0o600)
        self.assertEqual(self.main(["--check"])[0], 0)

    def test_the_probe_verb_needs_a_url(self):
        rc, _, err = self.main(["--probe"])
        self.assertEqual(rc, 2)
        self.assertIn("CLAIM_PUBLIC_URL", err)

    def test_the_probe_verb_takes_its_url_from_the_environment(self):
        # No service behind it: the verdict is "nothing answered", exit 1, and
        # the URL it judged is the one from the environment.
        url = f"http://127.0.0.1:{closed_port()}/claim"
        rc, _, err = self.main(["--probe"], {**self.env, "CLAIM_PUBLIC_URL": url})
        self.assertEqual(rc, 1)
        self.assertIn(url, err)
        self.assertIn("nothing answered", err)


if __name__ == "__main__":
    unittest.main()
