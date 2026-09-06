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

import datetime
import json
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import claim_edge as ce  # noqa: E402
import vexa_claim as vc  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
