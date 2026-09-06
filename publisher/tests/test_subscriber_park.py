# SPDX-License-Identifier: Apache-2.0
"""`vexa_subscriber.py add --park`: the checks that run BEFORE the mint, the
transport, and what reaches the ledger.

The cluster half is not exercised here — `add` writes a Secret and rolls a
Deployment, and neither is what a bug in this path would break. What a bug here
breaks is one of two things, and both are tested: a subscriber locked out because
a preflight that should have refused ran after the rotation, or a credential
written somewhere it was never supposed to exist.
"""

import argparse
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vexa_subscriber as vs  # noqa: E402
import vexa_claim as vc  # noqa: E402  (re-exported through vexa_subscriber's path insert)
import vexa_stations as vst  # noqa: E402

ARMOR_HEAD = "-----BEGIN AGE ENCRYPTED FILE-----"
PASSWORD = "not-a-real-password"


def new_ledger():
    root = pathlib.Path(tempfile.mkdtemp(prefix="vexa-ledger-"))
    for cmd in (["init", "-q", "-b", "main"],
                ["config", "user.email", "test@vexa.invalid"],
                ["config", "user.name", "test"]):
        subprocess.run(["git", "-C", str(root), *cmd], check=True,
                       capture_output=True)
    (root / "README.md").write_text("ledger\n")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "init"], check=True,
                   capture_output=True)
    return root


def args(**kw):
    base = dict(park=True, channel="pilot-stable", station=None, edge=None,
                edge_recipient=None, park_out=None, park_ssh=None, ledger=None,
                ttl=vc.TTL_SECONDS, parked_by="tester")
    base.update(kw)
    return argparse.Namespace(**base)


class Preflight(unittest.TestCase):
    """Everything here runs BEFORE the mint, because `add` ROTATES: the old
    credential stops working the moment the Secret is written. A missing
    recipients file discovered afterwards would leave the subscriber locked out
    with nothing parked and nothing printed — an outage caused by a typo."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="vexa-preflight-"))
        self.ledger = new_ledger()
        self.recipients = self.dir / "edge.recipients"
        self.recipients.write_text(
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n")
        for key in ("CHANNEL_CLAIM_EDGE", "CHANNEL_CLAIM_EDGE_RECIPIENT",
                    "CHANNEL_CLAIM_SPOOL", "CHANNEL_CLAIM_SPOOL_SSH",
                    "VEXA_STATIONS_DIR"):
            os.environ.pop(key, None)

    def ok_args(self, **kw):
        base = dict(edge="https://channel.example/claim",
                    edge_recipient=str(self.recipients),
                    park_out=str(self.dir / "spool"),
                    ledger=str(self.ledger))
        base.update(kw)
        return args(**base)

    @unittest.skipUnless(vc.have_age(), "no `age` binary on this host")
    def test_a_complete_set_of_inputs_resolves(self):
        ctx = vs.park_preflight(self.ok_args(), "pilot")
        self.assertEqual(ctx["station"], "pilot")
        self.assertEqual(ctx["channel"], "pilot-stable")
        self.assertEqual(ctx["root"], self.ledger.resolve())

    @unittest.skipUnless(vc.have_age(), "no `age` binary on this host")
    def test_station_defaults_to_the_account(self):
        self.assertEqual(vs.park_preflight(self.ok_args(), "pilot")["station"], "pilot")
        self.assertEqual(
            vs.park_preflight(self.ok_args(station="second"), "pilot")["station"],
            "second")

    def test_no_channel_refuses(self):
        with self.assertRaises(vs.SubscriberError) as caught:
            vs.park_preflight(self.ok_args(channel=None), "pilot")
        self.assertIn("--channel", str(caught.exception))

    def test_no_recipients_file_refuses_and_names_the_variable(self):
        with self.assertRaises(vs.SubscriberError) as caught:
            vs.park_preflight(self.ok_args(edge_recipient=None), "pilot")
        self.assertIn("CHANNEL_CLAIM_EDGE_RECIPIENT", str(caught.exception))

    def test_no_edge_url_refuses_and_names_the_variable(self):
        with self.assertRaises(vs.SubscriberError) as caught:
            vs.park_preflight(self.ok_args(edge=None), "pilot")
        self.assertIn("CHANNEL_CLAIM_EDGE", str(caught.exception))

    def test_no_transport_and_both_transports_both_refuse(self):
        # Exactly one. Neither is a park that goes nowhere; both is a park in
        # two places, one of which nobody is watching.
        for kw in ({"park_out": None}, {"park_ssh": "root@host:/srv/claims"}):
            with self.subTest(kw=sorted(kw)):
                with self.assertRaises(vs.SubscriberError) as caught:
                    vs.park_preflight(self.ok_args(**kw), "pilot")
                self.assertIn("exactly one park transport", str(caught.exception))

    @unittest.skipUnless(vc.have_age(), "no `age` binary on this host")
    def test_a_malformed_recipients_file_is_caught_before_the_mint(self):
        bad = self.dir / "bad.recipients"
        bad.write_text("this is not an age recipient\n")
        with self.assertRaises(vc.ClaimError):
            vs.park_preflight(self.ok_args(edge_recipient=str(bad)), "pilot")

    def test_an_empty_recipients_file_refuses(self):
        empty = self.dir / "empty.recipients"
        empty.write_text("\n")
        with self.assertRaises(vc.ClaimError):
            vs.park_preflight(self.ok_args(edge_recipient=str(empty)), "pilot")

    def test_a_ttl_outside_the_band_refuses(self):
        # The window IS the control. A generous one makes the code a password
        # with extra steps; a 30-second one gets read aloud twice.
        for ttl in (0, 30, 59, 3601, 86400):
            with self.subTest(ttl=ttl):
                with self.assertRaises(vs.SubscriberError) as caught:
                    vs.park_preflight(self.ok_args(ttl=ttl), "pilot")
                self.assertIn("--ttl", str(caught.exception))

    def test_a_ledger_that_is_not_a_checkout_refuses(self):
        with self.assertRaises(vs.SubscriberError) as caught:
            vs.park_preflight(self.ok_args(ledger=str(self.dir)), "pilot")
        self.assertIn("audit trail", str(caught.exception))

    def test_an_unsafe_station_name_refuses(self):
        with self.assertRaises(vc.ClaimError):
            vs.park_preflight(self.ok_args(station="../../etc"), "pilot")


@unittest.skipUnless(vc.have_age(), "no `age` binary on this host")
class ParkEndToEnd(unittest.TestCase):
    """Mint excluded: seal, record, place, and what a reader of either artefact
    can see."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="vexa-park-e2e-"))
        self.spool = self.dir / "spool"
        self.ledger = new_ledger()
        subprocess.run(["age-keygen", "-o", str(self.dir / "edge.key")],
                       capture_output=True, check=True)
        public = [ln.split(": ", 1)[1]
                  for ln in (self.dir / "edge.key").read_text().splitlines()
                  if ln.startswith("# public key: ")][0]
        (self.dir / "edge.recipients").write_text(public + "\n")
        self.args = args(edge="https://channel.example/claim",
                         edge_recipient=str(self.dir / "edge.recipients"),
                         park_out=str(self.spool), ledger=str(self.ledger))
        self.ctx = vs.park_preflight(self.args, "pilot")

    def park(self, **kw):
        self.park_and_read_code(rotating=kw.get("rotating", False))
        return json.loads(vc.park_path(self.spool, "pilot").read_text())

    def park_and_read_code(self, *, rotating=False):
        """One park, with stdout captured. The code is on stdout and nowhere
        else — not in the record, not in the ledger — so capturing it here is
        the only way a test can hold one."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            vs.park_credential(self.ctx, self.args, account="pilot",
                               password=PASSWORD, rotating=rotating)
        return out.getvalue().strip()

    def test_the_park_file_holds_ciphertext_and_no_password(self):
        record = self.park()
        self.assertTrue(record["ciphertext"].startswith(ARMOR_HEAD))
        self.assertNotIn(PASSWORD, vc.park_path(self.spool, "pilot").read_text())

    def test_the_edge_and_only_the_edge_can_open_it(self):
        record = self.park()
        opened = json.loads(vc.age_decrypt(str(self.dir / "edge.key"),
                                           record["ciphertext"]))
        self.assertEqual(opened, {"username": "pilot", "password": PASSWORD})

    def test_the_ledger_row_holds_no_value_and_no_ciphertext(self):
        self.park()
        path = (vst.station_dir(self.ledger, "pilot-stable", "pilot")
                / "credential-events.yaml")
        text = path.read_text()
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn("BEGIN AGE", text)
        event = vst.load_yaml(path)["events"][0]
        self.assertEqual(event["event"], "park")
        self.assertEqual(event["account"], "pilot")
        self.assertEqual(event["ttl_seconds"], vc.TTL_SECONDS)
        self.assertEqual(len(event["code_sha256"]), 64)

    def test_rotation_is_recorded_as_such(self):
        event = None
        self.park(rotating=True)
        event = vst.load_yaml(
            vst.station_dir(self.ledger, "pilot-stable", "pilot")
            / "credential-events.yaml")["events"][0]
        self.assertTrue(event["rotation"])

    def test_the_code_is_printed_and_the_ledger_only_commits_to_its_hash(self):
        code = self.park_and_read_code()
        # Six digits, grouped for reading aloud: `123 456`.
        self.assertRegex(code, r"^[0-9]{3} [0-9]{3}$")
        record = json.loads(vc.park_path(self.spool, "pilot").read_text())
        self.assertEqual(record["code_sha256"],
                         vc.code_sha256(record["code_salt"], code))
        # The code itself appears in neither durable artefact.
        ledger_text = (vst.station_dir(self.ledger, "pilot-stable", "pilot")
                       / "credential-events.yaml").read_text()
        self.assertNotIn(code.replace(" ", ""),
                         vc.park_path(self.spool, "pilot").read_text())
        self.assertNotIn(code.replace(" ", ""), ledger_text)

    def test_the_ledger_gets_the_digest_and_never_the_salt(self):
        # Six digits behind a bare SHA-256 is a million-candidate search, and
        # the ledger is a git repository that outlives the park. Without the
        # salt the row commits to a code nobody can recover; with it, the row
        # WOULD BE the code. `park_event` is an allowlist, and `check_event`
        # refuses `code_salt` outright — two independent stops.
        self.park_and_read_code()
        record = json.loads(vc.park_path(self.spool, "pilot").read_text())
        path = (vst.station_dir(self.ledger, "pilot-stable", "pilot")
                / "credential-events.yaml")
        self.assertNotIn(record["code_salt"], path.read_text())
        event = vst.load_yaml(path)["events"][0]
        self.assertNotIn("code_salt", event)
        self.assertEqual(event["code_sha256"], record["code_sha256"])
        with self.assertRaises(vst.LedgerError):
            vst.check_event({"event": "park", "ts": record["parked_at"],
                             "code_salt": record["code_salt"]})

    def test_the_parked_credential_survives_a_full_round_trip(self):
        # Park here, redeem with the state machine the edge runs. The two halves
        # of the format meeting is the property that no unit test of either can
        # establish on its own.
        code = self.park_and_read_code()
        out = vc.redeem(
            self.spool, station="pilot", code=code,
            decrypt=lambda a: vc.age_decrypt(str(self.dir / "edge.key"), a))
        self.assertEqual(out, {"station": "pilot", "username": "pilot",
                               "password": PASSWORD})


class AttemptsIngest(unittest.TestCase):
    """`vexa-stations record-credential`: the return leg, and the two ways a
    public endpoint's request body could have poisoned it."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="vexa-ingest-"))
        self.ledger = new_ledger()
        # A station only has a directory once it has been parked to, which is
        # necessarily before anyone can claim against it.
        vst.record_credential_events(
            self.ledger, channel="pilot-stable", station="pilot",
            events=[{"event": "park", "ts": "2026-09-06T12:00:00Z",
                     "park_id": "0123456789abcdef", "account": "pilot",
                     "code_sha256": "a" * 64,
                     "expires_at": "2026-09-06T12:15:00Z"}])

    def write_log(self, events):
        path = self.dir / "attempts.ndjson"
        path.write_text("".join(json.dumps(e) + "\n" for e in events))
        return path

    def ingest(self, path):
        # The CLI reports per station on stdout; captured so `make test` output
        # stays about pass and fail.
        with contextlib.redirect_stdout(io.StringIO()):
            return vst.main(["--ledger", str(self.ledger), "record-credential",
                             "--channel", "pilot-stable", "--events", str(path)])

    def events(self, station="pilot"):
        path = (vst.station_dir(self.ledger, "pilot-stable", station)
                / "credential-events.yaml")
        return vst.load_yaml(path).get("events", []) if path.is_file() else []

    def test_attempts_land_against_their_station(self):
        self.assertEqual(self.ingest(self.write_log([
            {"event": "claim", "ts": "2026-09-06T12:01:00Z", "station": "pilot",
             "outcome": "wrong-code", "source": "203.0.113.7"},
            {"event": "claim", "ts": "2026-09-06T12:02:00Z", "station": "pilot",
             "outcome": "claimed", "source": "203.0.113.7"},
        ])), 0)
        # The park row seeded in setUp is still there; the two attempts joined it.
        self.assertEqual([e["event"] for e in self.events()],
                         ["park", "claim", "claim"])
        self.assertEqual([e["outcome"] for e in self.events()
                          if e["event"] == "claim"],
                         ["wrong-code", "claimed"])

    def test_a_junk_probe_does_not_block_the_real_events(self):
        # One malformed POST at a public endpoint used to refuse the WHOLE
        # batch, which is a denial of the record by anyone with curl.
        self.assertEqual(self.ingest(self.write_log([
            {"event": "claim", "ts": "2026-09-06T12:01:00Z",
             "station": vc.UNATTRIBUTED, "outcome": "malformed", "source": "x"},
            {"event": "claim", "ts": "2026-09-06T12:02:00Z", "station": "pilot",
             "outcome": "claimed", "source": "203.0.113.7"},
        ])), 0)
        claims = [e["outcome"] for e in self.events() if e["event"] == "claim"]
        self.assertEqual(claims, ["claimed"])

    def test_a_station_the_channel_does_not_know_creates_no_directory(self):
        # A well-formed name for a station that does not exist would otherwise
        # CREATE its directory: a caller posting a thousand plausible names
        # would grow a thousand directories in the ledger, one commit each.
        self.ingest(self.write_log([
            {"event": "claim", "ts": "2026-09-06T12:01:00Z", "station": "invented",
             "outcome": "no-park", "source": "203.0.113.9"},
        ]))
        self.assertFalse(
            vst.station_dir(self.ledger, "pilot-stable", "invented").exists())

    def test_re_ingesting_the_same_log_adds_nothing(self):
        path = self.write_log([
            {"event": "claim", "ts": "2026-09-06T12:02:00Z", "station": "pilot",
             "outcome": "claimed", "source": "203.0.113.7"},
        ])
        self.ingest(path)
        before = len(self.events())
        self.ingest(path)
        self.assertEqual(len(self.events()), before)

    def test_a_burst_inside_one_second_keeps_its_count(self):
        # Dedup-by-content plus a second-resolution `ts` collapsed ten identical
        # attempts into ONE row — in the file whose reason for existing is to
        # show that somebody hammered a station. The edge's per-attempt `seq` is
        # what keeps the count (2026-09-07 rehearsal, finding 3).
        burst = [{"event": "claim", "ts": "2026-09-06T12:03:00Z",
                  "station": "pilot", "outcome": "no-park",
                  "source": "203.0.113.7", "seq": n} for n in range(1, 11)]
        path = self.write_log(burst)
        self.assertEqual(self.ingest(path), 0)
        rows = [e for e in self.events() if e.get("outcome") == "no-park"]
        self.assertEqual(len(rows), 10)
        self.assertEqual([e["seq"] for e in rows], list(range(1, 11)))
        # ...and the property that made dedup-by-content worth having survives:
        # the same log ingested twice still adds nothing, with no cursor.
        before = len(self.events())
        self.ingest(path)
        self.assertEqual(len(self.events()), before)

    def test_attempts_sharing_a_second_are_ordered_by_sequence(self):
        # A second copy of the log can overlap the first, so rows arrive out of
        # order; within one second `ts` cannot order them and `seq` can.
        self.ingest(self.write_log([
            {"event": "claim", "ts": "2026-09-06T12:04:00Z", "station": "pilot",
             "outcome": "wrong-code", "source": "203.0.113.7", "seq": 3},
            {"event": "claim", "ts": "2026-09-06T12:04:00Z", "station": "pilot",
             "outcome": "rate-limited", "source": "203.0.113.7", "seq": 1},
            {"event": "claim", "ts": "2026-09-06T12:04:00Z", "station": "pilot",
             "outcome": "wrong-code", "source": "203.0.113.7", "seq": 2},
        ]))
        self.assertEqual([e["seq"] for e in self.events() if e.get("seq")],
                         [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
