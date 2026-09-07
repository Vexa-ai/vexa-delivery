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
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vexa_subscriber as vs  # noqa: E402
import vexa_claim as vc  # noqa: E402  (re-exported through vexa_subscriber's path insert)
import vexa_stations as vst  # noqa: E402

ARMOR_HEAD = "-----BEGIN AGE ENCRYPTED FILE-----"
PASSWORD = "not-a-real-password"
ARMOR = f"{ARMOR_HEAD}\nnot-a-real-envelope\n-----END AGE ENCRYPTED FILE-----\n"

# Stand-ins for the two commands the scp transport runs on the edge host. Each
# logs its argv to $STUB_LOG, so a test can assert on what would have run and
# in which order; `scp` also lands the file in $STUB_SCP_DEST so the copy is
# observable. Answers are steered by environment variables the tests set.
SSH_STUB = """#!/usr/bin/env python3
import os, sys
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write("ssh " + " ".join(sys.argv[1:]) + "\\n")
rc = int(os.environ.get("STUB_SSH_RC", "0"))
if rc:
    sys.stderr.write("ssh: connect to host edge port 22: Connection refused\\n")
    sys.exit(rc)
command = sys.argv[-1]
if "stat -c" in command:
    # The remote shell runs `test -d P && stat ... || echo no-such-directory`,
    # which exits 0 either way; a missing spool is the sentinel on stdout.
    if os.environ.get("STUB_SSH_NO_DIR"):
        sys.stdout.write("no-such-directory\\n")
        sys.exit(0)
    sys.stdout.write(os.environ.get("STUB_SSH_STAT", "65532:65532") + "\\n")
    sys.exit(0)
if "chown" in command:
    rc = int(os.environ.get("STUB_SSH_CHOWN_RC", "0"))
    if rc:
        sys.stderr.write("chown: changing ownership: Operation not permitted\\n")
    sys.exit(rc)
sys.exit(0)
"""
SCP_STUB = """#!/usr/bin/env python3
import os, shutil, sys
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write("scp " + " ".join(sys.argv[1:]) + "\\n")
src, target = sys.argv[-2], sys.argv[-1]
dest = os.environ.get("STUB_SCP_DEST")
if dest:
    shutil.copy2(src, os.path.join(dest, os.path.basename(target)))
sys.exit(int(os.environ.get("STUB_SCP_RC", "0")))
"""


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


class SshTransport(unittest.TestCase):
    """The scp leg, against stub `ssh` and `scp`: what runs on the edge host
    BEFORE the mint, and what runs AFTER the copy.

    The park is copied as the SSH user — root on the standalone host — and
    landed `root:root 0600` in a spool owned by 65532, unreadable to the
    service (2026-09-06 receipt, finding 4). Two things close that: the spool's
    owner is read before anything is rotated, and the file is handed to that
    owner before the code is printed.
    """

    TARGET = "root@edge:/srv/channel/claims"

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="vexa-ssh-"))
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        for name, text in (("ssh", SSH_STUB), ("scp", SCP_STUB)):
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        self.log = self.dir / "calls.log"
        self.remote = self.dir / "remote"
        self.remote.mkdir()
        self.saved = dict(os.environ)
        for key in ("CHANNEL_CLAIM_EDGE", "CHANNEL_CLAIM_EDGE_RECIPIENT",
                    "CHANNEL_CLAIM_SPOOL", "CHANNEL_CLAIM_SPOOL_SSH",
                    "VEXA_STATIONS_DIR", "STUB_SSH_RC", "STUB_SSH_STAT",
                    "STUB_SSH_NO_DIR", "STUB_SSH_CHOWN_RC", "STUB_SCP_RC"):
            os.environ.pop(key, None)
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
        os.environ["STUB_LOG"] = str(self.log)
        os.environ["STUB_SCP_DEST"] = str(self.remote)
        self.ledger = new_ledger()
        self.recipients = self.dir / "edge.recipients"
        self.recipients.write_text(
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.is_file() else []

    def ok_args(self, **kw):
        base = dict(edge="https://channel.example/claim",
                    edge_recipient=str(self.recipients), park_out=None,
                    park_ssh=self.TARGET, ledger=str(self.ledger))
        base.update(kw)
        return args(**base)

    def record(self):
        return vc.build_park(station="pilot", account="pilot", code="123456",
                             ciphertext=ARMOR, parked_by="tester",
                             edge="https://channel.example/claim")

    # ---------------------------------------------------------------- target

    def test_an_scp_target_splits_into_what_ssh_dials_and_the_path(self):
        self.assertEqual(vs.split_scp_target(self.TARGET),
                         ("root@edge", "/srv/channel/claims"))
        self.assertEqual(vs.split_scp_target("root@edge:/srv/channel/claims/"),
                         ("root@edge", "/srv/channel/claims"))
        # scp wants an IPv6 literal bracketed; ssh wants it bare.
        self.assertEqual(vs.split_scp_target("[2001:db8::1]:/srv/claims"),
                         ("2001:db8::1", "/srv/claims"))
        for bad in ("edge", "edge:", ":/srv/claims", "edge:relative/path", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(vs.SubscriberError):
                    vs.split_scp_target(bad)

    # ------------------------------------------------------------- preflight

    @unittest.skipUnless(vc.have_age(), "no `age` binary on this host")
    def test_the_spool_owner_is_read_before_the_mint(self):
        ctx = vs.park_preflight(self.ok_args(), "pilot")
        self.assertEqual(ctx["spool_owner"], "65532:65532")
        (call,) = self.calls()
        self.assertTrue(call.startswith("ssh -o BatchMode=yes root@edge -- "), call)
        self.assertIn("test -d /srv/channel/claims", call)
        self.assertIn("stat -c %u:%g /srv/channel/claims", call)

    def test_a_root_owned_spool_refuses_before_the_mint(self):
        # With the shipped image (USER 65532) every park into it would be
        # unreadable. Refused here, with nothing rotated and the one-line fix.
        os.environ["STUB_SSH_STAT"] = "0:0"
        with self.assertRaises(vs.SubscriberError) as caught:
            vs.park_preflight(self.ok_args(), "pilot")
        self.assertIn("owned by root", str(caught.exception))
        self.assertIn("chown 65532:65532 /srv/channel/claims", str(caught.exception))
        self.assertIn("Nothing was minted", str(caught.exception))

    def test_an_edge_host_that_does_not_answer_refuses_before_the_mint(self):
        # This used to fail at the scp — after the rotation, with the
        # subscriber's old credential already dead and nothing parked.
        os.environ["STUB_SSH_RC"] = "255"
        with self.assertRaises(vs.SubscriberError) as caught:
            vs.park_preflight(self.ok_args(), "pilot")
        self.assertIn("Connection refused", str(caught.exception))

    def test_a_spool_that_is_not_a_directory_refuses_before_the_mint(self):
        os.environ["STUB_SSH_NO_DIR"] = "1"
        with self.assertRaises(vs.SubscriberError) as caught:
            vs.park_preflight(self.ok_args(), "pilot")
        self.assertIn("not a directory", str(caught.exception))
        self.assertIn("Nothing was minted", str(caught.exception))

    def test_a_local_spool_is_not_probed_over_ssh(self):
        spool = self.dir / "spool"
        with contextlib.suppress(vs.SubscriberError, vc.ClaimError):
            vs.park_preflight(self.ok_args(park_ssh=None, park_out=str(spool)),
                              "pilot")
        self.assertEqual(self.calls(), [])

    # -------------------------------------------------------------- delivery

    def test_the_copy_is_followed_by_a_chown_to_the_spools_owner(self):
        where = vs.deliver_park(self.record(), spool=None, ssh=self.TARGET,
                                owner="65532:65532")
        scp, ssh = self.calls()
        self.assertTrue(scp.startswith("scp -q "), scp)
        self.assertTrue(scp.endswith(" root@edge:/srv/channel/claims/pilot.park.json"), scp)
        self.assertIn("chown 65532:65532 /srv/channel/claims/pilot.park.json", ssh)
        self.assertIn("chmod 600 /srv/channel/claims/pilot.park.json", ssh)
        self.assertTrue(ssh.startswith("ssh -o BatchMode=yes root@edge -- "), ssh)
        # What the operator's receipt line says, so the owner is on the screen
        # during the call instead of discovered from a uniform 403.
        self.assertEqual(where, f"{self.TARGET}/pilot.park.json (owner 65532:65532, the spool's)")
        # The copy really happened, and the local temp copy is gone.
        landed = json.loads((self.remote / "pilot.park.json").read_text())
        self.assertEqual(landed["station"], "pilot")
        local_copy = pathlib.Path(scp.split()[2])
        self.assertEqual(local_copy.name, "pilot.park.json")
        self.assertFalse(local_copy.parent.exists())

    def test_without_an_owner_in_hand_the_delivery_reads_it_first(self):
        vs.deliver_park(self.record(), spool=None, ssh=self.TARGET)
        stat, scp, chown = self.calls()
        self.assertIn("stat -c", stat)
        self.assertTrue(scp.startswith("scp "))
        self.assertIn("chown 65532:65532", chown)

    def test_a_chown_that_fails_refuses_and_names_the_fix(self):
        # The park is on the host and the code is NOT printed: the refusal says
        # what to run before anyone reads six digits aloud against it.
        os.environ["STUB_SSH_CHOWN_RC"] = "1"
        with self.assertRaises(vs.SubscriberError) as caught:
            vs.deliver_park(self.record(), spool=None, ssh=self.TARGET,
                            owner="65532:65532")
        text = str(caught.exception)
        self.assertIn("chown 65532:65532 /srv/channel/claims/pilot.park.json", text)
        self.assertIn("Do not read the code out", text)
        self.assertIn("Operation not permitted", text)

    def test_a_copy_that_fails_never_reaches_the_chown(self):
        os.environ["STUB_SCP_RC"] = "1"
        with self.assertRaises(vs.SubscriberError):
            vs.deliver_park(self.record(), spool=None, ssh=self.TARGET,
                            owner="65532:65532")
        self.assertEqual([c.split()[0] for c in self.calls()], ["scp"])

    # ----------------------------------------------------------- local spool

    def test_a_local_park_already_owned_by_the_spools_owner_is_left_alone(self):
        spool = self.dir / "spool"
        path = vc.write_park(spool, self.record())
        with unittest.mock.patch("os.chown") as chown:
            self.assertIsNone(vs.adopt_spool_owner(path))
        chown.assert_not_called()

    def test_a_local_park_takes_the_owner_of_its_spool(self):
        # A publisher running as root on the edge host itself, writing into the
        # service's spool: same defect, one transport over. Only root can hand
        # a file to another uid, so the file's owner is faked and the chown is
        # observed rather than performed.
        spool = self.dir / "spool"
        path = vc.write_park(spool, self.record())
        real_stat = pathlib.Path.stat

        def as_if_root_wrote_it(self_, *a, **kw):
            st = real_stat(self_, *a, **kw)
            if self_ == path:
                fields = list(st)
                fields[4] = fields[5] = 0
                return os.stat_result(fields)
            return st

        with unittest.mock.patch.object(pathlib.Path, "stat", as_if_root_wrote_it), \
                unittest.mock.patch("os.chown") as chown:
            self.assertIsNone(vs.adopt_spool_owner(path))
            chown.assert_called_once_with(path, os.getuid(), os.getgid())

        with unittest.mock.patch.object(pathlib.Path, "stat", as_if_root_wrote_it), \
                unittest.mock.patch("os.chown", side_effect=PermissionError):
            warning = vs.adopt_spool_owner(path)
        self.assertIn(f"chown {os.getuid()}:{os.getgid()}", warning)


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
