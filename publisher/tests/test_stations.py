# SPDX-License-Identifier: Apache-2.0
"""The ledger reducer: what it writes, what it refuses, and what it must not
sweep into a commit that is not its own."""
import datetime
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import vexa_stations as vs  # noqa: E402


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args],
                          capture_output=True, text=True, check=True)


def new_ledger():
    root = pathlib.Path(tempfile.mkdtemp(prefix="vexa-ledger-"))
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "test@vexa.invalid")
    git(root, "config", "user.name", "test")
    (root / "README.md").write_text("ledger\n")
    git(root, "add", "README.md")
    git(root, "commit", "-q", "-m", "init")
    return root


def entry(seq=1, channel="pilot-stable", release="v0.12.23", expires=None):
    e = {
        "schema_version": 1,
        "channel": {"name": channel, "entry_seq": seq, "supersedes": None},
        "release": {"version": release, "source_sha": "abc123"},
        "chart": {"version": "0.12.35", "digest": "sha256:" + "9" * 64},
        "publication": {"mode": "published", "published_at": "2026-08-24T17:47:22Z"},
    }
    if expires:
        e["expires"] = expires
    return e


class PublishReducer(unittest.TestCase):
    def setUp(self):
        self.root = new_ledger()

    def test_writes_channel_yaml_and_commits(self):
        out = vs.record_publish(self.root, entry(seq=4), entry_digest="sha256:" + "a" * 64,
                                registry_ref="reg/vexa/channel/pilot-stable",
                                channel_tag="current")
        doc = vs.load_yaml(vs.channel_file(self.root, "pilot-stable"))
        self.assertEqual(doc["last_entry_seq"], 4)
        self.assertEqual(doc["current"]["release"], "v0.12.23")
        self.assertEqual(doc["registry_ref"], "reg/vexa/channel/pilot-stable")
        self.assertIsNotNone(out["commit"])
        # The commit exists and touched exactly the channel file.
        names = git(self.root, "show", "--name-only", "--format=", "HEAD").stdout.split()
        self.assertEqual(names, ["channels/pilot-stable/channel.yaml"])

    def test_second_entry_appends_and_advances(self):
        vs.record_publish(self.root, entry(seq=1), channel_tag="current")
        vs.record_publish(self.root, entry(seq=2, release="v0.12.24"), channel_tag="current")
        doc = vs.load_yaml(vs.channel_file(self.root, "pilot-stable"))
        self.assertEqual(doc["last_entry_seq"], 2)
        self.assertEqual([e["entry_seq"] for e in doc["entries"]], [1, 2])
        self.assertEqual(doc["current"]["release"], "v0.12.24")

    def test_a_candidate_publish_does_not_move_current(self):
        """`current` MIRRORS THE CHANNEL TAG, and is not a synonym for newest.

        Caught publishing the seq-3 estate candidate, 2026-08-25. A candidate
        by definition does not move the tag, and the reducer moved `current`
        anyway — so the registry's tag pointed at seq 1 while the ledger said
        seq 3, and nothing errored. That is the worst shape a durability store
        can fail in: channel.yaml exists to answer "what was published, and
        where was every station pointed" when the bucket is gone, and a
        `current` that means something other than the tag answers it wrongly,
        confidently, and only in the case that matters."""
        vs.record_publish(self.root, entry(seq=1), channel_tag="current")
        vs.record_publish(self.root, entry(seq=2, release="v0.12.24"))   # candidate
        doc = vs.load_yaml(vs.channel_file(self.root, "pilot-stable"))
        self.assertEqual(doc["last_entry_seq"], 2, "the sequence still advances")
        self.assertEqual([e["entry_seq"] for e in doc["entries"]], [1, 2],
                         "and the entry is still recorded")
        self.assertEqual(doc["current"]["entry_seq"], 1,
                         "but `current` stays where the tag is")

    def test_the_first_publish_of_a_channel_leaves_current_absent_if_no_tag_moved(self):
        """Nothing is invented to fill it. A channel whose tag has never been
        moved has no current entry, and saying so is the honest answer."""
        vs.record_publish(self.root, entry(seq=1))
        doc = vs.load_yaml(vs.channel_file(self.root, "pilot-stable"))
        self.assertIsNone(doc["current"])
        self.assertEqual(doc["last_entry_seq"], 1)

    def test_refuses_a_sequence_that_goes_backwards(self):
        vs.record_publish(self.root, entry(seq=3))
        with self.assertRaises(vs.LedgerError) as cm:
            vs.record_publish(self.root, entry(seq=2))
        # The refusal must name the consequence, not merely the mismatch.
        self.assertIn("does not advance", str(cm.exception))

    def test_expiry_index_lists_only_entries_that_declare_one(self):
        vs.record_publish(self.root, entry(seq=1))
        vs.record_publish(self.root, entry(seq=2, expires="2026-09-24T00:00:00Z"))
        doc = vs.load_yaml(vs.channel_file(self.root, "pilot-stable"))
        self.assertEqual([r["entry_seq"] for r in doc["expiry"]], [2])

    def test_refuses_an_entry_with_no_sequence(self):
        broken = entry()
        del broken["channel"]["entry_seq"]
        with self.assertRaises(vs.LedgerError):
            vs.record_publish(self.root, broken)

    def test_refuses_a_channel_name_that_escapes_the_tree(self):
        with self.assertRaises(vs.LedgerError):
            vs.record_publish(self.root, entry(channel="../../etc"))

    def test_no_yaml_aliases_in_the_written_file(self):
        """`current` and the last of `entries` are the same row. Emitted as an
        alias, a reviewer cannot see what changed in a diff."""
        vs.record_publish(self.root, entry(seq=1))
        text = vs.channel_file(self.root, "pilot-stable").read_text()
        self.assertNotIn("&id001", text)
        self.assertNotIn("*id001", text)


class CommitByPathspec(unittest.TestCase):
    """2026-08-21: `git add <two paths> && git commit` committed 180 files,
    because commit commits THE INDEX. The ledger is written by tooling that may
    be running twice at once, so this is a test, not a comment."""

    def test_does_not_sweep_another_writers_staged_file(self):
        root = new_ledger()
        stowaway = root / "someone-elses-work.txt"
        stowaway.write_text("a concurrent agent staged this\n")
        git(root, "add", "someone-elses-work.txt")

        vs.record_publish(root, entry(seq=1))

        names = git(root, "show", "--name-only", "--format=", "HEAD").stdout.split()
        self.assertEqual(names, ["channels/pilot-stable/channel.yaml"])
        still_staged = git(root, "diff", "--cached", "--name-only").stdout.split()
        self.assertIn("someone-elses-work.txt", still_staged)

    def test_a_no_op_reduction_makes_no_commit(self):
        root = new_ledger()
        vs.record_publish(root, entry(seq=1))
        before = git(root, "rev-parse", "HEAD").stdout.strip()
        # Same entry again: the only field that moves is recorded_at, so this
        # is not truly a no-op — assert on what a real no-op does instead.
        path = vs.channel_file(root, "pilot-stable")
        self.assertIsNone(vs.commit_paths(root, "nothing moved", [path]))
        self.assertEqual(git(root, "rev-parse", "HEAD").stdout.strip(), before)


def manifest(station="pilot", verdicts=("PASS", "PASS")):
    return {
        "schema_version": 1,
        "station": station,
        "generated_at": "2026-08-25T12:27:43+00:00",
        "kit": {"commit": "03d4c79", "describe": "03d4c79-dirty"},
        "kubernetes": {"server_version": "v1.36.3"},
        "provider": {"name": "lke"},
        "namespaces": {"target": "vexa-staging"},
        "contract": {"contract_id": "rehearsal-2026-01", "sha256": "f" * 64},
        "phases": {"preflight": {"verdict": verdicts[0]}, "smoke": {"verdict": verdicts[1]}},
        "files": [],
    }


def receipt(station="pilot", ts="2026-08-25T17:36:09Z", **kw):
    r = {"station": station, "ingested_at": ts, "bundle": f"station-{station}.tar.gz",
         "bundle_sha256": "c" * 64, "checks_passed": ["S1", "S2", "S3", "S4"]}
    r.update(kw)
    return r


class IngestReducer(unittest.TestCase):
    def setUp(self):
        self.root = new_ledger()
        vs.record_publish(self.root, entry(seq=4))

    def test_writes_state_and_stores_the_receipt(self):
        out = vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                               receipt=receipt(), manifest=manifest())
        state = vs.load_yaml(pathlib.Path(out["path"]))
        self.assertEqual(state["station"], "pilot")
        self.assertEqual(state["last_receipt"]["verdict"], "PASS")
        self.assertEqual(state["identity"]["provider"], "lke")
        self.assertEqual(state["identity"]["kit_version"], "03d4c79-dirty")
        stored = pathlib.Path(out["receipts"]) / "ingest-receipt.json"
        self.assertEqual(json.loads(stored.read_text())["bundle_sha256"], "c" * 64)

    def test_stores_the_bundle_verbatim(self):
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as fh:
            fh.write(b"not really a tarball, but byte-identical is the point")
            bundle = pathlib.Path(fh.name)
        out = vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                               receipt=receipt(), manifest=manifest(), bundle=bundle)
        copied = pathlib.Path(out["receipts"]) / bundle.name
        self.assertEqual(copied.read_bytes(), bundle.read_bytes())

    def test_ingest_never_writes_channel_yaml(self):
        """One writer per surface. The commit is the proof."""
        vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                         receipt=receipt(), manifest=manifest())
        names = git(self.root, "show", "--name-only", "--format=", "HEAD").stdout.split()
        self.assertTrue(names, "the ingest made no commit")
        for n in names:
            self.assertTrue(n.startswith("channels/pilot-stable/stations/pilot/"), n)

    def test_position_is_read_from_the_stations_own_values(self):
        out = vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                               receipt=receipt(), manifest=manifest(),
                               values_text="spec:\n  targetRevision: \"0.12.35\"\n")
        self.assertEqual(vs.load_yaml(pathlib.Path(out["path"]))["subscribed_position"], "0.12.35")

    def test_an_unstated_position_is_unknown_not_assumed(self):
        out = vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                               receipt=receipt(), manifest=manifest())
        self.assertEqual(vs.load_yaml(pathlib.Path(out["path"]))["subscribed_position"], "unknown")

    def test_an_unstated_entry_seq_stays_null(self):
        """Defaulting it to the channel's newest would make `stale` unable to
        fire for exactly the stations we are least sure about."""
        out = vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                               receipt=receipt(), manifest=manifest())
        self.assertIsNone(vs.load_yaml(pathlib.Path(out["path"]))["last_receipt"]["entry_seq"])

    def test_a_failed_phase_is_a_contract_breach(self):
        out = vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                               receipt=receipt(), manifest=manifest(verdicts=("PASS", "FAIL")))
        self.assertIn("contract-breach", vs.load_yaml(pathlib.Path(out["path"]))["flags"])

    def test_behind_the_newest_entry_is_stale(self):
        out = vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                               receipt=receipt(entry_seq=2), manifest=manifest())
        self.assertIn("stale", vs.load_yaml(pathlib.Path(out["path"]))["flags"])

    def test_an_old_receipt_is_stale_even_at_the_right_sequence(self):
        out = vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                               receipt=receipt(ts="2026-01-01T00:00:00Z"), manifest=manifest())
        self.assertIn("stale", vs.load_yaml(pathlib.Path(out["path"]))["flags"])

    def test_revoked_is_a_humans_word_and_survives_a_reduction(self):
        vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                         receipt=receipt(), manifest=manifest())
        spath = vs.station_dir(self.root, "pilot-stable", "pilot") / "state.yaml"
        doc = vs.load_yaml(spath)
        doc["flags"] = ["revoked"]
        vs.write_yaml(spath, vs.STATE_HEADER, doc)
        vs.record_ingest(self.root, channel="pilot-stable", station="pilot",
                         receipt=receipt(ts="2026-08-26T00:00:00Z"), manifest=manifest())
        self.assertIn("revoked", vs.load_yaml(spath)["flags"])


class PinMoves(unittest.TestCase):
    def setUp(self):
        self.root = new_ledger()
        vs.record_publish(self.root, entry(seq=4))

    def test_a_pin_move_records_the_justification_in_history(self):
        vs.record_pin(self.root, channel="pilot-stable", station="pilot", position="0.12.35",
                      justification="dev station receipt 2026-08-25: PASS")
        body = git(self.root, "log", "-1", "--format=%B").stdout
        self.assertIn("dev station receipt 2026-08-25: PASS", body)
        self.assertIn("unset -> 0.12.35", body)
        doc = vs.load_yaml(vs.channel_file(self.root, "pilot-stable"))
        self.assertEqual(doc["pins"]["pilot"], "0.12.35")

    def test_a_pin_move_with_no_reason_is_refused(self):
        with self.assertRaises(vs.LedgerError):
            vs.record_pin(self.root, channel="pilot-stable", station="pilot",
                          position="0.12.35", justification="   ")

    def test_a_pin_on_an_unpublished_channel_is_refused(self):
        with self.assertRaises(vs.LedgerError):
            vs.record_pin(self.root, channel="nowhere", station="x", position="*",
                          justification="because")


class Guards(unittest.TestCase):
    def test_a_directory_that_is_not_a_git_checkout_is_refused(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        with self.assertRaises(vs.LedgerError) as cm:
            vs.resolve_root(tmp)
        self.assertIn("audit trail", str(cm.exception))

    def test_derive_flags_on_an_empty_state_claims_nothing(self):
        self.assertEqual(vs.derive_flags({}, {}), [])

    def test_stale_by_age_uses_the_declared_threshold(self):
        now = datetime.datetime(2026, 8, 25, tzinfo=datetime.timezone.utc)
        fresh = {"last_receipt": {"ts": "2026-08-20T00:00:00Z", "verdict": "PASS"}}
        old = {"last_receipt": {"ts": "2026-01-01T00:00:00Z", "verdict": "PASS"}}
        self.assertEqual(vs.derive_flags(fresh, {}, now=now), [])
        self.assertEqual(vs.derive_flags(old, {}, now=now), ["stale"])


if __name__ == "__main__":
    unittest.main()
