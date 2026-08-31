# SPDX-License-Identifier: Apache-2.0
"""The publisher half of `carriage.require_entry_values_proven` (2026-08-31).

The clause was void in both directions. This file covers the writing end: the
schema and the `platform-entry --values-proven` flag that fills it, and the
station-side builder that produces the block from a station's committed fills
rather than from someone's memory.

The refusals are the point. Every one of them is a shape that would otherwise
reach a subscriber's PreSync hook looking like proof: a `proven` row with no
evidence, a waiver with nobody's name on it, two rows claiming one value, a
verdict outside the enum, evidence about an image the entry does not ship. The
in-cluster verifier refuses each of them too — see
kit/verify/tests/test_values_proven.sh — and it is the one that binds; these
checks exist so the publisher finds out at build time instead.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "publisher"))

import vexa_channel  # noqa: E402

FIX = REPO / "kit/verify/tests/fixtures/values-proven"
CONTRACT = REPO / "kit/verify/tests/fixtures/contracts/estate-values-proven.json"
BUILDER = REPO / "publisher/vexa_values_proven.py"


def good_row(**over):
    row = {
        "id": "V-fix-1",
        "verdict": "proven",
        "evidence": [{
            "what": "2026-08-31T08:00Z E0 PASS  the station said so",
            "ref": "stations/fixture/row-fills.log",
            "tested_at": "2026-08-31T08:00:00Z",
        }],
        "station": "fixture-station",
    }
    row.update(over)
    return row


class ValuesProvenSchema(unittest.TestCase):
    """check_values_proven — the one definition both writers call."""

    def refuses(self, rows, needle):
        with self.assertRaises(vexa_channel.CheckFailure) as cm:
            vexa_channel.check_values_proven(rows)
        self.assertIn(needle, str(cm.exception))
        self.assertTrue(str(cm.exception).startswith("E4:"), cm.exception)

    def test_a_well_formed_block_is_accepted(self):
        rows = [good_row()]
        self.assertEqual(vexa_channel.check_values_proven(rows), rows)

    def test_an_empty_block_is_not_a_block(self):
        self.refuses([], "non-empty JSON array")

    def test_id_must_be_a_non_empty_string(self):
        self.refuses([good_row(id="")], "non-empty string")
        self.refuses([good_row(id=1)], "non-empty string")

    def test_one_value_cannot_carry_two_claims(self):
        """Two rows for one id means nothing says which one binds."""
        self.refuses([good_row(), good_row()], "appears twice")

    def test_verdict_is_an_enum_not_a_free_field(self):
        self.refuses([good_row(verdict="partially-proven")], "must be 'proven' or 'waived'")

    def test_proven_with_no_evidence_is_an_assertion(self):
        self.refuses([good_row(evidence=[])], "at least one evidence row")
        row = good_row()
        row.pop("evidence")
        self.refuses([row], "at least one evidence row")

    def test_evidence_rows_must_say_what_where_and_when(self):
        for field in ("what", "ref", "tested_at"):
            row = good_row()
            row["evidence"][0][field] = ""
            self.refuses([row], f"'{field}' must be a non-empty string")

    def test_tested_at_must_be_a_real_instant(self):
        row = good_row()
        row["evidence"][0]["tested_at"] = "2026-08-31T08:0xZ"
        self.refuses([row], "not an ISO-8601 Z stamp")

    def test_a_waiver_must_name_the_human(self):
        self.refuses([{"id": "V-fix-1", "verdict": "waived", "station": "s"}],
                     "must name the human who granted it")
        self.assertTrue(vexa_channel.check_values_proven(
            [{"id": "V-fix-1", "verdict": "waived", "station": "s", "waived_by": "A Human"}]))

    def test_a_claim_must_name_its_station(self):
        self.refuses([good_row(station="")], "must name the station")

    def test_subject_digest_must_be_a_digest(self):
        row = good_row()
        row["evidence"][0]["subject_digest"] = "latest"
        self.refuses([row], "not sha256:<64 hex>")


class PlatformEntryCarriesTheBlock(unittest.TestCase):
    """`platform-entry --values-proven` — the block reaches the signed entry."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="values-proven-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def build(self, values_proven=None):
        argv = [
            "platform-entry",
            "--spec", str(FIX / "estate-spec.yaml"),
            "--validation-contract", str(FIX / "validation-contract.yaml"),
            "--release", "0.0.1-estate-20260831",
            "--channel", "fixture-estate",
            "--entry-seq", "12",
            "--identity", "fixture",
            "--signing-mode", "test_key",
            "--signing-note", "fixture",
            "--publication-mode", "candidate",
            "--publisher", "fixture",
            "--out", str(self.tmp / "entry"),
        ]
        if values_proven is not None:
            path = self.tmp / "values-proven.json"
            path.write_text(json.dumps(values_proven))
            argv += ["--values-proven", str(path)]
        rc = vexa_channel.main(argv)
        return rc, self.tmp / "entry" / "entry.json"

    def test_the_block_lands_in_the_entry_verbatim(self):
        rows = [good_row()]
        rc, entry = self.build(rows)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(entry.read_text())["values_proven"], rows)

    def test_the_entry_still_validates_against_the_sealed_schema(self):
        """C9 runs on the assembled entry; values_proven is part of it now."""
        rc, entry = self.build([good_row()])
        self.assertEqual(rc, 0)
        sys.path.insert(0, str(REPO / "spec"))
        try:
            import validate as v
            self.assertEqual(v.validate_file(entry, v.load_schema()), [])
        finally:
            sys.path.remove(str(REPO / "spec"))

    def test_the_block_is_optional_so_release_entries_are_unaffected(self):
        """Every entry ever published lacks it; the schema must still admit them.
        Whether that is ACCEPTABLE is the contract's decision, not the schema's."""
        rc, entry = self.build(None)
        self.assertEqual(rc, 0)
        self.assertNotIn("values_proven", json.loads(entry.read_text()))

    def test_evidence_about_another_release_is_refused_at_build_time(self):
        row = good_row()
        row["evidence"][0]["subject_digest"] = "sha256:" + "9" * 64
        rc = self.build([row])[0]
        self.assertEqual(rc, 3, "a foreign subject_digest should REFUSE, not build")

    def test_evidence_about_an_image_this_entry_ships_is_accepted(self):
        row = good_row()
        row["evidence"][0]["subject_digest"] = "sha256:" + "a" * 64
        rc, entry = self.build([row])
        self.assertEqual(rc, 0)
        self.assertIn("subject_digest", json.loads(entry.read_text())["values_proven"][0]["evidence"][0])

    def test_a_malformed_block_refuses_the_whole_build(self):
        rc = self.build([good_row(verdict="maybe")])[0]
        self.assertEqual(rc, 3)


class BuilderFromStationFills(unittest.TestCase):
    """vexa_values_proven.py — evidence is COPIED out of the station's log."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="vp-builder-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "values-proven.json"

    def run_builder(self, mapping, fills=None):
        map_path = self.tmp / "map.json"
        map_path.write_text(json.dumps(mapping))
        proc = subprocess.run(
            [sys.executable, str(BUILDER),
             "--contract", str(CONTRACT),
             "--fills", str(fills or FIX / "row-fills.log"),
             "--map", str(map_path),
             "--station", "fixture-station",
             "--out", str(self.out)],
            capture_output=True, text=True, cwd=REPO)
        return proc

    def test_a_mapped_pass_becomes_evidence_verbatim(self):
        proc = self.run_builder({"E0": "V-fix-1", "E5": "V-fix-1", "F0": "V-fix-3"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rows = json.loads(self.out.read_text())
        self.assertEqual([r["id"] for r in rows], ["V-fix-1", "V-fix-3"])
        self.assertEqual(len(rows[0]["evidence"]), 2, "both mapped PASS rows should contribute")
        line = (FIX / "row-fills.log").read_text().splitlines()[1].strip()
        self.assertEqual(rows[0]["evidence"][0]["what"], line,
                         "the fill line must be quoted verbatim, not summarised")
        self.assertEqual(rows[0]["station"], "fixture-station")

    def test_it_refuses_to_prove_a_required_value_with_no_pass(self):
        proc = self.run_builder({"E3": "V-fix-1", "F0": "V-fix-3"})
        self.assertEqual(proc.returncode, 3, proc.stdout)
        self.assertIn("V-fix-1", proc.stderr)
        self.assertIn("E3 PART", proc.stderr, "the refusal should say what it found instead")
        self.assertFalse(self.out.exists(),
                         "a refusal must write NOTHING — a partial block looks complete")

    def test_a_required_value_nobody_mapped_is_a_refusal_not_a_silence(self):
        proc = self.run_builder({"E0": "V-fix-1"})
        self.assertEqual(proc.returncode, 3)
        self.assertIn("no station row is mapped to it", proc.stderr)

    def test_a_map_naming_a_value_the_contract_lacks_is_a_typo_and_refuses(self):
        proc = self.run_builder({"E0": "V-fix-9"})
        self.assertEqual(proc.returncode, 3)
        self.assertIn("which this contract does not declare", proc.stderr)

    def test_only_the_exact_token_PASS_proves(self):
        """PART, PASS*, FINDING are the station saying 'not entirely'. A tool
        that reads them as proof launders a caveat into a green tick."""
        fills = self.tmp / "fills.log"
        fills.write_text(
            "2026-08-31T08:00Z E0 PASS*  passed with an asterisk\n"
            "2026-08-31T08:10Z F0 PASS  clean\n")
        proc = self.run_builder({"E0": "V-fix-1", "F0": "V-fix-3"}, fills=fills)
        self.assertEqual(proc.returncode, 3)
        self.assertIn("E0 PASS*", proc.stderr)

    def test_the_coarse_station_stamp_is_rounded_down_not_invented(self):
        proc = self.run_builder({"E0": "V-fix-1", "F0": "V-fix-3"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rows = json.loads(self.out.read_text())
        # the log says 08:0xZ — no seconds, and a digit nobody wrote down
        self.assertEqual(rows[0]["evidence"][0]["tested_at"], "2026-08-31T08:00:00Z")

    def test_an_unreadable_stamp_disqualifies_the_line(self):
        fills = self.tmp / "fills.log"
        fills.write_text("yesterday E0 PASS  it worked\n"
                         "2026-08-31T08:10Z F0 PASS  clean\n")
        proc = self.run_builder({"E0": "V-fix-1", "F0": "V-fix-3"}, fills=fills)
        self.assertEqual(proc.returncode, 3)
        self.assertIn("unreadable timestamp", proc.stderr)

    def test_it_does_not_mint_waivers(self):
        """A waiver is a human accepting an unproven value. The refusal says so,
        because the alternative is a machine deciding what a human may excuse."""
        proc = self.run_builder({"E3": "V-fix-1", "F0": "V-fix-3"})
        self.assertIn("this tool does not mint waivers", proc.stderr)

    def test_advisory_values_are_skipped_out_loud(self):
        proc = self.run_builder({"E0": "V-fix-1", "E3": "V-fix-2", "F0": "V-fix-3"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("skipped (advisory, unproven): V-fix-2", proc.stdout)
        self.assertNotIn("V-fix-2", [r["id"] for r in json.loads(self.out.read_text())])

    def test_its_output_passes_the_same_check_the_entry_builder_runs(self):
        proc = self.run_builder({"E0": "V-fix-1", "F0": "V-fix-3"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rows = json.loads(self.out.read_text())
        self.assertEqual(vexa_channel.check_values_proven(rows), rows)


if __name__ == "__main__":
    unittest.main()
