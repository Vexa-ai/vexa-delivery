# SPDX-License-Identifier: Apache-2.0
"""The publisher half of `require_attestations` (2026-08-31, lane B).

`internal-prod.json` has required `{kind: station-verdict, station:
vexa-staging}` since the prod migration. The verifier could already read an
in-toto attestation ACCUMULATED on the channel beside a published entry, which
binds by release version and image digest set. What nothing could produce was
the object the station cell actually departs with: a verdict bound to the
CANDIDATE COMMIT and to the sha256 of the `values_proven` block lane A added,
riding inside the entry beside the proof it signs.

These tests cover the writing end.

  * the verdict is COMPUTED. There is no --verdict flag; a required value with
    no proven-or-waived row makes it REFUSED, and the REFUSED object names the
    ids. That is the whole point of lane B and it is the first test here.
  * the canonical hash agrees with `jq -Sc`. The verifier recomputes
    `values_proven_sha256` with jq and refuses a mismatch, so if the two
    encoders ever disagree the check turns from a gate into a permanent
    refusal of honest entries. Tested against the real jq, not asserted.
  * `platform-entry --station-verdict` refuses the four ways a verdict can be
    attached to an entry it is not about: a REFUSED verdict, a different
    candidate, a different proof block, and an unsigned file.

The in-cluster verifier makes every one of these checks again — see
kit/verify/tests/test_station_verdict.sh — and it is the copy that binds.
"""
import contextlib
import io
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
import vexa_station_verdict as vsv  # noqa: E402

FIX = REPO / "kit/verify/tests/fixtures/values-proven"
CONTRACT = REPO / "kit/verify/tests/fixtures/contracts/estate-station-verdict.json"
GOLDEN = REPO / "spec/goldens/station-verdict"
STATION = "vexa-staging-fixture"
ZERO_SHA = "0" * 40
MANIFEST_SHA = "e" * 64


def proven(vid, station=STATION):
    return {
        "id": vid,
        "verdict": "proven",
        "evidence": [{
            "what": f"2026-08-31T08:00Z E0 PASS  the station proved {vid}",
            "ref": "stations/fixture/row-fills.log",
            "tested_at": "2026-08-31T08:00:00Z",
        }],
        "station": station,
    }


def render(tmp, rows, station=STATION, candidate=ZERO_SHA, contract=CONTRACT):
    """render(), through the module rather than the CLI, so a failure reports a
    Python traceback instead of an exit code."""
    vp = pathlib.Path(tmp) / "values-proven.json"
    vp.write_text(json.dumps(rows, indent=1) + "\n")
    out = pathlib.Path(tmp) / "verdict"

    class A:
        pass

    a = A()
    a.station, a.candidate_sha, a.manifest_sha256 = station, candidate, MANIFEST_SHA
    a.contract, a.values_proven, a.out = str(contract), str(vp), str(out)
    vsv.cmd_render(a)
    return json.loads((out / vsv.VERDICT_NAME).read_text()), out, vp


class ComputedVerdict(unittest.TestCase):
    """ELIGIBLE is earned, not declared."""

    def test_every_required_value_answered_is_eligible(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc, _, _ = render(tmp, [proven("V-fix-1"), proven("V-fix-3")])
        self.assertEqual(doc["verdict"], "ELIGIBLE")
        self.assertNotIn("unanswered_values", doc)

    def test_a_missing_required_value_refuses_and_names_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc, _, _ = render(tmp, [proven("V-fix-1")])
        self.assertEqual(doc["verdict"], "REFUSED")
        self.assertEqual([u["id"] for u in doc["unanswered_values"]], ["V-fix-3"])
        # A refusal that does not say what it refused sends the reader back to
        # guessing; the schema makes the list mandatory on REFUSED.
        self.assertIn("no proven or waived row", doc["unanswered_values"][0]["reason"])

    def test_an_unproven_advisory_value_does_not_refuse(self):
        # V-fix-2 is advisory in this contract and is answered by nothing.
        with tempfile.TemporaryDirectory() as tmp:
            doc, _, _ = render(tmp, [proven("V-fix-1"), proven("V-fix-3")])
        self.assertEqual(doc["verdict"], "ELIGIBLE")

    def test_a_named_human_waiver_answers_a_required_value(self):
        rows = [proven("V-fix-1"),
                {"id": "V-fix-3", "verdict": "waived", "station": STATION,
                 "waived_by": "A Named Human"}]
        with tempfile.TemporaryDirectory() as tmp:
            doc, _, _ = render(tmp, rows)
        self.assertEqual(doc["verdict"], "ELIGIBLE")

    def test_an_anonymous_waiver_is_refused_by_lane_As_shape_rules(self):
        # Imported, not re-implemented: check_values_proven owns this refusal,
        # so a renderer that stopped calling it would fail here.
        rows = [proven("V-fix-1"), {"id": "V-fix-3", "verdict": "waived", "station": STATION}]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(vexa_channel.CheckFailure) as cm:
                render(tmp, rows)
        self.assertIn("waived_by", str(cm.exception))

    def test_a_proven_row_with_no_evidence_never_reaches_a_verdict(self):
        rows = [proven("V-fix-1"), {"id": "V-fix-3", "verdict": "proven", "station": STATION}]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(vexa_channel.CheckFailure):
                render(tmp, rows)

    def test_the_operator_cannot_supply_a_verdict(self):
        parser_help = subprocess.run(
            [sys.executable, str(REPO / "publisher/vexa_station_verdict.py"), "render", "--help"],
            capture_output=True, text=True, cwd=REPO).stdout
        self.assertNotIn("--verdict ", parser_help)
        self.assertIn("--values-proven", parser_help)

    def test_the_contract_bytes_are_hashed_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc, _, _ = render(tmp, [proven("V-fix-1"), proven("V-fix-3")])
            self.assertEqual(doc["contract_sha256"], vexa_channel.sha256_file(CONTRACT))
            # A contract with different bytes gives a different verdict object,
            # which is what lets an auditor answer "under which promise?".
            other = pathlib.Path(tmp) / "contract.json"
            body = json.loads(CONTRACT.read_text())
            body["contract_id"] = "fixture-renamed"
            other.write_text(json.dumps(body, indent=2) + "\n")
            doc2, _, _ = render(tmp, [proven("V-fix-1"), proven("V-fix-3")], contract=other)
        self.assertEqual(doc2["contract_id"], "fixture-renamed")
        self.assertNotEqual(doc2["contract_sha256"], doc["contract_sha256"])


class CanonicalForm(unittest.TestCase):
    """The hash both sides must compute, or the check is a permanent refusal."""

    def jq(self, rows):
        blob = json.dumps(rows)
        out = subprocess.run(["jq", "-Sc", "."], input=blob, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.rstrip("\n")

    def setUp(self):
        if not shutil.which("jq"):
            self.skipTest("jq not installed; the verifier requires it, this test needs it too")

    def test_python_and_jq_serialise_the_block_identically(self):
        rows = json.loads((GOLDEN / "values-proven.json").read_text())
        self.assertEqual(vexa_channel.canonical_values_proven(rows), self.jq(rows))

    def test_they_agree_on_non_ascii_and_on_key_order(self):
        rows = [proven("V-fix-1")]
        rows[0]["evidence"][0]["what"] = "row → ready ✓  \"quoted\"\ttabbed"
        rows[0] = dict(reversed(list(rows[0].items())))
        self.assertEqual(vexa_channel.canonical_values_proven(rows), self.jq(rows))

    def test_row_order_is_part_of_the_identity(self):
        a = [proven("V-fix-1"), proven("V-fix-3")]
        self.assertNotEqual(vexa_channel.canonical_values_proven_sha256(a),
                            vexa_channel.canonical_values_proven_sha256(list(reversed(a))))


class Golden(unittest.TestCase):
    """spec/goldens/station-verdict — re-rendered from committed inputs."""

    def test_the_golden_is_what_the_code_emits_today(self):
        # Relative paths, from the repo root — the builder records `--fills`
        # VERBATIM as the evidence `ref`, so an absolute path here would bake
        # this machine's home directory into the comparison.
        rel_contract = "kit/verify/tests/fixtures/contracts/estate-station-verdict.json"
        with tempfile.TemporaryDirectory() as tmp:
            block = subprocess.run(
                [sys.executable, "publisher/vexa_values_proven.py",
                 "--contract", rel_contract,
                 "--fills", "kit/verify/tests/fixtures/values-proven/row-fills.log",
                 "--map", "kit/verify/tests/fixtures/values-proven/rows.json",
                 "--station", STATION, "--out", f"{tmp}/values-proven.json"],
                capture_output=True, text=True, cwd=REPO)
            self.assertEqual(block.returncode, 0, block.stderr)
            self.assertEqual(pathlib.Path(f"{tmp}/values-proven.json").read_text(),
                             (GOLDEN / "values-proven.json").read_text())

            out = subprocess.run(
                [sys.executable, "publisher/vexa_station_verdict.py", "render",
                 "--station", STATION, "--candidate-sha", ZERO_SHA,
                 "--manifest-sha256", MANIFEST_SHA, "--contract", rel_contract,
                 "--values-proven", f"{tmp}/values-proven.json", "--out", f"{tmp}/v"],
                capture_output=True, text=True, cwd=REPO)
            self.assertEqual(out.returncode, 0, out.stderr)
            got = json.loads(pathlib.Path(f"{tmp}/v/station-verdict.json").read_text())

        want = json.loads((GOLDEN / "station-verdict.json").read_text())
        self.assertEqual(sorted(got), sorted(want))
        for key in want:
            if key == "rendered_at":
                continue
            self.assertEqual(got[key], want[key], f"{key} drifted from the golden")

    def test_the_golden_validates_against_its_schema(self):
        vsv.schema_validate(json.loads((GOLDEN / "station-verdict.json").read_text()))

    def test_the_schema_refuses_an_eligible_verdict_that_names_unanswered_values(self):
        doc = json.loads((GOLDEN / "station-verdict.json").read_text())
        doc["unanswered_values"] = [{"id": "V-fix-3", "reason": "unproven"}]
        with self.assertRaises(vexa_channel.CheckFailure):
            vsv.schema_validate(doc)

    def test_the_schema_refuses_a_refused_verdict_that_names_none(self):
        doc = json.loads((GOLDEN / "station-verdict.json").read_text())
        doc["verdict"] = "REFUSED"
        with self.assertRaises(vexa_channel.CheckFailure):
            vsv.schema_validate(doc)


class CarriedByPlatformEntry(unittest.TestCase):
    """`platform-entry --station-verdict` — the four ways a verdict can be
    attached to an entry it is not about."""

    def argv(self, tmp, verdict_dir, values_proven, extra=()):
        out = pathlib.Path(tmp) / "entry"
        argv = ["platform-entry",
                "--spec", str(FIX / "estate-spec.yaml"),
                "--validation-contract", str(FIX / "validation-contract.yaml"),
                "--release", "0.0.1-estate-20260831", "--channel", "fixture-estate",
                "--entry-seq", "12", "--identity", "fixture", "--signing-mode", "test_key",
                "--signing-note", "fixture", "--publication-mode", "candidate",
                "--publisher", "fixture", "--out", str(out), *extra]
        if values_proven is not None:
            argv += ["--values-proven", str(values_proven)]
        if verdict_dir is not None:
            argv += ["--station-verdict", str(verdict_dir)]
        return argv, out

    def build(self, tmp, verdict_dir, values_proven, extra=()):
        argv, out = self.argv(tmp, verdict_dir, values_proven, extra)
        rc = vexa_channel.main(argv)
        self.assertEqual(rc, 0, "expected the entry to build")
        return json.loads((out / "entry.json").read_text()), out

    def staged(self, tmp, rows=None, **over):
        """A rendered, 'signed' verdict for the fixture estate. The signature is
        a stub file: what platform-entry checks is that a bundle is THERE — the
        cryptographic check belongs to the verifier and is exercised in the
        shell suite against a real cosign invocation."""
        rows = rows or [proven("V-fix-1"), proven("V-fix-3")]
        doc, vdir, vp = render(tmp, rows, **over)
        (vdir / (vsv.VERDICT_NAME + ".sigstore.json")).write_text('{"fixture": true}\n')
        return doc, vdir, vp

    def test_a_matching_verdict_rides_the_entry_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            _doc, vdir, vp = self.staged(tmp)
            entry, out = self.build(tmp, vdir, vp)
            rows = [e for e in entry["evidence"] if e["kind"] == "station_verdict"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["name"], f"station-verdict-{STATION}.json")
            self.assertIn(STATION, rows[0]["description"])
            # Both files ride the evidence dir, like the validation contract does.
            self.assertTrue((out / "evidence" / rows[0]["name"]).is_file())
            self.assertTrue((out / "evidence" / f"{rows[0]['name']}.sigstore.json").is_file())
            # And the bundle is digest-listed too, so §3 of the verifier checks it.
            self.assertIn(f"{rows[0]['name']}.sigstore.json",
                          [e["name"] for e in entry["evidence"]])

    def test_the_carried_verdict_binds_to_the_entrys_own_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc, vdir, vp = self.staged(tmp)
            entry, out = self.build(tmp, vdir, vp)
        got = vexa_channel.canonical_values_proven_sha256(entry["values_proven"])
        self.assertEqual(got, doc["values_proven_sha256"])
        self.assertEqual(doc["candidate_sha"], entry["release"]["source_sha"])

    def refuses(self, argvfn, needle):
        """A refusal is exit 3 AND a message that says which check and why —
        the exit code alone would let a rename of the reason go unnoticed."""
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(err):
                rc = vexa_channel.main(argvfn(tmp))
            out = pathlib.Path(tmp) / "entry" / "entry.json"
            built = out.exists()
        self.assertEqual(rc, 3, f"expected a refusal, got {rc}")
        self.assertFalse(built, "a refused build must not leave an entry.json behind")
        self.assertIn("REFUSED E5:", err.getvalue())
        self.assertIn(needle, err.getvalue())

    def test_an_entry_does_not_carry_a_stations_no(self):
        def go(tmp):
            _doc, vdir, vp = self.staged(tmp, rows=[proven("V-fix-1")])
            return self.argv(tmp, vdir, vp)[0]
        self.refuses(go, "An entry does not carry a station's no")

    def test_a_verdict_about_another_candidate_is_refused(self):
        def go(tmp):
            _doc, vdir, vp = self.staged(tmp, candidate="a" * 40)
            return self.argv(tmp, vdir, vp)[0]
        self.refuses(go, "proves nothing here")

    def test_a_verdict_over_another_proof_block_is_refused(self):
        def go(tmp):
            _doc, vdir, _vp = self.staged(tmp)
            # The station signed one block; ship a different one.
            other = pathlib.Path(tmp) / "other.json"
            other.write_text(json.dumps(
                [proven("V-fix-1"), proven("V-fix-3", station="somewhere-else")], indent=1))
            return self.argv(tmp, vdir, other)[0]
        self.refuses(go, "over a different proof")

    def test_an_unsigned_verdict_is_refused(self):
        def go(tmp):
            _doc, vdir, vp = render(tmp, [proven("V-fix-1"), proven("V-fix-3")])
            return self.argv(tmp, vdir, vp)[0]
        self.refuses(go, "carries no signature")

    def test_a_verdict_with_no_block_to_bind_to_is_refused(self):
        def go(tmp):
            _doc, vdir, _vp = self.staged(tmp)
            return self.argv(tmp, vdir, None)[0]
        self.refuses(go, "this entry carries none")

    def test_two_verdicts_from_one_station_are_refused(self):
        def go(tmp):
            _doc, vdir, vp = self.staged(tmp)
            second = pathlib.Path(tmp) / "verdict2"
            second.mkdir()
            shutil.copy(vdir / vsv.VERDICT_NAME, second / vsv.VERDICT_NAME)
            shutil.copy(vdir / (vsv.VERDICT_NAME + ".sigstore.json"),
                        second / (vsv.VERDICT_NAME + ".sigstore.json"))
            return self.argv(tmp, vdir, vp, extra=["--station-verdict", str(second)])[0]
        self.refuses(go, "One station, one departure")

    def test_an_entry_without_the_flag_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            _doc, _vdir, vp = self.staged(tmp)
            entry, _ = self.build(tmp, None, vp)
        self.assertEqual([e for e in entry["evidence"] if e["kind"] == "station_verdict"], [])


if __name__ == "__main__":
    unittest.main()
