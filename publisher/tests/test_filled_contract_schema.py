# SPDX-License-Identifier: Apache-2.0
"""The filled channel contract — one document, filled in by a station run.

THE RULING (Vexa-ai/vexa-delivery#12, two comments, 2026-08-29). There is no
separate "validation contract" artifact. The CHANNEL's contract is a form
stating the demand; a station run returns that same form with a proof column
added per row. So a filled instance carries the SAME contract_id as the demand
and binds itself to the demand's exact BYTES, the demand is constant across a
channel, and what varies per set is the proof column. A contract belongs to a
channel — stations are enforcement points, not owners.

WHAT THESE TESTS ARE FOR. `spec/filled-contract.schema.json` is not evaluated
by the in-cluster verifier yet; turn 2 teaches it to read this. Until then the
schema is the definition, and a definition nothing validates against drifts
from the instances people actually write. These tests hold the shape:

  * the golden instance validates, and it is a REAL station run — the seq-6
    run on bbb, findings and all — because a golden built from a happy path
    would not exercise `unproven`, `not-run`, `fidelity` or `does_not_prove`,
    which are the four fields the whole document exists for;
  * the fields that carry the ruling are STRUCTURALLY required, not merely
    documented — a filled contract with no binding hash, or one that quietly
    drops a row of the demand, is refused here rather than in review;
  * `additionalProperties: false` holds, so a typo'd key is an error and not
    a silently ignored claim.
"""
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "spec/filled-contract.schema.json"
GOLDEN = ROOT / "spec/goldens/0.12.23-estate-20260829-seq6/filled-contract.json"

# The unfilled demand the golden answers, as a fixture rather than as the live
# record: the real ledger is private, and a test that needed it could not run.
DEMAND_ROWS = ["V-est-1", "V-est-2", "V-est-3",
               "V-est-4", "V-est-5", "V-est-6", "V-est-7"]


def schema():
    return json.loads(SCHEMA_PATH.read_text())


def golden():
    return json.loads(GOLDEN.read_text())


def errors(doc):
    import jsonschema
    v = jsonschema.Draft202012Validator(schema())
    return sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path))


def without(doc, key):
    d = json.loads(json.dumps(doc))
    d.pop(key, None)
    return d


class TheSchemaIsWellFormed(unittest.TestCase):

    def test_the_schema_is_itself_a_valid_2020_12_schema(self):
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(schema())

    def test_it_says_the_verifier_does_not_evaluate_it_yet(self):
        """An honest state marker, in the artifact and not only in the docs.

        The gate admits entries on the carriage block alone today. A schema
        that read as enforced would be read as enforced."""
        self.assertIn("turn 2", schema()["description"])


class TheGoldenIsAReadStationRun(unittest.TestCase):

    def test_it_validates(self):
        self.assertEqual([], [e.message for e in errors(golden())])

    def test_it_binds_to_the_demands_bytes_not_its_name(self):
        """The load-bearing half of the binding. An id is what a document
        calls itself; the drift that matters keeps the id and moves a
        threshold, so the hash is what makes the instance checkable."""
        g = golden()
        self.assertEqual(g["contract_id"], g["fills_contract"]["id"])
        self.assertEqual(
            g["fills_contract"]["sha256"],
            "a76cef3c62c21d0ee01984fcf5a511b4040f49b5a03dca248148705cdf479551")

    def test_it_carries_every_row_of_the_demand(self):
        """Including the ones it could not answer. An instance that omitted
        them would read as complete while being narrower than the contract it
        claims to fill."""
        self.assertEqual([r["id"] for r in golden()["required_values"]], DEMAND_ROWS)

    def test_every_row_carries_a_proof_column(self):
        for row in golden()["required_values"]:
            self.assertIn("proof", row, row["id"])
            self.assertIn(row["proof"]["status"],
                          ("proven", "unproven", "not-run"), row["id"])

    def test_the_golden_exercises_all_three_statuses(self):
        """A golden built from a happy path would never exercise the fields
        this document exists for."""
        seen = {r["proof"]["status"] for r in golden()["required_values"]}
        self.assertEqual(seen, {"proven", "unproven", "not-run"})

    def test_a_proven_row_points_at_evidence_with_a_hash(self):
        """A proof with no pointer is an assertion, and a pointer with no hash
        names a location whose contents can change after the claim was made."""
        proven = [r for r in golden()["required_values"]
                  if r["proof"]["status"] == "proven"]
        self.assertTrue(proven)
        for row in proven:
            ev = row["proof"].get("evidence") or []
            self.assertTrue(ev, row["id"])
            for e in ev:
                self.assertRegex(e.get("sha256", ""), r"^[0-9a-f]{64}$")

    def test_every_row_states_what_it_does_not_prove(self):
        """The scope limit lives ON THE ROW. A caveat kept anywhere else is a
        caveat nobody reads at the moment they are reading the row — which is
        how the seq-6 V-est-3 PASS could otherwise have been read as a claim
        about the published artifact rather than about a local build of the
        same commit."""
        for row in golden()["required_values"]:
            self.assertTrue(row["proof"].get("does_not_prove"), row["id"])

    def test_a_row_proven_against_a_double_lists_the_double(self):
        """Real by default; a double carries its justification. A row proven
        against stand-ins nobody listed is the most expensive kind of green."""
        v3 = next(r for r in golden()["required_values"] if r["id"] == "V-est-3")
        fid = v3["proof"]["fidelity"]
        self.assertTrue(fid)
        for f in fid:
            if f["kind"] in ("double", "absent"):
                self.assertTrue(f.get("justification"), f["dependency"])

    def test_a_required_row_left_unproven_makes_the_instance_not_eligible(self):
        g = golden()
        blocked = [r for r in g["required_values"]
                   if r["enforcement"] == "required"
                   and r["proof"]["status"] != "proven"]
        self.assertTrue(blocked)
        self.assertEqual(g["verdict"], "NOT_ELIGIBLE")


class TheShapeIsEnforcedNotJustDocumented(unittest.TestCase):

    def test_the_binding_to_the_demand_is_required(self):
        self.assertTrue(errors(without(golden(), "fills_contract")))

    def test_the_filling_station_is_required(self):
        """An unattributable filled contract looks like proof and is not —
        the same reason --verdict-out refuses to write a verdict with no
        --station."""
        self.assertTrue(errors(without(golden(), "station")))

    def test_the_verdict_is_required(self):
        self.assertTrue(errors(without(golden(), "verdict")))

    def test_a_binding_hash_must_be_a_sha256(self):
        d = golden()
        d["fills_contract"]["sha256"] = "a76cef3c"
        self.assertTrue(errors(d))

    def test_an_invented_proof_status_is_refused(self):
        """`partially-proven` is the shape of every green that should not
        have been green."""
        d = golden()
        d["required_values"][0]["proof"]["status"] = "partially-proven"
        self.assertTrue(errors(d))

    def test_an_invented_verdict_is_refused(self):
        d = golden()
        d["verdict"] = "PASS"
        self.assertTrue(errors(d))

    def test_a_typod_key_is_an_error_not_a_silently_ignored_claim(self):
        d = golden()
        d["required_values"][0]["proof"]["does_not_prove_"] = "typo"
        self.assertTrue(errors(d))

    def test_an_unknown_top_level_key_is_refused(self):
        d = golden()
        d["approved"] = True
        self.assertTrue(errors(d))

    def test_an_instance_with_no_rows_is_refused(self):
        d = golden()
        d["required_values"] = []
        self.assertTrue(errors(d))


class TheEvidenceKindStaysLegacyThisTurn(unittest.TestCase):

    def test_the_carriage_block_still_names_validation_contract(self):
        """The ruling renames the DOCUMENT, not the wire string. Entries
        already published carry `validation_contract` as an evidence kind and
        their verifiers match on it, so the string stays this turn and the
        prose calls it the filled contract."""
        carriage = golden()["carriage"]
        self.assertIn("validation_contract", carriage["require_evidence_kinds"])
        self.assertIn("validation_contract", carriage["forbid_absent_evidence"])


if __name__ == "__main__":
    unittest.main()
