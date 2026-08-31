# SPDX-License-Identifier: Apache-2.0
"""ADR-0011's five objects: each schema validates its golden, and each schema's
refusing clause actually refuses.

A schema test that only proves the happy instance passes is the same shape as a
gate that cannot refuse - it says nothing about whether the clause does any work.
So every clause ADR-0011 names a refuser for gets a NEGATIVE case here: the
mutation that should be rejected, rejected.

Hermetic: no network, no cluster, no cosign. The goldens under
spec/goldens/value-chain/ are the worked example, and fills.log says in its own
header that its digests are placeholders - the station's record lives in
DmitriyG228/vexa-stations, not here.
"""
import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SPEC = ROOT / "spec"
GOLDEN = SPEC / "goldens" / "value-chain"

sys.path.insert(0, str(SPEC))
import fill_line as fl  # noqa: E402

try:
    import jsonschema  # noqa: F401

    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover - environment-dependent
    HAVE_JSONSCHEMA = False


def schema(name):
    return json.loads((SPEC / f"{name}.schema.json").read_text())


def golden(name):
    return json.loads((GOLDEN / name).read_text())


def errors(doc, sch):
    import jsonschema

    validator = jsonschema.Draft7Validator(sch)
    return sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
class GoldensValidate(unittest.TestCase):
    """One golden instance per schema, valid."""

    CASES = [
        ("consist-manifest", "consist-manifest.json"),
        ("station-prd", "station-prd.json"),
        ("values-proven", "values-proven.json"),
        ("station-verdict", "station-verdict.json"),
        ("station-verdict", "station-verdict-refused.json"),
    ]

    def test_each_golden_validates(self):
        for sch_name, instance in self.CASES:
            with self.subTest(schema=sch_name, instance=instance):
                self.assertEqual([], [e.message for e in errors(golden(instance), schema(sch_name))])

    def test_every_schema_has_a_golden(self):
        """A schema with no worked example is a schema nobody has run."""
        shipped = {p.stem.replace(".schema", "") for p in SPEC.glob("*.schema.json")}
        for name in ("consist-manifest", "station-prd", "fill-line", "values-proven", "station-verdict"):
            self.assertIn(name, shipped, f"{name}.schema.json is not shipped")
        self.assertTrue((GOLDEN / "fills.log").is_file(), "fill-line's golden is the log itself")


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
class ClausesRefuse(unittest.TestCase):
    """Every clause ADR-0011 names a refuser for, refusing."""

    def test_manifest_not_aboard_may_not_be_silently_empty(self):
        m = copy.deepcopy(golden("consist-manifest.json"))
        m["not_aboard"] = []
        self.assertTrue(errors(m, schema("consist-manifest")), "an empty not_aboard section was accepted")

    def test_manifest_sentinel_may_not_ride_alongside_real_rows(self):
        m = copy.deepcopy(golden("consist-manifest.json"))
        m["not_aboard"] = [
            {"pr": "none-considered-excluded", "reason": "nothing was excluded"},
            {"pr": "Vexa-ai/vexa#1", "reason": "but also this"},
        ]
        self.assertTrue(errors(m, schema("consist-manifest")), "the sentinel was accepted next to a real row")

    def test_manifest_image_closure_row_needs_a_row0_decision(self):
        m = copy.deepcopy(golden("consist-manifest.json"))
        del m["image_closure"][0]["row0_required"]
        self.assertTrue(errors(m, schema("consist-manifest")), "an image with no row-0 decision was accepted")

    def test_prd_rows_key_on_contract_value_ids(self):
        """A1 and F3 - the per-train labels this pattern replaces."""
        p = copy.deepcopy(golden("station-prd.json"))
        p["rows"][0]["value_id"] = "A1"
        self.assertTrue(errors(p, schema("station-prd")), "a per-train row id was accepted")

    def test_prd_proposed_values_is_mandatory_even_when_empty(self):
        p = copy.deepcopy(golden("station-prd.json"))
        del p["proposed_values"]
        self.assertTrue(errors(p, schema("station-prd")), "a PRD with no proposed_values array was accepted")

    def test_prd_slot_is_a_closed_vocabulary(self):
        p = copy.deepcopy(golden("station-prd.json"))
        p["rows"][0]["slot"] = "probably"
        self.assertTrue(errors(p, schema("station-prd")), "an invented slot was accepted")

    def test_proven_row_needs_evidence(self):
        vp = copy.deepcopy(golden("values-proven.json"))
        row = next(r for r in vp if r["verdict"] == "proven")
        row["evidence"] = []
        self.assertTrue(errors(vp, schema("values-proven")), "a proven row with no evidence was accepted")
        del row["evidence"]
        self.assertTrue(errors(vp, schema("values-proven")), "a proven row missing evidence was accepted")

    def test_waived_row_needs_a_named_human(self):
        vp = copy.deepcopy(golden("values-proven.json"))
        row = next(r for r in vp if r["verdict"] == "waived")
        del row["waived_by"]
        self.assertTrue(errors(vp, schema("values-proven")), "an anonymous waiver was accepted")

    def test_evidence_subject_digest_is_a_digest(self):
        vp = copy.deepcopy(golden("values-proven.json"))
        row = next(r for r in vp if r.get("evidence") and "subject_digest" in r["evidence"][0])
        row["evidence"][0]["subject_digest"] = "latest"
        self.assertTrue(errors(vp, schema("values-proven")), "a tag was accepted where a digest is required")

    def test_refused_verdict_must_say_why(self):
        v = copy.deepcopy(golden("station-verdict.json"))
        v["verdict"] = "REFUSED"
        self.assertTrue(errors(v, schema("station-verdict")), "a refusal with no reason was accepted")

    def test_verdict_has_no_third_value(self):
        v = copy.deepcopy(golden("station-verdict.json"))
        v["verdict"] = "MOSTLY"
        self.assertTrue(errors(v, schema("station-verdict")), "a verdict outside ELIGIBLE/REFUSED was accepted")

    def test_verdict_carries_the_hashes_the_chain_is_read_through(self):
        for field in ("manifest_sha256", "contract_sha256", "values_proven_sha256"):
            v = copy.deepcopy(golden("station-verdict.json"))
            del v[field]
            with self.subTest(field=field):
                self.assertTrue(errors(v, schema("station-verdict")), f"a verdict with no {field} was accepted")


class FillGrammar(unittest.TestCase):
    def test_golden_log_parses_clean(self):
        records, malformed = fl.parse_file(GOLDEN / "fills.log")
        self.assertEqual([], malformed)
        self.assertTrue(records)

    @unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
    def test_every_parsed_record_validates(self):
        records, _ = fl.parse_file(GOLDEN / "fills.log")
        sch = schema("fill-line")
        for rec in records:
            with self.subTest(line=rec.get("source_line")):
                self.assertEqual([], [e.message for e in errors(rec, sch)])

    def test_regex_and_schema_carry_the_same_grammar(self):
        """The regex lives in two files on purpose; it may not live in two versions."""
        declared = schema("fill-line")["properties"]["line_grammar"]["const"]
        self.assertEqual(declared, fl.LINE_RE.pattern)

    def test_per_train_row_ids_are_malformed(self):
        for bad in (
            "2026-08-31T12:00:00Z A1 PASS live gmeet join from a noble-built bot",
            "2026-08-31T12:00:00Z F3 PASS transcripts machine-read",
        ):
            with self.subTest(line=bad):
                with self.assertRaises(fl.MalformedFill):
                    fl.parse_line(bad, lineno=1)

    def test_truncated_timestamps_are_malformed(self):
        with self.assertRaises(fl.MalformedFill):
            fl.parse_line("2026-08-30T13:0xZ V-est-1 PASS the shape several real logs carry", lineno=1)

    def test_malformed_lines_are_reported_not_dropped(self):
        text = "\n".join(
            [
                "# a comment",
                "",
                "2026-08-31T12:00:00Z V-stg-1 PASS a good line",
                "this line is prose someone pasted in",
            ]
        )
        records, malformed = fl.parse_log(text)
        self.assertEqual(1, len(records))
        self.assertEqual(1, len(malformed), "a non-fill line was silently skipped")

    def test_invented_verdicts_are_malformed(self):
        with self.assertRaises(fl.MalformedFill):
            fl.parse_line("2026-08-31T12:00:00Z V-stg-1 MOSTLY it kind of worked", lineno=1)

    def test_fail_and_part_compile_to_nothing(self):
        text = "\n".join(
            [
                "2026-08-31T12:00:00Z V-stg-1 FAIL row 0 mismatch on the spawn image",
                "2026-08-31T12:01:00Z V-stg-2 PART one lane green, one red",
            ]
        )
        records, _ = fl.parse_log(text)
        self.assertEqual([], fl.compile_values_proven(records, "s"))

    def test_waived_without_a_named_human_refuses(self):
        records, _ = fl.parse_log("2026-08-31T12:00:00Z V-est-6 WAIVED deferred to a retry")
        with self.assertRaises(ValueError):
            fl.compile_values_proven(records, "station-3-bbb-staging")

    def test_compiled_evidence_is_verbatim_and_carries_the_digest(self):
        records, _ = fl.parse_file(GOLDEN / "fills.log")
        vp = fl.compile_values_proven(records, "s", waived_by_of={"V-est-6": "Dmitriy Grankin"})
        row = next(r for r in vp if r["id"] == "V-stg-2")
        self.assertEqual(3, len(row["evidence"]), "one evidence row per row-0 image")
        for ev, rec in zip(row["evidence"], [r for r in records if r["value_id"] == "V-stg-2"]):
            self.assertEqual(rec["evidence"], ev["what"])
            self.assertEqual(rec["digest"], ev["subject_digest"])


class ChainIsClosed(unittest.TestCase):
    """The goldens are one candidate, and the hashes say so.

    This is property (a) of ADR-0011 - ADMIT verifies the previous DEPART - as a
    test rather than as a paragraph.
    """

    def test_prd_manifest_and_verdict_name_one_candidate(self):
        m, p, v = golden("consist-manifest.json"), golden("station-prd.json"), golden("station-verdict.json")
        self.assertEqual(m["candidate_sha"], p["candidate_sha"])
        self.assertEqual(m["candidate_sha"], v["candidate_sha"])
        self.assertEqual(p["manifest_sha256"], v["manifest_sha256"])
        self.assertEqual(p["contract_id"], v["contract_id"])
        self.assertEqual(p["contract_sha256"], v["contract_sha256"])

    def test_manifest_hash_in_the_prd_is_the_manifest(self):
        import hashlib

        body = (GOLDEN / "consist-manifest.json").read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), golden("station-prd.json")["manifest_sha256"])

    def test_values_proven_hash_in_the_verdict_is_the_values_proven(self):
        import hashlib

        body = (GOLDEN / "values-proven.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(body).hexdigest(), golden("station-verdict.json")["values_proven_sha256"]
        )

    def test_every_prd_row_has_a_values_proven_row(self):
        """An unexercised row has no fill, and the missing row refuses departure."""
        prd_ids = {r["value_id"] for r in golden("station-prd.json")["rows"]}
        proven_ids = {r["id"] for r in golden("values-proven.json")}
        self.assertEqual(set(), prd_ids - proven_ids, "PRD rows with no compiled value")

    def test_inherited_rows_carry_their_upstream_station(self):
        prd = golden("station-prd.json")
        vp = {r["id"]: r for r in golden("values-proven.json")}
        for row in prd["rows"]:
            if row["slot"] == "inherited":
                self.assertIn("inherited_from", row, f"{row['value_id']} inherits from nowhere")
                self.assertEqual(row["inherited_from"], vp[row["value_id"]]["station"])

    def test_waiver_rows_land_as_waived_with_a_name(self):
        prd = golden("station-prd.json")
        vp = {r["id"]: r for r in golden("values-proven.json")}
        for row in prd["rows"]:
            if row["slot"] == "waiver":
                self.assertEqual("waived", vp[row["value_id"]]["verdict"])
                self.assertTrue(vp[row["value_id"]].get("waived_by"))


class EmbeddedValuesProven(unittest.TestCase):
    """values_proven exists in two files. It may not exist in two shapes.

    channel-entry.schema.json embeds the block because that is the copy the
    in-cluster verifier enforces; spec/values-proven.schema.json is the
    addressable definition. This test resolves the embedded $refs and compares.
    A drift between them is a finding, not a variant - the same treatment
    internal-estate.json gets against its YAML.
    """

    def test_shapes_are_identical(self):
        entry = json.loads((SPEC / "channel-entry.schema.json").read_text())
        embedded = entry.get("properties", {}).get("values_proven")
        if embedded is None:
            self.skipTest(
                "channel-entry.schema.json does not carry values_proven yet "
                "(lane B, values-proven-enforcement) - nothing to drift from"
            )
        defs = entry.get("$defs", {})

        def resolve(node):
            if isinstance(node, dict):
                if "$ref" in node:
                    key = node["$ref"].rsplit("/", 1)[-1]
                    merged = dict(resolve(defs[key]))
                    merged.update({k: v for k, v in node.items() if k != "$ref"})
                    return merged
                return {k: resolve(v) for k, v in node.items() if k != "description"}
            if isinstance(node, list):
                return [resolve(v) for v in node]
            return node

        standalone = json.loads((SPEC / "values-proven.schema.json").read_text())

        def strip(node):
            if isinstance(node, dict):
                return {
                    k: strip(v)
                    for k, v in node.items()
                    if k not in ("description", "$schema", "$id", "title", "$comment")
                }
            if isinstance(node, list):
                return [strip(v) for v in node]
            return node

        self.assertEqual(
            strip(resolve(embedded)["items"]),
            strip(standalone)["items"],
            "values_proven has drifted between channel-entry.schema.json and values-proven.schema.json",
        )


class VendoredGeneratorSchema(unittest.TestCase):
    """render-manifest.py vendors the consist-manifest schema because it runs in
    another repository. The copy is allowed; a divergence is not.

    The generator is not on this repo's disk, so this test is a skip when it is
    absent rather than a failure - a checkout of vexa-delivery alone must still
    pass `make test`.
    """

    GENERATOR = pathlib.Path.home() / "dev/biz/skills/lifecycle/deliver/bin/render-manifest.py"

    def test_vendored_copy_accepts_and_refuses_the_same_documents(self):
        if not self.GENERATOR.is_file():
            self.skipTest(f"{self.GENERATOR} not present in this checkout")
        import importlib.util

        spec = importlib.util.spec_from_file_location("render_manifest", self.GENERATOR)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        m = golden("consist-manifest.json")
        self.assertEqual([], mod.validate(m), "the vendored validator rejects a valid manifest")

        bad = copy.deepcopy(m)
        bad["not_aboard"] = []
        self.assertTrue(mod.validate(bad), "the vendored validator accepts an empty not_aboard")

        bad = copy.deepcopy(m)
        del bad["image_closure"][0]["row0_required"]
        self.assertTrue(mod.validate(bad), "the vendored validator accepts an image with no row-0 decision")

        bad = copy.deepcopy(m)
        bad["candidate_sha"] = "not-a-sha"
        self.assertTrue(mod.validate(bad), "the vendored validator accepts a non-sha candidate")


if __name__ == "__main__":
    unittest.main()
