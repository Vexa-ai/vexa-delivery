# SPDX-License-Identifier: Apache-2.0
"""S10 — the ingest side of the telemetry ladder.

The ladder's enforcement claim is two-directional and only one half of it is
worth anything to a customer. That their station cannot COLLECT above its
declared rung is a property of code they can read. That we will not KEEP a
bundle exceeding it is a property of code they cannot read, running on our
machine, and it is the half that has to be tested rather than asserted.

The named validation from the ladder's design note:

    a T3-shaped bundle against a T2 contract is refused with a named error;
    a T2 bundle passes and reduces to state including the health counters.

Both are below, plus the three ways a bundle can exceed a scope (a higher
declared tier, a higher-tier BLOCK under an honest label, and a tier the
contract does not permit at all), plus the compatibility case that must NOT
break: a pre-ladder contract with no `tier` at all.
"""
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "publisher"))
import vexa_station as vs  # noqa: E402


def contract(tier=None, extra=""):
    body = "contract_id: t-2026-01\nrequire: []\nreport_scope:\n  schema: report.v1\n"
    body += "  trigger: explicit-command-only\n  destination: channel.vexa.ai\n"
    if tier is not None:
        body += f"  tier: {tier}\n  cadence: daily\n"
    return body + extra


HEALTH = {"collected_at": "2026-08-25T00:00:00Z", "window_hours": 24,
          "pods": {"running": 12, "pending": 0, "failed": 0, "succeeded": 3,
                   "unknown": 0, "restarts_total": 4}}
USAGE = {"collected_at": "2026-08-25T00:00:00Z", "activated_users": 41}
RELEASE = {"app": "vexa-prod", "pin": "0.1.0-estate.20260825.rev139",
           "sync_status": "Synced", "health_status": "Healthy",
           "verifier": {"verdict": "ELIGIBLE"}}


def make_bundle(path, files, station="vexa-prod", kind="telemetry", tier=2, **blocks):
    import hashlib
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ladder-"))
    root = tmp / "station"
    root.mkdir()
    for name, text in files.items():
        (root / name).write_text(text)
    manifest = {
        "schema_version": 1, "bundle_kind": kind, "tier": tier, "station": station,
        "generated_at": "2026-08-25T00:00:00+00:00", "generator": "test",
        "kit": {}, "kubernetes": {}, "provider": {"name": "lke"},
        "namespaces": {"target": "vexa-production"}, "contract": {},
        "phases": {}, "tiers": {"flows": False},
        "redaction": {"verified": True, "values_redacted": 0, "leaks": 0},
        **blocks,
    }
    manifest["files"] = sorted(
        ({"name": f.name, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
         for f in root.iterdir() if f.is_file()), key=lambda r: r["name"])
    (root / "station.json").write_text(json.dumps(manifest, indent=1))
    with tarfile.open(path, "w:gz") as tar:
        tar.add(root, arcname="station")
    return path


class LadderIngest(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ladder-ingest-"))

    def ingest(self, bundle, station="vexa-prod"):
        return vs.main(["--stations-dir", str(self.tmp / "stations"),
                        "ingest", "--bundle", str(bundle), "--station", station])

    def receipt(self, station="vexa-prod"):
        return json.loads(
            (self.tmp / "stations" / station / "ingest-receipt.json").read_text())

    # ---- the two named validations -------------------------------------

    def test_a_t2_bundle_against_a_t2_contract_is_kept_with_its_counters(self):
        b = make_bundle(self.tmp / "t2.tar.gz", {"contract.yaml": contract(2)},
                        tier=2, release=RELEASE, health=HEALTH)
        self.assertEqual(self.ingest(b), 0)
        r = self.receipt()
        self.assertEqual(r["report_scope"], {"declared_tier": 2, "bundle_tier": 2,
                                             "blocks": ["health", "release"]})
        kept = json.loads(
            (self.tmp / "stations" / "vexa-prod" / "station.json").read_text())
        self.assertEqual(kept["health"]["pods"]["restarts_total"], 4)

    def test_a_t3_shaped_bundle_against_a_t2_contract_is_refused(self):
        b = make_bundle(self.tmp / "t3.tar.gz", {"contract.yaml": contract(2)},
                        tier=3, release=RELEASE, health=HEALTH, usage=USAGE)
        self.assertEqual(self.ingest(b), 3)
        self.assertFalse((self.tmp / "stations" / "vexa-prod").exists(),
                         "a refused bundle must leave nothing behind")

    # ---- the three ways a bundle can exceed a scope ----------------------

    def test_a_higher_tier_block_is_refused_even_under_an_honest_label(self):
        """Declares tier 2 — which the contract permits — and carries a usage
        block anyway. The block is the payload; the label cannot authorise its
        own contents."""
        b = make_bundle(self.tmp / "sneaky.tar.gz", {"contract.yaml": contract(2)},
                        tier=2, release=RELEASE, health=HEALTH, usage=USAGE)
        self.assertEqual(self.ingest(b), 3)

    def test_a_silent_station_that_submits_is_a_violation_on_our_side(self):
        b = make_bundle(self.tmp / "t0.tar.gz", {"contract.yaml": contract(0)},
                        tier=1, release=RELEASE)
        self.assertEqual(self.ingest(b), 3)

    def test_tier_four_never_travels_this_path(self):
        b = make_bundle(self.tmp / "t4.tar.gz", {"contract.yaml": contract(4)},
                        tier=4, release=RELEASE)
        self.assertEqual(self.ingest(b), 3)

    def test_a_contract_with_no_report_scope_is_refused(self):
        b = make_bundle(self.tmp / "bare.tar.gz",
                        {"contract.yaml": "contract_id: t\nrequire: []\n"},
                        tier=1, release=RELEASE)
        self.assertEqual(self.ingest(b), 3)

    # ---- compatibility, which must not break ----------------------------

    def test_a_pre_ladder_contract_with_no_tier_reads_as_t1(self):
        b = make_bundle(self.tmp / "legacy.tar.gz", {"contract.yaml": contract(None)},
                        tier=1, release=RELEASE)
        self.assertEqual(self.ingest(b), 0)
        self.assertEqual(self.receipt()["report_scope"]["declared_tier"], 1)

    def test_a_pre_ladder_bundle_with_no_tier_field_reads_as_t1(self):
        b = make_bundle(self.tmp / "legacy2.tar.gz", {"contract.yaml": contract(None)},
                        tier=None)
        # tier=None writes "tier": null; strip it the way a real old bundle has it
        self.assertEqual(self.ingest(self._drop_tier(b)), 0)
        self.assertEqual(self.receipt()["report_scope"]["bundle_tier"], 1)

    def _drop_tier(self, path):
        import hashlib
        tmp = pathlib.Path(tempfile.mkdtemp())
        with tarfile.open(path) as tar:
            try:
                tar.extractall(tmp, filter="data")
            except TypeError:
                tar.extractall(tmp)
        root = tmp / "station"
        m = json.loads((root / "station.json").read_text())
        m.pop("tier", None)
        m["files"] = sorted(
            ({"name": f.name, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
             for f in root.iterdir() if f.is_file() and f.name != "station.json"),
            key=lambda r: r["name"])
        (root / "station.json").write_text(json.dumps(m, indent=1))
        out = self.tmp / "legacy-notier.tar.gz"
        with tarfile.open(out, "w:gz") as tar:
            tar.add(root, arcname="station")
        return out

    # ---- the bundle KIND decides which files are required ---------------

    def test_a_telemetry_bundle_needs_no_smoke_or_preflight_receipt(self):
        """It ran no phases. Demanding a receipt for a phase that did not
        happen would mean either refusing every T2 submission or having the
        sender fabricate one — a manufactured artifact inside a signed
        bundle, which is the worse of the two by a distance."""
        b = make_bundle(self.tmp / "tele.tar.gz", {"contract.yaml": contract(2)},
                        kind="telemetry", tier=2, release=RELEASE, health=HEALTH)
        self.assertEqual(self.ingest(b), 0)

    def test_an_install_bundle_still_needs_all_six_roles(self):
        b = make_bundle(self.tmp / "inst.tar.gz", {"contract.yaml": contract(2)},
                        kind="install", tier=1, release=RELEASE)
        self.assertEqual(self.ingest(b), 3)

    def test_an_unknown_bundle_kind_is_refused_not_defaulted(self):
        b = make_bundle(self.tmp / "weird.tar.gz", {"contract.yaml": contract(2)},
                        kind="whatever", tier=1)
        self.assertEqual(self.ingest(b), 3)


class TierTableAgreesWithTheSchema(unittest.TestCase):
    """One rule, three enforcers — the packager's collector gate, the schema's
    if/then, and S10. This pins them together so they cannot drift into two
    opinions, which is the failure mode every silent divergence in this system
    has taken."""

    def test_the_table_matches_the_schemas_if_then_rules(self):
        sys.path.insert(0, str(ROOT / "kit/validate"))
        import collectors

        schema = json.loads((ROOT / "spec/report.v1.schema.json").read_text())
        # For each block, the lowest tier at which the schema stops forbidding it.
        lowest = {}
        for rule in schema["allOf"]:
            cap = rule["if"]["properties"]["tier"]
            cap = cap.get("const", cap.get("maximum"))
            forbidden = rule["then"].get("not", {})
            names = ([forbidden["required"][0]] if "required" in forbidden
                     else [a["required"][0] for a in forbidden.get("anyOf", [])])
            for n in names:
                lowest[n] = max(lowest.get(n, 0), cap + 1)
        self.assertEqual(lowest, {block: tier for tier, block
                                  in collectors.TIER_BLOCKS.items() if block})

    def test_the_schema_has_no_tier_four(self):
        schema = json.loads((ROOT / "spec/report.v1.schema.json").read_text())
        self.assertEqual(schema["properties"]["tier"]["maximum"], 3)
        sys.path.insert(0, str(ROOT / "kit/validate"))
        import collectors
        self.assertEqual(collectors.MAX_SUBMITTABLE_TIER, 3)


if __name__ == "__main__":
    unittest.main()
