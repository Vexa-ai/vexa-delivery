# SPDX-License-Identifier: Apache-2.0
"""The committed v0.12.23 golden IS the spec (P8): these tests hold the worked
example to the same checks the publisher runs, hermetically — no cosign, no
network, no archive. Signature and provenance verification against bytes are
exercised by `vexa-channel verify` with the archive present (see VERIFY.md in
the golden)."""
import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
GOLDEN = ROOT / "spec" / "goldens" / "v0.12.23"

sys.path.insert(0, str(ROOT / "publisher"))
import vexa_channel as vc  # noqa: E402


def entry():
    return json.loads((GOLDEN / "entry.json").read_text())


class GoldenEntry(unittest.TestCase):
    def test_schema_valid(self):
        vc.schema_validate(entry())

    def test_evidence_digests_match_files(self):
        for row in entry()["evidence"]:
            p = GOLDEN / "evidence" / row["name"]
            self.assertTrue(p.exists(), row["name"])
            self.assertEqual(
                hashlib.sha256(p.read_bytes()).hexdigest(), row["sha256"], row["name"]
            )

    def test_map_pin_one_carrier_per_fact(self):
        receipt = json.loads((GOLDEN / "evidence" / "delivery-receipt.json").read_text())
        vc.check_map_pin((GOLDEN / "evidence" / "candidate-images.json").read_bytes(), receipt)

    def test_image_consistency(self):
        receipt = json.loads((GOLDEN / "evidence" / "delivery-receipt.json").read_text())
        cmap = json.loads((GOLDEN / "evidence" / "candidate-images.json").read_text())
        vc.check_image_consistency(cmap, receipt)

    def test_worked_example_identity(self):
        e = entry()
        self.assertEqual(e["release"]["version"], "v0.12.23")
        self.assertEqual(e["release"]["source_sha"], "e59874bc2dfff3a75475696ac33cc0c62e71e75a")
        self.assertEqual(len(e["images"]), 10)
        self.assertEqual(e["publication"]["mode"], "dry_run")
        self.assertEqual(e["signing"]["mode"], "test_key")
        absent = {a["kind"] for a in e["evidence_absent"]}
        self.assertIn("image_provenance", absent)
        self.assertIn("chart", absent)

    def test_prod_deployed_images_carry_prod_receipts(self):
        for img in entry()["images"]:
            kinds = {r["kind"] for r in img["validation_receipts"]}
            if img["class"] == "prod_deployed":
                self.assertIn("prod", kinds, img["name"])
            else:
                self.assertNotIn("prod", kinds, img["name"])


if __name__ == "__main__":
    unittest.main()
