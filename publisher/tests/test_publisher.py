# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the publisher's cross-checks and entry assembly.

Every test is hermetic: no network, no subprocess, synthetic fixtures shaped
like the real v0.12.23 documents (the real worked example lives in
spec/goldens/ and is exercised by test_golden.py).
"""
import copy
import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_channel as vc  # noqa: E402

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
SHA = "e" * 40


def synthetic_map():
    return {
        "schema_version": 1,
        "release": "v9.9.9",
        "stable_tag": "v9.9.9",
        "candidate_tag": "v9.9.9-rc.1",
        "build_source": "b" * 40,
        "validation_source": "c" * 40,
        "build_run": "https://example.invalid/build",
        "validation_run": "https://example.invalid/validate",
        "images": {
            "vexaai/one": {
                "class": "prod_deployed",
                "digest": D1,
                "platforms": ["linux/amd64"],
                "platform_manifests": {"linux/amd64": {"manifest_digest": D2, "config_digest": D3}},
            },
            "vexaai/two": {
                "class": "oss_only",
                "digest": D2,
                "platforms": ["linux/amd64"],
                "platform_manifests": None,
            },
        },
    }


def synthetic_receipt(map_bytes):
    return {
        "schema_version": 1,
        "release": "v9.9.9",
        "packet": {"sha256": "sha256:" + hashlib.sha256(map_bytes).hexdigest()},
        "prod": {"hold_receipt": "prod hold: rev N live, sweep green"},
        "oss": {
            "tag": "v9.9.9",
            "source_sha": SHA,
            "release_url": "https://example.invalid/release",
            "images": [
                {
                    "name": "vexaai/one",
                    "class": "prod_deployed",
                    "index_digest": D1,
                    "platform_manifests": {"linux/amd64": {"manifest_digest": D2}},
                    "source_sha": SHA,
                    "validation_receipts": [
                        {"kind": "prod", "receipt": "ran in prod"},
                        {"kind": "stage", "receipt": "ran in stage"},
                    ],
                },
                {
                    "name": "vexaai/two",
                    "class": "oss_only",
                    "index_digest": D2,
                    "platform_manifests": None,
                    "source_sha": SHA,
                    "validation_receipts": [{"kind": "lite", "receipt": "lite green"}],
                },
            ],
        },
    }


class MapPin(unittest.TestCase):
    def test_pin_matches(self):
        mb = json.dumps(synthetic_map()).encode()
        vc.check_map_pin(mb, synthetic_receipt(mb))

    def test_pin_mismatch_refused(self):
        mb = json.dumps(synthetic_map()).encode()
        receipt = synthetic_receipt(mb)
        with self.assertRaises(vc.CheckFailure) as cm:
            vc.check_map_pin(mb + b"\n", receipt)
        self.assertEqual(cm.exception.check, "C3")


class ReceiptIdentity(unittest.TestCase):
    def test_ok(self):
        mb = json.dumps(synthetic_map()).encode()
        vc.check_receipt_identity("v9.9.9", SHA, synthetic_receipt(mb))

    def test_wrong_source_sha(self):
        mb = json.dumps(synthetic_map()).encode()
        with self.assertRaises(vc.CheckFailure) as cm:
            vc.check_receipt_identity("v9.9.9", "f" * 40, synthetic_receipt(mb))
        self.assertEqual(cm.exception.check, "C4")

    def test_wrong_tag(self):
        mb = json.dumps(synthetic_map()).encode()
        r = synthetic_receipt(mb)
        r["oss"]["tag"] = "v9.9.8"
        with self.assertRaises(vc.CheckFailure):
            vc.check_receipt_identity("v9.9.9", SHA, r)


class ImageConsistency(unittest.TestCase):
    def setUp(self):
        self.map = synthetic_map()
        self.receipt = synthetic_receipt(json.dumps(self.map).encode())

    def test_consistent(self):
        vc.check_image_consistency(self.map, self.receipt)

    def test_digest_disagreement_refused(self):
        bad = copy.deepcopy(self.receipt)
        bad["oss"]["images"][0]["index_digest"] = D3
        with self.assertRaises(vc.CheckFailure) as cm:
            vc.check_image_consistency(self.map, bad)
        self.assertEqual(cm.exception.check, "C5")

    def test_missing_image_refused(self):
        bad = copy.deepcopy(self.receipt)
        bad["oss"]["images"].pop()
        with self.assertRaises(vc.CheckFailure):
            vc.check_image_consistency(self.map, bad)

    def test_platform_manifest_disagreement_refused(self):
        bad = copy.deepcopy(self.receipt)
        bad["oss"]["images"][0]["platform_manifests"]["linux/amd64"]["manifest_digest"] = D3
        with self.assertRaises(vc.CheckFailure):
            vc.check_image_consistency(self.map, bad)


class BuildImages(unittest.TestCase):
    def test_identity_from_map_receipts_from_receipt(self):
        m = synthetic_map()
        r = synthetic_receipt(json.dumps(m).encode())
        images = vc.build_images(m, r)
        by_name = {i["name"]: i for i in images}
        self.assertEqual(by_name["vexaai/one"]["index_digest"], D1)
        self.assertEqual(by_name["vexaai/one"]["class"], "prod_deployed")
        kinds = {v["kind"] for v in by_name["vexaai/one"]["validation_receipts"]}
        self.assertIn("prod", kinds)
        self.assertIsNone(by_name["vexaai/two"]["platform_manifests"])


class SchemaGate(unittest.TestCase):
    """The assembled entry must satisfy the sealed schema, including the
    conditional rules that encode the founder gates."""

    def entry(self):
        m = synthetic_map()
        r = synthetic_receipt(json.dumps(m).encode())
        return {
            "schema_version": 1,
            "channel": {"name": "test-channel", "entry_seq": 1, "supersedes": None},
            "release": {
                "version": "v9.9.9",
                "source_sha": SHA,
                "tag_object_sha": "d" * 40,
                "release_url": "https://example.invalid/release",
            },
            "source": {
                "archive_name": "vexa-core-v9.9.9.tar.gz",
                "archive_sha256": "a" * 64,
                "provenance_predicate": "https://slsa.dev/provenance/v1",
                "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                "certificate_identity_pattern": "^https://github.com/Vexa-ai/vexa/",
            },
            "images": vc.build_images(m, r),
            "evidence": [
                {"name": "candidate-images.json", "kind": "candidate_map", "sha256": "a" * 64,
                 "media_type": "application/json", "description": "map"},
                {"name": "delivery-receipt.json", "kind": "delivery_receipt", "sha256": "b" * 64,
                 "media_type": "application/json", "description": "receipt"},
                {"name": "source-provenance.sigstore.json", "kind": "source_provenance", "sha256": "c" * 64,
                 "media_type": "application/json", "description": "slsa"},
                {"name": "trusted-root.jsonl", "kind": "trusted_root", "sha256": "d" * 64,
                 "media_type": "application/jsonl", "description": "root"},
            ],
            "evidence_absent": vc.default_absent_rows(),
            "prod_soak": {"receipt": "prod hold", "carrier": "delivery_receipt:prod.hold_receipt"},
            "expires": "2099-01-01T00:00:00Z",
            "chart": None,
            "break_glass": None,
            "signing": {"mode": "test_key", "identity": "sha256:testkey", "note": "test"},
            "publication": {"mode": "dry_run", "published_at": "2026-08-21T00:00:00Z",
                            "publisher": "unit test"},
        }

    def test_valid_entry_passes(self):
        vc.schema_validate(self.entry())

    def test_published_without_approval_refused(self):
        e = self.entry()
        e["publication"]["mode"] = "published"
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)

    def test_test_key_cannot_publish(self):
        e = self.entry()
        e["publication"]["mode"] = "published"
        e["publication"]["approved_by"] = "founder"
        e["publication"]["approval_receipt"] = "receipt"
        # signing.mode test_key forces dry_run
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)

    def test_prod_deployed_requires_prod_receipt(self):
        e = self.entry()
        for img in e["images"]:
            if img["class"] == "prod_deployed":
                img["validation_receipts"] = [{"kind": "stage", "receipt": "stage only"}]
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)

    def test_missing_required_evidence_kind_refused(self):
        e = self.entry()
        e["evidence"] = [r for r in e["evidence"] if r["kind"] != "source_provenance"]
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)


class CandidateMode(unittest.TestCase):
    """A candidate entry is published BEFORE prod runs — no delivery receipt,
    no soak, lite image receipts. The strict rules apply to every other mode."""

    def candidate(self):
        m = synthetic_map()
        return {
            "schema_version": 1,
            "channel": {"name": "vexa-internal", "entry_seq": 1, "supersedes": None},
            "release": {
                "version": "v9.9.9",
                "source_sha": SHA,
                "tag_object_sha": "d" * 40,
                "release_url": "https://example.invalid/release",
            },
            "source": {
                "archive_name": "vexa-core-v9.9.9.tar.gz",
                "archive_sha256": "a" * 64,
                "provenance_predicate": "https://slsa.dev/provenance/v1",
                "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                "certificate_identity_pattern": "^https://github.com/Vexa-ai/vexa/",
            },
            "images": vc.build_images(m, None),
            "evidence": [
                {"name": "candidate-images.json", "kind": "candidate_map", "sha256": "a" * 64,
                 "media_type": "application/json", "description": "map"},
                {"name": "source-provenance.sigstore.json", "kind": "source_provenance", "sha256": "c" * 64,
                 "media_type": "application/json", "description": "slsa"},
                {"name": "trusted-root.jsonl", "kind": "trusted_root", "sha256": "d" * 64,
                 "media_type": "application/jsonl", "description": "root"},
            ],
            "evidence_absent": vc.default_absent_rows(candidate=True),
            "prod_soak": None,
            "expires": "2099-01-01T00:00:00Z",
            "chart": None,
            "break_glass": None,
            "signing": {"mode": "test_key", "identity": "sha256:testkey", "note": "test"},
            "publication": {"mode": "candidate", "published_at": "2026-08-21T00:00:00Z",
                            "publisher": "unit test"},
        }

    def test_candidate_entry_passes(self):
        vc.schema_validate(self.candidate())

    def test_candidate_lite_images_pass(self):
        # prod receipts do not exist yet — receipts accumulate as attestations
        e = self.candidate()
        for img in e["images"]:
            self.assertNotIn({"kind": "prod"}, img.get("validation_receipts", []))
        vc.schema_validate(e)

    def test_non_candidate_missing_receipt_refused(self):
        e = self.candidate()
        e["publication"]["mode"] = "dry_run"
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)

    def test_non_candidate_null_soak_refused(self):
        e = self.candidate()
        e["publication"]["mode"] = "dry_run"
        m = synthetic_map()
        r = synthetic_receipt(json.dumps(m).encode())
        e["images"] = vc.build_images(m, r)
        e["evidence"].append(
            {"name": "delivery-receipt.json", "kind": "delivery_receipt", "sha256": "b" * 64,
             "media_type": "application/json", "description": "receipt"})
        # receipt restored, images strict — the null soak alone must refuse it
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)

    def test_candidate_cannot_claim_published(self):
        e = self.candidate()
        e["publication"]["mode"] = "published"
        e["publication"]["approved_by"] = "founder"
        e["publication"]["approval_receipt"] = "receipt"
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)


class BreakGlass(unittest.TestCase):
    def test_parse_complete(self):
        bg = vc.parse_break_glass("actor=Jane Doe,reason=registry outage,approved_by=founder,receipt=issue-1")
        self.assertEqual(bg["actor"], "Jane Doe")
        self.assertIn("at", bg)

    def test_parse_incomplete_refused(self):
        with self.assertRaises(SystemExit):
            vc.parse_break_glass("actor=Jane Doe,reason=x")


if __name__ == "__main__":
    unittest.main()
