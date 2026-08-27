# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the station bundle's two load-bearing behaviours: redaction
keeps the structure and drops the values, and the leak scan actually catches a
value that survived. No cluster, no network."""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from vexa_validate import REDACTED, redact, scan_for_leaks  # noqa: E402

VALUES = {
    "secrets": {
        "existingSecretName": "",
        "adminApiToken": "adm-0123456789abcdef",
        "internalApiSecret": "int-0123456789abcdef",
    },
    "meetingApi": {"transcriptionServiceUrl": "http://whisper.internal:9000"},
    "global": {"imagePullSecrets": [], "tolerations": [{"key": "workload", "value": "vexa"}]},
    "flows": {"enabled": True, "apiKey": "flw-0123456789abcdef",
              "mail": {"address": "ops@bank.example", "appPassword": "pw-0123456789"}},
    "runtime": {"extraEnv": [{"name": "VEXA_RUNNER", "value": "k8s"},
                             {"name": "RUNTIME_SECRET_MOUNT", "value": "/very/secret/path"}]},
    "replicas": 3,
}


class TestRedact(unittest.TestCase):
    def setUp(self):
        self.removed = set()
        self.out = redact(VALUES, removed=self.removed)

    def test_secrets_section_is_gone(self):
        self.assertEqual(self.out["secrets"]["adminApiToken"], REDACTED)
        self.assertEqual(self.out["secrets"]["internalApiSecret"], REDACTED)
        self.assertEqual(self.out["flows"]["apiKey"], REDACTED)
        self.assertEqual(self.out["flows"]["mail"]["appPassword"], REDACTED)

    def test_env_var_named_secret_is_redacted_by_its_sibling_name(self):
        env = {e["name"]: e["value"] for e in self.out["runtime"]["extraEnv"]}
        self.assertEqual(env["RUNTIME_SECRET_MOUNT"], REDACTED)
        self.assertEqual(env["VEXA_RUNNER"], "k8s")

    def test_structure_and_non_secret_config_survive(self):
        self.assertEqual(self.out["meetingApi"]["transcriptionServiceUrl"],
                         "http://whisper.internal:9000")
        self.assertEqual(self.out["flows"]["enabled"], True)
        self.assertEqual(self.out["replicas"], 3)
        self.assertEqual(self.out["global"]["imagePullSecrets"], [])
        self.assertEqual(list(self.out.keys()), list(VALUES.keys()))

    def test_empty_scalars_stay_empty_not_redacted(self):
        # "" means not-set, which is configuration information, not a secret
        self.assertEqual(self.out["secrets"]["existingSecretName"], "")

    def test_a_tolerations_key_named_key_is_redacted_conservatively(self):
        # `tolerations[].key` is harmless, but the rule is blunt on purpose:
        # a false positive costs one line of config, a false negative a credential
        self.assertEqual(self.out["global"]["tolerations"][0]["key"], REDACTED)

    def test_removed_set_carries_exactly_the_plaintext_values(self):
        self.assertIn("adm-0123456789abcdef", self.removed)
        self.assertIn("pw-0123456789", self.removed)
        self.assertNotIn("", self.removed)
        self.assertNotIn("k8s", self.removed)


class TestLeakScan(unittest.TestCase):
    def test_clean_tree_has_no_hits(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "values.redacted.yaml").write_text(f"adminApiToken: {REDACTED}\n")
            self.assertEqual(scan_for_leaks(root, {"adm-0123456789abcdef"}), [])

    def test_survivor_is_caught_in_any_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "sub").mkdir()
            (root / "sub" / "smoke-receipt-x.md").write_text("token adm-0123456789abcdef used\n")
            hits = scan_for_leaks(root, {"adm-0123456789abcdef"})
            self.assertEqual([p for p, _ in hits], ["sub/smoke-receipt-x.md"])

    def test_short_values_are_not_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "station.json").write_text('{"namespace": "prod"}')
            self.assertEqual(scan_for_leaks(root, {"prod"}), [])


if __name__ == "__main__":
    unittest.main()
