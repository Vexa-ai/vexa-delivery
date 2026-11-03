# SPDX-License-Identifier: Apache-2.0
"""S1: platform-chart refuses to package a chart that carries secret material.

A published chart is readable by every account that can pull the channel, so a
credential in its values is a credential handed to every subscriber. The keys
live in a Secret created out of band and the chart names it.

Hermetic: no helm, no cluster, no network. The refusal happens before helm is
ever called, which is what the end-to-end test below relies on: without the
guard, packaging proceeds to `helm package` and the test fails.
"""
import argparse
import pathlib
import shutil
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_channel as vc  # noqa: E402

# Built at run time so no PEM-shaped or token-shaped literal sits in the repo.
PEM_HEAD = "-----BEGIN " + "PRIVATE KEY-----"
PEM_TAIL = "-----END " + "PRIVATE KEY-----"
FAKE_PEM = PEM_HEAD + "\n" + "A" * 64 + "\n" + PEM_TAIL + "\n"
FAKE_TOKEN = "f" * 8 + "0123456789abcdef" * 3 + "e" * 8          # 64 hex chars, not a real token
PUBLIC_PEM = "-----BEGIN PUBLIC KEY-----\n" + "B" * 60 + "\n-----END PUBLIC KEY-----\n"


def findings(tree):
    return vc.scan_values_for_secrets(tree, "t")


class TestScanValues(unittest.TestCase):
    def test_private_key_pem_anywhere_is_found(self):
        f = findings({"a": {"b": [{"c": FAKE_PEM}]}})
        self.assertTrue(any("PEM private key" in x and "a.b.0.c" in x for x in f), f)

    def test_core0134_credentials_are_found(self):
        f = findings({"core0134": {"runtimeApiToken": FAKE_TOKEN, "identitySigningKeyPem": FAKE_PEM}})
        self.assertTrue(any("core0134.runtimeApiToken" in x for x in f), f)
        self.assertTrue(any("core0134.identitySigningKeyPem" in x for x in f), f)

    def test_secret_named_key_with_a_literal_is_found(self):
        f = findings({"flows": {"apiKey": FAKE_TOKEN}, "db": {"password": "hunter2-hunter2"}})
        self.assertTrue(any("flows.apiKey" in x for x in f), f)
        self.assertTrue(any("db.password" in x for x in f), f)

    def test_env_entry_with_a_literal_secret_is_found(self):
        f = findings({"x": {"extraEnv": [{"name": "STRIPE_SECRET_KEY", "value": FAKE_TOKEN}]}})
        self.assertTrue(any("STRIPE_SECRET_KEY" in x for x in f), f)

    def test_provider_token_shapes_are_found(self):
        f = findings({"notes": "gh" + "p_" + "A" * 30})
        self.assertTrue(any("GitHub token" in x for x in f), f)

    def test_references_and_public_material_pass(self):
        tree = {
            "core0134": {"enabled": True, "existingSecret": "vexa-platform-core0134-keys",
                         "runtimeApiToken": "", "identitySigningKeyPem": ""},
            "vexa": {"identity": {"existingSecret": "vexa-platform-core0134-keys",
                                  "publicKeyFromSecret": True, "publicKey": PUBLIC_PEM},
                     "secrets": {"runtimeApiTokenKey": "RUNTIME_API_TOKEN",
                                 "runtimeApiTokenSecret": "vexa-platform-core0134-keys",
                                 "existingSecretName": "vexa-platform-vexa-secrets",
                                 "adminApiToken": "CHANGE_ME", "dispatchSigningKey": ""},
                     "meetingApi": {"image": {"digest": "sha256:" + "a" * 64},
                                    "extraEnv": [
                                        {"name": "VEXA_SERVICE_AUTHORITY_SECRET",
                                         "valueFrom": {"secretKeyRef": {"name": "vexa-platform-vexa-secrets",
                                                                        "key": "VEXA_SERVICE_AUTHORITY_SECRET"}}},
                                        {"name": "ADMIN_READ_TOKEN_SHA256", "value": "c" * 64},
                                        {"name": "VEXA_SYSTEM_WEBHOOK_ALLOW_PRIVATE_HTTP", "value": "true"}]}},
            "verify": {"pullSecret": "channel-pull"},
        }
        self.assertEqual(findings(tree), [])

    def test_a_refusal_never_contains_the_value(self):
        f = findings({"core0134": {"runtimeApiToken": FAKE_TOKEN}, "k": FAKE_PEM})
        self.assertTrue(f)
        for x in f:
            self.assertNotIn(FAKE_TOKEN, x)
            self.assertNotIn("A" * 64, x)


class TestPackagingRefuses(unittest.TestCase):
    """End to end through platform-chart's overlay mode, stopped before helm."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="s1-"))
        self.chart = self.tmp / "vexa-platform"
        (self.chart / "templates").mkdir(parents=True)
        (self.chart / "Chart.yaml").write_text("apiVersion: v2\nname: vexa-platform\nversion: 0.1.0\n")
        (self.chart / "values.yaml").write_text(yaml.safe_dump({"core0134": {"enabled": False}}))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def args(self, *layers):
        files = []
        for i, layer in enumerate(layers):
            f = self.tmp / f"layer-{i}.yaml"
            f.write_text(yaml.safe_dump(layer))
            files.append(str(f))
        return argparse.Namespace(pins_values=files, no_verify_gate=True, release="0.0.0-test",
                                  chart_version="0.0.0-test", out_dir=str(self.tmp / "out"),
                                  entry_seq=None, push=None, insecure=False, rollout_safety="warn")

    def package(self, *layers):
        return vc._platform_chart_from_overlay(self.args(*layers), self.chart, [])

    def test_runtime_token_in_a_layer_is_refused(self):
        with self.assertRaises(vc.CheckFailure) as cm:
            self.package({"core0134": {"enabled": True, "runtimeApiToken": FAKE_TOKEN}})
        self.assertEqual(cm.exception.check, "S1")
        self.assertIn("core0134.runtimeApiToken", str(cm.exception))
        self.assertNotIn(FAKE_TOKEN, str(cm.exception))
        self.assertFalse((self.tmp / "out").exists(), "nothing may be packaged")

    def test_private_key_in_a_layer_is_refused(self):
        with self.assertRaises(vc.CheckFailure) as cm:
            self.package({"core0134": {"identitySigningKeyPem": FAKE_PEM}})
        self.assertEqual(cm.exception.check, "S1")

    def test_private_key_in_a_shipped_chart_file_is_refused(self):
        (self.chart / "files").mkdir()
        (self.chart / "files" / "key.pem").write_text(FAKE_PEM)
        with self.assertRaises(vc.CheckFailure) as cm:
            self.package({"core0134": {"enabled": True, "existingSecret": "vexa-platform-core0134-keys"}})
        self.assertEqual(cm.exception.check, "S1")
        self.assertIn("files/key.pem", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
