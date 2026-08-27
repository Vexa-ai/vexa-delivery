# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the platform-chart pin resolver.

Hermetic: no helm, no cluster, no network. The end-to-end packaging path is
exercised by hand against the real chart (see the PR that introduced it); these
cover the pure functions that decide what gets pinned and what gets refused.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_channel as vc  # noqa: E402

DA = "sha256:" + "a" * 64
DB = "sha256:" + "b" * 64


class TestParsePinSet(unittest.TestCase):
    def test_comments_and_blanks_ignored(self):
        auto, explicit = vc.parse_pin_set(f"# note\n\n  caddy@{DA}  # trailing\n")
        self.assertEqual(auto, {"caddy": DA})
        self.assertEqual(explicit, {})

    def test_explicit_assignment(self):
        auto, explicit = vc.parse_pin_set(f"backups.database.image=postgres@{DA}\n")
        self.assertEqual(auto, {})
        self.assertEqual(explicit, {"backups.database.image": ("postgres", DA)})

    def test_malformed_line_refused(self):
        with self.assertRaises(vc.CheckFailure) as cm:
            vc.parse_pin_set("caddy:2-alpine\n")
        self.assertEqual(cm.exception.check, "P1")

    def test_same_repo_twice_refuses_rather_than_guesses(self):
        with self.assertRaises(vc.CheckFailure) as cm:
            vc.parse_pin_set(f"postgres@{DA}\npostgres@{DB}\n")
        self.assertEqual(cm.exception.check, "P1")
        self.assertIn("refusing to guess", str(cm.exception))


class TestRefRepo(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual(vc.ref_repo("caddy:2-alpine"), "caddy")
        self.assertEqual(vc.ref_repo("vexaai/dashboard"), "vexaai/dashboard")
        self.assertEqual(vc.ref_repo("registry.k8s.io/pause:3.9"), "registry.k8s.io/pause")
        self.assertEqual(vc.ref_repo("host:5000/x:1"), "host:5000/x")
        self.assertEqual(vc.ref_repo(f"caddy:2-alpine@{DA}"), "caddy")


class TestResolvePlatformPins(unittest.TestCase):
    def test_split_path_keeps_tag_in_front_of_digest(self):
        merged = {"caddy": {"image": {"repository": "caddy", "tag": "2-alpine"}}}
        overlay, mapping = vc.resolve_platform_pins({"caddy": DA}, {}, merged, {})
        self.assertEqual(overlay["caddy"]["image"]["tag"], f"2-alpine@{DA}")
        self.assertEqual(overlay["caddy"]["image"]["repository"], "caddy")
        self.assertEqual([m["values_path"] for m in mapping], ["caddy.image"])

    def test_whole_path_is_a_single_reference_string(self):
        merged = {"backups": {"recordings": {"image": "amazon/aws-cli:2.30.0"}}}
        overlay, _ = vc.resolve_platform_pins({"amazon/aws-cli": DA}, {}, merged, {})
        self.assertEqual(overlay["backups"]["recordings"]["image"], f"amazon/aws-cli:2.30.0@{DA}")

    def test_subchart_global_tag_is_blanked(self):
        merged = {"vexa": {"global": {"imageTag": "0.12.4-hc7"},
                           "gateway": {"image": {"repository": "vexaai/v012-gateway", "tag": "v012"}}}}
        overlay, _ = vc.resolve_platform_pins({"vexaai/v012-gateway": DA}, {}, merged, {})
        # global.imageTag would otherwise win over the pinned per-component tag
        self.assertEqual(overlay["vexa"]["global"]["imageTag"], "")
        self.assertEqual(overlay["vexa"]["gateway"]["image"]["tag"], f"0.12.4-hc7@{DA}")

    def test_one_repo_fans_out_to_every_path_that_uses_it(self):
        merged = {"analytics": {k: {"image": {"repository": "vexaai/analytics-refresh", "tag": "0.3.0"}}
                                for k in ("refresh", "meterSync", "customerMetricsSync")}}
        _, mapping = vc.resolve_platform_pins({"vexaai/analytics-refresh": DA}, {}, merged, {})
        self.assertEqual(len(mapping), 3)

    def test_pin_with_no_values_path_is_refused(self):
        with self.assertRaises(vc.CheckFailure) as cm:
            vc.resolve_platform_pins({"bitnami/kubectl": DA}, {}, {}, {})
        self.assertEqual(cm.exception.check, "P2")
        self.assertIn("bitnami/kubectl", str(cm.exception))

    def test_declared_unpinnable_is_allowed_through(self):
        overlay, mapping = vc.resolve_platform_pins(
            {"bitnami/kubectl": DA}, {}, {}, {"bitnami/kubectl": "hardcoded in three cronjobs"})
        self.assertEqual(mapping, [])

    def test_explicit_path_must_exist_in_the_table(self):
        with self.assertRaises(vc.CheckFailure) as cm:
            vc.resolve_platform_pins({}, {"nope.image": ("postgres", DA)}, {}, {})
        self.assertEqual(cm.exception.check, "P2")


class TestRenderCoverage(unittest.TestCase):
    def test_rendered_image_with_no_pin_is_named(self):
        with self.assertRaises(vc.CheckFailure) as cm:
            vc.check_render_coverage(["python:3.12-slim", "caddy:2-alpine"], {"caddy"}, {})
        self.assertEqual(cm.exception.check, "P2")
        self.assertIn("python:3.12-slim", str(cm.exception))
        self.assertNotIn("caddy:2-alpine", str(cm.exception))

    def test_unpinnable_declaration_satisfies_coverage(self):
        vc.check_render_coverage(["python:3.12-slim"], set(), {"python": "hardcoded"})


class TestUnpinnableSpec(unittest.TestCase):
    def test_reason_is_mandatory(self):
        for spec in ("bitnami/kubectl", "bitnami/kubectl="):
            with self.assertRaises(vc.CheckFailure):
                vc.parse_unpinnable([spec])


if __name__ == "__main__":
    unittest.main()
