# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the platform-chart pin resolver.

Hermetic: no helm, no cluster, no network. The end-to-end packaging path is
exercised by hand against the real chart (see the PR that introduced it); these
cover the pure functions that decide what gets pinned and what gets refused.
"""
import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

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


class TestEntryTagStamp(unittest.TestCase):
    """THE PACKAGE STAMPS ITS OWN ENTRY TAG.

    bbb station, entry seq 7, 2026-08-29: the chart published INSIDE entry
    seq 7 baked `entryTag: 0.12.23-estate-20260829-seq6`, read from the
    estate's values file. Installed unmodified on a subscriber, that sync
    would have pulled, verified and recorded a green verdict for SEQ 6 — a
    gate passing on the previous entry's evidence, which is the one failure a
    verifier must not have. A values file cannot know its own future; the
    publisher, handed --release and --entry-seq, can.
    """

    def test_derivation(self):
        self.assertEqual(vc.entry_tag_for("0.12.23-estate-20260829", 8),
                         "0.12.23-estate-20260829-seq8")
        self.assertEqual(vc.entry_tag_for("v0.12.23-estate-20260829", 8),
                         "0.12.23-estate-20260829-seq8")

    def test_a_stale_values_entry_tag_is_overridden(self):
        values = {"verify": {"enabled": True,
                             "entryTag": "0.12.23-estate-20260829-seq6"}}
        vc.stamp_entry_tag(values, "0.12.23-estate-20260829", 8, announce=False)
        self.assertEqual(values["verify"]["entryTag"],
                         "0.12.23-estate-20260829-seq8")

    def test_without_an_entry_seq_the_old_behaviour_is_kept(self):
        """Kept, and loud. A silent fallback reproduces the defect."""
        values = {"verify": {"entryTag": "0.12.23-estate-20260829-seq6"}}
        vc.stamp_entry_tag(values, "0.12.23-estate-20260829", None, announce=False)
        self.assertEqual(values["verify"]["entryTag"],
                         "0.12.23-estate-20260829-seq6")


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class TestEntryTagStampEndToEnd(unittest.TestCase):
    """Package a chart whose values carry the PREVIOUS entry's tag, then read
    the tag back out of the rendered PreSync Job. This is the assertion the
    seq-7 station had to make by hand, as a test."""

    RELEASE = "0.12.23-estate-20260829"
    STALE = "0.12.23-estate-20260829-seq6"

    def _package(self, tmp, entry_seq):
        chart = tmp / "vexa-platform"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text(yaml.safe_dump({
            "apiVersion": "v2", "name": "vexa-platform",
            "version": "0.1.0", "appVersion": "0.12.23-estate"}))
        (chart / "values.yaml").write_text(yaml.safe_dump({"verify": {}}))
        overlay = tmp / "values-channel-verify.yaml"
        overlay.write_text(yaml.safe_dump({"verify": {
            "enabled": True,
            "registry": "registry.invalid",
            "channel": "vexa-internal",
            "image": "registry.invalid/verifier@sha256:" + "c" * 64,
            # what the estate's own file carries: the PREVIOUS entry.
            "entryTag": self.STALE,
        }}))
        out = tmp / "out"
        args = argparse.Namespace(
            release=self.RELEASE, chart_dir=str(chart), pin_set=None,
            values=None, pins_values=[str(overlay)], unpinnable=None,
            chart_version="0.1.0-estate.test", out_dir=str(out), push=None,
            insecure=False, no_verify_gate=False, entry_seq=entry_seq)
        self.assertEqual(vc.cmd_platform_chart(args), 0)
        return out / "vexa-platform-0.1.0-estate.test.tgz", out

    def _rendered_entry_refs(self, tgz):
        r = subprocess.run(["helm", "template", "gate", str(tgz), "-n", "vexa-station"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        job = next(d for d in yaml.safe_load_all(r.stdout)
                   if d and d.get("kind") == "Job")
        c = job["spec"]["template"]["spec"]["containers"][0]
        vals = list(c.get("args") or []) + [e.get("value") for e in (c.get("env") or [])]
        return [v for v in vals if v and "vexa-internal:" in str(v)]

    def test_the_rendered_job_verifies_the_entry_that_carries_this_chart(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            tgz, out = self._package(tmp, entry_seq=8)
            refs = self._rendered_entry_refs(tgz)
            self.assertTrue(refs, "the Job names no entry ref at all")
            for ref in refs:
                self.assertTrue(ref.endswith("-seq8"), ref)
                self.assertNotIn(self.STALE, ref)
            # ...and values-pins.yaml, which an operator applies LAST, must not
            # put the stale tag back after the stamp removed it.
            pins = yaml.safe_load((out / "platform-pins-0.1.0-estate.test.yaml").read_text())
            self.assertEqual(pins["verify"]["entryTag"], self.RELEASE + "-seq8")

    def test_without_an_entry_seq_the_values_file_still_decides(self):
        """The escape hatch, so this lands without breaking a caller — and it
        is exactly the shape the stamp exists to retire."""
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            tgz, _ = self._package(tmp, entry_seq=None)
            refs = self._rendered_entry_refs(tgz)
            self.assertTrue(refs)
            for ref in refs:
                self.assertTrue(ref.endswith(self.STALE), ref)


if __name__ == "__main__":
    unittest.main()
