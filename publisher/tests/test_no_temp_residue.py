# SPDX-License-Identifier: Apache-2.0
"""vexa_channel.py leaves nothing behind in the temp dir it was given.

Until 2026-11-04 every chart command copied the chart into its own
$TMPDIR/vexa-*-chart-* and never removed it, and cosign_env() wrote the
registry auths to $TMPDIR/vexa-channel-dockercfg for good. A chart copy
carries every values layer the operator merged in, secrets included, so each
run left those secrets at rest after it ended.

Each test runs the CLI in a subprocess with TMPDIR set to a fresh, empty
directory and asserts that directory is empty once the process is gone: after
a refusal, after a packaged chart, after SIGTERM mid-run, and after
cosign_env(). The fake secret below is a fixture, never a key.
"""
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

PUBLISHER = pathlib.Path(__file__).resolve().parent.parent
CLI = PUBLISHER / "vexa_channel.py"
FAKE_SECRET = "fixture-not-a-secret-" + "0" * 24


def _chart(root, dependency=False):
    chart = root / "vexa-platform"
    (chart / "templates").mkdir(parents=True)
    cy = {"apiVersion": "v2", "name": "vexa-platform", "version": "0.1.0", "appVersion": "0.0.0"}
    if dependency:
        # declared but not vendored: prune_stale_subcharts refuses (P4) right
        # after the chart was copied into the temp dir
        cy["dependencies"] = [{"name": "sub", "version": "1.0.0", "repository": "file://../sub"}]
        (chart / "charts").mkdir()
    (chart / "Chart.yaml").write_text(yaml.safe_dump(cy))
    (chart / "values.yaml").write_text(yaml.safe_dump({"core": {"fixtureApiToken": ""}}))
    (chart / "templates" / "cm.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture\ndata:\n  enabled: \"true\"\n")
    overlay = root / "values-secret.yaml"
    overlay.write_text(yaml.safe_dump({"core": {"fixtureApiToken": FAKE_SECRET}}))
    return chart, overlay


def _argv(chart, overlay, out):
    return [sys.executable, str(CLI), "platform-chart", "--release", "0.0.0-fixture",
            "--chart-dir", str(chart), "--pins-values", str(overlay),
            "--chart-version", "0.1.0-fixture", "--out-dir", str(out), "--no-verify-gate"]


class TempResidue(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="vexa-residue-test-")).resolve()
        self.tmp = self.work / "tmpdir"          # the TMPDIR the CLI is given
        self.tmp.mkdir()
        self.env = dict(os.environ, TMPDIR=str(self.tmp))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)

    def assertNothingLeft(self):
        left = sorted(str(p.relative_to(self.tmp)) for p in self.tmp.rglob("*"))
        self.assertEqual(left, [], "left behind in TMPDIR")

    def test_a_refused_run_leaves_nothing(self):
        chart, overlay = _chart(self.work, dependency=True)
        r = subprocess.run(_argv(chart, overlay, self.work / "out"), env=self.env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("P4", r.stderr)
        self.assertNothingLeft()

    @unittest.skipUnless(shutil.which("helm"), "helm not installed")
    def test_a_packaged_chart_leaves_nothing(self):
        chart, overlay = _chart(self.work)
        out = self.work / "out"
        r = subprocess.run(_argv(chart, overlay, out), env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((out / "vexa-platform-0.1.0-fixture.tgz").is_file())
        self.assertNothingLeft()

    def test_sigterm_mid_run_leaves_nothing(self):
        chart, overlay = _chart(self.work)
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        ready = self.work / "helm-started"
        helm = bin_dir / "helm"
        # a helm that never finishes: the chart copy exists while it runs
        helm.write_text(f"#!/bin/sh\necho $$ > {ready}\nexec sleep 60\n")
        helm.chmod(0o755)
        env = dict(self.env, PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
        p = subprocess.Popen(_argv(chart, overlay, self.work / "out"), env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 30
            while not (ready.exists() and ready.read_text().strip()):
                self.assertIsNone(p.poll(), "the CLI exited before calling helm")
                self.assertLess(time.monotonic(), deadline, "helm was never called")
                time.sleep(0.05)
            self.assertTrue(any(self.tmp.rglob("vexa-platform-chart-*")), "no chart copy while running")
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=30)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            if ready.exists() and ready.read_text().strip():
                try:
                    os.kill(int(ready.read_text()), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
            p.stderr.close()
        self.assertEqual(p.returncode, 128 + signal.SIGTERM)
        self.assertNothingLeft()

    def test_the_registry_auths_leave_with_the_run(self):
        home = self.work / "home"
        (home / ".docker").mkdir(parents=True)
        (home / ".docker" / "config.json").write_text(json.dumps(
            {"auths": {"registry.invalid": {"auth": "Zml4dHVyZTpub3QtYS1zZWNyZXQ="}},
             "credsStore": "desktop"}))
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import vexa_channel as vc; "
                "e = vc.cosign_env(); print(e['DOCKER_CONFIG'])")
        r = subprocess.run([sys.executable, "-c", code, str(PUBLISHER)], capture_output=True, text=True,
                           env=dict(self.env, HOME=str(home)))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(pathlib.Path(r.stdout.strip()).resolve().is_relative_to(self.tmp),
                        "DOCKER_CONFIG is not under the caller's TMPDIR")
        self.assertNothingLeft()

    def test_a_caller_tmpdir_that_is_not_a_directory_is_refused(self):
        chart, overlay = _chart(self.work)
        env = dict(self.env, TMPDIR=str(self.work / "no-such-dir"))
        r = subprocess.run(_argv(chart, overlay, self.work / "out"), env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("TMPDIR", r.stderr)
        self.assertFalse((self.work / "out").exists())


if __name__ == "__main__":
    unittest.main()
