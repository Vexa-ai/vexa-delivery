# SPDX-License-Identifier: Apache-2.0
"""The minutes chart, rendered with the flows tier ON, against a fixture map.

`test_chart_pins.py` asserts what `build_pins` EMITS. This asserts what a
customer's cluster would PULL — the two are different facts, and the gap
between them is exactly where the defect lived: for six months the publisher
emitted a pin table that looked complete, `helm package` succeeded, the entry
signed, and the flows tier still reached a station gate on a mutable `:v012`
tag. Nothing errored anywhere along that chain. S8 refused the chart, which is
the only reason anyone found out.

So the assertion here is the gate's own: EVERY container image in the rendered
manifests carries `@sha256:`, and so does every image reference the runtime
spawns by name. Not "flows is pinned" — every one, counted, with the flows
tier turned on. A tier added next release fails this test on the day it is
added rather than at a customer's gate.

THE FIXTURE. `fixtures/minutes-chart/` is the image-bearing surface of
Vexa-ai/vexa branch minutes-mcp-viewer @ 33379e2c4 — the four image resolvers
verbatim, and every `image:` expression copied character-for-character with its
upstream file:line named. It is not the whole chart and does not try to be;
see the headers in those files for what is deliberately absent and why. It is
a COPY, so it can go stale: if an upstream resolver changes and this fixture
does not, this test passes while saying nothing. The commit is named in both
fixture files so that staleness is checkable rather than invisible.

Renders through `helm`, so it SKIPS where helm is absent — including CI, which
installs python and nothing else. That matches every other render test in this
directory (test_verify_gate_injection, test_platform_chart, test_station); the
hermetic half of this defect is covered by test_chart_pins.py, which does run
in CI.
"""
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_channel as vc  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
CHART_SRC = HERE / "fixtures/minutes-chart"
GOLDEN_MAP = HERE.parents[1] / "spec/goldens/v0.12.23/evidence/candidate-images.json"

RELEASE = "v0.12.27"
FLOWS = "vexaai/v012-flows"
# Every container the flows tier renders on the default databaseName: three
# Deployments, each with its ensure-db initContainer. The number the issue
# reported as unpinned.
FLOWS_CONTAINERS = 6


def candidate_map():
    """The v0.12.23 golden's real ten images, plus the flows row that entered
    the release set at v0.12.27 (Vexa-ai/vexa release/candidate-image-map.mjs
    FLOWS_REQUIRED_FROM). Read-only: the golden's bytes are pinned as evidence
    and are copied here, never rewritten."""
    cmap = json.loads(GOLDEN_MAP.read_text())
    cmap = copy.deepcopy(cmap)
    cmap["release"] = RELEASE
    cmap["stable_tag"] = RELEASE
    cmap["images"][FLOWS] = {
        "class": "candidate_only",
        "digest": "sha256:" + "f1" * 32,
        "platforms": ["linux/amd64", "linux/arm64"],
        "attestations": True,
        "evidence": "fixture — not a published digest",
    }
    return cmap


def render(pins, values_over=None):
    """Package the fixture chart the way `vexa-channel chart` packages the real
    one — deep_merge the pins over values.yaml — and return the manifests."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="minutes-chart-"))
    try:
        chart = tmp / "vexa"
        shutil.copytree(CHART_SRC, chart)
        values_path = chart / "values.yaml"
        values = yaml.safe_load(values_path.read_text())
        vc.deep_merge(values, copy.deepcopy(pins))
        if values_over:
            vc.deep_merge(values, copy.deepcopy(values_over))
        values_path.write_text(yaml.safe_dump(values, sort_keys=False))
        out = subprocess.run(
            ["helm", "template", "line", str(chart)],
            capture_output=True, text=True, check=True).stdout
        return [d for d in yaml.safe_load_all(out) if d]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def image_refs(docs):
    """Every image reference the manifests ask a node for: the containers, the
    initContainers, and the three the runtime spawns by name at dispatch time.
    A spawned ref is not in any pod spec and is exactly as unpinnable when it
    floats, so leaving it out would let half the defect back in."""
    refs = {}
    spawned = {"BROWSER_IMAGE", "AGENT_IMAGE", "AGENT_WORKER_IMAGE"}
    for doc in docs:
        pod = doc.get("spec", {}).get("template", {}).get("spec", {})
        workload = doc.get("metadata", {}).get("name", "?")
        for key in ("initContainers", "containers"):
            for c in pod.get(key) or []:
                refs[f"{workload}/{c['name']}"] = c["image"]
                for env in c.get("env") or []:
                    if env.get("name") in spawned:
                        refs[f"{workload}/{c['name']}:{env['name']}"] = env["value"]
    return refs


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class MinutesChartIsFullyPinned(unittest.TestCase):
    def setUp(self):
        self.pins = vc.build_pins(RELEASE, candidate_map())

    def test_every_rendered_image_is_digest_pinned_with_flows_on(self):
        refs = image_refs(render(self.pins, {"flows": {"enabled": True}}))
        floating = {k: v for k, v in refs.items() if "@sha256:" not in v}
        self.assertEqual(floating, {}, f"unpinned image references: {floating}")
        # A render that produced nothing would also produce no findings.
        self.assertGreaterEqual(len(refs), 10 + FLOWS_CONTAINERS)

    def test_the_flows_tier_is_six_containers_on_one_pinned_image(self):
        refs = image_refs(render(self.pins, {"flows": {"enabled": True}}))
        flows = {k: v for k, v in refs.items() if k.startswith("flows-")}
        self.assertEqual(len(flows), FLOWS_CONTAINERS)
        self.assertEqual(set(flows.values()),
                         {f"{FLOWS}:{self.pins['flows']['image']['tag']}"})
        for ref in flows.values():
            self.assertIn(f"@{candidate_map()['images'][FLOWS]['digest']}", ref)

    def test_the_repository_survives_the_merge(self):
        # The other half of the 2026-09-03 defect: merging {"image": {"tag": ...}}
        # over a FLAT STRING replaces it, and the render then asks for an image
        # named after its own tag. Nothing raises; the ref is simply wrong.
        refs = image_refs(render(self.pins, {"flows": {"enabled": True}}))
        for name, ref in refs.items():
            self.assertNotIn("@sha256:", ref.split(":", 1)[0], f"{name}: {ref}")
            self.assertTrue(ref.startswith("vexaai/"), f"{name}: {ref}")

    def test_flows_off_is_the_shape_every_release_before_this_one_shipped(self):
        docs = render(vc.build_pins(
            "v0.12.23", json.loads(GOLDEN_MAP.read_text())))
        refs = image_refs(docs)
        self.assertEqual([k for k in refs if k.startswith("flows-")], [])
        self.assertEqual({k: v for k, v in refs.items() if "@sha256:" not in v}, {})


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class WithoutTheFlowsEntry(unittest.TestCase):
    """The defect, reproduced. Drop `flows` from the component table and the
    publisher raises nothing, packages happily, and ships six containers on a
    mutable tag — which is what the station gate refused."""

    def test_the_six_containers_float_and_nothing_complains(self):
        table = {k: v for k, v in vc.CHART_COMPONENT_IMAGES.items() if k != "flows"}
        with unittest.mock.patch.object(vc, "CHART_COMPONENT_IMAGES", table):
            pins = vc.build_pins(RELEASE, candidate_map())
        self.assertNotIn("flows", pins)
        refs = image_refs(render(pins, {"flows": {"enabled": True}}))
        floating = {k: v for k, v in refs.items() if "@sha256:" not in v}
        self.assertEqual(len(floating), FLOWS_CONTAINERS)
        self.assertEqual(set(floating.values()), {f"{FLOWS}:v012"})


if __name__ == "__main__":
    unittest.main()
