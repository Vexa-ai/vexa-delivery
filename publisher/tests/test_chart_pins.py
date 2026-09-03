# SPDX-License-Identifier: Apache-2.0
"""The chart pin injector — what it can address, and what it refuses to skip.

The 2026-09-03 OeNB line-commit dry run found the flows tier (Vexa Minutes) was the one component
a customer channel entry could not pin: `flows` was absent from CHART_COMPONENT_IMAGES, and the
chart's `flows.image` was a flat string that the injector's {"image": {"tag": ...}} shape cannot
address at all. These tests hold both halves.
"""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_channel as vc  # noqa: E402

FLOWS = "vexaai/v012-flows"


def image_row(n):
    return {"digest": "sha256:" + str(n) * 64}


def candidate_map(release, images):
    return {"release": release, "stable_tag": release,
            "images": {repo: image_row(i + 1) for i, repo in enumerate(images)}}


TEN = sorted(set(vc.CHART_COMPONENT_IMAGES.values()) - {FLOWS} | set(vc.SPAWNED_IMAGES.values()))
ELEVEN = sorted(set(TEN) | {FLOWS})


class ChartComponentTable(unittest.TestCase):
    def test_flows_is_a_pinnable_component(self):
        self.assertEqual(vc.CHART_COMPONENT_IMAGES["flows"], FLOWS)

    def test_flows_floor_matches_the_line(self):
        # Vexa-ai/vexa release/candidate-image-map.mjs FLOWS_REQUIRED_FROM
        self.assertEqual(vc.CHART_COMPONENT_SINCE["flows"], "v0.12.27")


class BuildPins(unittest.TestCase):
    def test_pins_flows_from_the_floor_release(self):
        pins = vc.build_pins("v0.12.27", candidate_map("v0.12.27", ELEVEN))
        self.assertIn("flows", pins)
        self.assertTrue(pins["flows"]["image"]["tag"].startswith("v0.12.27@sha256:"))
        # every other component still pinned, and the spawned images still ride runtime
        for component in vc.CHART_COMPONENT_IMAGES:
            self.assertIn(component, pins)
        self.assertIn("browserImage", pins["runtime"])

    def test_a_pre_flows_release_still_packages(self):
        # v0.12.23/25/26 candidate maps carry ten images. Refusing them would break `chart` for
        # every release already published.
        pins = vc.build_pins("v0.12.23", candidate_map("v0.12.23", TEN))
        self.assertNotIn("flows", pins)
        self.assertIn("gateway", pins)

    def test_a_post_floor_release_may_not_skip_the_flows_pin(self):
        with self.assertRaises(vc.CheckFailure) as caught:
            vc.build_pins("v0.12.27", candidate_map("v0.12.27", TEN))
        self.assertIn(FLOWS, str(caught.exception))

    def test_an_unparseable_version_fails_closed(self):
        self.assertFalse(vc.component_predates_image("0.12.23-estate-20260829", "flows"))
        with self.assertRaises(vc.CheckFailure):
            vc.build_pins("0.12.23-estate-20260829", candidate_map("x", TEN))


class PinInjection(unittest.TestCase):
    """deep_merge over the chart's values — the half that failed silently."""

    LINE_VALUES = {
        "gateway": {"image": {"repository": "vexaai/v012-gateway", "tag": "v012"}},
        "flows": {"enabled": False,
                  "image": {"repository": "vexaai/v012-flows", "tag": "v012"},
                  "databaseName": "flows"},
    }
    OLD_VALUES = {
        "gateway": {"image": {"repository": "vexaai/v012-gateway", "tag": "v012"}},
        "flows": {"enabled": False, "image": "vexaai/v012-flows:dev", "databaseName": "flows"},
    }

    def test_the_pin_reaches_flows_on_the_structured_chart(self):
        pins = vc.build_pins("v0.12.27", candidate_map("v0.12.27", ELEVEN))
        values = copy.deepcopy(self.LINE_VALUES)
        vc.deep_merge(values, pins)
        flows = values["flows"]["image"]
        self.assertEqual(flows["repository"], "vexaai/v012-flows")
        self.assertEqual(flows["tag"], pins["flows"]["image"]["tag"])
        self.assertIn("@sha256:", flows["tag"])
        self.assertFalse(values["flows"]["enabled"])          # the pin is identity, not a toggle
        self.assertEqual(values["flows"]["databaseName"], "flows")

    def test_a_flat_string_image_would_swallow_the_repository(self):
        # Why the chart had to change too: merging a map over a string REPLACES it. Nothing
        # errors — the rendered ref simply loses its repository, and the gate reports the tier as
        # unpinned. This is the defect, asserted so it cannot come back.
        pins = vc.build_pins("v0.12.27", candidate_map("v0.12.27", ELEVEN))
        values = copy.deepcopy(self.OLD_VALUES)
        vc.deep_merge(values, pins)
        self.assertNotIn("repository", values["flows"]["image"])


if __name__ == "__main__":
    unittest.main()
