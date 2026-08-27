# SPDX-License-Identifier: Apache-2.0
"""The station bundle's subscription gate.

The load-bearing test is `test_the_subscription_can_be_turned_off`, and it
exists because through chart 1.0.5 it could not be. Every other piece of
machinery in this bundle has a switch — admission, floor, the receipt sender —
and the ONE object that stands up a whole Vexa stack had none. Installing the
chart for the sender alone would therefore have created
`ApplicationSet/vexa-channel-subscription`, subscribing `vexa-staging` on
auto-sync at `position: '*'`, in namespaces a station's contract may not
permit.

The other load-bearing test is the DEFAULT: on. A gate that changed an existing
subscriber's render would be a different defect wearing this one's clothes.
"""
import pathlib
import shutil
import subprocess
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHART = ROOT / "station/chart"

BASE = [
    "--set", "channelPublicKey=x",
    "--set", "floor.image=reg.invalid/tools/kubectl@sha256:" + "a" * 64,
]


def render(extra=()):
    out = subprocess.run(["helm", "template", "st", str(CHART), *extra],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(out.stderr[-2000:])
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def kinds(docs, kind):
    return [d for d in docs if d.get("kind") == kind]


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class SubscriptionGate(unittest.TestCase):

    def test_on_by_default(self):
        """Following the channel is what a station IS. Every subscriber that
        installed 1.0.5 must render byte-identically on 1.0.6."""
        docs = render(BASE)
        appsets = kinds(docs, "ApplicationSet")
        self.assertEqual(len(appsets), 1)
        self.assertEqual(appsets[0]["metadata"]["name"], "vexa-channel-subscription")

    def test_the_subscription_can_be_turned_off(self):
        """THE ONE THAT MATTERS. An estate already running Vexa by another path
        installs this bundle for its machinery, not for a second stack."""
        docs = render(BASE + ["--set", "subscription.enabled=false"])
        self.assertEqual(kinds(docs, "ApplicationSet"), [])

    def test_turning_it_off_leaves_the_other_machinery_standing(self):
        """The gate is on the subscription, not on the bundle. Admission and
        the floor are the reason an estate installs this at all."""
        docs = render(BASE + ["--set", "subscription.enabled=false"])
        self.assertTrue(kinds(docs, "ClusterPolicy"), "admission must survive")
        self.assertTrue(kinds(docs, "CronJob"), "the floor must survive")

    def test_the_entry_contracts_ride_the_same_gate(self):
        """Cohesion, stated as a test. The `vexa-contract-*` ConfigMaps have
        exactly one consumer — the PreSync verify gate of the Applications the
        ApplicationSet generates. No subscription, no Applications, no gate,
        nothing reading them. A second switch would only let an operator
        produce that orphan state on purpose."""
        on = [d["metadata"]["name"] for d in kinds(render(BASE), "ConfigMap")]
        self.assertIn("vexa-contract-staging", on)
        self.assertIn("vexa-contract-prod", on)
        off = [d["metadata"]["name"]
               for d in kinds(render(BASE + ["--set", "subscription.enabled=false"]),
                              "ConfigMap")]
        self.assertNotIn("vexa-contract-staging", off)
        self.assertNotIn("vexa-contract-prod", off)

    def test_the_sender_installs_without_the_subscription(self):
        """The shape 1.0.6 exists for: our own production cluster, which runs
        Vexa already and needs the return leg and nothing else."""
        docs = render(BASE + [
            "--set", "subscription.enabled=false",
            "--set", "admission.enabled=false",
            "--set", "floor.enabled=false",
            "--set", "receiptSender.enabled=true",
            "--set", "receiptSender.station=vexa-prod",
            "--set", "receiptSender.contractConfigMap=vexa-station-contract",
            "--set", "receiptSender.image=reg.invalid/x/vexaai/kit-runtime@sha256:" + "b" * 64,
        ])
        self.assertEqual(kinds(docs, "ApplicationSet"), [])
        self.assertTrue([d for d in kinds(docs, "Job")
                         if d["metadata"]["name"] == "vexa-receipt-postsync"])


if __name__ == "__main__":
    unittest.main()
