# SPDX-License-Identifier: Apache-2.0
"""Pod placement in the station chart — the fifth defect of one shape.

PROD, 2026-08-26. The receipt sender's PostSync Job never scheduled: this
cluster's single node pool is tainted `vexa.ai/pool=main:NoSchedule` and the
pod template carried no toleration, so the pod sat Pending on "untolerated
taint" until `activeDeadlineSeconds` fired and the Job went DeadlineExceeded.
The sync reported a failed hook and the failure named the deadline rather than
the taint — the same sentence, three days after the PreSync verify gate hit the
identical wall (`test_verify_gate_injection.py`).

Two assertions per pod, and the NEGATIVE one is the load-bearing half. A
station that declares no placement must render a pod spec with NO `nodeSelector`
and NO `tolerations` keys at all — not empty ones — or every existing
subscriber's render diff moves the day this ships, and a diff nobody can read is
a diff nobody checks.

Three pods, because the audit that found the sender's hole found the floor's in
the same pass: the PostSync Job, the cadenced CronJob, and the floor CronJob.
"""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHART = ROOT / "station/chart"

PROD_TOLERATION = {"key": "vexa.ai/pool", "operator": "Equal",
                   "value": "main", "effect": "NoSchedule"}
PROD_NODE_SELECTOR = {"vexa.ai/pool": "main"}

BASE = [
    "--set", "channelPublicKey=x",
    "--set", "floor.image=reg.invalid/tools/kubectl@sha256:" + "a" * 64,
    "--set", "receiptSender.enabled=true",
    "--set", "receiptSender.station=vexa-prod",
    "--set", "receiptSender.image=reg.invalid/tools/kit@sha256:" + "b" * 64,
    "--set", "receiptSender.contractConfigMap=vexa-station-contract",
    "--set", "receiptSender.trigger=scheduled",
]


def render(values=None):
    extra = []
    tmp = None
    if values:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        yaml.safe_dump(values, tmp)
        tmp.close()
        extra = ["-f", tmp.name]
    try:
        out = subprocess.run(["helm", "template", "st", str(CHART), *BASE, *extra],
                             capture_output=True, text=True)
    finally:
        if tmp:
            pathlib.Path(tmp.name).unlink(missing_ok=True)
    if out.returncode != 0:
        raise AssertionError(out.stderr[-2000:])
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def named(docs, kind, name):
    return next(d for d in docs
                if d.get("kind") == kind
                and (d.get("metadata") or {}).get("name") == name)


def pod_specs(docs):
    """The three pod specs this bundle spawns, by the name an operator sees."""
    return {
        "postsync-job":
            named(docs, "Job", "vexa-receipt-postsync")["spec"]["template"]["spec"],
        "sender-cronjob":
            named(docs, "CronJob", "vexa-receipt-sender")
            ["spec"]["jobTemplate"]["spec"]["template"]["spec"],
        "floor-cronjob":
            named(docs, "CronJob", "station-floor")
            ["spec"]["jobTemplate"]["spec"]["template"]["spec"],
    }


PLACED = {
    "receiptSender": {"tolerations": [PROD_TOLERATION],
                      "nodeSelector": PROD_NODE_SELECTOR},
    "floor": {"tolerations": [PROD_TOLERATION],
              "nodeSelector": PROD_NODE_SELECTOR},
}


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class StationPlacement(unittest.TestCase):

    def test_every_pod_this_bundle_spawns_is_covered(self):
        """The list itself is the assertion. A pod added to this chart later
        with no placement values is the sixth instance of this defect, and this
        test is where it should be noticed rather than in a Pending pod."""
        self.assertEqual(sorted(pod_specs(render())),
                         ["floor-cronjob", "postsync-job", "sender-cronjob"])

    def test_placement_defaults_are_absent_not_empty(self):
        for name, spec in pod_specs(render()).items():
            self.assertNotIn("nodeSelector", spec, name)
            self.assertNotIn("tolerations", spec, name)

    def test_placement_values_reach_every_pod_spec(self):
        for name, spec in pod_specs(render(PLACED)).items():
            self.assertEqual(spec["tolerations"], [PROD_TOLERATION], name)
            self.assertEqual(spec["nodeSelector"], PROD_NODE_SELECTOR, name)

    def test_the_two_sender_shapes_cannot_drift_apart(self):
        """Placement rides the SHARED pod spec, not two copies of it: a receipt
        that schedules per release and a cadenced one that silently does not is
        the failure this chart's one-definition rule exists to prevent."""
        specs = pod_specs(render(PLACED))
        self.assertEqual(specs["postsync-job"], specs["sender-cronjob"])

    def test_the_sender_and_the_floor_are_independent(self):
        """One estate, two owners is a real shape — the floor runs in the
        argocd namespace and the sender in the station namespace, and those can
        sit on different pools. Setting one must not set the other."""
        specs = pod_specs(render({"receiptSender": PLACED["receiptSender"]}))
        self.assertEqual(specs["postsync-job"]["tolerations"], [PROD_TOLERATION])
        self.assertNotIn("tolerations", specs["floor-cronjob"])

    def test_no_toleration_is_hard_coded(self):
        """Whoever owns the cluster owns the taint. A toleration baked into our
        template is our guess about someone else's nodes — the same mistake as
        a subscriber's registry address inside the verify gate's NetworkPolicy.

        Asserted against the RENDER, not the template text. Two substring
        assertions in this suite were reading COMMENTARY and failed on the prose
        explaining the very rule they enforce (1.0.6); the comments below name
        `vexa.ai/pool` because that is the taint this defect was found on, and
        the property that matters is that no render carries it unasked."""
        self.assertNotIn("vexa.ai/pool", yaml.safe_dump_all(render()))


if __name__ == "__main__":
    unittest.main()
