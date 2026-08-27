# SPDX-License-Identifier: Apache-2.0
"""The station-side half of the ladder: what may be collected, and what may not.

The claim being tested is structural, not behavioural. "We filter the output
afterwards" is a promise; "the function is never called" is a property, and it
is the property a customer's security team is being asked to believe about a
program they will read once and then run daily on their own cluster.

So the first test does not inspect the OUTPUT of a T2 run for the absence of
usage data — it records which collectors were invoked at all.
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import collectors  # noqa: E402


class FakeKube:
    """Answers `get` from a dict. Absent keys report a reason, the way a real
    cluster does when RBAC is narrower than the chart asked for."""

    def __init__(self, docs):
        self.docs, self.asked = docs, []

    def get(self, resource, name=None, namespace=True, timeout=60):
        self.asked.append(resource)
        key = (resource, name) if name else resource
        if key in self.docs:
            return self.docs[key], None
        return None, f"kubectl get {resource} exited 1"


PODS = {"items": [
    {"metadata": {"name": "api-7c9-aaa",
                  "ownerReferences": [{"kind": "ReplicaSet", "name": "api-7c9"}]},
     "status": {"phase": "Running",
                "containerStatuses": [
                    {"restartCount": 3,
                     "imageID": "docker-pullable://vexaai/api@sha256:" + "a" * 64}]}},
    {"metadata": {"name": "worker-1"},
     "status": {"phase": "Pending", "containerStatuses": []}},
]}
DEPLOYS = {"items": [{"metadata": {"name": "api"},
                      "spec": {"replicas": 2},
                      "status": {"readyReplicas": 1, "availableReplicas": 1}}]}
CRONJOBS = {"items": [
    {"metadata": {"name": "db-backup"}, "spec": {"suspend": False},
     "status": {"lastSuccessfulTime": "2026-08-25T00:00:00Z", "active": []}},
    {"metadata": {"name": "never-ran"}, "spec": {"suspend": True}, "status": {}},
]}
ALL = {"pods": PODS, "deployments.apps": DEPLOYS, "cronjobs.batch": CRONJOBS}


class TierGating(unittest.TestCase):

    def setUp(self):
        self.called = []
        self._real = dict(collectors.COLLECTORS)
        for tier, (name, fn) in self._real.items():
            collectors.COLLECTORS[tier] = (name, self._spy(name, fn))
        self.addCleanup(collectors.COLLECTORS.update, self._real)

    def _spy(self, name, fn):
        def wrapper(kube, cfg):
            self.called.append(name)
            return fn(kube, cfg)
        return wrapper

    def test_t1_never_reaches_the_health_collector(self):
        collectors.collect(1, FakeKube(ALL), {"app": "vexa-prod"})
        self.assertEqual(self.called, ["release"])

    def test_t2_never_reaches_the_usage_collector(self):
        collectors.collect(2, FakeKube(ALL), {})
        self.assertEqual(self.called, ["release", "health"])

    def test_t3_runs_all_three(self):
        collectors.collect(3, FakeKube(ALL), {})
        self.assertEqual(self.called, ["release", "health", "usage"])

    def test_t0_collects_nothing_and_says_so(self):
        with self.assertRaises(collectors.TierRefusal) as e:
            collectors.collect(0, FakeKube(ALL), {})
        self.assertIn("silent", str(e.exception))
        self.assertEqual(self.called, [])

    def test_t4_has_no_automatic_collector_at_all(self):
        with self.assertRaises(collectors.TierRefusal) as e:
            collectors.collect(4, FakeKube(ALL), {})
        self.assertIn("export-diagnostics", str(e.exception))
        self.assertEqual(self.called, [])


class TierResolution(unittest.TestCase):

    def test_no_report_scope_is_a_refusal_not_a_default(self):
        for scope in ({}, None, "tier: 2"):
            with self.assertRaises(collectors.TierRefusal):
                collectors.resolve_tier(scope)

    def test_a_scope_without_a_tier_is_t1_so_existing_stations_keep_working(self):
        self.assertEqual(collectors.resolve_tier({"destination": "channel.vexa.ai"}), 1)

    def test_a_declared_tier_wins(self):
        self.assertEqual(collectors.resolve_tier({"tier": 3}), 3)

    def test_a_tier_that_is_not_an_integer_0_4_is_refused(self):
        for bad in ("2", 2.0, True, -1, 5, None):
            with self.assertRaises(collectors.TierRefusal):
                collectors.resolve_tier({"tier": bad})


class HealthCounters(unittest.TestCase):

    def test_counters_are_aggregates_and_carry_no_content(self):
        h = collectors.collect_health(FakeKube(ALL), {"collectNodes": False})
        self.assertEqual(h["pods"], {"running": 1, "pending": 1, "failed": 0,
                                     "succeeded": 0, "unknown": 0, "restarts_total": 3})
        self.assertEqual(h["deployments"],
                         [{"name": "api", "desired": 2, "ready": 1,
                           "available": 1, "restarts": 3}])

    def test_a_cronjob_that_never_succeeded_is_null_not_zero(self):
        """Zero and never are different facts, and rendering them the same is
        how a dashboard shows green on a dead job."""
        h = collectors.collect_health(FakeKube(ALL), {"collectNodes": False})
        rows = {r["name"]: r for r in h["cronjobs"]}
        self.assertIsNone(rows["never-ran"]["last_success_age_seconds"])
        self.assertIsNotNone(rows["db-backup"]["last_success_age_seconds"])

    def test_what_could_not_be_read_is_named_absent_not_defaulted_to_zero(self):
        h = collectors.collect_health(FakeKube({"pods": PODS}), {"collectNodes": False})
        absent = {r["what"] for r in h["absent"]}
        self.assertIn("deployments", absent)
        self.assertIn("cronjobs", absent)
        self.assertNotIn("deployments", h)

    def test_a_cluster_error_message_never_enters_the_report(self):
        """A cluster's own stderr names hosts and users routinely, and this
        document promises not to carry that. The reason says what failed."""
        h = collectors.collect_health(FakeKube({}), {"collectNodes": False})
        blob = repr(h)
        self.assertNotIn("stderr", blob)
        for row in h["absent"]:
            self.assertLess(len(row["reason"]), 300)


class ReleaseReceipt(unittest.TestCase):

    def test_image_digests_come_from_the_pods_not_from_the_chart(self):
        """The chart says what should run; the pods say what does. Reading the
        chart for both sides of that comparison would make drift structurally
        undetectable, which is the one thing this rung is for."""
        r = collectors.collect_release(FakeKube(ALL), {"app": "vexa-prod"})
        self.assertEqual(r["images"],
                         [{"repository": "vexaai/api", "digest": "sha256:" + "a" * 64}])

    def test_an_unreadable_verifier_verdict_is_ABSENT_not_ELIGIBLE(self):
        """ABSENT means the gate did not run, which is a finding. Defaulting it
        to ELIGIBLE would report a passed check that never happened."""
        r = collectors.collect_release(FakeKube(ALL), {"app": "vexa-prod"})
        self.assertEqual(r["verifier"]["verdict"], "ABSENT")


class UsageIsAnInterfaceNotNumbers(unittest.TestCase):

    def test_it_reports_absent_rather_than_inventing_counts(self):
        u = collectors.collect_usage(FakeKube(ALL), {})
        self.assertIsNone(u["activated_users"])
        self.assertIsNone(u["meetings_dispatched"])
        self.assertTrue(u["absent"])
        self.assertIn("absent over faked", u["absent"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
