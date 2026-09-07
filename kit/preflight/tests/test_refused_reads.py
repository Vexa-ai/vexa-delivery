# SPDX-License-Identifier: Apache-2.0
"""A refused cluster-scoped read is UNKNOWN, never a traceback — rehearsal defect 2.

`take_snapshot` did an UNWRAPPED `kubectl get nodes` while every sibling read in
the same function, `storageclasses` included, sat inside `try/except
RuntimeError`. A namespace-scoped tenant — "project not cluster" being the
OpenShift profile's own premise — therefore got a Python traceback out of a
conformance tool, and `install.sh` printed `preflight FAILED` on top of it,
which was a lie: nothing had been checked.

The other half of the defect is quieter and was already in the code: a refused
`storageclass` read became `[]`, and `[]` reads as "this cluster has no default
StorageClass" — P8 FAIL, invented out of a permission error.

What is asserted here: the refusal is caught, it is recorded with its reason,
each affected check says UNEVALUATED instead of guessing, the verdict says so,
and nothing about the rendering path trips over the new status.
"""
import io
import json
import contextlib
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_preflight as pf  # noqa: E402


FORBIDDEN = ('Error from server (Forbidden): nodes is forbidden: User '
             '"system:serviceaccount:vexa-dev:tenant" cannot list resource '
             '"nodes" in API group "" at the cluster scope')


def fake_kubectl(refuse):
    """A kubectl that refuses exactly the reads named in `refuse`."""
    def _kubectl(args, kubeconfig=None, context=None, input_=None, timeout=120):
        target = args[1] if len(args) > 1 else args[0]
        if args[0] == "version":
            if "server_version" in refuse:
                return subprocess.CompletedProcess(args, 1, "", "forbidden")
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"serverVersion": {"minor": "31", "gitVersion": "v1.31.0"}}), "")
        if args[0] == "api-versions":
            return subprocess.CompletedProcess(args, 0, "v1\napps/v1\n", "")
        if target in refuse:
            return subprocess.CompletedProcess(args, 1, "", FORBIDDEN)
        if target == "namespace":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"metadata": {"name": "vexa-dev", "labels": {},
                                                  "annotations": {}}}), "")
        return subprocess.CompletedProcess(args, 0, json.dumps({"items": []}), "")
    return _kubectl


class RefusedReadsAreCaught(unittest.TestCase):
    def setUp(self):
        self._real = pf.kubectl
        self.addCleanup(lambda: setattr(pf, "kubectl", self._real))

    def test_take_snapshot_does_not_raise_on_a_refused_nodes_read(self):
        pf.kubectl = fake_kubectl({"nodes"})
        snap = pf.take_snapshot("vexa-dev")            # used to raise RuntimeError
        self.assertEqual(snap["nodes"], [])
        self.assertIn("nodes", snap["unreadable"])
        self.assertIn("cannot list resource", snap["unreadable"]["nodes"])

    def test_every_cluster_scoped_read_is_wrapped(self):
        pf.kubectl = fake_kubectl({"nodes", "storageclass", "limitrange",
                                   "resourcequota", "networkpolicy", "namespace",
                                   "server_version"})
        snap = pf.take_snapshot("vexa-dev")
        for key in ("nodes", "storageclasses", "limitranges", "resourcequotas",
                    "networkpolicies", "namespace", "server_version"):
            self.assertIn(key, snap["unreadable"], f"{key} read is not wrapped")

    def test_kubectl_absent_is_a_reason_not_a_stack_trace(self):
        def missing(*a, **kw):
            raise FileNotFoundError(2, "No such file or directory", "kubectl")
        pf.kubectl = missing
        snap = pf.take_snapshot("vexa-dev")
        self.assertEqual(snap["unreadable"]["nodes"], "kubectl is not on PATH")


class RefusedReadsBecomeUnknown(unittest.TestCase):
    """The status, not just the absence of a crash: UNKNOWN is a third answer."""

    SNAP = {"namespace_name": "vexa-dev", "nodes": [], "limitranges": [],
            "resourcequotas": [], "networkpolicies": [], "storageclasses": [],
            "namespace": {"metadata": {"name": "vexa-dev", "labels": {}, "annotations": {}}},
            "server_version": {}, "openshift_scc": False,
            "unreadable": {"nodes": FORBIDDEN, "storageclasses": FORBIDDEN,
                           "server_version": "kubectl returned output that is not JSON"}}

    def test_p1_is_unknown_and_names_the_refused_read(self):
        c = pf.check_taints(self.SNAP, [dict(pf.BOT_PROFILE)])
        self.assertEqual(c.status, "UNKNOWN")
        self.assertIn("UNEVALUATED", " ".join(c.findings))
        self.assertIn("nodes", " ".join(c.findings))

    def test_p8_says_unknown_rather_than_inventing_a_missing_storageclass(self):
        objects = [{"kind": "PersistentVolumeClaim", "metadata": {"name": "data"}}]
        c = pf.check_storage(self.SNAP, objects)
        self.assertEqual(c.status, "UNKNOWN")
        self.assertNotIn("no default StorageClass", " ".join(c.findings))

    def test_p9_is_unknown_when_the_version_could_not_be_read(self):
        self.assertEqual(pf.check_version(self.SNAP).status, "UNKNOWN")

    def test_unknown_never_overrides_a_real_fail(self):
        c = pf.Check("P2", "t", "a")
        c.fail("a container declares no limits")
        c.unknown("and the LimitRange could not be read")
        self.assertEqual(c.status, "FAIL")

    def test_render_and_verdict_carry_the_new_status(self):
        checks = [pf.check_taints(self.SNAP, [dict(pf.BOT_PROFILE)]),
                  pf.check_version(self.SNAP)]
        text = pf.render(checks)                      # used to KeyError on the badge map
        self.assertIn("P1", text)
        self.assertIn("NOT EVALUATED", text)
        self.assertNotIn("VERDICT: FAIL", text)
        self.assertNotIn("VERDICT: PASS\n", text)
        parsed = json.loads(pf.render(checks, as_json=True))
        self.assertEqual({c["status"] for c in parsed["checks"]}, {"UNKNOWN"})


class EndToEnd(unittest.TestCase):
    """The whole CLI, on a snapshot a namespace-scoped tenant could produce."""

    def _run(self, snap):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "snap.json"
            p.write_text(json.dumps(snap))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = pf.main(["--namespace", "vexa-dev", "--snapshot", str(p)])
            return rc, buf.getvalue()

    def test_main_reports_unknown_and_does_not_exit_1(self):
        rc, out = self._run(dict(RefusedReadsBecomeUnknown.SNAP))
        self.assertNotEqual(rc, 1, "a refused read must not be reported as a failed check")
        self.assertIn("????", out)
        self.assertIn("NOT EVALUATED", out)
        self.assertNotIn("Traceback", out)

    def test_unevaluated_has_its_own_exit_code(self):
        """4, not 0.

        Sharing 0 with a clean run is what made "fails closed" untrue for the
        rows the docs list: a namespace-scoped tenant got exit 0 with the node,
        storage and version checks never run, and `install.sh` proceeded on it
        with nothing said. 4 is not a failure — it says the answer is
        incomplete, and it is the thing a caller can test.
        """
        rc, _ = self._run(dict(RefusedReadsBecomeUnknown.SNAP))
        self.assertEqual(rc, 4)

    def test_a_snapshot_that_was_fully_readable_still_exits_zero(self):
        """The other side of it: no UNKNOWN, no FAIL -> 0, unchanged.

        The namespace now carries a PSA enforce label, because since 2026-09-07
        a namespace that enforces NOTHING is itself UNKNOWN (P4, test below).
        "Fully readable" has to mean there was something to read.
        """
        snap = json.loads(json.dumps(RefusedReadsBecomeUnknown.SNAP))
        snap["unreadable"] = {}
        snap["namespace"]["metadata"]["labels"] = {
            "pod-security.kubernetes.io/enforce": "baseline"}
        rc, out = self._run(snap)
        self.assertEqual(rc, 0)
        self.assertNotIn("NOT EVALUATED", out)

    def test_a_namespace_that_enforces_nothing_is_unknown_not_a_pass(self):
        """2026-09-07: P4 returned PASS on a project whose PSA labels and SCC
        annotations the installer had just stripped — "no SCC and no PSA enforce
        label ... nothing to trip, nothing verified" printed as a green. A pass
        obtained from the enforcement being absent is the one shape this check
        must never produce."""
        snap = json.loads(json.dumps(RefusedReadsBecomeUnknown.SNAP))
        snap["unreadable"] = {}
        c = pf.check_pod_security(snap, [dict(pf.BOT_PROFILE)])
        self.assertEqual(c.status, "UNKNOWN")
        text = " ".join(c.findings)
        self.assertIn("enforces nothing", text)
        self.assertIn("This is not a pass", text)
        rc, out = self._run(snap)
        self.assertEqual(rc, 4)
        self.assertIn("NOT EVALUATED", out)


if __name__ == "__main__":
    unittest.main()
