# SPDX-License-Identifier: Apache-2.0
"""OpenShift provider conformance — the preflight against RECORDED constraints.

Sibling of test_preflight.py: that file asserts each check's logic one failure
class at a time; this one feeds P4 and P2/P6 the constraint values actually
recorded for OpenShift and asserts the DELIVERED set passes or fails exactly as
the rehearsal recorded it.

Every fixture value below is quoted from a receipt, never invented:

  UID_RANGE_ANNOTATION  docs/engineering/openshift-parity.mdx — measured on a
                        real admitted bot pod in the customer's project:
                        runAsUser 1000920000 (so the project's
                        openshift.io/sa.scc.uid-range starts there)
  AUDIT_UID_RANGE       openshift readiness audit 2026-08-19 fixture range
                        1000600000/10000 (same range test_preflight.py uses)
  ARGO_UPSTREAM_UIDS    parity.mdx § genuine-OpenShift run: upstream Argo CD's
                        own images hard-code dex 1001, redis 999 — rejected
  RIG_LIMITRANGE        docs/receipts/2026-08-21-m2-throwaway-test.md §5:
                        LimitRange default 64Mi / max 1Gi; bot limit 2560Mi
                        named as above max
  DELIVERED_STOCK       parity.mdx: 25 chart objects admitted stock, zero SCC
                        rejects, random-UID contexts injected on all 21 pods —
                        i.e. the delivered set carries NO securityContext

The rehearsal's recorded outcomes, which are what this file asserts:
  1. delivered set, no securityContext, SCC restricted-v2      -> P4 PASS
  2. same set on a PSA-restricted namespace                    -> P4 FAIL
     (SCC mutates seccomp/caps/UID but NEVER sets runAsNonRoot)
  3. upstream Argo CD's hard-coded UIDs under SCC              -> P4 FAIL
  4. bot 2560Mi against the recorded LimitRange max 1Gi        -> P2 + P6 FAIL
  5. LimitRange max raised to 2560Mi                           -> P2 + P6 PASS
  6. P4 PASS says nothing about HOME-writability at runtime    -> open finding
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_preflight as pf  # noqa: E402

# ------------------------------------------------------------------ recorded

# Measured on the customer's cluster (parity.mdx): the admitted bot pod ran as
# 1000920000. OpenShift allocates /10000 blocks, so that is the range start.
UID_RANGE_ANNOTATION = "1000920000/10000"
# The 2026-08-19 audit fixture range, kept so both recorded ranges are covered.
AUDIT_UID_RANGE_ANNOTATION = "1000600000/10000"

# M2 receipt §5: the LimitRange the rig enforced, and the value that fixes it.
RIG_LIMITRANGE = {
    "metadata": {"name": "tenant-defaults"},
    "spec": {"limits": [{
        "type": "Container",
        "default": {"memory": "64Mi", "cpu": "100m"},
        "defaultRequest": {"memory": "32Mi"},
        "max": {"memory": "1Gi"},
    }]},
}
RAISED_LIMITRANGE = {
    "metadata": {"name": "tenant-defaults"},
    "spec": {"limits": [{
        "type": "Container",
        "default": {"memory": "64Mi", "cpu": "100m"},
        "defaultRequest": {"memory": "32Mi"},
        # the remedy the preflight itself prints: "at least 2560Mi"
        "max": {"memory": "2560Mi"},
    }]},
}

# Nodes big enough that P6 can only fail on the LimitRange, never on capacity.
NODES = [{"metadata": {"name": "worker-0"},
          "spec": {"taints": []},
          "status": {"allocatable": {"memory": "7Gi"}}}]


def workload(name, kind="Deployment", resources=None, sec=None, pod_sec=None,
             shm=0, volumes=None, host_flags=None, ports=None):
    return {
        "kind": kind,
        "name": name,
        "containers": [{
            "name": name,
            "resources": resources or {},
            "security_context": sec or {},
            "ports": ports or [],
        }],
        "tolerations": [],
        "pod_security_context": pod_sec or {},
        "host_flags": host_flags or {},
        "volumes": volumes or [],
        "shm_bytes": shm,
    }


DECLARED = {
    "requests": {"cpu": "100m", "memory": "256Mi"},
    "limits": {"cpu": "500m", "memory": "512Mi"},
}


def delivered_stock():
    """The delivered set as OpenShift admission saw it: resources declared,
    NO securityContext anywhere (parity.mdx: 25 objects admitted stock)."""
    return [
        workload("vexa-api-gateway", resources=DECLARED),
        workload("vexa-admin-api", resources=DECLARED),
        workload("vexa-bot-manager", resources=DECLARED),
        workload("vexa-transcription-collector", resources=DECLARED),
        dict(pf.BOT_PROFILE),  # spawned per meeting; in no render
    ]


def scc_snapshot(uid_range=UID_RANGE_ANNOTATION, limitranges=None):
    """A restricted-v2 OpenShift project: SCC on, no PSA enforce label."""
    return {
        "openshift_scc": True,
        "namespace": {"metadata": {
            "annotations": {"openshift.io/sa.scc.uid-range": uid_range},
            "labels": {},
        }},
        "limitranges": limitranges if limitranges is not None else [],
        "nodes": NODES,
    }


def psa_snapshot(limitranges=None):
    """A plain Kubernetes namespace with PSA enforce=restricted — the shape
    the M2 rig seeded, and the one an SCC-clean spec does NOT satisfy."""
    return {
        "openshift_scc": False,
        "namespace": {"metadata": {
            "annotations": {},
            "labels": {"pod-security.kubernetes.io/enforce": "restricted"},
        }},
        "limitranges": limitranges if limitranges is not None else [],
        "nodes": NODES,
    }


# ------------------------------------------------------------------ P4 / SCC


class DeliveredSetUnderSCC(unittest.TestCase):
    """Recorded outcome 1: stock, no securityContext, zero SCC rejects."""

    def test_delivered_set_is_admitted(self):
        c = pf.check_pod_security(scc_snapshot(), delivered_stock())
        self.assertEqual(c.status, "PASS", "\n".join(c.findings))

    def test_the_measured_uid_range_is_reported(self):
        c = pf.check_pod_security(scc_snapshot(), delivered_stock())
        self.assertIn("1000920000–1000929999", " ".join(c.findings))

    def test_admitted_under_the_audit_range_too(self):
        c = pf.check_pod_security(
            scc_snapshot(uid_range=AUDIT_UID_RANGE_ANNOTATION), delivered_stock())
        self.assertEqual(c.status, "PASS", "\n".join(c.findings))

    def test_injected_uid_is_accepted_when_it_appears_in_the_spec(self):
        """The SCC-assigned UID itself is inside the range, so a spec that
        echoes it back (a rendered live pod) still passes."""
        w = workload("vexa-bot", sec={"runAsUser": 1000920000}, resources=DECLARED)
        c = pf.check_pod_security(scc_snapshot(), [w])
        self.assertEqual(c.status, "PASS", "\n".join(c.findings))


class HardenedSpecsAreTheRejectedOnes(unittest.TestCase):
    """Recorded outcome 3, plus the general inversion: self-hardening loses."""

    ARGO_UPSTREAM_UIDS = {"argocd-dex-server": 1001, "argocd-redis": 999}

    def test_upstream_argocd_images_are_rejected(self):
        ws = [workload(name, sec={"runAsUser": uid})
              for name, uid in sorted(self.ARGO_UPSTREAM_UIDS.items())]
        c = pf.check_pod_security(scc_snapshot(), ws)
        self.assertEqual(c.status, "FAIL")
        text = " ".join(c.findings)
        self.assertIn("runAsUser: 1001", text)
        self.assertIn("runAsUser: 999", text)
        self.assertIn("MustRunAsRange", text)

    def test_explicit_fsgroup_outside_the_range_is_rejected(self):
        w = workload("vexa-api-gateway", pod_sec={"fsGroup": 2000}, resources=DECLARED)
        c = pf.check_pod_security(scc_snapshot(), [w])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("fsGroup: 2000", " ".join(c.findings))

    def test_remedy_says_drop_the_securitycontext(self):
        w = workload("vexa-api-gateway", sec={"runAsUser": 1001}, resources=DECLARED)
        c = pf.check_pod_security(scc_snapshot(), [w])
        self.assertIn("drop explicit", c.remedy or "")

    def test_hostpath_is_rejected_regardless_of_uid(self):
        w = workload("runtime",
                     volumes=[{"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}}])
        c = pf.check_pod_security(scc_snapshot(), [w])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("hostPath", " ".join(c.findings))


class SccCleanIsNotPsaClean(unittest.TestCase):
    """Recorded outcome 2 — the delta that bites when a cluster enforces both.

    SCC mutates seccomp, capabilities and the UID in. It never sets
    runAsNonRoot, and PSA restricted validates rather than mutates.
    """

    def test_the_same_delivered_set_fails_psa_restricted(self):
        c = pf.check_pod_security(psa_snapshot(), delivered_stock())
        self.assertEqual(c.status, "FAIL")
        text = " ".join(c.findings)
        self.assertIn("runAsNonRoot", text)
        self.assertIn("seccompProfile", text)
        self.assertIn("capabilities.drop", text)

    def test_the_bot_is_named_among_the_psa_failures(self):
        c = pf.check_pod_security(psa_snapshot(), delivered_stock())
        self.assertIn("vexa-bot", " ".join(c.findings))


class AdmissionPassIsNotRuntimeSuccess(unittest.TestCase):
    """Recorded outcome 6 — the HOME finding, still OPEN at v0.12.23.

    Under a random UID, HOME is absent from the bot and agent-worker images;
    minio-init fails with `mkdir /.mc: permission denied` and the Application
    never converges. No preflight check sees this. This test pins the boundary
    so a green P4 is never read as "it runs" — and it will start failing the
    day someone adds a HOME check, which is the right moment to revisit it.
    """

    def test_p4_passes_while_the_home_defect_remains_undetected(self):
        c = pf.check_pod_security(scc_snapshot(), delivered_stock())
        self.assertEqual(c.status, "PASS")
        self.assertNotIn("HOME", " ".join(c.findings))


# ------------------------------------------------------------- P2 / P6 quota


class RecordedLimitRange(unittest.TestCase):
    """Recorded outcomes 4 and 5: the bot against the tenant LimitRange."""

    def test_bot_limit_exceeds_the_recorded_max(self):
        c = pf.check_limitranges(scc_snapshot(limitranges=[RIG_LIMITRANGE]),
                                 delivered_stock())
        self.assertEqual(c.status, "FAIL")
        text = " ".join(c.findings)
        self.assertIn("2560Mi", text)
        self.assertIn("above the LimitRange max", text)

    def test_shm_check_refuses_the_bot_against_the_recorded_max(self):
        c = pf.check_shm(scc_snapshot(limitranges=[RIG_LIMITRANGE]),
                         delivered_stock())
        self.assertEqual(c.status, "FAIL")
        self.assertIn("LimitRange max", " ".join(c.findings))
        self.assertIn("2560Mi", c.remedy or "")

    def test_raised_max_admits_the_whole_delivered_set(self):
        snap = scc_snapshot(limitranges=[RAISED_LIMITRANGE])
        self.assertEqual(pf.check_limitranges(snap, delivered_stock()).status, "PASS")
        self.assertEqual(pf.check_shm(snap, delivered_stock()).status, "PASS")

    def test_an_undeclared_container_is_squeezed_to_the_recorded_default(self):
        """The 64Mi default is what silently absorbs anything undeclared —
        the reason every delivered container declares resources explicitly."""
        c = pf.check_limitranges(scc_snapshot(limitranges=[RIG_LIMITRANGE]),
                                 [workload("third-party-sidecar", resources={})])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("64Mi", " ".join(c.findings))


# ------------------------------------------------------------------- profile


class ProfileFile(unittest.TestCase):
    """The profile must keep saying what the evidence supports."""

    PROFILE = pathlib.Path(__file__).resolve().parents[2] / "providers" / "openshift" / "profile.env"

    def values(self):
        out = {}
        for line in self.PROFILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
        return out

    def test_profile_exists_and_pins_the_validated_versions(self):
        v = self.values()
        self.assertEqual(v["ARGOCD_VERSION"], "v3.5.1")
        self.assertEqual(v["KYVERNO_VERSION"], "v1.19.0")

    def test_profile_does_not_claim_to_be_tested(self):
        """No OpenShift cluster has run install.sh. Until one has, this is
        'no' — install.sh prints the caveat off exactly this value."""
        self.assertEqual(self.values()["PROFILE_TESTED"], "no")

    def test_profile_records_the_rung_it_actually_reached(self):
        self.assertEqual(self.values()["PROFILE_RUNG"],
                         "rehearsed-against-recorded-constraints")

    def test_readme_states_the_home_finding_as_open(self):
        readme = (self.PROFILE.parent / "README.md").read_text()
        self.assertIn("HOME", readme)
        self.assertIn("open product defect", readme.lower())


if __name__ == "__main__":
    unittest.main()
