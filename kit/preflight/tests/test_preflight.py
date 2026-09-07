# SPDX-License-Identifier: Apache-2.0
"""Preflight unit tests — one fixture per observed failure class (handoff §6).

Each fixture reproduces the shape of a real incident:
  taints        vexa-platform#337 — every node tainted, addon pods tolerate nothing
  limitrange    vexa#1005 — a customer namespace default squeezed undeclared pods to 64Mi
  scc           openshift audit — hard-coded UID 1001 outside the namespace range
  psa           openshift audit — PSA restricted refuses missing runAsNonRoot
  netpol        default-deny egress with no DNS allowance
  shm           bot 2560Mi limit vs LimitRange max 1Gi / small nodes
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_preflight as pf  # noqa: E402


def node(name, taints=None, alloc_mem="7Gi"):
    return {
        "metadata": {"name": name},
        "spec": {"taints": taints or []},
        "status": {"allocatable": {"memory": alloc_mem}},
    }


def workload(name, kind="Deployment", resources=None, tolerations=None,
             sec=None, pod_sec=None, shm=0, host_flags=None, volumes=None, ports=None):
    return {
        "kind": kind,
        "name": name,
        "containers": [
            {
                "name": "main",
                "resources": resources or {},
                "security_context": sec or {},
                "ports": ports or [],
            }
        ],
        "tolerations": tolerations or [],
        "pod_security_context": pod_sec or {},
        "host_flags": host_flags or {},
        "volumes": volumes or [],
        "shm_bytes": shm,
    }


DECLARED = {
    "requests": {"cpu": "100m", "memory": "256Mi"},
    "limits": {"cpu": "500m", "memory": "512Mi"},
}


class Taints(unittest.TestCase):
    """vexa-platform#337: cluster-wide custom taint, workloads tolerate nothing."""

    CUSTOM_TAINT = {"key": "vexa.ai/dedicated", "value": "app", "effect": "NoSchedule"}

    def test_untolerated_taint_fails_and_names_the_taint(self):
        snap = {"nodes": [node("n1", [self.CUSTOM_TAINT]), node("n2", [self.CUSTOM_TAINT])]}
        c = pf.check_taints(snap, [workload("gateway", resources=DECLARED)])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("vexa.ai/dedicated", " ".join(c.findings))

    def test_matching_toleration_passes(self):
        snap = {"nodes": [node("n1", [self.CUSTOM_TAINT])]}
        tol = [{"key": "vexa.ai/dedicated", "operator": "Equal", "value": "app", "effect": "NoSchedule"}]
        c = pf.check_taints(snap, [workload("gateway", resources=DECLARED, tolerations=tol)])
        self.assertEqual(c.status, "PASS")

    def test_exists_toleration_matches_any_value(self):
        snap = {"nodes": [node("n1", [self.CUSTOM_TAINT])]}
        tol = [{"key": "vexa.ai/dedicated", "operator": "Exists"}]
        c = pf.check_taints(snap, [workload("g", resources=DECLARED, tolerations=tol)])
        self.assertEqual(c.status, "PASS")


class LimitRanges(unittest.TestCase):
    """vexa#1005: namespace LimitRange default 64Mi + undeclared resources = squeeze."""

    CUSTOMER_LR = {
        "metadata": {"name": "ns-default"},
        "spec": {"limits": [{"type": "Container",
                             "default": {"memory": "64Mi", "cpu": "100m"},
                             "defaultRequest": {"memory": "32Mi"}}]},
    }

    def test_undeclared_resources_fail_naming_the_squeeze(self):
        snap = {"limitranges": [self.CUSTOMER_LR], "nodes": []}
        c = pf.check_limitranges(snap, [workload("bot", resources={})])
        self.assertEqual(c.status, "FAIL")
        text = " ".join(c.findings)
        self.assertIn("64Mi", text)
        self.assertIn("does not declare", text)

    def test_declared_within_range_passes(self):
        lr = {
            "metadata": {"name": "caps"},
            "spec": {"limits": [{"type": "Container", "max": {"memory": "4Gi"}, "min": {"memory": "16Mi"}}]},
        }
        snap = {"limitranges": [lr], "nodes": []}
        c = pf.check_limitranges(snap, [workload("gateway", resources=DECLARED)])
        self.assertEqual(c.status, "PASS")

    def test_declared_above_max_fails(self):
        lr = {
            "metadata": {"name": "caps"},
            "spec": {"limits": [{"type": "Container", "max": {"memory": "256Mi"}}]},
        }
        snap = {"limitranges": [lr], "nodes": []}
        c = pf.check_limitranges(snap, [workload("gateway", resources=DECLARED)])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("above the LimitRange max", " ".join(c.findings))

    # ---- 2026-09-07: the three quarters of admission the check did not read.
    #
    # The LimitRanger compares `max` and `min` against the REQUEST and the
    # LIMIT, for every resource the LimitRange names. This check compared one of
    # those four pairs, in one dimension, so cpu was declared and never checked
    # against anything, and a request over the ceiling was invisible.

    TENANT_LR = {                      # the tenant grant's own shape
        "metadata": {"name": "vexa-dev-limits"},
        "spec": {"limits": [{"type": "Container",
                             "max": {"cpu": "8", "memory": "2560Mi"},
                             "min": {"cpu": "5m", "memory": "16Mi"},
                             "default": {"cpu": "1", "memory": "512Mi"},
                             "defaultRequest": {"cpu": "10m", "memory": "64Mi"}}]},
    }

    def test_the_delivered_postgres_against_the_documented_ceiling(self):
        """The exact refusal of 2026-09-07, predicted instead of observed."""
        pg = {"requests": {"cpu": "200m", "memory": "512Mi"},
              "limits": {"cpu": "4000m", "memory": "4Gi"}}
        c = pf.check_limitranges({"limitranges": [self.TENANT_LR], "nodes": []},
                                 [workload("postgres", kind="StatefulSet", resources=pg)])
        self.assertEqual(c.status, "FAIL")
        text = " ".join(c.findings)
        self.assertIn("limits.memory 4Gi above the LimitRange max 2560Mi", text)
        self.assertIn("maximum memory usage per Container is 2560Mi", text)

    def test_a_request_over_the_max_fails_even_when_the_limit_fits(self):
        lr = {"metadata": {"name": "caps"},
              "spec": {"limits": [{"type": "Container", "max": {"memory": "256Mi"}}]}}
        res = {"requests": {"cpu": "100m", "memory": "512Mi"},
               "limits": {"cpu": "500m", "memory": "256Mi"}}
        c = pf.check_limitranges({"limitranges": [lr], "nodes": []},
                                 [workload("g", resources=res)])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("requests.memory 512Mi above the LimitRange max 256Mi",
                      " ".join(c.findings))

    def test_cpu_is_compared_too(self):
        res = {"requests": {"cpu": "100m", "memory": "256Mi"},
               "limits": {"cpu": "16", "memory": "512Mi"}}
        c = pf.check_limitranges({"limitranges": [self.TENANT_LR], "nodes": []},
                                 [workload("greedy", resources=res)])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("limits.cpu 16 above the LimitRange max 8", " ".join(c.findings))

    def test_a_limit_below_the_min_fails(self):
        res = {"requests": {"cpu": "10m", "memory": "20Mi"},
               "limits": {"cpu": "100m", "memory": "8Mi"}}
        c = pf.check_limitranges({"limitranges": [self.TENANT_LR], "nodes": []},
                                 [workload("tiny", resources=res)])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("limits.memory 8Mi below the LimitRange min 16Mi",
                      " ".join(c.findings))

    def test_a_pass_names_the_ceiling_it_compared_against(self):
        """Positive evidence. A PASS that says only 'a LimitRange exists' cannot
        be distinguished, an hour later, from a PASS taken against a ceiling
        somebody has since lowered — which is exactly what happened on
        2026-09-07, where the live max.memory was 8Gi at preflight time and
        2560Mi by the time postgres was admitted."""
        c = pf.check_limitranges({"limitranges": [self.TENANT_LR], "nodes": []},
                                 [workload("gateway", resources=DECLARED)])
        self.assertEqual(c.status, "PASS")
        text = " ".join(c.findings)
        self.assertIn("vexa-dev-limits", text)
        self.assertIn("max.memory=2560Mi", text)
        self.assertIn("max.cpu=8", text)


class Quota(unittest.TestCase):
    """P3 summed memory and nothing else, so a quota's `limits.cpu` — which the
    tenant grant carries — bounded a total the check never computed."""

    def quota(self, hard, used=None):
        return {"metadata": {"name": "vexa-dev-quota"},
                "status": {"hard": hard, "used": used or {}}}

    def test_cpu_headroom_is_checked(self):
        res = {"requests": {"cpu": "2", "memory": "256Mi"},
               "limits": {"cpu": "8", "memory": "512Mi"}}
        snap = {"resourcequotas": [self.quota({"limits.cpu": "4"})]}
        c = pf.check_quota(snap, [workload("greedy", resources=res)])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("limits.cpu", " ".join(c.findings))

    def test_memory_headroom_still_checked_and_used_is_subtracted(self):
        snap = {"resourcequotas": [self.quota({"limits.memory": "1Gi"},
                                              {"limits.memory": "768Mi"})]}
        c = pf.check_quota(snap, [workload("g", resources=DECLARED),
                                  workload("h", resources=DECLARED)])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("limits.memory", " ".join(c.findings))

    def test_headroom_that_covers_it_passes(self):
        snap = {"resourcequotas": [self.quota({"limits.memory": "8Gi", "limits.cpu": "16"})]}
        c = pf.check_quota(snap, [workload("g", resources=DECLARED)])
        self.assertEqual(c.status, "PASS")


class PodSecuritySCC(unittest.TestCase):
    """openshift audit: the hardened workloads (hard-coded UID 1001) are the SCC-rejected ones."""

    def ns_snapshot(self):
        return {
            "openshift_scc": True,
            "namespace": {"metadata": {
                "annotations": {"openshift.io/sa.scc.uid-range": "1000600000/10000"},
                "labels": {},
            }},
            "nodes": [],
        }

    def test_hardcoded_uid_outside_range_rejected(self):
        w = workload("billing-worker", sec={"runAsUser": 1001}, resources=DECLARED)
        c = pf.check_pod_security(self.ns_snapshot(), [w])
        self.assertEqual(c.status, "FAIL")
        text = " ".join(c.findings)
        self.assertIn("runAsUser: 1001", text)
        self.assertIn("MustRunAsRange", text)

    def test_uid_inside_range_passes(self):
        w = workload("ok", sec={"runAsUser": 1000600007}, resources=DECLARED)
        c = pf.check_pod_security(self.ns_snapshot(), [w])
        self.assertEqual(c.status, "PASS")

    def test_hostpath_always_rejected(self):
        w = workload("runtime", volumes=[{"name": "d", "hostPath": {"path": "/var/run/docker.sock"}}])
        c = pf.check_pod_security(self.ns_snapshot(), [w])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("hostPath", " ".join(c.findings))


class PodSecurityPSA(unittest.TestCase):
    """PSA restricted: runAsNonRoot/seccomp/drop-ALL are validated, never mutated in."""

    def ns_snapshot(self):
        return {
            "openshift_scc": False,
            "namespace": {"metadata": {
                "labels": {"pod-security.kubernetes.io/enforce": "restricted"},
                "annotations": {},
            }},
            "nodes": [],
        }

    def test_missing_runasnonroot_fails(self):
        c = pf.check_pod_security(self.ns_snapshot(), [workload("gateway", resources=DECLARED)])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("runAsNonRoot", " ".join(c.findings))

    def test_fully_hardened_passes(self):
        sec = {
            "runAsNonRoot": True,
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        c = pf.check_pod_security(self.ns_snapshot(), [workload("g", sec=sec, resources=DECLARED)])
        self.assertEqual(c.status, "PASS")


class NetPol(unittest.TestCase):
    def test_default_deny_without_dns_fails(self):
        pol = {
            "metadata": {"name": "default-deny"},
            "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": []},
        }
        c = pf.check_netpol_static({"networkpolicies": [pol]}, [])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("DNS", " ".join(c.findings))

    def test_default_deny_with_dns_warns_toward_live_probe(self):
        deny = {"metadata": {"name": "deny"}, "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": []}}
        allow = {
            "metadata": {"name": "dns"},
            "spec": {"podSelector": {}, "policyTypes": ["Egress"],
                     "egress": [{"ports": [{"port": 53, "protocol": "UDP"}]}]},
        }
        c = pf.check_netpol_static({"networkpolicies": [deny, allow]}, [])
        self.assertEqual(c.status, "WARN")


class Shm(unittest.TestCase):
    """The bot's 2Gi Memory shm + 2560Mi limit vs the environment."""

    def bot(self):
        return dict(pf.BOT_PROFILE)

    def test_limitrange_max_below_bot_limit_fails(self):
        lr = {"metadata": {"name": "caps"},
              "spec": {"limits": [{"type": "Container", "max": {"memory": "1Gi"}}]}}
        snap = {"limitranges": [lr], "nodes": [node("n1", alloc_mem="7Gi")]}
        c = pf.check_shm(snap, [self.bot()])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("LimitRange max", " ".join(c.findings))

    def test_small_nodes_fail(self):
        snap = {"limitranges": [], "nodes": [node("n1", alloc_mem="1900Mi")]}
        c = pf.check_shm(snap, [self.bot()])
        self.assertEqual(c.status, "FAIL")
        self.assertIn("Pending", " ".join(c.findings))

    def test_adequate_environment_passes(self):
        snap = {"limitranges": [], "nodes": [node("n1", alloc_mem="7Gi")]}
        c = pf.check_shm(snap, [self.bot()])
        self.assertEqual(c.status, "PASS")


class Quantities(unittest.TestCase):
    def test_parse_memory(self):
        self.assertEqual(pf.parse_memory("64Mi"), 64 * 1024**2)
        self.assertEqual(pf.parse_memory("2Gi"), 2 * 1024**3)
        self.assertEqual(pf.parse_memory("1500M"), 1_500_000_000)

    def test_parse_cpu(self):
        self.assertEqual(pf.parse_cpu("500m"), 500)
        self.assertEqual(pf.parse_cpu("2"), 2000)


class WorkloadExtraction(unittest.TestCase):
    def test_cronjob_and_deployment_and_shm(self):
        objs = [
            {"kind": "Deployment", "metadata": {"name": "g"},
             "spec": {"template": {"spec": {"containers": [{"name": "c", "resources": {}}],
                                           "volumes": [{"name": "shm", "emptyDir": {"medium": "Memory", "sizeLimit": "2Gi"}}]}}}},
            {"kind": "CronJob", "metadata": {"name": "backup"},
             "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "b"}]}}}}}},
        ]
        ws = pf.extract_workloads(objs)
        self.assertEqual({w["name"] for w in ws}, {"g", "backup"})
        self.assertEqual(ws[0]["shm_bytes"], 2 * 1024**3)


if __name__ == "__main__":
    unittest.main()
