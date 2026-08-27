# SPDX-License-Identifier: Apache-2.0
"""The station chart's receipt sender: what renders, and what refuses to.

The load-bearing assertion is the negative one. A timer that reports back from
inside a customer's cluster is exactly the object their security review exists
to find, and the claim we make about it — that it is authorised by their own
contract and not by our values file — is only worth something if a contract
that has not authorised it produces no CronJob at all.
"""
import pathlib
import re
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
ON = BASE + [
    "--set", "receiptSender.enabled=true",
    "--set", "receiptSender.station=vexa-prod",
    "--set", "receiptSender.image=reg.invalid/tools/kit@sha256:" + "b" * 64,
    "--set", "receiptSender.contractConfigMap=vexa-station-contract",
    "--set", "receiptSender.app=vexa-prod",
]


def render(extra=()):
    out = subprocess.run(["helm", "template", "st", str(CHART), *extra],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(out.stderr[-2000:])
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def render_error(extra=()):
    """The stderr of a render that must NOT succeed."""
    out = subprocess.run(["helm", "template", "st", str(CHART), *extra],
                         capture_output=True, text=True)
    if out.returncode == 0:
        raise AssertionError("expected the render to be refused, it succeeded")
    return out.stderr


def named(docs, kind, name):
    return [d for d in docs
            if d.get("kind") == kind and (d.get("metadata") or {}).get("name") == name]


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class ReceiptSenderRender(unittest.TestCase):

    def test_off_by_default(self):
        docs = render(BASE)
        self.assertEqual([d for d in docs if "receipt" in str(
            (d.get("metadata") or {}).get("name", ""))], [])

    def test_explicit_command_only_renders_no_cronjob(self):
        """THE ONE THAT MATTERS. A contract that has not authorised a timer
        must not get one, and `enabled: true` is not that authorisation —
        report_scope.trigger is, mirrored here."""
        docs = render(ON)
        self.assertEqual(named(docs, "CronJob", "vexa-receipt-sender"), [])
        self.assertTrue(named(docs, "Job", "vexa-receipt-postsync"),
                        "the per-release receipt is not a timer and should still render")

    def test_scheduled_renders_the_cronjob(self):
        docs = render(ON + ["--set", "receiptSender.trigger=scheduled"])
        cj = named(docs, "CronJob", "vexa-receipt-sender")
        self.assertEqual(len(cj), 1)
        self.assertEqual(cj[0]["spec"]["concurrencyPolicy"], "Forbid")
        self.assertEqual(cj[0]["spec"]["startingDeadlineSeconds"], 3600)

    def test_the_rbac_is_read_only_and_touches_no_secret(self):
        """A customer auditing this Role should conclude in one pass that the
        sender cannot read a workload's data, because it holds no permission
        that would let it."""
        role = named(render(ON), "Role", "vexa-receipt-sender")[0]
        verbs, resources = set(), set()
        for rule in role["rules"]:
            verbs |= set(rule["verbs"])
            resources |= set(rule["resources"])
        self.assertTrue(verbs <= {"get", "list"}, verbs)
        self.assertNotIn("secrets", resources)
        self.assertNotIn("pods/exec", resources)
        self.assertNotIn("pods/log", resources)
        # configmap read is resourceName-scoped to the verdict object alone
        cm_rule = next(r for r in role["rules"] if "configmaps" in r["resources"])
        self.assertEqual(cm_rule["resourceNames"], ["vexa-verify-verdict"])

    def test_no_tier_is_settable_from_values(self):
        """The rung has ONE authority — report_scope.tier in the station's own
        contract. A tier in a values file would be a second authority that
        could disagree with the first, silently."""
        text = (CHART / "values.yaml").read_text()
        sender = text.split("receiptSender:", 1)[1].split("\nfloor:", 1)[0]
        # KEYS, not prose. The comments in this block EXPLAIN why no tier lives
        # here, so a search over the raw text finds the word in its own
        # explanation and fails on the documentation of the rule it enforces.
        keys = "\n".join(l for l in sender.splitlines()
                         if l.strip() and not l.lstrip().startswith("#"))
        self.assertNotIn("tier", keys)
        for f in (CHART / "templates").glob("*receipt-sender*"):
            self.assertNotIn(".Values.receiptSender.tier", f.read_text())

    def test_the_credential_comes_from_the_environment_never_argv(self):
        """A password on a command line lands in every process listing on the
        node and in the pod's own spec, which anyone with pod read can see."""
        for kind, name, path in (("Job", "vexa-receipt-postsync", ("spec",)),
                                 ("CronJob", "vexa-receipt-sender",
                                  ("spec", "jobTemplate", "spec"))):
            docs = render(ON + ["--set", "receiptSender.trigger=scheduled"])
            obj = named(docs, kind, name)[0]
            for key in path:
                obj = obj[key]
            c = obj["template"]["spec"]["containers"][0]
            env = {e["name"]: e for e in c["env"]}
            for var in ("VEXA_CHANNEL_USER", "VEXA_CHANNEL_PASS"):
                self.assertIn("secretKeyRef", env[var]["valueFrom"], f"{kind} {var}")
                self.assertNotIn("value", env[var], f"{kind} {var}")
            self.assertNotIn("PASS", " ".join(c["args"]))

    def test_both_shapes_share_one_pod_spec(self):
        """Two copies of a pod spec is two RBAC postures, two credential mounts
        and two security contexts that drift apart silently — and the one that
        drifts is always the one nobody looks at."""
        docs = render(ON + ["--set", "receiptSender.trigger=scheduled"])
        job = named(docs, "Job", "vexa-receipt-postsync")[0]["spec"]["template"]["spec"]
        cron = (named(docs, "CronJob", "vexa-receipt-sender")[0]
                ["spec"]["jobTemplate"]["spec"]["template"]["spec"])
        self.assertEqual(job, cron)

    def test_the_container_is_locked_down(self):
        job = named(render(ON), "Job", "vexa-receipt-postsync")[0]
        sc = job["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        self.assertTrue(sc["runAsNonRoot"])
        self.assertTrue(sc["readOnlyRootFilesystem"])
        self.assertFalse(sc["allowPrivilegeEscalation"])
        self.assertEqual(sc["capabilities"]["drop"], ["ALL"])

    # ------------------------------------------------------------------ egress
    # AUDITED AFTER THE VERIFY GATE HIT THE SAME WALL (prod, 2026-08-25, seq 4).
    # `vexa-production` denies egress by default and enumerates one policy per
    # WORKLOAD; a hook Job is in nobody's enumeration, so the PreSync verifier
    # could not pull the entry. This sender is a Job and a CronJob in that same
    # namespace whose whole purpose is outbound HTTPS — it would have failed
    # identically, on install, on its first receipt.

    def test_the_sender_ships_its_own_egress_policy(self):
        np = named(render(ON), "NetworkPolicy", "vexa-receipt-sender-egress")
        self.assertEqual(len(np), 1)
        spec = np[0]["spec"]
        self.assertEqual(spec["podSelector"]["matchLabels"],
                         {"app.kubernetes.io/name": "vexa-receipt-sender"})
        self.assertEqual(spec["policyTypes"], ["Egress"])
        dns, https = spec["egress"]
        self.assertEqual(sorted((p["protocol"], p["port"]) for p in dns["ports"]),
                         [("TCP", 53), ("UDP", 53)])
        self.assertEqual(https["ports"], [{"protocol": "TCP", "port": 443}])
        self.assertEqual(https["to"], [{"ipBlock": {"cidr": "0.0.0.0/0"}}])

    def test_the_policy_selector_matches_what_both_pod_shapes_carry(self):
        """A selector that names a label the pods do not carry is a policy that
        silently protects nothing — and the pods still cannot talk."""
        docs = render(ON + ["--set", "receiptSender.trigger=scheduled"])
        sel = named(docs, "NetworkPolicy", "vexa-receipt-sender-egress")[0][
            "spec"]["podSelector"]["matchLabels"]
        job = named(docs, "Job", "vexa-receipt-postsync")[0][
            "spec"]["template"]["metadata"]["labels"]
        cron = named(docs, "CronJob", "vexa-receipt-sender")[0]["spec"][
            "jobTemplate"]["spec"]["template"]["metadata"]["labels"]
        for labels in (job, cron):
            self.assertLessEqual(set(sel.items()), set(labels.items()))

    def test_the_policy_lands_in_the_station_namespace(self):
        np = named(render(ON + ["--set", "prodNamespace=vexa-production"]),
                   "NetworkPolicy", "vexa-receipt-sender-egress")[0]
        self.assertEqual(np["metadata"]["namespace"], "vexa-production")

    def test_the_policy_can_be_turned_off(self):
        docs = render(ON + ["--set", "receiptSender.networkPolicy=false"])
        self.assertEqual(named(docs, "NetworkPolicy", "vexa-receipt-sender-egress"), [])
        self.assertTrue(named(docs, "Job", "vexa-receipt-postsync"))

    def test_the_contract_is_mounted_as_a_file_the_tool_reads(self):
        job = named(render(ON), "Job", "vexa-receipt-postsync")[0]
        spec = job["spec"]["template"]["spec"]
        vol = next(v for v in spec["volumes"] if v["name"] == "contract")
        self.assertEqual(vol["configMap"]["name"], "vexa-station-contract")
        args = " ".join(spec["containers"][0]["args"])
        self.assertIn("--contract /contract/contract.yaml", args)
        self.assertIn("--report", args)

    # ------------------------------------------------- the contract mismatch
    # FIXED IN 1.0.6. The sender passes `--contract /contract/contract.yaml`
    # and the tool reads `report_scope` off it — the station's own REPORT
    # contract. `templates/contracts.yaml` renders a DIFFERENT document
    # (publication mode, evidence kinds, attestations) under the key
    # `policy.json`, into the ARGOCD namespace, for the PreSync verify gate.
    # The default `contractConfigMap` named one of those, so the mount asked a
    # gate policy in another namespace for a key it does not have. Same word,
    # two documents, two readers — and nothing would have said so until the
    # first receipt failed in production.

    def test_the_mount_names_the_key_it_needs(self):
        """`items` is the difference between a kubelet that refuses to start
        the pod and names the missing key, and a pod that starts happily and
        fails deep inside the tool on a file that is not there."""
        spec = named(render(ON), "Job", "vexa-receipt-postsync")[0][
            "spec"]["template"]["spec"]
        vol = next(v for v in spec["volumes"] if v["name"] == "contract")
        self.assertEqual(vol["configMap"]["items"],
                         [{"key": "contract.yaml", "path": "contract.yaml"}])
        mount = next(m for m in spec["containers"][0]["volumeMounts"]
                     if m["name"] == "contract")
        self.assertEqual(mount["mountPath"], "/contract")
        self.assertTrue(mount["readOnly"])

    def test_the_report_contract_is_referenced_never_rendered(self):
        """Contracts are customer-owned. A `report_scope` this chart authored
        would make Vexa the author of the document that bounds Vexa, and the
        tier would have two authorities that could disagree silently."""
        docs = render(ON)
        for cm in [d for d in docs if d.get("kind") == "ConfigMap"]:
            self.assertNotIn("report_scope", str(cm.get("data") or {}),
                             f"{cm['metadata']['name']} authors a report contract")
        for f in (CHART / "templates").glob("*"):
            # The templates' commentary explains the rule; strip Helm comment
            # blocks so the assertion reads the TEMPLATE and not its prose.
            body = re.sub(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", "", f.read_text(), flags=re.S)
            body = "\n".join(l for l in body.splitlines()
                             if not l.lstrip().startswith("#"))
            self.assertNotIn("report_scope", body, f.name)

    def test_the_sender_contract_is_not_the_argocd_gate_contract(self):
        """The two must not be able to collide by default: no value points the
        sender at a ConfigMap this chart renders for the verify gate."""
        rendered = {(d["metadata"]["name"], d["metadata"].get("namespace"))
                    for d in render(ON) if d.get("kind") == "ConfigMap"}
        spec = named(render(ON), "Job", "vexa-receipt-postsync")[0][
            "spec"]["template"]["spec"]
        vol = next(v for v in spec["volumes"] if v["name"] == "contract")
        name = vol["configMap"]["name"]
        self.assertNotIn((name, "argocd"), rendered)
        # ...and the chart ships no default at all: an operator must name their
        # own object, in their own namespace, holding their own declaration.
        values = yaml.safe_load((CHART / "values.yaml").read_text())
        self.assertEqual(values["receiptSender"]["contractConfigMap"], "")

    # ------------------------------------------- refusals at render, not run

    def test_the_three_required_values_are_refused_empty(self):
        """Each of these fails silently-then-late: `image: ""` renders a pod
        the API server accepts and the kubelet cannot pull; an empty station
        submits to `/v2/vexa/stations//bundles` and reads back as a bad
        credential; an empty contract ConfigMap surfaces three layers away as a
        missing report_scope. The sentence belongs at `helm template` time."""
        for key in ("image", "station", "contractConfigMap"):
            with self.subTest(key):
                pruned = []
                for arg in ON:
                    if arg.startswith(f"receiptSender.{key}="):
                        pruned.pop()          # ...and the "--set" before it
                        continue
                    pruned.append(arg)
                err = render_error(pruned)
                self.assertIn(f"receiptSender.{key} is empty", err)

    def test_nothing_is_required_while_the_sender_is_off(self):
        """The refusals are scoped to `enabled: true`. A station that never
        turns the sender on renders with no sender values at all."""
        self.assertTrue(render(BASE))


if __name__ == "__main__":
    unittest.main()
