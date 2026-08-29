# SPDX-License-Identifier: Apache-2.0
"""The PreSync verify gate rides EVERY chart the publisher ships.

Until 2026-08-25 only the OSS path (`vexa-channel chart`) injected
kit/verify/chart-template/channel-verify.yaml. An estate published through
`platform-chart` therefore reached a subscriber's Argo CD with no PreSync
verification at all: signature, contract, revocation list and human approval
were checked by nothing, because the object that checks them was never in the
chart. Nothing failed — the estate simply synced.

These tests render the template with helm and assert three things that were
each a live defect:

  * INERT BY DEFAULT — verify.enabled false renders zero objects, so adding
    the template to an existing estate chart is a no-op in the render diff.
    Without this the seq-3 diff could not have been read.
  * THE ENTRY REF IS RIGHT FOR AN ESTATE — the derivation `v<appVersion>` is
    correct only for an OSS release. An estate's chart appVersion is
    `0.12.23-estate` while its entry tag is `0.12.23-estate-20260825`, so the
    derived ref asks for a tag that does not exist and every sync fails on a
    404 that says nothing about the evidence. verify.entryTag overrides it.
  * THE VERIFIER'S INPUTS ARE CHART-MANAGED — the contract ConfigMap and the
    pinned channel key were kubectl-created during the prod ceremony and owned
    by nobody. They now render from the chart, as PreSync hooks at wave -1 so
    they exist before the wave-0 Job that mounts them.
"""
import hashlib
import pathlib
import shutil
import subprocess
import tempfile
import unittest

import yaml

REPO = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "kit/verify/chart-template/channel-verify.yaml"

BASE_VALUES = {
    "verify": {
        "enabled": False,
        "registry": "registry.invalid",
        "channel": "fixture-estate",
        "image": "registry.invalid/tools/verifier@sha256:" + "c" * 64,
        "contractConfigMap": "vexa-contract-prod",
        "registrySecret": "",
        "deadlineSeconds": 300,
        "requireApproval": "",
        "approvalNamespace": "argocd",
        "insecure": False,
        "entryTag": "",
        "contractPolicy": "",
        "channelPublicKey": "",
        "tolerations": [],
        "nodeSelector": {},
        # Mirrors the publisher default: ON. See the egress tests below.
        "networkPolicy": True,
        "egressCIDR": "0.0.0.0/0",
    },
    "global": {"imagePullSecrets": []},
}

# The real prod placement, verbatim: LKE 590708 has one node pool and it is
# tainted. Kept as a fixture constant so the test reads as the incident.
PROD_TOLERATION = {"key": "vexa.ai/pool", "operator": "Equal",
                   "value": "main", "effect": "NoSchedule"}


def have_helm():
    return shutil.which("helm") is not None


def render(values, app_version="0.12.23-estate", namespace="vexa-production"):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="verify-gate-"))
    try:
        chart = tmp / "fixture"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text(yaml.safe_dump({
            "apiVersion": "v2", "name": "fixture",
            "version": "0.1.0-estate.20260825.rev139", "appVersion": app_version,
        }))
        (chart / "values.yaml").write_text(yaml.safe_dump(values, sort_keys=False))
        shutil.copy(TEMPLATE, chart / "templates/channel-verify.yaml")
        out = subprocess.run(
            ["helm", "template", "fixture", str(chart), "-n", namespace],
            capture_output=True, text=True)
        if out.returncode != 0:
            raise AssertionError(out.stderr[-2000:])
        return [d for d in yaml.safe_load_all(out.stdout) if d]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def deep(values, **verify):
    import copy
    v = copy.deepcopy(values)
    v["verify"].update(verify)
    return v


@unittest.skipUnless(have_helm(), "helm not installed")
class VerifyGateRender(unittest.TestCase):

    def test_disabled_renders_nothing(self):
        """The whole reason adding this to a live estate chart is safe."""
        self.assertEqual(render(BASE_VALUES), [])

    def test_enabled_renders_the_presync_job(self):
        docs = render(deep(BASE_VALUES, enabled=True))
        kinds = sorted(d["kind"] for d in docs)
        # The Role/RoleBinding pair is the verdict RECORD's, in the release
        # namespace, and it renders whenever the gate does (2026-08-29): the
        # gate ran in prod for four consecutive nights and every station report
        # read `verifier.verdict: ABSENT`, because nothing wrote the verdict
        # down. The approvals Role is a different pair and still renders only
        # under verify.requireApproval.
        self.assertEqual(kinds, ["Job", "NetworkPolicy", "Role", "RoleBinding",
                                 "ServiceAccount"])
        job = next(d for d in docs if d["kind"] == "Job")
        self.assertEqual(job["metadata"]["annotations"]["argocd.argoproj.io/hook"], "PreSync")
        role = next(d for d in docs if d["kind"] == "Role")
        self.assertEqual(role["metadata"]["namespace"], "vexa-production")
        self.assertTrue(role["metadata"]["name"].startswith("vexa-verify-verdict-"))

    def test_the_verdict_record_can_be_turned_off(self):
        """The escape hatch, for a subscriber whose Argo may not create a Role
        in the workload namespace. Off, the render is the pre-2026-08-29 one.
        Full behavioural coverage: kit/verify/tests/test_verdict_wiring.sh."""
        docs = render(deep(BASE_VALUES, enabled=True, recordVerdict=False))
        self.assertEqual(sorted(d["kind"] for d in docs),
                         ["Job", "NetworkPolicy", "ServiceAccount"])
        c = next(d for d in docs
                 if d["kind"] == "Job")["spec"]["template"]["spec"]["containers"][0]
        self.assertNotIn("command", c)
        self.assertNotIn("--verdict-out", c["args"])

    # ------------------------------------------------------------------ egress
    # PROD, seq 4, 2026-08-25. The pod scheduled and the verifier started; its
    # first act — `oras pull` of the entry — was blocked by the namespace's
    # default-deny NetworkPolicy, because a PreSync hook is in no workload's
    # enumerated egress policy. The container image had pulled fine, which is
    # the confusing part: the kubelet pulls from the NODE's network namespace,
    # where NetworkPolicy does not apply.

    def test_the_verify_pod_carries_a_label_a_policy_can_name(self):
        """Selecting on the controller's generated `job-name` would make our
        policy depend on a label somebody else owns."""
        job = next(d for d in render(deep(BASE_VALUES, enabled=True)) if d["kind"] == "Job")
        self.assertEqual(
            job["spec"]["template"]["metadata"]["labels"],
            {"app.kubernetes.io/name": "vexa-verify"})

    def test_the_egress_policy_selects_the_verify_pod_and_opens_dns_and_443(self):
        np = next(d for d in render(deep(BASE_VALUES, enabled=True))
                  if d["kind"] == "NetworkPolicy")
        self.assertEqual(np["metadata"]["name"], "vexa-verify-egress")
        self.assertEqual(np["spec"]["podSelector"]["matchLabels"],
                         {"app.kubernetes.io/name": "vexa-verify"})
        self.assertEqual(np["spec"]["policyTypes"], ["Egress"])
        dns, https = np["spec"]["egress"]
        # DNS first: resolution happens before any connection, and a policy
        # that opens 443 and forgets 53 blocks everything while looking right.
        self.assertEqual(sorted((p["protocol"], p["port"]) for p in dns["ports"]),
                         [("TCP", 53), ("UDP", 53)])
        self.assertNotIn("to", dns)
        self.assertEqual(https["ports"], [{"protocol": "TCP", "port": 443}])
        self.assertEqual(https["to"], [{"ipBlock": {"cidr": "0.0.0.0/0"}}])

    def test_the_egress_cidr_is_a_value(self):
        """The registry host is one address today. Hard-coding it here would
        put a subscriber's registry inside our template."""
        np = next(d for d in render(deep(BASE_VALUES, enabled=True,
                                         egressCIDR="139.162.0.0/16"))
                  if d["kind"] == "NetworkPolicy")
        self.assertEqual(np["spec"]["egress"][1]["to"],
                         [{"ipBlock": {"cidr": "139.162.0.0/16"}}])

    def test_the_policy_exists_before_the_job_and_survives_the_run(self):
        """Wave -1 like the contract and the key, so it is applied before the
        wave-0 Job. BeforeHookCreation and NOT a bare absence: the policy must
        be gone before the NEXT run recreates it, but present for this one."""
        np = next(d for d in render(deep(BASE_VALUES, enabled=True))
                  if d["kind"] == "NetworkPolicy")
        ann = np["metadata"]["annotations"]
        self.assertEqual(ann["argocd.argoproj.io/hook"], "PreSync")
        self.assertEqual(ann["argocd.argoproj.io/sync-wave"], "-1")
        self.assertEqual(ann["argocd.argoproj.io/hook-delete-policy"], "BeforeHookCreation")
        self.assertEqual(ann["helm.sh/hook-delete-policy"], "before-hook-creation")

    def test_the_policy_can_be_turned_off(self):
        """A subscriber whose registry is not on 443, or who writes their own
        egress policy for this pod, declares that — and still gets the gate."""
        docs = render(deep(BASE_VALUES, enabled=True, networkPolicy=False))
        self.assertEqual([d for d in docs if d["kind"] == "NetworkPolicy"], [])
        self.assertTrue([d for d in docs if d["kind"] == "Job"])

    def test_entry_ref_derivation_is_wrong_for_an_estate_without_entry_tag(self):
        """Not a bug being asserted as correct — a documented sharp edge.

        The derivation is right for an OSS release and wrong for an estate,
        which is exactly why entryTag exists. Pinning it here means a future
        change to the derivation cannot quietly stop honouring the override.
        """
        job = next(d for d in render(deep(BASE_VALUES, enabled=True)) if d["kind"] == "Job")
        args = job["spec"]["template"]["spec"]["containers"][0]["args"]
        ref = args[args.index("--entry-ref") + 1]
        self.assertEqual(ref, "registry.invalid/vexa/channel/fixture-estate:v0.12.23-estate")

    def test_entry_tag_overrides_the_derivation(self):
        job = next(d for d in render(
            deep(BASE_VALUES, enabled=True, entryTag="0.12.23-estate-20260825")
        ) if d["kind"] == "Job")
        args = job["spec"]["template"]["spec"]["containers"][0]["args"]
        ref = args[args.index("--entry-ref") + 1]
        self.assertEqual(
            ref, "registry.invalid/vexa/channel/fixture-estate:0.12.23-estate-20260825")

    def test_contract_and_key_render_into_the_release_namespace(self):
        docs = render(deep(
            BASE_VALUES, enabled=True,
            contractPolicy='{"contract_id": "fixture-estate-2026-08"}',
            channelPublicKey="-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        ))
        cm = next(d for d in docs if d["kind"] == "ConfigMap")
        sec = next(d for d in docs if d["kind"] == "Secret")
        self.assertEqual(cm["metadata"]["name"], "vexa-contract-prod")
        self.assertEqual(cm["metadata"]["namespace"], "vexa-production")
        self.assertEqual(sec["metadata"]["name"], "vexa-channel-pubkey")
        self.assertEqual(sec["metadata"]["namespace"], "vexa-production")
        # The Job mounts /contract/contract.json — one filename, one carrier.
        self.assertIn("contract.json", cm["data"])
        self.assertIn("channel.pub", sec["stringData"])

    def test_the_contract_configmap_carries_the_records_exact_bytes(self):
        """THE SEQ-6 DEFECT, AND IT COST A WHOLE STATION RUN (2026-08-29).

        This ConfigMap rendered as `contract.json: |-`, and `|-` strips the
        trailing newline from what it carries. The gate's wrapper hashes the
        MOUNTED COPY, so the verdict recorded in-cluster named

            contract_sha256: 355eddae4f036662b10d62834150c762ca5540b3df66da…

        for a contract whose own bytes — in the stations ledger, in this
        chart's baked verify.contractPolicy, and in every verdict rendered by
        reading the file directly — hash to

            a76cef3c62c21d0ee01984fcf5a511b4040f49b5a03dca248148705cdf479551

        differing by the single `0a` the template dropped. A verdict that names
        a contract hash matching no record cannot be audited, which is what the
        stations ledger README means by "every historical gate report would
        start pointing at a hash nothing matches".

        Asserted as a HASH and not only as equality, because the hash is the
        thing a verdict actually carries."""
        for label, policy in (
            ("one newline", '{"contract_id": "fixture-estate-2026-09"}\n'),
            ("no newline", '{"contract_id": "fixture-estate-2026-09"}'),
            ("two newlines", '{"contract_id": "fixture-estate-2026-09"}\n\n'),
            ("blank line inside", '{\n\n  "contract_id": "x"\n}\n'),
        ):
            with self.subTest(label):
                docs = render(deep(BASE_VALUES, enabled=True, contractPolicy=policy))
                cm = next(d for d in docs if d["kind"] == "ConfigMap")
                rendered = cm["data"]["contract.json"]
                self.assertEqual(rendered, policy, label)
                self.assertEqual(
                    hashlib.sha256(rendered.encode()).hexdigest(),
                    hashlib.sha256(policy.encode()).hexdigest(),
                    f"{label}: the mounted contract does not hash to the record, "
                    f"so every verdict rendered against it names a hash nothing matches")

    def test_contract_and_key_land_before_the_job(self):
        """A plain resource is applied in the Sync phase, i.e. AFTER PreSync —
        it would arrive too late for the Job that mounts it. Both must be
        PreSync hooks at a lower wave than the Job, and must NOT carry a
        delete policy, or they vanish between syncs."""
        docs = render(deep(
            BASE_VALUES, enabled=True,
            contractPolicy='{"contract_id": "x"}',
            channelPublicKey="k",
        ))
        for kind in ("ConfigMap", "Secret"):
            ann = next(d for d in docs if d["kind"] == kind)["metadata"]["annotations"]
            self.assertEqual(ann["argocd.argoproj.io/hook"], "PreSync", kind)
            self.assertEqual(ann["argocd.argoproj.io/sync-wave"], "-1", kind)
            self.assertNotIn("argocd.argoproj.io/hook-delete-policy", ann, kind)
        job = next(d for d in docs if d["kind"] == "Job")
        self.assertNotIn("argocd.argoproj.io/sync-wave", job["metadata"]["annotations"])

    def test_it_renders_in_a_chart_with_no_top_level_global(self):
        """Caught building the seq-3 candidate, 2026-08-25.

        The OSS chart always defines a top-level `global`; the platform ESTATE
        chart does not. A bare `.Values.global.imagePullSecrets` on nil is a
        TEMPLATE ERROR rather than an empty value, so injecting this template
        into an estate chart failed the render outright. The only good thing
        about that defect is that it failed loudly — a chart that cannot render
        cannot be packaged."""
        values = {k: v for k, v in BASE_VALUES.items() if k != "global"}
        values["verify"] = dict(BASE_VALUES["verify"], enabled=True)
        docs = render(values)
        job = next(d for d in docs if d["kind"] == "Job")
        self.assertNotIn("imagePullSecrets", job["spec"]["template"]["spec"])

    def test_a_registry_secret_alone_still_produces_a_pull_secret(self):
        values = {k: v for k, v in BASE_VALUES.items() if k != "global"}
        values["verify"] = dict(BASE_VALUES["verify"], enabled=True,
                                registrySecret="vexa-channel-registry")
        job = next(d for d in render(values) if d["kind"] == "Job")
        self.assertEqual(job["spec"]["template"]["spec"]["imagePullSecrets"],
                         [{"name": "vexa-channel-registry"}])

    def test_placement_defaults_are_absent_not_empty(self):
        """The no-op half. An estate that asks for no placement must render a
        pod spec with NO nodeSelector and NO tolerations keys at all — not
        empty ones — or every existing subscriber's render diff moves the day
        this ships, and a diff nobody can read is a diff nobody checks."""
        job = next(d for d in render(deep(BASE_VALUES, enabled=True)) if d["kind"] == "Job")
        spec = job["spec"]["template"]["spec"]
        self.assertNotIn("nodeSelector", spec)
        self.assertNotIn("tolerations", spec)

    def test_placement_values_reach_the_pod_spec(self):
        """PROD, 2026-08-25. The single node pool is tainted
        vexa.ai/pool=main:NoSchedule; the Job rendered no toleration, so the
        pod never scheduled (FailedScheduling "untolerated taint",
        NotTriggerScaleUp), activeDeadlineSeconds fired at 300s, the Job went
        DeadlineExceeded and the sync failed closed. Nothing was verified and
        the failure named the deadline rather than the taint."""
        job = next(d for d in render(deep(
            BASE_VALUES, enabled=True,
            tolerations=[PROD_TOLERATION],
            nodeSelector={"vexa.ai/pool": "main"},
        )) if d["kind"] == "Job")
        spec = job["spec"]["template"]["spec"]
        self.assertEqual(spec["tolerations"], [PROD_TOLERATION])
        self.assertEqual(spec["nodeSelector"], {"vexa.ai/pool": "main"})

    def test_a_gate_that_cannot_start_fails_once_and_on_a_clock(self):
        """The two fields that turned an unschedulable pod into a visible
        failed sync instead of an Argo hook that waits forever.

        backoffLimit 0: a failed verification is a verdict, not a flake, and a
        retrying Job would re-run the gate against the same evidence forever.
        activeDeadlineSeconds: with backoffLimit 0 a pod that never terminates
        (ImagePullBackOff, or Pending on a taint) means the Job never fails,
        so Argo waits on the hook with no self-recovery. Both are asserted
        because losing either one silently restores a deadlock."""
        job = next(d for d in render(deep(BASE_VALUES, enabled=True)) if d["kind"] == "Job")
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 300)
        self.assertEqual(
            next(d for d in render(deep(BASE_VALUES, enabled=True, deadlineSeconds=600))
                 if d["kind"] == "Job")["spec"]["activeDeadlineSeconds"], 600)

    def test_absent_content_leaves_the_objects_to_an_external_owner(self):
        """Empty is a legitimate choice — a subscriber may keep the contract in
        their own GitOps repo. What is not legitimate is the accidental version
        of it, where nobody owns them at all."""
        docs = render(deep(BASE_VALUES, enabled=True))
        self.assertEqual([d for d in docs if d["kind"] in ("ConfigMap", "Secret")], [])


class VerifyGateInjection(unittest.TestCase):
    """The publisher-side half: every packaging path must inject the template."""

    def test_defaults_cover_every_value_the_template_reads(self):
        import sys
        sys.path.insert(0, str(REPO / "publisher"))
        import vexa_channel

        text = TEMPLATE.read_text()
        for key in vexa_channel.VERIFY_DEFAULTS:
            self.assertIn(f".Values.verify.{key}", text,
                          f"VERIFY_DEFAULTS carries '{key}' that the template never reads")
        # ...and the reverse: a value the template reads with no default is an
        # "unbound variable" at render time on somebody else's cluster.
        import re
        for key in sorted(set(re.findall(r"\.Values\.verify\.([A-Za-z]+)", text))):
            self.assertIn(key, vexa_channel.VERIFY_DEFAULTS,
                          f"template reads verify.{key} which has no publisher default")

    def test_a_new_default_reaches_a_chart_that_already_declares_verify(self):
        """The estate publishes its own `verify:` block — entry tag, pull
        secret, placement. `values.setdefault("verify", DEFAULTS)` meant that
        block REPLACED the defaults instead of overriding them, so every
        default added after that file was written silently never arrived.

        Caught adding verify.networkPolicy: the egress fix would have rendered
        nothing on the one cluster it was written for, and said nothing."""
        import sys
        import tempfile
        sys.path.insert(0, str(REPO / "publisher"))
        import vexa_channel

        chart = pathlib.Path(tempfile.mkdtemp(prefix="verify-inject-"))
        (chart / "templates").mkdir()
        try:
            values = {"verify": {"enabled": True, "entryTag": "0.12.23-estate-20260825"}}
            vexa_channel.inject_channel_verify(chart, values)
            self.assertTrue(values["verify"]["networkPolicy"],
                            "a default added later must still reach this chart")
            # ...and the operator's own keys are untouched.
            self.assertEqual(values["verify"]["entryTag"], "0.12.23-estate-20260825")
            self.assertIs(values["verify"]["enabled"], True)
        finally:
            shutil.rmtree(chart, ignore_errors=True)

    def test_injection_is_a_single_shared_function(self):
        src = (REPO / "publisher/vexa_channel.py").read_text()
        # One writer of templates/channel-verify.yaml. Three call sites.
        self.assertEqual(src.count('templates/channel-verify.yaml'), 1)
        self.assertEqual(src.count("inject_channel_verify("), 4)  # def + 3 calls


if __name__ == "__main__":
    unittest.main()
