#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-preflight — cluster conformance preflight for a private channel.

Answers, BEFORE first sync and on every upgrade, in plain language: will this
cluster run what the channel delivers? Every check is anchored to a failure
observed in the field — clusters carry taints, LimitRanges and admission
policies we do not control, and the first sync is the wrong moment to learn
that.

Checks
  P1 taints-tolerations   every delivered workload can schedule on ≥1 node
                          (anchor: addon pods stranded 6h by a cluster-wide
                          custom taint; Argo's own pods Pending on tainted
                          nodes)
  P2 limitranges          every container declares requests+limits, and the
                          declared values fit the namespace LimitRange
                          (anchor: a LimitRange squeezed undeclared bot pods to
                          64Mi; sizing env vars were dead code for a month)
  P3 resourcequota        quota headroom covers the declared sums
  P4 pod-security         OpenShift SCC restricted-v2: explicit UIDs/fsGroups
                          outside the namespace range are REJECTED (mutation
                          fixes the rest); PSA restricted: runAsNonRoot,
                          seccomp, drop-ALL required (anchor: an OpenShift
                          readiness review — the hardened workloads are exactly
                          the SCC-rejected ones)
  P5 networkpolicy        default-deny detection, DNS egress, registry
                          reachability (static + optional live probe)
  P6 shm                  the bot's 2Gi Memory-medium /dev/shm counts against
                          its memory limit; LimitRange max and node allocatable
                          must fit it (anchor: 2Gi shm against a 2560Mi limit is
                          production's actual configuration)
  P7 image-pull           the cluster can actually pull a release image by
                          digest with the namespace's pull secrets (anchor:
                          images "pulled" only because nodes had them cached;
                          a real install fails here)
  P8 storage              a default StorageClass exists if the manifests carry
                          PVCs
  P9 kubernetes version   sanity floor

EIGHT of those nine run by default: P1-P6, P8, P9. The two LIVE probes are
opt-in because they create a pod in your cluster — the live half of P5 needs
--live-probes --registry-host, and P7 needs --live-probes --pull-test-image.
P7 also needs the namespace's image-pull Secret to exist already, which an
install writes; run it AFTER the install, not as the before-anything check.

Modes
  live (default)          reads the cluster via kubectl; --live-probes adds
                          the in-cluster probe pods (P5 live, P7)
  --snapshot FILE         air-gapped: read a snapshot produced by
                          --dump-snapshot on a connected workstation

Workloads under test come from --manifests (rendered YAML; converted via
`kubectl create --dry-run=client -o json`, so kubectl is the only dependency)
plus the built-in dynamic-bot profile (bots are spawned per meeting and never
appear in a chart render; sizes are the measured production values,
overridable).

Exit codes
  0  every check that ran passed (warnings included), and every check ran
  1  at least one FAIL — this is the fails-closed case
  2  usage error
  4  nothing failed AND at least one check was NOT EVALUATED (see below)

A READ THIS CREDENTIAL IS REFUSED IS NOT A FINDING. Every cluster-scoped read
is wrapped, and a check whose input could not be read reports UNKNOWN, naming
the read and the refusal — never a traceback, never a PASS, never a FAIL. A
namespace-scoped tenant cannot list nodes; saying so is the honest answer, and
`--dump-snapshot` as an admin then `--snapshot` as the tenant is the way to
turn an UNKNOWN into an answer.

WHICH IS WHY UNKNOWN HAS ITS OWN EXIT CODE. It used to share 0 with a clean
run, so a caller — a script, a CI job, `install.sh` — could not tell "your
cluster is fine" from "four of these were never looked at", and the second one
read as the first. 4 is not a failure and does not mean stop; it means the
answer is incomplete and says which parts. Callers that must not proceed on an
incomplete answer now have something to test.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

# The dynamic bot pod: spawned per meeting by the runtime, absent from every
# chart render. Sizes are production's measured values (prod p50 922Mi / max
# 1292Mi across 10 bots -> request 1Gi; limit 2560Mi; /dev/shm 2Gi
# Memory-medium emptyDir, which counts against the memory limit).
BOT_PROFILE = {
    "kind": "DynamicPod",
    "name": "vexa-bot (spawned per meeting; not in any render)",
    "containers": [
        {
            "name": "bot",
            "resources": {
                "requests": {"cpu": "500m", "memory": "1Gi"},
                "limits": {"cpu": "2", "memory": "2560Mi"},
            },
        }
    ],
    "shm_bytes": 2 * 1024**3,
    "tolerations": [],
    "pod_security_context": {},
    "host_flags": {},
    "volumes": [],
}

MIN_K8S_MINOR = 29


# ----------------------------------------------------------------- quantities


def parse_memory(q):
    if q is None:
        return None
    s = str(q)
    m = re.fullmatch(r"([0-9.]+)(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E|m)?", s)
    if not m:
        raise ValueError(f"unparseable quantity {q!r}")
    n = float(m.group(1))
    suf = m.group(2)
    mult = {
        None: 1, "m": 1e-3,
        "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4, "Pi": 1024**5, "Ei": 1024**6,
        "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
    }[suf]
    return int(n * mult)


def parse_cpu(q):
    if q is None:
        return None
    s = str(q)
    if s.endswith("m"):
        return int(float(s[:-1]))
    return int(float(s) * 1000)


def fmt_mem(b):
    for unit, size in (("Gi", 1024**3), ("Mi", 1024**2), ("Ki", 1024)):
        if b >= size:
            v = b / size
            return f"{v:.1f}{unit}" if v != int(v) else f"{int(v)}{unit}"
    return f"{b}"


# ---------------------------------------------------------------- tolerations


def toleration_matches(tol, taint):
    op = tol.get("operator", "Equal")
    if tol.get("key"):
        if tol["key"] != taint.get("key"):
            return False
        if op == "Equal" and tol.get("value", "") != taint.get("value", ""):
            return False
    else:
        if op != "Exists":
            return False
    t_eff = tol.get("effect", "")
    return t_eff in ("", taint.get("effect"))


def pod_schedulable_on(node, tolerations):
    blocking = []
    for taint in node.get("spec", {}).get("taints", []) or []:
        if taint.get("effect") not in ("NoSchedule", "NoExecute"):
            continue
        if not any(toleration_matches(t, taint) for t in tolerations):
            blocking.append(taint)
    return blocking


# ------------------------------------------------------------------ workloads

POD_CARRIERS = {
    "Deployment": ("spec", "template"),
    "StatefulSet": ("spec", "template"),
    "DaemonSet": ("spec", "template"),
    "Job": ("spec", "template"),
    "ReplicaSet": ("spec", "template"),
}


def extract_workloads(objects):
    """Flatten rendered objects into per-workload pod profiles."""
    out = []
    for obj in objects:
        kind = obj.get("kind")
        name = obj.get("metadata", {}).get("name", "?")
        if kind in POD_CARRIERS:
            tmpl = obj.get("spec", {}).get("template", {})
            out.append(workload_from_podspec(kind, name, tmpl.get("spec", {})))
        elif kind == "CronJob":
            tmpl = (
                obj.get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
            )
            out.append(workload_from_podspec(kind, name, tmpl.get("spec", {})))
        elif kind == "Pod":
            out.append(workload_from_podspec(kind, name, obj.get("spec", {})))
    return out


def workload_from_podspec(kind, name, spec):
    shm = 0
    for v in spec.get("volumes", []) or []:
        ed = v.get("emptyDir")
        if ed and ed.get("medium") == "Memory":
            shm = max(shm, parse_memory(ed.get("sizeLimit", "0")) or 0)
    return {
        "kind": kind,
        "name": name,
        "containers": [
            {
                "name": c.get("name", "?"),
                "resources": c.get("resources", {}) or {},
                "security_context": c.get("securityContext", {}) or {},
                "ports": c.get("ports", []) or [],
            }
            for c in (spec.get("containers", []) or [])
        ],
        "tolerations": spec.get("tolerations", []) or [],
        "pod_security_context": spec.get("securityContext", {}) or {},
        "host_flags": {
            k: bool(spec.get(k))
            for k in ("hostNetwork", "hostPID", "hostIPC")
            if spec.get(k)
        },
        "volumes": spec.get("volumes", []) or [],
        "shm_bytes": shm,
    }


# --------------------------------------------------------------------- report


class Check:
    def __init__(self, cid, title, anchor):
        self.cid, self.title, self.anchor = cid, title, anchor
        self.findings, self.status, self.remedy = [], "PASS", None

    def fail(self, msg, remedy=None):
        self.status = "FAIL"
        self.findings.append(msg)
        if remedy:
            self.remedy = remedy

    def warn(self, msg):
        if self.status == "PASS":
            self.status = "WARN"
        self.findings.append(msg)

    def unknown(self, msg, remedy=None):
        """The check could not be evaluated — say so, never guess.

        A read this credential is refused is NOT a finding about the cluster: a
        namespace-scoped tenant cannot list nodes, and reporting that as PASS
        claims something was verified, while reporting it as FAIL claims a
        defect that was never observed. Both are lies of a different sign, and
        the second is the one the field hit — `install.sh` printed
        `preflight FAILED` having checked nothing at all.

        UNKNOWN outranks PASS and WARN and never overrides a real FAIL: a check
        that found something AND could not finish still found something.
        """
        if self.status in ("PASS", "WARN"):
            self.status = "UNKNOWN"
        self.findings.append(msg)
        if remedy and not self.remedy:
            self.remedy = remedy

    def note(self, msg):
        self.findings.append(msg)

    def skip(self, msg):
        self.status = "SKIP"
        self.findings.append(msg)

    def as_dict(self):
        return {
            "id": self.cid,
            "title": self.title,
            "anchor": self.anchor,
            "status": self.status,
            "findings": self.findings,
            "remedy": self.remedy,
        }


# --------------------------------------------------------------------- checks


def refused(snapshot, key):
    """The reason `key` could not be read, or None if it could."""
    return (snapshot.get("unreadable") or {}).get(key)


def unknown_because(check, snapshot, key, what, remedy=None):
    """If `key` was refused, mark the check UNKNOWN and say so. Returns True.

    The sentence names the READ, not the cluster: "this could not be evaluated
    because that read was refused" is a different claim from "this cluster is
    fine" and from "this cluster is broken", and the caller must not be able to
    mistake it for either.
    """
    reason = refused(snapshot, key)
    if not reason:
        return False
    check.unknown(
        f"UNEVALUATED — {what} needs `{key}`, and that read was refused: {reason}. "
        f"This says nothing about the cluster; it says this credential cannot see it.",
        remedy=remedy or (
            "run it once with a credential that can read cluster scope and keep the result: "
            "`vexa_preflight.py --dump-snapshot snap.json` as an admin, then "
            "`--snapshot snap.json` with your own"),
    )
    return True


def check_taints(snapshot, workloads):
    c = Check("P1", "Every delivered workload can schedule despite node taints",
              "vexa-platform#337 (6h addon strand); argocd spike finding 5")
    if unknown_because(c, snapshot, "nodes", "scheduling against node taints"):
        return c
    nodes = snapshot.get("nodes", [])
    if not nodes:
        c.skip("no nodes visible in snapshot")
        return c
    tainted = [n for n in nodes if n.get("spec", {}).get("taints")]
    if tainted:
        c.note(
            f"{len(tainted)}/{len(nodes)} nodes carry taints: "
            + "; ".join(
                f"{n['metadata']['name']}: "
                + ",".join(
                    f"{t.get('key')}={t.get('value','')}:{t.get('effect')}"
                    for t in n["spec"]["taints"]
                )
                for n in tainted[:4]
            )
        )
    for w in workloads:
        schedulable_nodes = [
            n for n in nodes if not pod_schedulable_on(n, w["tolerations"])
        ]
        if not schedulable_nodes:
            example = pod_schedulable_on(nodes[0], w["tolerations"])
            taint = example[0] if example else {}
            c.fail(
                f"{w['kind']}/{w['name']} cannot schedule on any node — no toleration for "
                f"taint {taint.get('key')}:{taint.get('effect')} (and possibly others). "
                f"Its pods will sit Pending exactly like the LKE addon pods did for 6 hours.",
                remedy="add matching tolerations to the delivered values (kit overlay), or remove/scope the taint",
            )
    return c


def container_requirements(container):
    res = container.get("resources", {}) or {}
    req, lim = res.get("requests", {}) or {}, res.get("limits", {}) or {}
    return req, lim


# The two dimensions LimitRange constrains, with the parser and the printer for
# each. Memory was the only one compared until 2026-09-07; cpu was declared and
# then never checked against anything, which is the same hole one column over.
DIMENSIONS = (
    ("memory", parse_memory, fmt_mem),
    ("cpu", parse_cpu, lambda v: f"{v}m"),
)


def limitrange_ceiling(container_lr):
    """One line naming what P2 is comparing against — the LimitRange's own
    numbers, printed whether or not anything trips them.

    POSITIVE EVIDENCE, and it is the point. On 2026-09-07 P2 said only
    "namespace has 1 LimitRange(s)" and PASSED, and the receipt read that pass
    as proof the check does not compare against `max` at all. It does. What it
    could not say was WHICH ceiling it had compared against — the live
    `max.memory` was 8Gi at that moment and was reset to 2560Mi afterwards, so
    the pass was true when taken and false an hour later, and nothing in the
    output could distinguish those two worlds. A check that prints the number it
    used is auditable; one that prints "a LimitRange exists" is not.
    """
    bits = []
    for name, parse, fmt in DIMENSIONS:
        for key in ("max", "min", "default", "defaultRequest"):
            vals = {i.get(key, {}).get(name) for i in container_lr
                    if (i.get(key) or {}).get(name)}
            for v in sorted(vals):
                bits.append(f"{key}.{name}={v}")
    return ", ".join(bits) if bits else "no Container limits declared in it"


def check_limitranges(snapshot, workloads):
    c = Check("P2", "Declared resources on every container, and they fit the LimitRange",
              "vexa#1005 (a customer LimitRange squeezed undeclared bots to 64Mi); vexa-platform#338 (sizing env vars dead code)")
    unknown_because(c, snapshot, "limitranges",
                    "comparing declared limits against the namespace ceiling")
    lrs = snapshot.get("limitranges", [])
    lr_items = [i for lr in lrs for i in lr.get("spec", {}).get("limits", [])]
    container_lr = [i for i in lr_items if i.get("type") == "Container"]
    if lrs:
        names = ", ".join(lr.get("metadata", {}).get("name", "?") for lr in lrs)
        c.note(f"namespace has {len(lrs)} LimitRange(s): {names}")
        c.note(f"compared against — {limitrange_ceiling(container_lr)}")
    for w in workloads:
        for ct in w["containers"]:
            req, lim = container_requirements(ct)
            missing = [
                what
                for what, d in (("requests.memory", req), ("limits.memory", lim))
                if "memory" not in d
            ] + [
                what
                for what, d in (("requests.cpu", req), ("limits.cpu", lim))
                if "cpu" not in d
            ]
            if missing:
                squeeze = ""
                for i in container_lr:
                    dflt = (i.get("default") or {}).get("memory")
                    if dflt and "memory" in " ".join(missing):
                        squeeze = (
                            f" — the LimitRange would silently assign it {dflt}"
                            f" (the exact 64Mi-squeeze class)"
                        )
                c.fail(
                    f"{w['kind']}/{w['name']} container '{ct['name']}' does not declare {', '.join(missing)}{squeeze}. "
                    f"Every delivered workload declares resources explicitly.",
                    remedy="declare requests+limits in the delivered values; sizes for bots: request 1Gi / limit 2560Mi (measured)",
                )
                continue
            # EVERY DECLARED NUMBER AGAINST BOTH BOUNDS, IN BOTH DIMENSIONS.
            #
            # The LimitRanger admission plugin checks `max` and `min` against
            # the request AND the limit, for every resource named in the
            # LimitRange — plugin/pkg/admission/limitranger/admission.go,
            # maxConstraint/minConstraint. This check compared exactly one of
            # those four pairs (limits.memory vs max, requests.memory vs min)
            # and no cpu at all, so three quarters of what admission will refuse
            # was invisible to the check whose whole job is to predict it.
            for i in container_lr:
                mx = i.get("max") or {}
                mn = i.get("min") or {}
                lrname = "LimitRange"
                for name, parse, _fmt in DIMENSIONS:
                    for field, declared in (("requests", req), ("limits", lim)):
                        raw = declared.get(name)
                        if raw is None:
                            continue
                        value = parse(raw)
                        if value is None:
                            continue
                        if mx.get(name) is not None and value > parse(mx[name]):
                            c.fail(
                                f"{w['kind']}/{w['name']} '{ct['name']}' declares {field}.{name} "
                                f"{raw} above the {lrname} max {mx[name]} — admission will refuse "
                                f"the pod ('maximum {name} usage per Container is {mx[name]}, "
                                f"but {field[:-1]} is {raw}').",
                                remedy=("raise the LimitRange max, or deliver a smaller profile for this "
                                        "environment (kit/profiles/vexa/customer-values.example.yaml "
                                        "caps the delivered postgres for exactly this reason)"),
                            )
                        if mn.get(name) is not None and value < parse(mn[name]):
                            c.fail(
                                f"{w['kind']}/{w['name']} '{ct['name']}' declares {field}.{name} "
                                f"{raw} below the {lrname} min {mn[name]} — admission will refuse the pod.",
                                remedy="raise the declared value, or lower the LimitRange min",
                            )
    return c


def check_quota(snapshot, workloads):
    c = Check("P3", "ResourceQuota headroom covers the declared totals", "handoff §6.1")
    if unknown_because(c, snapshot, "resourcequotas", "quota headroom"):
        return c
    quotas = snapshot.get("resourcequotas", [])
    if not quotas:
        c.note("no ResourceQuota in the namespace")
        return c
    # Memory AND cpu. cpu was summed nowhere, so a quota with `limits.cpu` — the
    # tenant grant's own shape — was a bound nothing compared anything against.
    def total(index, dimension, parse):
        return sum(
            parse((container_requirements(ct)[index]).get(dimension) or "0")
            for w in workloads
            for ct in w["containers"]
        )

    needs = {
        "requests.memory": (total(0, "memory", parse_memory), parse_memory, fmt_mem),
        "limits.memory": (total(1, "memory", parse_memory), parse_memory, fmt_mem),
        "requests.cpu": (total(0, "cpu", parse_cpu), parse_cpu, lambda v: f"{v}m"),
        "limits.cpu": (total(1, "cpu", parse_cpu), parse_cpu, lambda v: f"{v}m"),
    }
    for q in quotas:
        hard = q.get("status", {}).get("hard") or q.get("spec", {}).get("hard") or {}
        used = q.get("status", {}).get("used", {}) or {}
        for key, (need, parse, fmt) in needs.items():
            if key in hard:
                free = parse(hard[key]) - parse(used.get(key, "0"))
                if need > free:
                    c.fail(
                        f"quota '{q['metadata']['name']}' leaves {fmt(free)} of {key} "
                        f"but the delivered set declares {fmt(need)} — admission will refuse pods at the margin.",
                        remedy="raise the quota or shrink the delivered profile",
                    )
                else:
                    c.note(f"quota '{q['metadata']['name']}' {key}: need {fmt(need)}, free {fmt(free)}")
    return c


def parse_uid_range(annotation):
    # openshift.io/sa.scc.uid-range: "1000600000/10000" (start/size)
    m = re.fullmatch(r"(\d+)/(\d+)", annotation or "")
    if not m:
        return None
    start, size = int(m.group(1)), int(m.group(2))
    return start, start + size - 1


def check_pod_security(snapshot, workloads):
    c = Check("P4", "SCC restricted-v2 / PodSecurity 'restricted' admission",
              "openshift readiness audit 2026-08-19: SCC mutates, then REJECTS explicit UIDs outside the namespace range; the hardened workloads are the rejected ones")
    unknown_because(c, snapshot, "namespace",
                    "reading the namespace's SCC uid-range and PSA labels")
    ns = snapshot.get("namespace", {})
    annotations = ns.get("metadata", {}).get("annotations", {}) or {}
    labels = ns.get("metadata", {}).get("labels", {}) or {}
    is_openshift = snapshot.get("openshift_scc", False)
    psa_enforce = labels.get("pod-security.kubernetes.io/enforce")

    # THE EFFECTIVE ADMISSION, READ AND PRINTED BEFORE ANY VERDICT (2026-09-07).
    #
    # This check used to end with a NOTE — "no SCC and no PSA enforce label on
    # the namespace — admission here is permissive" — and a PASS. On the
    # 2026-09-07 rehearsal that PASS was produced by the installer having just
    # stripped the project's PSA labels and SCC annotations (`ensure_namespace`,
    # now create-only). A green obtained from the enforcement being absent, in
    # the one check whose subject IS the enforcement. Had the run stopped there
    # it would have reported a hardened estate that was not one.
    #
    # Two changes, and the second is the one that matters:
    #   - the effective admission is stated, always, so a PASS says what it was
    #     measured against instead of only that it happened;
    #   - "nothing enforces here" is UNKNOWN, never PASS. Nothing was verified,
    #     which is exactly what UNKNOWN means in this file, and install.sh
    #     already renders exit 4 as "not a verdict on your cluster".
    scc_annotations = sorted(k for k in annotations if k.startswith("openshift.io/sa.scc."))
    effective = [
        f"PSA enforce={psa_enforce or 'none'}"
        f" (audit={labels.get('pod-security.kubernetes.io/audit') or 'none'},"
        f" warn={labels.get('pod-security.kubernetes.io/warn') or 'none'})",
        f"SCC API on this cluster: {'present' if is_openshift else 'absent'}",
        f"namespace SCC annotations: {', '.join(scc_annotations) if scc_annotations else 'none'}",
    ]
    c.note("effective admission — " + "; ".join(effective))

    for w in workloads:
        flags = w.get("host_flags", {})
        if flags:
            c.fail(
                f"{w['kind']}/{w['name']} sets {', '.join(flags)} — refused by SCC restricted-v2 and PSA restricted alike."
            )
        for v in w.get("volumes", []) or []:
            if "hostPath" in v:
                c.fail(
                    f"{w['kind']}/{w['name']} mounts hostPath '{v['hostPath'].get('path')}' — "
                    f"allowHostDirVolumePlugin=false under restricted-v2; hard rejection."
                )
        for ct in w["containers"]:
            for p in ct.get("ports", []):
                if p.get("hostPort"):
                    c.fail(f"{w['kind']}/{w['name']} '{ct['name']}' uses hostPort {p['hostPort']} — refused under restricted profiles.")

    if is_openshift:
        rng = parse_uid_range(annotations.get("openshift.io/sa.scc.uid-range"))
        if rng:
            c.note(f"OpenShift namespace UID range {rng[0]}–{rng[1]}")
            for w in workloads:
                ctxs = [("pod", w.get("pod_security_context", {}))] + [
                    (f"container '{ct['name']}'", ct.get("security_context", {}))
                    for ct in w["containers"]
                ]
                for where, sc in ctxs:
                    for field in ("runAsUser", "fsGroup", "runAsGroup"):
                        val = sc.get(field)
                        if val is not None and not (rng[0] <= int(val) <= rng[1] or int(val) == 0 and field == "runAsGroup"):
                            c.fail(
                                f"{w['kind']}/{w['name']} {where} hard-codes {field}: {val}, outside the namespace "
                                f"range {rng[0]}–{rng[1]} — SCC restricted-v2 REJECTS this (MustRunAsRange). "
                                f"The fix is to delete the line and let the SCC assign the UID.",
                                remedy="drop explicit runAsUser/runAsGroup/fsGroup from delivered values on OpenShift",
                            )
        else:
            c.note("OpenShift detected but namespace carries no uid-range annotation yet (created on first use)")
    if psa_enforce in ("restricted", "baseline"):
        c.note(f"PodSecurity enforce={psa_enforce} on the namespace")
        if psa_enforce == "restricted":
            for w in workloads:
                pod_sc = w.get("pod_security_context", {}) or {}
                for ct in w["containers"]:
                    sc = ct.get("security_context", {}) or {}
                    rnr = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
                    if rnr is not True:
                        c.fail(
                            f"{w['kind']}/{w['name']} '{ct['name']}': runAsNonRoot is not true — PSA restricted refuses the pod "
                            f"(SCC would have mutated other fields, but never this one)."
                        )
                    ape = sc.get("allowPrivilegeEscalation")
                    if ape is not False:
                        c.fail(f"{w['kind']}/{w['name']} '{ct['name']}': allowPrivilegeEscalation must be false under PSA restricted.")
                    drops = (sc.get("capabilities") or {}).get("drop") or []
                    if "ALL" not in drops:
                        c.fail(f"{w['kind']}/{w['name']} '{ct['name']}': capabilities.drop must include ALL under PSA restricted.")
                    seccomp = (sc.get("seccompProfile") or pod_sc.get("seccompProfile") or {}).get("type")
                    if seccomp not in ("RuntimeDefault", "Localhost"):
                        c.fail(f"{w['kind']}/{w['name']} '{ct['name']}': seccompProfile RuntimeDefault required under PSA restricted.")
    if not psa_enforce and not scc_annotations:
        c.unknown(
            "UNEVALUATED — this namespace enforces nothing: no PSA enforce label and no "
            "openshift.io/sa.scc.* annotations. Admission here is permissive, so nothing "
            "the delivered set declares can be tripped and NOTHING about hardened "
            "namespaces was verified. This is not a pass. If the project was created by "
            "your platform team with a security grant, that grant is missing NOW — read "
            "the namespace and compare it with the manifest it was created from.",
            remedy=("apply the project's own grant (PSA labels + SCC annotations) and re-run. "
                    "install.sh no longer writes to a namespace it did not create, so nothing "
                    "in this kit removes it"),
        )
    return c


def check_netpol_static(snapshot, workloads):
    c = Check("P5", "NetworkPolicy lets the delivered workloads resolve DNS and reach the registry",
              "handoff §6.1 (netpol reachability); spike finding 9 (the only defence was an unenforced hostAliases sink)")
    if unknown_because(c, snapshot, "networkpolicies", "detecting a default-deny egress policy"):
        return c
    pols = snapshot.get("networkpolicies", [])
    if not pols:
        c.note("no NetworkPolicies in the namespace — nothing blocks; nothing isolates either")
        return c
    default_deny_egress = False
    dns_allowed = False
    for p in pols:
        spec = p.get("spec", {})
        types = spec.get("policyTypes", []) or []
        sel = spec.get("podSelector", {})
        selects_all = not sel.get("matchLabels") and not sel.get("matchExpressions")
        egress_rules = spec.get("egress", []) or []
        if "Egress" in types and selects_all and not egress_rules:
            default_deny_egress = True
            c.note(f"default-deny egress policy '{p['metadata']['name']}' selects every pod")
        for rule in egress_rules:
            for port in rule.get("ports", []) or []:
                if str(port.get("port")) == "53":
                    dns_allowed = True
        if not egress_rules and "Egress" not in types:
            continue
    if default_deny_egress and not dns_allowed:
        c.fail(
            "egress is default-denied and no policy allows DNS (port 53) — every delivered pod will fail name "
            "resolution, and the failure will look like application errors, not policy.",
            remedy="allow UDP/TCP 53 to kube-dns and 443 to the channel registry from the vexa namespace",
        )
    elif default_deny_egress:
        c.warn("egress is default-denied; DNS is allowed, but verify registry egress with --live-probes (static analysis cannot prove reachability)")
    return c


def check_shm(snapshot, workloads):
    c = Check("P6", "The bot's Memory-backed /dev/shm fits the limits and the nodes",
              "openshift audit: 2Gi shm counts against the 2560Mi container limit; production's actual configuration")
    shm_workloads = [w for w in workloads if w.get("shm_bytes")]
    if not shm_workloads:
        c.note("no Memory-medium emptyDir in the delivered set (bot profile disabled?)")
        return c
    unknown_because(c, snapshot, "limitranges", "the LimitRange half of this check")
    unknown_because(c, snapshot, "nodes", "the node-allocatable half of this check")
    lr_items = [
        i
        for lr in snapshot.get("limitranges", [])
        for i in lr.get("spec", {}).get("limits", [])
        if i.get("type") == "Container"
    ]
    nodes = snapshot.get("nodes", [])
    max_alloc = 0
    for n in nodes:
        alloc = parse_memory(n.get("status", {}).get("allocatable", {}).get("memory", "0"))
        max_alloc = max(max_alloc, alloc or 0)
    for w in shm_workloads:
        shm = w["shm_bytes"]
        lim = max(
            (parse_memory((container_requirements(ct)[1]).get("memory") or "0") or 0)
            for ct in w["containers"]
        )
        c.note(
            f"{w['name']}: /dev/shm {fmt_mem(shm)} (Memory medium) + memory limit {fmt_mem(lim)}; "
            f"shm writes count against the limit"
        )
        for i in lr_items:
            mx = parse_memory((i.get("max") or {}).get("memory"))
            if mx and lim > mx:
                c.fail(
                    f"{w['name']}: memory limit {fmt_mem(lim)} exceeds LimitRange max {fmt_mem(mx)} — "
                    f"the bot pod will be refused at admission.",
                    remedy="raise the LimitRange max in the vexa namespace to at least 2560Mi",
                )
        if max_alloc and lim > max_alloc:
            c.fail(
                f"{w['name']}: no node has allocatable memory for a {fmt_mem(lim)} limit "
                f"(largest node allocatable: {fmt_mem(max_alloc)}) — pods will sit Pending.",
                remedy="add a node pool with ≥4GiB allocatable for bot workloads",
            )
    return c


def check_storage(snapshot, objects):
    c = Check("P8", "A default StorageClass exists for the delivered PVCs", "spike teardown lesson: Retain PVs strand")
    wants_pvc = any(
        o.get("kind") in ("PersistentVolumeClaim",)
        or (o.get("kind") == "StatefulSet" and o.get("spec", {}).get("volumeClaimTemplates"))
        for o in objects
    )
    if not wants_pvc:
        c.note("delivered set carries no PVCs")
        return c
    if unknown_because(c, snapshot, "storageclasses", "finding a default StorageClass"):
        return c
    scs = snapshot.get("storageclasses", [])
    default = [
        s
        for s in scs
        if (s.get("metadata", {}).get("annotations", {}) or {}).get(
            "storageclass.kubernetes.io/is-default-class"
        )
        == "true"
    ]
    if not default:
        c.fail(
            "the delivered set carries PersistentVolumeClaims but the cluster has no default StorageClass — "
            "claims will sit Pending forever.",
            remedy="mark a StorageClass default, or set storageClassName in the delivered values",
        )
    else:
        c.note(f"default StorageClass: {default[0]['metadata']['name']}")
    return c


def check_version(snapshot):
    c = Check("P9", "Kubernetes version floor", "kit pins Argo CD + Kyverno versions")
    if unknown_because(c, snapshot, "server_version", "reading the API server's version"):
        return c
    v = snapshot.get("server_version", {})
    minor = re.sub(r"\D", "", v.get("minor", "") or "")
    if not minor:
        c.skip("server version not in snapshot")
        return c
    if int(minor) < MIN_K8S_MINOR:
        c.fail(f"server {v.get('gitVersion')} is below the tested floor 1.{MIN_K8S_MINOR}")
    else:
        c.note(f"server {v.get('gitVersion')}")
    return c


# ------------------------------------------------------------------- kubectl


def kubectl(args, kubeconfig=None, context=None, input_=None, timeout=120):
    cmd = ["kubectl"]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    if context:
        cmd += ["--context", context]
    cmd += args
    return subprocess.run(cmd, capture_output=True, text=True, input=input_, timeout=timeout)


def kubectl_json(args, **kw):
    r = kubectl(args + ["-o", "json"], **kw)
    if r.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)}: {r.stderr.strip()[:300]}")
    return json.loads(r.stdout)


def read_failure_reason(exc):
    """One line naming why a read did not happen, safe to print.

    A kubectl RBAC refusal already says everything useful ("cannot list
    resource ... at the cluster scope"); the other cases have to be spelt out
    because their exception text does not name the act that failed.
    """
    if isinstance(exc, RuntimeError):
        return str(exc)
    if isinstance(exc, FileNotFoundError):
        return "kubectl is not on PATH"
    if isinstance(exc, subprocess.TimeoutExpired):
        return "the read timed out (the API server did not answer)"
    if isinstance(exc, ValueError):          # json.JSONDecodeError is a subclass
        return "kubectl returned output that is not JSON"
    return f"{type(exc).__name__}: {exc}"


# Every read in take_snapshot goes through this. THE UNWRAPPED READ WAS THE
# DEFECT: `kubectl get nodes` sat bare while every sibling — storageclasses
# included — was inside try/except, so a namespace-scoped tenant got a Python
# traceback out of a conformance tool, and `install.sh` then reported
# `preflight FAILED` having evaluated nothing. A refused read is a fact about
# this credential's scope, not about the cluster, and the checks below turn it
# into UNKNOWN rather than into a verdict.
def snapshot_read(snap, key, args, kubeconfig=None, context=None):
    try:
        return kubectl_json(args, kubeconfig=kubeconfig, context=context)
    except Exception as exc:                                        # noqa: BLE001
        snap.setdefault("unreadable", {})[key] = read_failure_reason(exc)
        return None


def take_snapshot(namespace, kubeconfig=None, context=None):
    snap = {"namespace_name": namespace, "unreadable": {}}
    nodes = snapshot_read(snap, "nodes", ["get", "nodes"],
                          kubeconfig=kubeconfig, context=context)
    snap["nodes"] = (nodes or {}).get("items", [])
    ns = snapshot_read(snap, "namespace", ["get", "namespace", namespace],
                       kubeconfig=kubeconfig, context=context)
    if ns is None:
        snap["namespace"] = {"metadata": {"name": namespace, "labels": {}, "annotations": {}}}
        snap["namespace_absent"] = True
    else:
        snap["namespace"] = ns
    for key, kind in (
        ("limitranges", "limitrange"),
        ("resourcequotas", "resourcequota"),
        ("networkpolicies", "networkpolicy"),
        ("storageclasses", "storageclass"),
    ):
        args = ["get", kind] if kind == "storageclass" else ["get", kind, "-n", namespace]
        got = snapshot_read(snap, key, args, kubeconfig=kubeconfig, context=context)
        snap[key] = (got or {}).get("items", [])
    try:
        api = kubectl(["api-versions"], kubeconfig=kubeconfig, context=context)
        snap["openshift_scc"] = "security.openshift.io/v1" in (api.stdout or "")
    except Exception as exc:                                        # noqa: BLE001
        snap["openshift_scc"] = False
        snap["unreadable"]["api_versions"] = read_failure_reason(exc)
    try:
        ver = kubectl(["version", "-o", "json"], kubeconfig=kubeconfig, context=context)
        snap["server_version"] = json.loads(ver.stdout).get("serverVersion", {})
    except Exception as exc:                                        # noqa: BLE001
        snap["server_version"] = {}
        snap["unreadable"]["server_version"] = read_failure_reason(exc)
    return snap


def load_manifests(path, kubeconfig=None):
    """Convert rendered YAML to JSON objects via kubectl client-side dry-run."""
    r = kubectl(
        ["create", "--dry-run=client", "-o", "json", "-f", path],
        kubeconfig=kubeconfig,
    )
    if r.returncode != 0:
        raise RuntimeError(f"could not parse manifests at {path}: {r.stderr.strip()[:300]}")
    objects = []
    dec = json.JSONDecoder()
    s = r.stdout
    i = 0
    while i < len(s):
        while i < len(s) and s[i] in " \t\r\n":
            i += 1
        if i >= len(s):
            break
        obj, j = dec.raw_decode(s, i)
        i = j
        if obj.get("kind") == "List":
            objects.extend(obj.get("items", []))
        else:
            objects.append(obj)
    return objects


# ---------------------------------------------------------------- live probes


def probe_overrides(name, image, command):
    """A fully PSA-restricted-compliant probe pod. NOTE: kubectl run
    --overrides replaces the generated containers list wholesale (json-merge,
    not strategic — the documented k8s_backend trap), so the container entry
    carries image and command itself."""
    return json.dumps(
        {
            "spec": {
                "containers": [
                    {
                        "name": name,
                        "image": image,
                        "command": command,
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 65532,
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                    }
                ]
            }
        }
    )


def probe_netpol(namespace, registry_host, kubeconfig=None, context=None, image="busybox:stable"):
    c = Check("P5-live", "In-cluster probe: DNS resolution and registry reachability",
              "handoff §6.1 — static analysis cannot prove reachability; a pod can")
    host, _, port = registry_host.partition(":")
    port = port or "443"
    script = (
        f"nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1 && echo DNS_OK || echo DNS_FAIL; "
        f"nc -z -w 5 {host} {port} >/dev/null 2>&1 && echo REG_OK || echo REG_FAIL"
    )
    name = "vexa-preflight-netprobe"
    kubectl(["delete", "pod", name, "-n", namespace, "--ignore-not-found"], kubeconfig=kubeconfig, context=context)
    r = kubectl(
        ["run", name, "-n", namespace, "--image", image, "--restart=Never",
         "--rm", "-i", "--quiet", "--pod-running-timeout=120s",
         "--overrides", probe_overrides(name, image, ["sh", "-c", script])],
        kubeconfig=kubeconfig, context=context, timeout=180,
    )
    out = (r.stdout or "") + (r.stderr or "")
    if "DNS_OK" in out:
        c.note("DNS resolution inside the namespace works")
    elif "DNS_FAIL" in out:
        c.fail("in-cluster DNS resolution FAILED — every delivered pod will fail name lookup",
               remedy="allow egress to kube-dns (port 53) from this namespace")
    else:
        c.warn(
            f"probe pod did not run to completion ({out.strip()[:160]}) — if P1 reports untolerated "
            f"taints, the probe pod is stuck on the same class; fix P1 first, then rerun"
        )
    if "REG_OK" in out:
        c.note(f"registry {host}:{port} reachable from the namespace")
    elif "REG_FAIL" in out:
        c.fail(f"registry {host}:{port} NOT reachable from the namespace — Argo cannot pull the channel",
               remedy="allow egress to the channel registry (TCP {port}) from this namespace".format(port=port))
    return c


def probe_image_pull(namespace, image_ref, kubeconfig=None, context=None, timeout=300):
    c = Check("P7", "The cluster pulls a release image by digest with this namespace's pull secrets",
              "argocd spike finding 8 — images 'pulled' only because nodes had them cached")
    name = "vexa-preflight-pullprobe"
    kubectl(["delete", "pod", name, "-n", namespace, "--ignore-not-found", "--wait=false"], kubeconfig=kubeconfig, context=context)
    r = kubectl(
        ["run", name, "-n", namespace, "--image", image_ref, "--restart=Never",
         "--image-pull-policy=Always",
         "--overrides", probe_overrides(name, image_ref, ["sh", "-c", "exit 0"])],
        kubeconfig=kubeconfig, context=context,
    )
    if r.returncode != 0:
        c.warn(f"could not create pull-probe pod: {r.stderr.strip()[:200]}")
        return c
    import time

    deadline = time.time() + timeout
    verdict = None
    while time.time() < deadline:
        p = kubectl_json(["get", "pod", name, "-n", namespace], kubeconfig=kubeconfig, context=context)
        phase = p.get("status", {}).get("phase")
        statuses = p.get("status", {}).get("containerStatuses", []) or []
        waiting = (statuses[0].get("state", {}).get("waiting") or {}) if statuses else {}
        reason = waiting.get("reason", "")
        if phase in ("Succeeded", "Running"):
            verdict = "ok"
            break
        if reason in ("ErrImagePull", "ImagePullBackOff"):
            verdict = waiting.get("message", reason)
            break
        sched = [x for x in (p.get("status", {}).get("conditions") or []) if x.get("type") == "PodScheduled"]
        if sched and sched[0].get("status") == "False" and sched[0].get("reason") == "Unschedulable":
            verdict = f"probe pod unschedulable: {sched[0].get('message', '')[:200]} — fix P1 first, then rerun"
            break
        time.sleep(5)
    kubectl(["delete", "pod", name, "-n", namespace, "--ignore-not-found", "--wait=false"], kubeconfig=kubeconfig, context=context)
    if verdict == "ok":
        c.note(f"pulled {image_ref} successfully")
    elif verdict is None:
        c.warn(f"pull of {image_ref} still not complete after {timeout}s — slow network or large image; rerun with a longer --pull-timeout")
    else:
        c.fail(
            f"cannot pull {image_ref}: {verdict[:300]}",
            remedy="create/attach an imagePullSecret for the registry in this namespace and reference it in the delivered values",
        )
    return c


# ------------------------------------------------------------------- render


def render(checks, as_json=False):
    if as_json:
        return json.dumps({"checks": [c.as_dict() for c in checks],
                           "verdict": overall(checks)}, indent=1)
    lines = []
    width = 78
    lines.append("vexa-preflight — cluster conformance for a private channel")
    lines.append("=" * width)
    for c in checks:
        badge = {"PASS": "PASS", "WARN": "WARN", "FAIL": "FAIL", "SKIP": "skip",
                 "UNKNOWN": "????"}[c.status]
        lines.append(f"[{badge}] {c.cid} · {c.title}")
        for f in c.findings:
            lines.append(f"       {f}")
        if c.remedy:
            lines.append(f"       remedy: {c.remedy}")
        lines.append(f"       (anchor: {c.anchor})")
        lines.append("-" * width)
    lines.append(f"VERDICT: {overall(checks)}")
    return "\n".join(lines)


def overall(checks):
    unknown = [c.cid for c in checks if c.status == "UNKNOWN"]
    if any(c.status == "FAIL" for c in checks):
        tail = f" ({len(unknown)} check(s) could not be evaluated: {', '.join(unknown)})" if unknown else ""
        return f"FAIL — fix the findings above before first sync{tail}"
    # UNKNOWN is not a pass and it is not a failure. Rolling it into either is
    # the error this verdict exists to stop: the field saw `preflight FAILED`
    # printed over checks that had never run.
    if unknown:
        return (f"PASS on what could be checked — {len(unknown)} check(s) NOT EVALUATED "
                f"({', '.join(unknown)}). Nothing failed; some things were never looked at.")
    if any(c.status == "WARN" for c in checks):
        return "PASS with warnings"
    return "PASS"


# ---------------------------------------------------------------------- main


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vexa-preflight", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--namespace", required=True, help="target namespace for the delivered workloads")
    ap.add_argument("--manifests", help="rendered manifests (file or dir) of the delivered set")
    ap.add_argument("--snapshot", help="read cluster state from a snapshot file (air-gapped mode)")
    ap.add_argument("--dump-snapshot", help="write the live cluster snapshot to a file and exit")
    ap.add_argument("--kubeconfig")
    ap.add_argument("--context")
    ap.add_argument("--bot-profile", choices=["default", "none"], default="default",
                    help="include the dynamic bot pod profile (absent from renders) in the checks")
    ap.add_argument("--live-probes", action="store_true", help="run in-cluster probe pods (DNS/registry, image pull)")
    ap.add_argument("--registry-host", help="channel registry host[:port] for the reachability probe")
    ap.add_argument("--pull-test-image", help="image ref (by digest) for the pull probe")
    ap.add_argument("--pull-timeout", type=int, default=300)
    ap.add_argument("--probe-image", default="busybox:stable")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.dump_snapshot:
        snap = take_snapshot(args.namespace, args.kubeconfig, args.context)
        pathlib.Path(args.dump_snapshot).write_text(json.dumps(snap, indent=1))
        print(f"snapshot written to {args.dump_snapshot}")
        return 0

    if args.snapshot:
        snapshot = json.loads(pathlib.Path(args.snapshot).read_text())
    else:
        snapshot = take_snapshot(args.namespace, args.kubeconfig, args.context)

    objects = []
    if args.manifests:
        objects = load_manifests(args.manifests, args.kubeconfig)
    workloads = extract_workloads(objects)
    if args.bot_profile == "default":
        workloads.append(dict(BOT_PROFILE))

    checks = [
        check_taints(snapshot, workloads),
        check_limitranges(snapshot, workloads),
        check_quota(snapshot, workloads),
        check_pod_security(snapshot, workloads),
        check_netpol_static(snapshot, workloads),
        check_shm(snapshot, workloads),
        check_storage(snapshot, objects),
        check_version(snapshot),
    ]

    if args.live_probes and not args.snapshot:
        if args.registry_host:
            checks.append(probe_netpol(args.namespace, args.registry_host,
                                       args.kubeconfig, args.context, args.probe_image))
        if args.pull_test_image:
            checks.append(probe_image_pull(args.namespace, args.pull_test_image,
                                           args.kubeconfig, args.context, args.pull_timeout))

    print(render(checks, as_json=args.json))
    if any(c.status == "FAIL" for c in checks):
        return 1
    # Not a failure, not a clean pass. See "Exit codes" at the top of this file:
    # sharing 0 with a clean run made an unevaluated check invisible to every
    # caller, which is the half of "fails closed" that was not true.
    if any(c.status == "UNKNOWN" for c in checks):
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
