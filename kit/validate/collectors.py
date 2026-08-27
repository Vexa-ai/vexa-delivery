# SPDX-License-Identifier: Apache-2.0
"""The telemetry ladder's collectors, and the gate that decides which may run.

    T0  silent      nothing leaves. A T0 station does not submit at all.
    T1  receipts    what is running here, under what verdict — per release.
    T2  health      aggregate counters. No identities, no content, no logs.
    T3  usage       activation and volume aggregates, pseudonymous.
    T4  diagnostics scrubbed bundles. NEVER AUTOMATIC — see export_diagnostics().

TIER GATING IS STRUCTURAL, WHICH IS A CLAIM ABOUT THE CODE AND NOT ABOUT OUR
INTENTIONS.

`collect()` resolves the declared tier to a list of collector callables BEFORE
calling any of them, and there is no other entry point. A T2 station does not
run the usage collector and discard its output — the function object is never
in the list. This matters because the customer's security team is being asked
to believe a claim about a program they will read once and then run daily on
their own cluster: "we filter the output afterwards" is a promise, and "the
code that reads it is not reachable" is a property.

The same rule is enforced twice more, in two other places, on purpose:

  * report.v1.schema.json refuses a payload whose blocks exceed its `tier`
    field, so the packager cannot emit one even if this module were wrong;
  * publisher/vexa_station.py refuses such a bundle AT INGEST — we enforce the
    customer's policy against ourselves, which is the half of the promise that
    is actually worth something.

ABSENT OVER FAKED, everywhere below. A counter that could not be collected is
reported as absent with a reason. It is never defaulted to zero: zero is a
claim, and a fabricated zero in a signed bundle is worse than a gap.
"""
import datetime
import json
import subprocess

# tier -> the report.v1 block that tier is permitted to add. The single table
# both this module and the ingest-side refusal read; publisher/vexa_station.py
# imports it rather than restating it, and a test pins it against the schema's
# own if/then rules so three implementations cannot drift into two opinions.
TIER_BLOCKS = {
    0: None,
    1: "release",
    2: "health",
    3: "usage",
}
MAX_SUBMITTABLE_TIER = 3          # T4 never travels this path. See export_diagnostics().

TIER_NAMES = {
    0: "silent",
    1: "receipts",
    2: "health",
    3: "usage",
    4: "diagnostics (on demand, never automatic)",
}


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Kube:
    """The narrowest kubectl wrapper that does the job.

    Read-only by construction: every call is `get -o json`. A collector that
    cannot read something records why rather than raising — a station that
    grants us less RBAC than the chart asked for should still submit the
    counters it can, with the gaps named.
    """

    def __init__(self, namespace, kubeconfig=None, context=None, binary="kubectl"):
        self.namespace, self.kubeconfig, self.context = namespace, kubeconfig, context
        self.binary = binary

    def _base(self):
        cmd = [self.binary]
        if self.kubeconfig:
            cmd += ["--kubeconfig", self.kubeconfig]
        if self.context:
            cmd += ["--context", self.context]
        return cmd

    def get(self, resource, name=None, namespace=True, timeout=60):
        cmd = self._base() + ["get", resource]
        if name:
            cmd.append(name)
        if namespace:
            cmd += ["-n", self.namespace]
        cmd += ["-o", "json"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            return None, f"kubectl get {resource}: {type(e).__name__}"
        if r.returncode != 0:
            # The stderr is NOT carried into the report. It is a cluster's own
            # message about a cluster's own objects, it routinely names hosts
            # and users, and this document promises not to carry that. The
            # reason field says what failed; the operator has the log.
            return None, f"kubectl get {resource} exited {r.returncode}"
        try:
            return json.loads(r.stdout), None
        except ValueError:
            return None, f"kubectl get {resource} returned unparseable json"


# ------------------------------------------------------------------ T1 · release


def collect_release(kube, cfg):
    """What is running here, and under what verdict.

    Sources, in order of authority: the Argo CD Application (the pin, the
    position, sync and health, the resolved revision), then the running pods
    for the image digests actually in service, then the PreSync verifier's own
    verdict ConfigMap if the gate wrote one.

    The image digests come from the PODS and not from the chart on purpose. The
    chart says what should be running; the pods say what is. A drift between
    the entry and the cluster is the single most useful thing this rung can
    report, and reading the chart for both sides of that comparison would make
    it structurally undetectable.
    """
    out = {"app": cfg.get("app") or "", "pin": cfg.get("pin") or ""}
    absent = []

    app, err = kube.get("applications.argoproj.io", cfg.get("app"),
                        namespace=False) if cfg.get("app") else (None, "no app name configured")
    if app:
        spec, status = app.get("spec") or {}, app.get("status") or {}
        src = spec.get("source") or {}
        out["pin"] = src.get("targetRevision") or out["pin"]
        sync = status.get("sync") or {}
        health = status.get("health") or {}
        out["sync_status"] = sync.get("status")
        out["health_status"] = health.get("status")
        out["revision"] = sync.get("revision")
        hist = status.get("history") or []
        if hist:
            out["synced_at"] = (hist[-1].get("deployedAt") or None)
    else:
        absent.append(err or "argo application not readable")

    for key in ("entry_seq", "entry_digest", "chart_version", "chart_digest"):
        if cfg.get(key) not in (None, ""):
            out[key] = cfg[key]

    pods, err = kube.get("pods")
    if pods:
        seen = {}
        for p in pods.get("items", []):
            for cs in ((p.get("status") or {}).get("containerStatuses") or []):
                image_id = cs.get("imageID") or ""
                if "@sha256:" not in image_id:
                    continue
                repo, digest = image_id.rsplit("@", 1)
                # An imageID may carry a registry prefix the image ref did not;
                # keep it, it is the identity of what was actually pulled.
                seen[repo.removeprefix("docker-pullable://")] = digest
        out["images"] = [{"repository": r, "digest": d} for r, d in sorted(seen.items())]
    else:
        absent.append(err or "pods not readable")

    verdict = {"verdict": "ABSENT"}
    cm, _ = kube.get("configmap", cfg.get("verifierVerdictConfigMap") or "vexa-verify-verdict")
    if cm:
        data = cm.get("data") or {}
        verdict = {
            "verdict": data.get("verdict") or "UNKNOWN",
            "contract_id": data.get("contract_id"),
            "contract_sha256": data.get("contract_sha256"),
            "checked_at": data.get("checked_at"),
            "failed_checks": int(data["failed_checks"]) if str(
                data.get("failed_checks", "")).isdigit() else None,
        }
    out["verifier"] = verdict
    if absent:
        # The release block has no `absent` array in the schema — it is
        # identifiers, and an identifier is either known or the field is
        # omitted. Anything that could not be read simply is not there, which
        # a reader can see. Nothing is invented to fill it.
        pass
    return {k: v for k, v in out.items() if v not in (None, "")}


# ------------------------------------------------------------------- T2 · health


def _restarts(pod):
    return sum((cs.get("restartCount") or 0)
               for cs in ((pod.get("status") or {}).get("containerStatuses") or []))


def _owner_prefix(pod):
    """Map a pod back to its Deployment by the ReplicaSet naming convention.

    Deliberately convention-based rather than an ownerReferences walk: walking
    would need RBAC on replicasets, which is more read access than a health
    counter is worth asking a bank for. When the convention does not hold the
    pod lands in no Deployment bucket and the cluster-wide totals still count
    it, so the failure mode is a missing row and never a wrong number.
    """
    for ref in ((pod.get("metadata") or {}).get("ownerReferences") or []):
        if ref.get("kind") == "ReplicaSet":
            name = ref.get("name") or ""
            return name.rsplit("-", 1)[0] if "-" in name else name
    return None


def collect_health(kube, cfg):
    """Aggregate counters. Integers and ratios; no identities, no content."""
    out = {"collected_at": utcnow(), "window_hours": float(cfg.get("windowHours") or 24)}
    absent = []

    pods, err = kube.get("pods")
    if pods:
        phases = {"running": 0, "pending": 0, "failed": 0, "succeeded": 0, "unknown": 0}
        restarts_total, by_owner = 0, {}
        for p in pods.get("items", []):
            phase = ((p.get("status") or {}).get("phase") or "Unknown").lower()
            phases[phase if phase in phases else "unknown"] += 1
            r = _restarts(p)
            restarts_total += r
            owner = _owner_prefix(p)
            if owner:
                by_owner[owner] = by_owner.get(owner, 0) + r
        out["pods"] = dict(phases, restarts_total=restarts_total)
    else:
        by_owner = {}
        absent.append({"what": "pods", "reason": err or "not readable"})

    deploys, err = kube.get("deployments.apps")
    if deploys:
        rows = []
        for d in deploys.get("items", []):
            name = (d.get("metadata") or {}).get("name") or ""
            st = d.get("status") or {}
            rows.append({
                "name": name,
                "desired": (d.get("spec") or {}).get("replicas") or 0,
                "ready": st.get("readyReplicas") or 0,
                "available": st.get("availableReplicas") or 0,
                "restarts": by_owner.get(name, 0),
            })
        out["deployments"] = sorted(rows, key=lambda r: r["name"])
    else:
        absent.append({"what": "deployments", "reason": err or "not readable"})

    cjs, err = kube.get("cronjobs.batch")
    if cjs:
        now = datetime.datetime.now(datetime.timezone.utc)
        rows = []
        for c in cjs.get("items", []):
            st = c.get("status") or {}
            last = st.get("lastSuccessfulTime")
            age = None
            if last:
                try:
                    t = datetime.datetime.fromisoformat(last.replace("Z", "+00:00"))
                    age = max(0, int((now - t).total_seconds()))
                except ValueError:
                    age = None
            rows.append({
                "name": (c.get("metadata") or {}).get("name") or "",
                "suspended": bool((c.get("spec") or {}).get("suspend")),
                # null, not 0. A CronJob that has NEVER succeeded is not a
                # CronJob that succeeded a moment ago, and rendering the two
                # the same is how a dashboard shows green on a dead job.
                "last_success_age_seconds": age,
                "active": len(st.get("active") or []),
            })
        out["cronjobs"] = sorted(rows, key=lambda r: r["name"])
    else:
        absent.append({"what": "cronjobs", "reason": err or "not readable"})

    if cfg.get("collectNodes", True):
        nodes, err = kube.get("nodes", namespace=False)
        if nodes:
            items = nodes.get("items", [])
            ready = sum(1 for n in items if any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in ((n.get("status") or {}).get("conditions") or [])))
            out["nodes"] = {"total": len(items), "ready": ready}
            # Requested-vs-allocatable needs every pod on every node, i.e.
            # cluster-wide pod read. The chart asks for the release namespace
            # only, so on most stations this is honestly absent rather than
            # quietly wrong.
            out["nodes"].update({"cpu_requested_pct": None,
                                 "memory_requested_pct": None, "pods_used_pct": None})
            absent.append({"what": "nodes.requested_pct",
                           "reason": "needs cluster-wide pod read; the station chart grants "
                                     "namespace-scoped read only"})
        else:
            absent.append({"what": "nodes", "reason": err or "not readable"})
    else:
        absent.append({"what": "nodes", "reason": "namespace-scoped station; nodes not visible"})

    if absent:
        out["absent"] = absent
    return out


# -------------------------------------------------------------------- T3 · usage


def collect_usage(kube, cfg):
    """Activation and volume aggregates — THE INTERFACE, NOT THE NUMBERS.

    Nothing in this repository can produce these today. The product's usage
    surface is not exposed to a station-side collector, and there is no
    endpoint here to call. So this returns the block with every counter null
    and one `absent` row saying why.

    That is the whole point and it is not a placeholder to be filled in
    quietly: fabricating plausible activation counts would put invented data
    into a customer's ledger, under our signature, in a document whose entire
    value is that it is inspectable. An honest empty rung is worth more than a
    populated fake one, and a T3 station that sees this row knows exactly what
    it is waiting for.

    When the exporter exists it plugs in HERE, and the rule it must keep is in
    the schema, not in this docstring: counts only, no identities, and there is
    no field for a meeting, a participant or a transcript at any rung.
    """
    return {
        "collected_at": utcnow(),
        "window_hours": float(cfg.get("windowHours") or 24),
        "activated_users": None,
        "meetings_dispatched": None,
        "minutes_transcribed": None,
        "absent": [{
            "what": "all usage counters",
            "reason": "no usage exporter is configured in this estate; the collector "
                      "interface exists and reports absent rather than emitting invented "
                      "counts (absent over faked)",
        }],
    }


COLLECTORS = {
    1: ("release", collect_release),
    2: ("health", collect_health),
    3: ("usage", collect_usage),
}


class TierRefusal(Exception):
    """Named, because a refusal a human cannot act on is an outage."""


LEGACY_TIER = 1


def resolve_tier(scope):
    """The declared tier, or a refusal.

    NO report_scope AT ALL IS A REFUSAL. A station whose contract does not
    bound what may leave is a station whose policy we do not know, and guessing
    is still us deciding their policy for them.

    A report_scope WITHOUT a `tier` is tier 1, and that is not the same
    judgment. Every station contract written before the ladder existed has this
    shape, and every one of them already permits exactly one thing: the
    operator's install bundle — phase verdicts, receipts, a redacted values
    file. That IS T1. Refusing them would break every existing subscriber to
    make a point about a field they could not have written; reading them as
    anything above T1 would let a ladder rung arrive by default, which is the
    real hazard and is what the `> tier` checks everywhere else prevent.
    """
    if not isinstance(scope, dict) or not scope:
        raise TierRefusal(
            "no report_scope in the station's contract — refusing to collect anything. "
            "The tier is the customer's declaration of what may leave; there is no default "
            "for it, and inferring one would be us deciding their policy.")
    tier = scope.get("tier", LEGACY_TIER)
    if not isinstance(tier, int) or isinstance(tier, bool) or not 0 <= tier <= 4:
        raise TierRefusal(f"report_scope.tier is {tier!r}; it must be an integer 0-4")
    return tier


def collect(tier, kube, cfg=None):
    """Run exactly the collectors at or below `tier`. Nothing above it exists here.

    The filter happens on the FUNCTION LIST, before any call. That is the
    structural claim: at T2 the usage collector is not called and its result
    discarded — it is never referenced.
    """
    cfg = cfg or {}
    if tier == 0:
        raise TierRefusal(
            "tier 0 is silent: a T0 station submits nothing at all. Nothing was collected "
            "and nothing should be sent.")
    if tier > MAX_SUBMITTABLE_TIER:
        raise TierRefusal(
            f"tier {tier} ({TIER_NAMES.get(tier)}) has no automatic collector and never will. "
            "T4 diagnostics are exported locally by your own admin, read by you, and handed "
            "over per incident — see `--export-diagnostics`.")
    enabled = [(name, fn) for level, (name, fn) in sorted(COLLECTORS.items()) if level <= tier]
    return {name: fn(kube, cfg) for name, fn in enabled}
