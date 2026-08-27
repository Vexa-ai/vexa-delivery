#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-state-report — what is running here, before you upgrade it.

STEP ONE FOR ANY DEPLOYMENT THAT HAS HISTORY, which is nearly all of them. An
operator runs this against their existing estate — a month old or three years
old, one release behind or six — and gets a bundle of plain files describing
the state an upgrade has to survive. They read it. They send it by hand. We
reproduce that state on a throwaway environment, rehearse THEIR upgrade against
it until it is green, and publish the rehearsed upgrade as the first entry of
their channel with the evidence attached.

    workloads.json   images + digests, replicas, resources, chart labels,
                     Kubernetes version, node classes (instance type, GPU)
    db.json          engine + version, migration revision, extensions,
                     per-table row counts, total size
    schema.sql       DDL only — no rows, ever
    probes.json      named invariant probes for known upgrade hazards, each
                     one an aggregate count, each one's SQL printed verbatim
    runtime.json     the transcription reproduction surface: model, size,
                     device, GPU-vs-CPU, allowlisted non-secret env
    report.json      tool version, date, the source of every section above,
                     and the redaction verdict

THREE REFUSALS, and they are the design rather than caveats on it.

1. IT DOES NOT TRANSMIT. There is no --submit, no destination flag and no
   endpoint constant anywhere in this file. It writes an archive, prints the
   path, and stops. What leaves the perimeter leaves because a human read it
   and sent it.

2. IT DOES NOT WRITE. Every cluster read is `kubectl get -o json`. Every
   database session is opened with `default_transaction_read_only=on`, so the
   server refuses a write even if this program had a bug that attempted one,
   and every probe is checked against an aggregate-count-only grammar before
   it goes near a connection.

3. IT CARRIES NO CONTENT. No rows, no meetings, no transcripts, no
   participants — the schema dump is DDL, the counts are integers, and there
   is no field anywhere below that could hold a customer's data. Environment
   capture is ALLOWLIST-FIRST: a variable is excluded unless its name matches
   the reproduction allowlist, so redaction is the second net and not the only
   one.

ABSENT OVER ZERO, everywhere. A source that could not be read is recorded as
absent with a reason. It is never defaulted to zero or to an empty list: zero
is a claim, and a fabricated zero in a document whose entire purpose is to let
somebody else rebuild your environment is worse than a stated gap.

────────────────────────────────────────────────────────────────────────────
ADDING A COLLECTOR — this file expects to be edited by people we have never met

This tool runs in estates we have not seen, and the first thing it will do in
some of them is miss something. That is not a failure mode to apologise for,
it is the lifecycle: the engineer standing in front of the gap is the only
person who can close it, the kit is Apache-2.0, and a patch back is worth more
to us than a support ticket.

So a collector is deliberately small and self-contained:

    def collect_thing(ctx):
        '''One paragraph: what this is for and what it refuses.'''
        out = {"source": "kubectl"}
        doc, err = ctx.kube.get("things")
        if doc is None:
            return ctx.absent_section(out, "things", err)   # absent, not zero
        out["things"] = [...]
        return out

...and then one line in COLLECTORS at the bottom of this file. That is the
whole contract:

  * take `ctx`, return a dict, and put `"source"` in it;
  * the dict IS the file — `("things.json", collect_thing)` writes it;
  * never raise to say "nothing here". Record absent with a reason. If you do
    raise, the driver names your collector, keeps every other section, and the
    report says which one failed — a broken collector must not cost an
    operator their whole run;
  * if you saw a value you decided not to write down, put it in
    `ctx.withheld`. The redaction self-check scans the finished archive for
    everything in that set, so an allowlist you extended stays checkable.

Release-specific hazards are DATA, not code: add a JSON file under
kit/report/probes/ rather than a function. See probes/README.md.
────────────────────────────────────────────────────────────────────────────

    python3 kit/report/vexa_state_report.py --namespace vexa \\
        [--db-host db.internal --db-name vexa --db-user vexa]

Three ways to reach the database, in the order you should try them. `--db-host`
(managed, external, or port-forwarded; the password comes from PGPASSWORD or
~/.pgpass, never from argv). `--db-pod`, which runs psql inside the pod and
therefore needs `create` on `pods/exec` — a privileged verb, declared as such
in docs/upgrade.mdx. Or `kubectl apply -f kit/report/job.yaml`, which
runs the database half from inside the cluster with a read-only ServiceAccount
and no exec at all. With none of them the cluster half is still collected and
the run still succeeds — but every probe reports `not run`, and the tool says
so loudly, because the probes are the only part of this report that reads your
data.

Exit codes: 0 written · 2 usage · 3 redaction leak (the bundle is kept for
inspection and must not be sent). A missing default probe set, an unreadable
resource and an absent database are NOT usage errors: they degrade to `absent`
with a reason and still write a bundle.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import traceback

HERE = pathlib.Path(__file__).resolve().parent
KIT = HERE.parent
REPO = KIT.parent

TOOL = "vexa-state-report"
TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = 1
DEFAULT_PROBE_SET = "v0.12.23"


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── redaction ───────────────────────────────────────────────────────────────
#
# The same blunt rule as the station bundle (kit/validate/vexa_validate.py), on
# purpose and to the letter: a false positive costs one redacted line of
# configuration, a false negative costs a credential. Sharing the WORDING
# matters as much as sharing the behaviour — an operator who has read one
# tool's redaction promise has read both.

SECRET_KEY_RE = re.compile(r"password|token|secret|key|apikey", re.IGNORECASE)
REDACTED = "REDACTED"
# Below this length a "secret" collides with ordinary text more often than it
# is a credential; scanning for it produces noise, not safety.
MIN_LEAK_SCAN_LEN = 6

# Environment variables that describe HOW THE MODEL RUNS, which is the whole
# reproduction surface. An allowlist, not a denylist: everything else is
# dropped before it is written down, so there is nothing left to redact. A name
# matching this AND matching SECRET_KEY_RE is still dropped — the refusal
# outranks the allowlist, which is why MODEL_API_KEY is absent and not
# REDACTED.
ENV_ALLOW_RE = re.compile(
    r"(model|whisper|language|^lang$|_lang|beam|device|cuda|gpu|cpu_threads|"
    r"compute_type|precision|quantiz|vad|replica|scale|concurrency|workers|"
    r"num_workers|batch|chunk|sample_rate|inference|engine|backend)",
    re.IGNORECASE)


def redact(node, key_matched: bool = False, removed=None):
    """A structural copy with secret-looking scalars replaced.

    Structure survives exactly — keys, nesting and list order are the shape of
    the deployment, which is the thing being reported. `key_matched` propagates
    downward, so everything nested under a `secrets:` block is secret whether or
    not each leaf key says so itself.
    """
    if removed is None:
        removed = set()
    if isinstance(node, dict):
        out = {}
        # env-var idiom: [{name: FOO_TOKEN, value: ...}] — the secret is named
        # by a sibling key, not by the key holding it.
        env_named = isinstance(node.get("name"), str) and bool(SECRET_KEY_RE.search(node["name"]))
        for k, v in node.items():
            child = key_matched or bool(SECRET_KEY_RE.search(str(k))) \
                or (env_named and k == "value")
            out[k] = redact(v, child, removed)
        return out
    if isinstance(node, list):
        return [redact(v, key_matched, removed) for v in node]
    if key_matched and node is not None and str(node) != "":
        removed.add(str(node))
        return REDACTED
    return node


# The two shapes a credential takes when it survives into a text dump:
#   ALTER ROLE vexa SET app.api_token = 'tok-...'    key <sep> value
#   OPTIONS (host '...', password 'fdw-...')         key <space> 'value'
# The second form accepts a QUOTED value only. Allowing a bare word after
# whitespace would redact the type in `secret_key text`, which destroys the DDL
# to remove nothing.
TEXT_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)                    # a key
        (?:(?P<sep>\s*[:=]\s*)(?P<value>'[^']*'|"[^"]*"|[^\s,;)]+)
          |(?P<wsep>\s+)(?P<qvalue>'[^']*'|"[^"]*"))
    """, re.VERBOSE)


def redact_text(text: str, removed=None) -> str:
    """The same rule applied to text this program did not assemble.

    schema.sql comes out of `pg_dump`, so it cannot be walked key by key like a
    structure we built. This is the second net over it: any assignment whose key
    looks like a credential loses its value. DDL is not supposed to contain one
    — which is exactly why the day it does is the day this matters.

    It catches assignments, not every possible hiding place: a literal sitting
    in a column DEFAULT two tokens away from a column named `api_key` is not an
    assignment and is not matched. Said out loud rather than left implied,
    because the guarantee an operator can rely on is the allowlist upstream of
    this, and a second net described as a first one is worse than no claim.
    """
    if removed is None:
        removed = set()

    def sub(m):
        if not SECRET_KEY_RE.search(m.group("key")):
            return m.group(0)
        raw = m.group("value") or m.group("qvalue")
        sep = m.group("sep") or m.group("wsep")
        inner = raw[1:-1] if raw[:1] in "'\"" and raw[-1:] == raw[:1] else raw
        if not inner:
            return m.group(0)
        removed.add(inner)
        quote = raw[0] if raw[:1] in "'\"" else ""
        return "%s%s%s%s%s" % (m.group("key"), sep, quote, REDACTED, quote)

    return TEXT_ASSIGNMENT.sub(sub, text)


def scan_for_leaks(root: pathlib.Path, secrets) -> list:
    """Return [(relative path, index of the leaked value)] — never the value.

    Naming the value in the failure message would put the credential into a
    terminal, a CI log and a screenshot, which is the thing this file exists to
    avoid.
    """
    hits = []
    candidates = sorted(s for s in secrets if len(s) >= MIN_LEAK_SCAN_LEN)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        blob = path.read_bytes()
        for i, secret in enumerate(candidates):
            if secret.encode() in blob:
                hits.append((str(path.relative_to(root)), i))
    return hits


def env_allowed(name: str) -> bool:
    if SECRET_KEY_RE.search(name or ""):
        return False                    # the refusal outranks the allowlist
    return bool(ENV_ALLOW_RE.search(name or ""))


# ── the two readers ─────────────────────────────────────────────────────────


class Kube:
    """The narrowest kubectl wrapper that does the job — every call is a read.

    Mirrors kit/validate/collectors.py: `get -o json` and nothing else, and a
    failure returns a reason rather than raising, so a cluster that grants less
    than the documented RBAC still produces the sections it can with the gaps
    named.
    """

    def __init__(self, namespace, kubeconfig=None, context=None, binary="kubectl"):
        self.namespace, self.kubeconfig, self.context = namespace, kubeconfig, context
        self.binary = binary

    def base(self):
        cmd = [self.binary]
        if self.kubeconfig:
            cmd += ["--kubeconfig", self.kubeconfig]
        if self.context:
            cmd += ["--context", self.context]
        return cmd

    def get(self, resource, name=None, namespace=True, timeout=60):
        cmd = self.base() + ["get", resource]
        if name:
            cmd.append(name)
        if namespace:
            cmd += ["-n", self.namespace]
        cmd += ["-o", "json"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            return None, "kubectl get %s: %s" % (resource, type(e).__name__)
        if r.returncode != 0:
            # stderr is NOT carried into the bundle. It is a cluster's own
            # message about a cluster's own objects and routinely names hosts
            # and users; this document promises not to carry that. The reason
            # says what failed, and the operator has their own terminal.
            return None, "kubectl get %s exited %d" % (resource, r.returncode)
        try:
            return json.loads(r.stdout), None
        except ValueError:
            return None, "kubectl get %s returned unparseable json" % resource

    def server_version(self):
        cmd = self.base() + ["version", "-o", "json"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return json.loads(r.stdout).get("serverVersion", {}).get("gitVersion"), None
        except Exception:                                            # noqa: BLE001
            return None, "kubectl version did not answer"


class SqlRefusal(Exception):
    """Named, because a refusal a human cannot act on is an outage."""


# Every probe must be a single aggregate read. Checked before a connection is
# opened, not delegated to the server's good manners.
AGGREGATE_ONLY_RE = re.compile(r"^\s*select\s+count\s*\(", re.IGNORECASE)
FORBIDDEN_SQL_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|grant|revoke|truncate|copy|"
    r"vacuum|reindex|lock|merge|prepare|execute|listen|notify)\b",
    re.IGNORECASE)


def check_probe_sql(sql: str) -> str:
    """Refuse anything that is not one aggregate count. Grammar, not trust.

    The operator is being asked to point this at a production database they
    care about. "It only reads" is a promise; "a statement that is not
    `SELECT count(...)` never reaches a connection" is a property, and the
    property is cheap enough that there is no reason to settle for the promise.
    """
    body = sql.strip().rstrip(";").strip()
    if ";" in body:
        raise SqlRefusal("more than one statement")
    if not AGGREGATE_ONLY_RE.match(body):
        raise SqlRefusal("does not start with SELECT count( — probes are aggregate counts only")
    hit = FORBIDDEN_SQL_RE.search(body)
    if hit:
        raise SqlRefusal("contains the forbidden keyword %r" % hit.group(1).lower())
    return body


UNIT = "\x1f"       # psql -F, chosen so no plausible column value collides with it


class Postgres:
    """psql over one of two transports, both read-only by construction.

    Direct (`--db-url`, or VEXA_REPORT_DB_URL) when the operator can reach the
    database from where they are running this; `kubectl exec` into the database
    pod when they cannot — which on a self-hosted estate is the common case,
    and is why this tool does not require a network route to Postgres.

    THE SESSION IS READ-ONLY AT THE SERVER. Every invocation carries
    `default_transaction_read_only=on`, so a write is refused by Postgres itself
    rather than by this program's good intentions, plus a statement timeout so a
    report can never become an incident.
    """

    def __init__(self, kube, url=None, host=None, port=None, pod=None, container=None,
                 dbname=None, user=None, timeout_ms=30000, binary="psql"):
        self.kube, self.url, self.pod, self.container = kube, url, pod, container
        self.host, self.port = host, port
        self.dbname, self.user, self.binary = dbname, user, binary
        self.pgoptions = ("-c default_transaction_read_only=on "
                          "-c statement_timeout=%d "
                          "-c idle_in_transaction_session_timeout=%d" % (timeout_ms, timeout_ms))

    @property
    def configured(self):
        return bool(self.url or self.host or self.pod)

    @property
    def transport(self):
        if self.url:
            return "--db-url"
        if self.host:
            return "--db-host"
        if self.pod:
            return "kubectl exec %s" % self.pod
        return None

    def argv(self, tool, extra):
        if self.url:
            return [tool, self.url] + extra
        if self.host:
            # HOST/PORT AND NO PASSWORD ANYWHERE ON THE COMMAND LINE. The
            # password comes from PGPASSWORD or ~/.pgpass, both of which the
            # operator already controls — argv is readable in every process
            # listing on the machine, which is exactly the objection --db-url
            # carries and this transport exists to avoid. It is also the only
            # transport that reaches a MANAGED database, which the Vexa chart
            # supports (postgres.enabled=false) and which no amount of
            # `kubectl exec` can talk to, because there is no pod to exec into.
            cmd = [tool, "-h", self.host]
            if self.port:
                cmd += ["-p", str(self.port)]
            if self.user:
                cmd += ["-U", self.user]
            if self.dbname:
                cmd += ["-d", self.dbname]
            return cmd + extra
        # kubectl exec — `create` on pods/exec, which is a privileged verb and
        # is declared as such in docs/upgrade.mdx. It is the last resort
        # of the three on purpose: reach for --db-host first, and for the
        # in-cluster Job (kit/report/job.yaml) when exec is not grantable.
        cmd = self.kube.base() + ["exec", "-n", self.kube.namespace, self.pod]
        if self.container:
            cmd += ["-c", self.container]
        cmd += ["--", "env", "PGOPTIONS=" + self.pgoptions, tool]
        if self.user:
            cmd += ["-U", self.user]
        if self.dbname:
            cmd += ["-d", self.dbname]
        return cmd + extra

    def _run(self, argv, timeout):
        env = dict(os.environ)
        env["PGOPTIONS"] = self.pgoptions
        env.setdefault("PGCONNECT_TIMEOUT", "10")
        try:
            return subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as e:
            return subprocess.CompletedProcess(argv, 1, "", type(e).__name__)

    def query(self, sql, timeout=120):
        """Rows as lists of strings, or (None, reason). Never raises upward."""
        argv = self.argv(self.binary,
                         ["-X", "-q", "-A", "-t", "-F", UNIT,
                          "-v", "ON_ERROR_STOP=1", "-c", sql])
        r = self._run(argv, timeout)
        if r.returncode != 0:
            # The server's error text quotes the statement and names the
            # database; the reason is kept to what failed. The operator sees
            # the full message in their own terminal, where it belongs.
            return None, "psql exited %d" % r.returncode
        rows = [line.split(UNIT) for line in r.stdout.splitlines() if line.strip() != ""]
        return rows, None

    def scalar(self, sql, timeout=120):
        rows, err = self.query(sql, timeout)
        if rows is None:
            return None, err
        if not rows or not rows[0]:
            return None, "query returned no rows"
        return rows[0][0].strip(), None

    def schema_dump(self, timeout=300):
        argv = self.argv("pg_dump", ["--schema-only", "--no-owner", "--no-privileges"])
        r = self._run(argv, timeout)
        if r.returncode != 0 or not r.stdout.strip():
            return None, "pg_dump --schema-only exited %d" % r.returncode
        return r.stdout, None


class Ctx:
    """Everything a collector may read, and the only two things it may write.

    `withheld` is the set of values we SAW and chose not to record. Feeding it
    to the redaction self-check is what makes the allowlist checkable rather
    than merely claimed: if one of them appears anywhere in the finished
    archive, the run exits 3 and names the file.
    """

    def __init__(self, kube, pg, args):
        self.kube, self.pg, self.args = kube, pg, args
        self.withheld = set()
        self.results = {}
        self.notes = []

    @staticmethod
    def absent_section(out, what, reason):
        out.setdefault("absent", []).append({"what": what, "reason": reason})
        return out


# ── collector · workloads ───────────────────────────────────────────────────

# Chart provenance lives on the workload object itself. These are the keys that
# say WHICH chart at WHICH version put it there; the rest of a customer's
# labels are theirs and are not read.
CHART_KEYS = (
    "helm.sh/chart",
    "meta.helm.sh/release-name",
    "meta.helm.sh/release-namespace",
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/version",
    "app.kubernetes.io/managed-by",
    "app.kubernetes.io/component",
    "argocd.argoproj.io/instance",
)

WORKLOAD_KINDS = (
    ("deployments.apps", "Deployment"),
    ("statefulsets.apps", "StatefulSet"),
    ("daemonsets.apps", "DaemonSet"),
    ("cronjobs.batch", "CronJob"),
)

GPU_RESOURCES = ("nvidia.com/gpu", "amd.com/gpu", "gpu.intel.com/i915", "habana.ai/gaudi")


def _chart_meta(meta):
    picked = {}
    for source in ("labels", "annotations"):
        for k, v in (meta.get(source) or {}).items():
            if k in CHART_KEYS:
                picked[k] = v
    return picked


def _pod_template(obj, kind):
    spec = obj.get("spec") or {}
    if kind == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def _containers(pod_spec, withheld):
    """Container identity and resources. NO env here — env belongs to
    runtime.json, behind the allowlist, and duplicating it into a second
    section would be a second door onto the same room with a different lock."""
    rows = []
    for group, init in (("containers", False), ("initContainers", True)):
        for c in (pod_spec.get(group) or []):
            res = c.get("resources") or {}
            gpu = {}
            for bucket in ("requests", "limits"):
                for name in GPU_RESOURCES:
                    if name in (res.get(bucket) or {}):
                        gpu[name] = (res[bucket])[name]
            rows.append({
                "name": c.get("name"),
                "init": init,
                "image": c.get("image"),
                "requests": (res.get("requests") or None),
                "limits": (res.get("limits") or None),
                "gpu": gpu or None,
            })
            # Every env value we are NOT writing down is still a value we saw.
            for e in (c.get("env") or []):
                v = e.get("value")
                if isinstance(v, str) and v and not env_allowed(e.get("name") or ""):
                    withheld.add(v)
    return rows


def _owner_of(pod):
    """Map a pod back to its workload by naming convention.

    Deliberately convention-based rather than an ownerReferences walk up to the
    Deployment: walking needs RBAC on replicasets, which is more read access
    than an image digest is worth asking a bank for. When the convention does
    not hold, the pod lands under `(unowned)` and is still reported — a missing
    grouping, never a missing image.
    """
    for ref in ((pod.get("metadata") or {}).get("ownerReferences") or []):
        name, kind = ref.get("name") or "", ref.get("kind")
        if kind in ("ReplicaSet", "Job"):
            return name.rsplit("-", 1)[0] if "-" in name else name
        if kind in ("StatefulSet", "DaemonSet"):
            return name
    return None


def _running_digests(ctx, out):
    """What is ACTUALLY running, read from pods rather than from the spec.

    The spec says what should be running; the pods say what is. Drift between
    the two is the single most useful thing an upgrade report can carry, and
    reading the spec for both sides of that comparison would make it
    structurally undetectable.
    """
    pods, err = ctx.kube.get("pods")
    if not pods:
        Ctx.absent_section(out, "running image digests", err or "pods not readable")
        return None
    by_owner = {}
    for p in pods.get("items", []):
        owner = _owner_of(p) or "(unowned)"
        for cs in ((p.get("status") or {}).get("containerStatuses") or []):
            image_id = cs.get("imageID") or ""
            if "@sha256:" not in image_id:
                continue
            repo, digest = image_id.rsplit("@", 1)
            if repo.startswith("docker-pullable://"):
                repo = repo[len("docker-pullable://"):]
            row = {"container": cs.get("name"), "repository": repo, "digest": digest,
                   "image": cs.get("image")}
            if row not in by_owner.setdefault(owner, []):
                by_owner[owner].append(row)
    return by_owner


def _node_classes(ctx, out):
    """Nodes grouped by SHAPE, and deliberately not by name.

    A reproduction needs to know there are three 16-core GPU nodes; it does not
    need to know what they are called, and node names in a document that leaves
    a perimeter are inventory. Grouping is the honest form of the same fact and
    drops the names as a consequence rather than as a promise.
    """
    nodes, err = ctx.kube.get("nodes", namespace=False)
    if not nodes:
        Ctx.absent_section(
            out, "node inventory",
            (err or "nodes not readable") + " — needs cluster-scoped node read; the "
            "minimal RBAC is in docs/upgrade.mdx. The rest of the report is "
            "unaffected.")
        return None
    classes = {}
    for n in nodes.get("items", []):
        labels = (n.get("metadata") or {}).get("labels") or {}
        status = n.get("status") or {}
        cap, alloc = status.get("capacity") or {}, status.get("allocatable") or {}
        info = status.get("nodeInfo") or {}
        gpu = {}
        for name in GPU_RESOURCES:
            if alloc.get(name) or cap.get(name):
                gpu[name] = alloc.get(name) or cap.get(name)
        for key in ("nvidia.com/gpu.product", "nvidia.com/gpu.memory",
                    "nvidia.com/cuda.driver.major"):
            if labels.get(key):
                gpu[key] = labels[key]
        shape = {
            "instance_type": labels.get("node.kubernetes.io/instance-type")
            or labels.get("beta.kubernetes.io/instance-type"),
            "region": labels.get("topology.kubernetes.io/region"),
            "arch": info.get("architecture"),
            "os_image": info.get("osImage"),
            "kernel": info.get("kernelVersion"),
            "container_runtime": info.get("containerRuntimeVersion"),
            "kubelet": info.get("kubeletVersion"),
            "cpu_capacity": cap.get("cpu"),
            "memory_capacity": cap.get("memory"),
            "pods_capacity": cap.get("pods"),
            "gpu": gpu or None,
        }
        key = json.dumps(shape, sort_keys=True)
        classes.setdefault(key, dict(shape, count=0))
        classes[key]["count"] += 1
    rows = sorted(classes.values(), key=lambda r: (-r["count"], str(r["instance_type"])))
    return {"total": sum(r["count"] for r in rows), "classes": rows,
            "note": "grouped by shape; node names are not collected"}


def collect_workloads(ctx):
    """Per-workload image refs and digests, replicas, resources, chart
    provenance, Kubernetes version, node shapes. The cluster half of a
    reproduction."""
    out = {"source": "kubectl", "namespace": ctx.kube.namespace, "collected_at": utcnow()}

    version, err = ctx.kube.server_version()
    if version:
        out["kubernetes_server_version"] = version
    else:
        Ctx.absent_section(out, "kubernetes server version", err)

    digests = _running_digests(ctx, out)
    rows = []
    for resource, kind in WORKLOAD_KINDS:
        doc, err = ctx.kube.get(resource)
        if doc is None:
            Ctx.absent_section(out, resource, err or "not readable")
            continue
        for obj in doc.get("items", []):
            meta, spec, status = (obj.get("metadata") or {}, obj.get("spec") or {},
                                  obj.get("status") or {})
            row = {
                "kind": kind,
                "name": meta.get("name"),
                "chart": _chart_meta(meta) or None,
                "containers": _containers(_pod_template(obj, kind), ctx.withheld),
            }
            if kind in ("Deployment", "StatefulSet"):
                row["replicas"] = {"desired": spec.get("replicas"),
                                   "ready": status.get("readyReplicas"),
                                   "available": status.get("availableReplicas")}
            elif kind == "DaemonSet":
                row["replicas"] = {"desired": status.get("desiredNumberScheduled"),
                                   "ready": status.get("numberReady")}
            elif kind == "CronJob":
                row["schedule"] = spec.get("schedule")
                row["suspended"] = bool(spec.get("suspend"))
            if digests is not None:
                row["running"] = digests.get(meta.get("name")) or []
            rows.append(row)
    out["workloads"] = sorted(rows, key=lambda r: (r["kind"], str(r["name"])))
    if not out["workloads"]:
        out["source"] = "absent"
        Ctx.absent_section(out, "workloads",
                           "no Deployment, StatefulSet, DaemonSet or CronJob was readable "
                           "in namespace %r" % ctx.kube.namespace)
    if digests is not None:
        named = {r["name"] for r in rows}
        orphans = {k: v for k, v in digests.items() if k not in named}
        if orphans:
            # Bot pods are spawned per meeting and belong to no Deployment.
            # They are the most upgrade-sensitive image in the estate, so
            # losing them to a grouping convention would be the wrong tidy.
            # They stay under `(unowned)` rather than under their pod names:
            # a per-meeting pod is NAMED after the meeting, and a meeting id is
            # the one thing this document promises not to carry.
            out["unowned_running_images"] = orphans

    nodes = _node_classes(ctx, out)
    if nodes:
        out["nodes"] = nodes
    return out


# ── collector · database ────────────────────────────────────────────────────

DB_SCALARS = (
    ("server_version", "SELECT current_setting('server_version')"),
    ("server_version_full", "SELECT version()"),
    ("database", "SELECT current_database()"),
    ("size_bytes", "SELECT pg_database_size(current_database())"),
)

EXTENSIONS_SQL = "SELECT extname, extversion FROM pg_extension ORDER BY extname"

# reltuples, not count(*). An exact count of every table on a production
# database is a scan per table, and a report is not worth an I/O storm.
# reltuples is -1 when a table has never been analysed, which is reported as
# null-with-a-reason rather than as zero — absent over zero, again.
ROWCOUNT_ESTIMATE_SQL = """
SELECT n.nspname, c.relname, c.reltuples::bigint, pg_total_relation_size(c.oid)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema')
ORDER BY n.nspname, c.relname
"""

TABLES_SQL = """
SELECT table_schema, table_name FROM information_schema.tables
WHERE table_type = 'BASE TABLE'
  AND table_schema NOT IN ('pg_catalog','information_schema')
ORDER BY table_schema, table_name
"""

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def safe_identifier(name):
    if not IDENTIFIER_RE.match(name or ""):
        raise SystemExit("%s: %r is not a plain SQL identifier and this tool will not "
                         "interpolate it" % (TOOL, name))
    return name


def collect_db(ctx):
    """Engine, version, migration revision, extensions, per-table row counts,
    total size. Integers and identifiers; no rows leave."""
    out = {"source": "psql", "engine": "postgresql", "collected_at": utcnow()}
    pg = ctx.pg
    if not pg.configured:
        out["source"] = "absent"
        return Ctx.absent_section(
            out, "database",
            "no database source given (--db-host, --db-url or --db-pod; or run the "
            "in-cluster Job at kit/report/job.yaml). The DB sections are absent, not "
            "empty — nothing here should be read as 'the database is fine'.")

    for key, sql in DB_SCALARS:
        value, err = pg.scalar(sql)
        if value is None:
            Ctx.absent_section(out, key, err)
        else:
            out[key] = int(value) if key.endswith("_bytes") else value

    out["migration"] = _collect_migration(ctx, pg)

    rows, err = pg.query(EXTENSIONS_SQL)
    if rows is None:
        Ctx.absent_section(out, "extensions", err)
    else:
        out["extensions"] = [{"name": r[0].strip(), "version": r[1].strip()}
                             for r in rows if len(r) >= 2]

    out["tables"] = _collect_row_counts(ctx, pg, out)
    if len(out) <= 4:
        out["source"] = "absent"
    return out


def _collect_migration(ctx, pg):
    """The migration revision — AND the fact that Vexa may not have one.

    This is worth stating plainly because a reader will otherwise draw the
    wrong conclusion from an empty field. Vexa's admin-api converges the
    database to its SQLAlchemy metadata at startup (`ensure_schema`); it runs
    no Alembic and writes no version table. On a Vexa estate an absent
    `alembic_version` is THE EXPECTED ANSWER, not a defect and not a gap in
    this tool.

    The query still runs, because the table is read here for two other reasons
    that both matter: an estate may carry one from an older or adjacent
    component, and when it exists, MORE THAN ONE ROW means branched heads —
    exactly the state a rehearsal has to know about, and exactly what reading
    a scalar would hide.
    """
    table = ctx.args.alembic_table
    rows, err = pg.query("SELECT version_num FROM %s ORDER BY version_num"
                         % safe_identifier(table))
    if rows is not None:
        return {"scheme": "alembic", "table": table,
                "revisions": [r[0].strip() for r in rows],
                "branched_heads": len(rows) > 1}
    return {
        "scheme": None,
        "table": table,
        "revisions": None,
        "reason": "%s — table %r was not readable" % (err, table),
        "note": "Vexa's admin-api converges the schema from SQLAlchemy metadata at "
                "startup (ensure_schema) and runs no Alembic, so on a Vexa estate this "
                "table legitimately does not exist. What stands in for a revision here "
                "is the schema itself plus the probes: see probes.json. Pass "
                "--alembic-table if your estate names a version table differently.",
    }


def _collect_row_counts(ctx, pg, out):
    if ctx.args.exact_row_counts:
        rows, err = pg.query(TABLES_SQL)
        if rows is None:
            Ctx.absent_section(out, "table list for exact counts", err)
            return None
        counts = []
        for schema, table in [(r[0].strip(), r[1].strip()) for r in rows if len(r) >= 2]:
            value, qerr = pg.scalar('SELECT count(*) FROM "%s"."%s"' % (schema, table))
            counts.append({"schema": schema, "table": table,
                           "rows": int(value) if value is not None else None,
                           "reason": None if value is not None else qerr})
        return {"method": "count(*) per table (--exact-row-counts)",
                "count": len(counts), "rows": counts}

    rows, err = pg.query(ROWCOUNT_ESTIMATE_SQL)
    if rows is None:
        Ctx.absent_section(out, "row counts", err)
        return None
    counts = []
    for r in rows:
        if len(r) < 4:
            continue
        est = int(r[2])
        counts.append({
            "schema": r[0].strip(), "table": r[1].strip(),
            # -1 means never analysed. Not zero. A table nobody has analysed is
            # not an empty table, and rendering the two the same is how a
            # rehearsal gets sized against nothing.
            "rows": None if est < 0 else est,
            "reason": ("never analysed (reltuples = -1); run ANALYZE or pass "
                       "--exact-row-counts") if est < 0 else None,
            "total_bytes": int(r[3]),
        })
    return {"method": "pg_class.reltuples (planner estimate, no table scan)",
            "count": len(counts), "rows": counts}


# ── collector · schema ──────────────────────────────────────────────────────

# The fallback when pg_dump is not reachable. Not real DDL, and labelled as
# such inside the file it produces: a reconstruction that pretends to be a dump
# is how somebody restores from it and loses a constraint.
FALLBACK_COLUMNS_SQL = """
SELECT table_schema, table_name, ordinal_position, column_name, data_type,
       coalesce(character_maximum_length::text,''), is_nullable,
       coalesce(column_default,'')
FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog','information_schema')
ORDER BY table_schema, table_name, ordinal_position
"""
FALLBACK_INDEXES_SQL = """
SELECT schemaname, tablename, indexname, indexdef FROM pg_indexes
WHERE schemaname NOT IN ('pg_catalog','information_schema')
ORDER BY schemaname, tablename, indexname
"""


def collect_schema(ctx):
    """DDL only — the dump when we can get one, a labelled reconstruction when
    we cannot, and nothing at all when neither works. `text` in the returned
    dict becomes schema.sql; it is never a row."""
    out = {"source": "absent"}
    pg = ctx.pg
    if not pg.configured:
        return Ctx.absent_section(out, "schema", "no database source given")

    text, err = pg.schema_dump()
    if text:
        out["source"] = "pg_dump --schema-only"
        out["text"] = redact_text(text, ctx.withheld)
        return out

    cols, cerr = pg.query(FALLBACK_COLUMNS_SQL)
    idx, ierr = pg.query(FALLBACK_INDEXES_SQL)
    if cols is None:
        return Ctx.absent_section(
            out, "schema", "%s; information_schema fallback also failed: %s" % (err, cerr))

    lines = [
        "-- Vexa state report — schema RECONSTRUCTED from information_schema.",
        "-- pg_dump was not reachable here (%s), so this is NOT a dump and must not" % err,
        "-- be restored from. It lists columns and indexes so a rehearsal can build an",
        "-- equivalent schema; constraints, triggers, functions and sequences that",
        "-- information_schema does not expose are NOT here.",
        "",
    ]
    current = None
    for r in cols:
        if len(r) < 8:
            continue
        schema, table, _, column, dtype, maxlen, nullable, default = [x.strip() for x in r[:8]]
        if (schema, table) != current:
            if current:
                lines += [");", ""]
            lines.append('CREATE TABLE "%s"."%s" (' % (schema, table))
            current = (schema, table)
        typ = "%s(%s)" % (dtype, maxlen) if maxlen else dtype
        lines.append('    "%s" %s%s%s' % (
            column, typ, "" if nullable == "YES" else " NOT NULL",
            " DEFAULT %s" % default if default else ""))
    if current:
        lines.append(");")
    lines.append("")
    lines.append("-- indexes: NOT READABLE (%s)" % ierr if idx is None
                 else "-- indexes")
    for r in (idx or []):
        if len(r) >= 4:
            lines.append("%s;" % r[3].strip())

    out["source"] = "information_schema (reconstruction, not a dump)"
    out["pg_dump_reason"] = err
    out["text"] = redact_text("\n".join(lines) + "\n", ctx.withheld)
    return out


# ── collector · probes ──────────────────────────────────────────────────────


def load_probe_set(name, explicit=False):
    """A probe set is DATA, not code, and it is versioned by release.

    The hazards an upgrade has to clear are release-specific and they accrete:
    every migration that adds a constraint to a table that already holds rows
    is a probe somebody should have run first. Keeping them as files under
    kit/report/probes/ means adding one is a data change an operator can read
    in full before running it — which is the only reason they should believe
    the SQL is a count.

    MISSING IS NOT FATAL WHEN NOBODY ASKED FOR IT. Operators copy one file to a
    jump box — this tool is a single script on purpose — and `probes/` does not
    travel with it. Killing the run there cost the whole report to a missing
    data file, in a tool whose own rule is that a broken section must not cost
    an operator their run. So an ABSENT DEFAULT DEGRADES: probes.json records
    absent with a reason and a remedy, every other section is collected, and
    the exit code stays 0.

    A probe set the operator NAMED and that does not exist is the other case
    and stays fatal — they asked for something specific and did not get it,
    which is a usage error and exits 2, the documented code. Silently reporting
    absent there would answer a question they did not ask.
    """
    if name in (None, "", "none"):
        return None, {"source": "disabled", "reason": "--probe-set none"}
    path = pathlib.Path(name)
    if not path.is_file():
        path = HERE / "probes" / ("%s.json" % name)
    if not path.is_file():
        available = sorted(p.stem for p in (HERE / "probes").glob("*.json"))
        if explicit:
            sys.stderr.write(
                "%s: no probe set %r (available here: %s)\n"
                % (TOOL, name, ", ".join(available) or "none — this tool has no "
                   "probes/ directory beside it"))
            raise SystemExit(2)
        return None, {
            "source": "absent",
            "reason": "the default probe set %r was not found beside this tool, and "
                      "%s. Copy kit/report/probes/ next to vexa_state_report.py, or "
                      "pass --probe-set /path/to/<set>.json. Every other section was "
                      "still collected — but the probes are the only part of this "
                      "report that reads your data, so this bundle cannot say whether "
                      "the upgrade would break on rows you already have."
                      % (name, "the probes/ directory does not exist" if not available
                         else "the sets present are: %s" % ", ".join(available)),
        }
    try:
        rel = str(path.resolve().relative_to(REPO))
    except ValueError:
        rel = str(path)
    return json.loads(path.read_text()), {"source": rel}


def evaluate(expect, count):
    """Does the count satisfy the probe's expectation? None when unknown.

    `expect` is explicit per probe rather than "0 is good", because the useful
    probes are not all the same polarity: a duplicate-row probe expects zero,
    and an index-exists probe expects one. Inferring polarity from a convention
    is how a green report gets printed for a missing index.
    """
    if count is None or not isinstance(expect, dict):
        return None
    if "equals" in expect:
        return count == expect["equals"]
    if "at_least" in expect:
        return count >= expect["at_least"]
    if "at_most" in expect:
        return count <= expect["at_most"]
    return None


def collect_probes(ctx):
    """Named invariant probes for known upgrade hazards.

    Every probe's SQL is printed VERBATIM whether or not it ran. That is the
    point of the file: the operator reads exactly what was asked of their
    database, in the same document that reports the answer, and never has to
    trust that a name like "active-meeting uniqueness" means what it says.
    """
    probe_set, meta = load_probe_set(ctx.args.probe_set,
                                     explicit=ctx.args.probe_set_explicit)
    out = {"source": meta.get("source"), "collected_at": utcnow(),
           "probe_set": (probe_set or {}).get("probe_set"),
           "description": (probe_set or {}).get("description"),
           "probes": []}
    if not probe_set:
        out["degraded"] = meta.get("source") if meta.get("source") != "disabled" else None
        return Ctx.absent_section(out, "probes", meta.get("reason", "no probe set"))
    if not ctx.pg.configured:
        # Machine-readable, so the console warning and the bundle agree and a
        # reader of the JSON alone cannot mistake "not run" for "nothing found".
        out["degraded"] = "no-database-source"

    for spec in probe_set.get("probes", []):
        row = {"name": spec.get("name"), "hazard": spec.get("hazard"),
               "migration": spec.get("migration"), "expect": spec.get("expect"),
               "if_violated": spec.get("if_violated"),
               "sql": spec.get("sql"), "count": None, "holds": None, "reason": None}
        if spec.get("todo"):
            row["todo"] = spec["todo"]
        try:
            body = check_probe_sql(spec.get("sql") or "")
        except SqlRefusal as e:
            row["reason"] = "refused before execution: %s" % e
            out["probes"].append(row)
            continue
        if not ctx.pg.configured:
            row["reason"] = ("no database source given (--db-host / --db-url / "
                             "--db-pod); this probe was not run")
        elif spec.get("todo"):
            # A probe whose columns are marked unverified must not produce a
            # number. A wrong zero here reads as "your data is clean" and is
            # the most expensive thing this file could possibly say.
            row["reason"] = ("not run: marked TODO — unverified against the shipped "
                             "schema, and a number from an unverified probe is worse "
                             "than no number")
        else:
            value, err = ctx.pg.scalar(body)
            if value is None:
                row["reason"] = err
            else:
                try:
                    row["count"] = int(value)
                except ValueError:
                    row["reason"] = "probe did not return an integer"
        row["holds"] = evaluate(row["expect"], row["count"])
        out["probes"].append(row)

    out["violations"] = [p["name"] for p in out["probes"] if p["holds"] is False]
    out["not_run"] = [p["name"] for p in out["probes"] if p["holds"] is None]
    return out


# ── collector · runtime ─────────────────────────────────────────────────────

TRANSCRIPTION_DEFAULT_MATCH = "whisper|transcri|asr|diariz|stt"
DEVICE_ENV_RE = re.compile(r"device|cuda|gpu", re.IGNORECASE)
MODEL_ENV_RE = re.compile(r"model|whisper", re.IGNORECASE)


def _device_of(env, gpu_requested):
    """What can be said, and no more.

    An explicit DEVICE variable is a statement. A GPU resource request is
    strong evidence. Neither present is UNKNOWN — not "cpu", which is the
    default a reader would assume and the one that quietly produces a rehearsal
    on the wrong hardware.
    """
    for e in env:
        if DEVICE_ENV_RE.search(e.get("name") or "") and e.get("value"):
            return {"value": e["value"], "from": e["name"]}
    if gpu_requested:
        return {"value": "gpu", "from": "resource request (no explicit device env)"}
    return {"value": None, "from": None,
            "reason": "no device env var and no GPU resource request; NOT assumed to be CPU"}


def _model_of(env):
    hits = [e for e in env if MODEL_ENV_RE.search(e.get("name") or "") and e.get("value")]
    if not hits:
        return {"value": None, "reason": "no model env var on this container"}
    return {"value": hits[0]["value"], "from": hits[0]["name"],
            "all": [{"name": e["name"], "value": e["value"]} for e in hits]}


def _env_by_owner(ctx, out):
    pods, err = ctx.kube.get("pods")
    if not pods:
        Ctx.absent_section(out, "pod environment", err or "pods not readable")
        return {}
    found = {}
    for p in pods.get("items", []):
        owner = _owner_of(p) or "(unowned)"
        for c in ((p.get("spec") or {}).get("containers") or []):
            rows = []
            for e in (c.get("env") or []):
                name = e.get("name") or ""
                if "valueFrom" in e:
                    # The NAME is configuration; the value lives in a Secret or
                    # ConfigMap and is not read. Recording the source tells a
                    # rehearsal what it must provide without carrying it.
                    rows.append({"name": name,
                                 "from": next(iter(e["valueFrom"] or {}), "unknown")})
                    continue
                v = e.get("value")
                if env_allowed(name):
                    rows.append({"name": name, "value": v})
                elif isinstance(v, str) and v:
                    ctx.withheld.add(v)
            if rows:
                found.setdefault(owner, {})[c.get("name")] = rows
    return found


def collect_runtime(ctx):
    """The transcription reproduction surface, and only that.

    A rehearsal that runs the customer's migration against the customer's
    schema on a CPU box, when they run a GPU model at a different beam size,
    has rehearsed something else. This section exists so the throwaway
    environment is the same MACHINE and not merely the same database.
    """
    out = {"source": "kubectl", "collected_at": utcnow(),
           "selector": ctx.args.transcription_match, "workloads": []}
    workloads = ctx.results.get("workloads.json") or {}
    match = re.compile(ctx.args.transcription_match, re.IGNORECASE)
    env_by_owner = _env_by_owner(ctx, out)

    for w in workloads.get("workloads", []):
        containers = w.get("containers") or []
        if not match.search(w.get("name") or "") and not any(
                match.search(c.get("image") or "") for c in containers):
            continue
        rows = []
        for c in containers:
            env = (env_by_owner.get(w["name"]) or {}).get(c["name"]) or []
            image = c.get("image") or ""
            rows.append({
                "name": c["name"],
                "image": image,
                "image_tag": image.rsplit(":", 1)[-1]
                if ":" in image and "@" not in image else None,
                "requests": c.get("requests"), "limits": c.get("limits"),
                "gpu_requested": c.get("gpu"),
                "inference_device": _device_of(env, bool(c.get("gpu"))),
                "model": _model_of(env),
                "env": env or None,
            })
        out["workloads"].append({
            "name": w["name"], "kind": w["kind"], "replicas": w.get("replicas"),
            "running": w.get("running"), "containers": rows or None,
        })
    if not out["workloads"]:
        out["source"] = "absent"
        Ctx.absent_section(
            out, "transcription workloads",
            "no workload in namespace %r matched %r — widen it with "
            "--transcription-match. This is ABSENT, not 'CPU inference'."
            % (ctx.kube.namespace, ctx.args.transcription_match))
    return out


# ── the registry ────────────────────────────────────────────────────────────
#
# One line per section. A collector takes ctx, returns a dict carrying
# "source", and that dict is the file. A returned "text" key is written to the
# named file instead — that is how schema.sql stays plain SQL.

COLLECTORS = (
    ("workloads.json", collect_workloads),
    ("db.json", collect_db),
    ("schema.sql", collect_schema),
    ("probes.json", collect_probes),
    ("runtime.json", collect_runtime),
)


# ── the bundle ──────────────────────────────────────────────────────────────

README = """Vexa upgrade state report.

NOTHING HERE HAS BEEN SENT ANYWHERE. This archive was written to your disk by a
command you typed. There is no transmit path in the tool that produced it: no
--submit, no destination, no endpoint. You read these files, then you send them
by whatever means your policy allows — or you do not.

What is in it
  report.json     what ran, when, and where every section below came from
  workloads.json  images and digests actually running, replicas, resources,
                  chart labels, Kubernetes version, node shapes
  db.json         engine, version, migration revision, extensions, row counts
  schema.sql      DDL only
  probes.json     the invariant probes, each with the exact SQL that was run
  runtime.json    the transcription reproduction surface

What is NOT in it, by construction: rows, meeting content, transcripts,
participants, credentials, and any environment variable that is not on the
reproduction allowlist in the tool's own source.

What we do with it: reproduce this state on a throwaway environment, rehearse
your upgrade against it until it is green, and publish the rehearsed upgrade as
the first entry of your channel with the evidence attached.

The kit is Apache-2.0. If this missed something your environment needed, the
collector you want is about twenty lines — see "ADDING A COLLECTOR" at the top
of kit/report/vexa_state_report.py — and a pull request is worth more to us
than a support ticket.
"""


def git_revision():
    """Which kit produced this report — or an honest null.

    Two sources, and the second exists because of the first's blind spot: on a
    workstation the kit is a git checkout, and inside the kit runtime image
    there is neither a .git nor a git binary, both left out on purpose.
    """
    out = {"commit": None, "describe": None}
    for field, args in (("commit", ["rev-parse", "--short", "HEAD"]),
                        ("describe", ["describe", "--tags", "--always", "--dirty"])):
        try:
            r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
        except OSError:
            break
        if r.returncode == 0:
            out[field] = r.stdout.strip()
    if out["commit"] or out["describe"]:
        return out
    stamp = REPO / "KIT_REVISION"
    if stamp.is_file():
        for line in stamp.read_text().splitlines():
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key in out and value and value != "unknown":
                out[key] = value
    return out


def run_collectors(ctx):
    """Run every collector; a broken one costs its own section and nothing else.

    This is the contribute-back property in one function. A collector written
    for an estate nobody here has seen WILL raise somewhere eventually, and the
    operator running it should still get the other five sections plus a line
    naming which collector failed — not a traceback and an empty directory.
    """
    files, sections = {}, {}
    for filename, fn in COLLECTORS:
        try:
            result = fn(ctx)
        except SystemExit:
            raise
        except Exception as e:                                       # noqa: BLE001
            print("!! collector %s (%s) failed: %s: %s"
                  % (fn.__name__, filename, type(e).__name__, e))
            print("   every other section still ran. This is a bug worth a PR — the "
                  "traceback is in report.json under sections.")
            sections[filename] = {
                "source": "absent",
                "reason": "collector %s raised %s: %s" % (fn.__name__, type(e).__name__, e),
                "traceback_tail": traceback.format_exc().strip().splitlines()[-3:],
            }
            continue
        ctx.results[filename] = result
        sections[filename] = {"source": result.get("source"),
                              "collector": fn.__name__}
        for key in ("pg_dump_reason", "reason"):
            if result.get(key):
                sections[filename][key] = result[key]
        # A .json section IS its dict. A text section carries "text" or writes
        # nothing at all — an absent schema must leave no schema.sql behind,
        # because a file that exists and says nothing reads as a schema with
        # nothing in it.
        if filename.endswith(".json"):
            files[filename] = json.dumps(redact(result, removed=ctx.withheld),
                                         indent=2) + "\n"
        else:
            text = result.pop("text", None)
            if text is not None:
                files[filename] = text
    return files, sections


def build(a):
    kube = Kube(a.namespace, kubeconfig=a.kubeconfig, context=a.context)
    db_url = a.db_url or os.environ.get("VEXA_REPORT_DB_URL")
    pg = Postgres(kube, url=db_url, host=a.db_host, port=a.db_port,
                  pod=a.db_pod, container=a.db_container,
                  dbname=a.db_name, user=a.db_user, timeout_ms=a.sql_timeout_ms)
    ctx = Ctx(kube, pg, a)
    if db_url:
        # A DSN carries a password. It is never written into the bundle, and
        # its password goes into the leak scan so that if it does turn up
        # anywhere the run fails now rather than the operator finding out later.
        m = re.search(r"://[^:/@]+:([^@]+)@", db_url)
        if m:
            ctx.withheld.add(m.group(1))

    print("== %s %s — reading, never writing" % (TOOL, TOOL_VERSION))
    print("   namespace: %s" % a.namespace)
    print("   database:  %s" % (pg.transport or "ABSENT (no source given) — the probes "
                                "will not run; see the warning at the end"))

    files, sections = run_collectors(ctx)

    out_dir = pathlib.Path(a.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="vexa-state-report-"))
    try:
        stage = tmp / "state-report"
        stage.mkdir()
        (stage / "README.txt").write_text(README)
        for filename, body in files.items():
            (stage / filename).write_text(body)

        absent = []
        for filename, result in ctx.results.items():
            for row in (result.get("absent") or []):
                absent.append(dict(row, section=filename))

        report = {
            "schema_version": SCHEMA_VERSION,
            "tool": TOOL,
            "tool_version": TOOL_VERSION,
            "generated_at": utcnow(),
            "kit": git_revision(),
            "namespace": a.namespace,
            "sections": sections,
            "absent": absent,
            "refuses": [
                "transmit: there is no submit path in this tool",
                "write: every DB session sets default_transaction_read_only=on and "
                "every probe is checked against an aggregate-count-only grammar",
                "content: no rows, no meetings, no transcripts, no participants",
            ],
            "redaction": {
                "rule": "values under keys matching password|token|secret|key|apikey -> "
                        "REDACTED; environment capture is allowlist-first, so most "
                        "values are never written rather than redacted after",
                "withheld_values": len(ctx.withheld),
                "verified": None, "leaks": None,
            },
        }
        if not a.verify_redaction:
            report["redaction"]["verified"] = False
            report["redaction"]["note"] = "--no-verify-redaction: NOT checked"
        else:
            staged_leaks = scan_for_leaks(stage, ctx.withheld)
            report["redaction"]["verified"] = not staged_leaks
            report["redaction"]["leaks"] = len(staged_leaks)
            if staged_leaks:
                report["redaction"]["leaking_files"] = sorted({p for p, _ in staged_leaks})
        report["contents"] = sorted([p.name for p in stage.iterdir()] + ["report.json"])
        (stage / "report.json").write_text(json.dumps(report, indent=2) + "\n")

        archive = out_dir / "state-report.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(stage, arcname="state-report")

        # Check WHAT WAS WRITTEN, not what we think we wrote: re-extract the
        # finished archive and scan that. A bug between the staging directory
        # and the tar would otherwise be invisible.
        leaks = []
        if a.verify_redaction:
            with tempfile.TemporaryDirectory() as verify_dir:
                with tarfile.open(archive) as tar:
                    try:
                        tar.extractall(verify_dir, filter="data")
                    except TypeError:          # python < 3.12 has no filters
                        tar.extractall(verify_dir)
                leaks = scan_for_leaks(pathlib.Path(verify_dir), ctx.withheld)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return archive, report, ctx.results.get("probes.json") or {}, leaks


def render(archive, report, probes, leaks):
    print("\n%s" % archive)
    for name in report["contents"]:
        print("  state-report/%s" % name)
    print("\nsections: " + " · ".join(
        "%s %s" % (k, v.get("source") or "absent") for k, v in report["sections"].items()))
    for row in report["absent"]:
        print("  absent · %s (%s) — %s" % (row.get("what"), row.get("section"),
                                           row.get("reason")))
    for p in probes.get("probes", []):
        state = "%d" % p["count"] if isinstance(p["count"], int) else "not run"
        mark = {True: "ok", False: "VIOLATED", None: "--"}[p["holds"]]
        print("probe %-46s %-8s %s%s" % (p["name"], state, mark,
                                         "" if not p["reason"] else "  (%s)" % p["reason"]))
    if probes.get("violations"):
        print("\n!! %d invariant probe(s) do not hold: %s"
              % (len(probes["violations"]), ", ".join(probes["violations"])))
        print("   That is what this report is FOR. Nothing is broken yet; the upgrade "
              "would break on it.")

    # THE DEGRADED RUN IS THE ONE THAT NEEDS THE LOUDEST LINE.
    #
    # A run with no database source succeeds, writes a bundle, exits 0 and
    # reports every probe as `not run` in a column an operator reads as
    # unremarkable. But the probes are the only part of this report that reads
    # THEIR data — everything else is an inventory of images and shapes — so a
    # quiet degraded run is the failure that costs the most and announces
    # itself the least. It stays exit 0 (a bundle WAS written, and the cluster
    # half of it is worth sending) and it does not get to be quiet.
    if probes.get("degraded"):
        names = probes.get("not_run") or []
        if probes["degraded"] == "no-database-source":
            print("\n!! %d of %d invariant probes DID NOT RUN — no database source:"
                  % (len(names), len(probes.get("probes") or names)))
            for name in names:
                print("     %s" % name)
            print("   These are the only part of this report that reads YOUR data.")
            print("   Without them this bundle is an inventory of images and shapes: it")
            print("   cannot say whether the upgrade would break on rows you already have.")
            print("   Give it a database — any ONE of:")
            print("     --db-host <host> [--db-port] --db-name <db> --db-user <user>"
                  "   (managed or external; password via PGPASSWORD or ~/.pgpass)")
            print("     --db-pod <pod> --db-name <db> --db-user <user>"
                  "                    (needs create on pods/exec)")
            print("     kubectl apply -f kit/report/job.yaml"
                  "                              (runs the DB half in-cluster; no exec)")
        else:
            print("\n!! NO INVARIANT PROBES RAN — the probe set could not be loaded.")
            print("   Probes are the only part of this report that reads YOUR data, and")
            print("   none of them were even asked. The cluster and database sections were")
            print("   still collected; probes.json names the remedy.")
        print("   Sending the bundle anyway is fine and useful — just know what is "
              "missing from it.")
    if leaks:
        print("\n!! REDACTION FAILED — %d withheld value(s) survived into %s"
              % (len(leaks), archive.name))
        for path, idx in leaks:
            print("   %s: value #%d (value withheld)" % (path, idx))
        print("   DO NOT SEND THIS FILE. Report the finding to Vexa without attaching it.")
        return 3
    if report["redaction"]["verified"]:
        print("redaction: %d value(s) withheld, 0 found in the archive"
              % report["redaction"]["withheld_values"])
    print("\nRead it. Then send it by hand — nothing here transmits, and nothing will.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog=TOOL, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--namespace", required=True,
                    help="the namespace the Vexa workloads run in")
    ap.add_argument("--kubeconfig")
    ap.add_argument("--context")
    ap.add_argument("--out", default=".", help="where state-report.tar.gz is written")
    ap.add_argument("--db-url",
                    help="postgres DSN, if you can reach the database directly. Prefer "
                         "VEXA_REPORT_DB_URL: a password on a command line lands in shell "
                         "history and in every process listing on the machine.")
    ap.add_argument("--db-host",
                    help="database host, when Postgres is managed or otherwise outside the "
                         "cluster. NO PASSWORD ON THE COMMAND LINE: it comes from PGPASSWORD "
                         "or ~/.pgpass. Prefer this over --db-url and over --db-pod.")
    ap.add_argument("--db-port", type=int, help="port for --db-host (default: psql's own)")
    ap.add_argument("--db-pod", help="database pod to run psql/pg_dump in via kubectl exec. "
                                     "This needs CREATE ON PODS/EXEC, which is a privileged "
                                     "verb in most estates — try --db-host first, or run "
                                     "kit/report/job.yaml in-cluster if exec is not grantable")
    ap.add_argument("--db-container")
    ap.add_argument("--db-name")
    ap.add_argument("--db-user")
    ap.add_argument("--alembic-table", default="alembic_version",
                    help="the migration-revision table to read (default alembic_version). "
                         "A Vexa estate has none — its schema converges from SQLAlchemy "
                         "metadata — and its absence is reported, not treated as an error.")
    ap.add_argument("--exact-row-counts", action="store_true",
                    help="count(*) every table instead of reading the planner's estimate. "
                         "Accurate, and a full scan per table; the estimate is the default "
                         "because a report should not become an incident.")
    ap.add_argument("--probe-set", default=None,
                    help="probe set name under kit/report/probes/, a path to one, or 'none' "
                         "(default %s). A set you NAME and that does not exist is a usage "
                         "error (exit 2); the default merely missing — this tool is one "
                         "file and gets copied without its probes/ directory — degrades to "
                         "absent and the run still produces a bundle." % DEFAULT_PROBE_SET)
    ap.add_argument("--transcription-match", default=TRANSCRIPTION_DEFAULT_MATCH,
                    help="regex matching the transcription workloads whose runtime shape is "
                         "captured (default %r)" % TRANSCRIPTION_DEFAULT_MATCH)
    ap.add_argument("--sql-timeout-ms", type=int, default=30000,
                    help="server-side statement_timeout for every query (default 30000)")
    ap.add_argument("--verify-redaction", dest="verify_redaction", action="store_true",
                    default=True,
                    help="re-extract the finished archive and refuse to finish if a withheld "
                         "value survived (default; exit 3)")
    ap.add_argument("--no-verify-redaction", dest="verify_redaction", action="store_false")
    a = ap.parse_args(argv)

    # argparse cannot see the difference between a default and the same value
    # typed out, and load_probe_set needs it: a missing DEFAULT degrades, a
    # missing set the operator NAMED is a usage error.
    a.probe_set_explicit = a.probe_set is not None
    if a.probe_set is None:
        a.probe_set = DEFAULT_PROBE_SET

    if a.db_container and not a.db_pod:
        ap.error("--db-container names a container inside --db-pod; give the pod too")
    if a.db_port and not (a.db_host or a.db_url):
        ap.error("--db-port needs --db-host")
    chosen = [flag for flag, value in (("--db-url", a.db_url), ("--db-host", a.db_host),
                                       ("--db-pod", a.db_pod)) if value]
    if len(chosen) > 1:
        ap.error("%s are %d ways to reach one database; pick one, so the report says "
                 "unambiguously how it was read" % (" and ".join(chosen), len(chosen)))

    archive, report, probes, leaks = build(a)
    return render(archive, report, probes, leaks)


if __name__ == "__main__":
    sys.exit(main())
