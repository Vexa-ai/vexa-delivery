#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-state-report — the shape of your setup, so what we ship fits it.

A READ-ONLY `kubectl get` SWEEP OF ONE NAMESPACE, WRITTEN TO ONE FILE. No
database connection, no `pods/exec`, no credentials of any kind, no SQL.

You already run Vexa. This reads the shape of the environment it runs in, so
the bundle we build for you works with what you already have and asks for
nothing you do not. If you are on 0.10, that is what tells us you are ready
for 0.12.

ONE FILE, AND THAT IS THE DESIGN. `state-report.yaml`. Not a directory, not an
archive, nothing to extract. The person who has to approve this before it
leaves their perimeter must read ALL of it, and a pile of JSON files is a
cross-referencing exercise rather than a read. YAML because the reader is a
Kubernetes engineer who reads it all day, and because it carries comments — so
the explanation of each section sits above the section instead of in a second
document that can drift from it.

WHAT IT COLLECTS, and the list is complete:

  1. PLATFORM     Kubernetes or OpenShift, its version, the cloud or distro
                  underneath, the node shapes available to schedule on, and
                  the storage this cluster offers
  2. WIRING       which components exist and how they are connected — the
                  database and transcription especially: in-cluster or
                  external, how each is addressed, versions, GPU or CPU
  3. RESOURCES    requests and limits per container, plus the namespace's
                  ResourceQuotas and LimitRanges. This is not decoration: a
                  quota-controlled namespace stopped a subscriber's bot pods
                  being admitted, because they declare no resources of their
                  own and no LimitRange supplied a default
  4. VERSIONS     the image tags and digests ACTUALLY running, so the jump is
                  known exactly rather than assumed
  5. VALUES       the settings this deployment has customised, so what we ship
                  does not overwrite a deliberate choice
  6. REGISTRY     whether images come from Docker Hub or through a mirror —
                  reported as observed, never as inferred

NEVER COLLECTED: schema, rows, row counts, SQL of any kind, transcripts,
meeting content, credentials. The database appears here only as a COMPONENT —
engine, version, in-cluster or external, how it is addressed, its resources —
and every one of those facts is read from the cluster, never by connecting.

THREE REFUSALS, and they are the design rather than caveats on it.

1. IT DOES NOT TRANSMIT. There is no --submit, no destination flag and no
   endpoint constant anywhere in this file. It writes one file, prints its
   path, and stops. What leaves the perimeter leaves because a human read it
   and sent it.

2. IT DOES NOT WRITE, AND IT DOES NOT CONNECT. Every call is `kubectl get -o
   json` or `kubectl version -o json`. No other verb: no exec, no apply, no
   patch, no delete, no port-forward, no logs. There is no database client in
   this file and no flag that would take a password.

3. IT CARRIES NO CONTENT. There is no field anywhere below that could hold a
   customer's data, because nothing here reads any. Settings capture is
   ALLOWLIST-FIRST: a variable is excluded unless its name matches the
   allowlist, so redaction is the second net and not the only one. Secret and
   ConfigMap VALUES are never read; a `valueFrom` records only that the
   deployment expects one. Node names, service addresses and ingress
   hostnames are not collected either — they are inventory, not shape.

ABSENT OVER ZERO, everywhere. A source that could not be read is recorded as
absent with a reason. It is never defaulted to zero or to an empty list: zero
is a claim, and a fabricated zero in a document whose whole purpose is to say
what somebody already has is worse than a stated gap.

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
        out = {}
        doc, err = ctx.kube.get("things")
        if doc is None:
            return ctx.absent(out, "things", err)      # absent, not zero
        out["things"] = [...]
        return out

...and then one line in SECTIONS at the bottom of this file, with the comment a
reader will see above it in the YAML. That is the whole contract:

  * take `ctx`, return a dict, and it becomes one block of state-report.yaml;
  * never raise to say "nothing here". Record absent with a reason. If you do
    raise, the driver names your collector, keeps every other section, and the
    report says which one failed — a broken collector must not cost an
    operator their whole run;
  * if you saw a value you decided not to write down, put it in
    `ctx.withheld`. The redaction self-check scans the finished document for
    everything in that set, so an allowlist you extended stays checkable;
  * BUDGET IS A FEATURE. This file is read end to end by somebody deciding
    whether to send it. Prefer one compact line to five nested ones; say each
    fact once. Roughly 150-250 lines, comments included, is the shape;
  * ONE TEST FOR WHETHER IT BELONGS: is it one of the six things above? Node
    shapes, quotas, ingress class, resource limits, GPU-vs-CPU, image digests,
    replica counts, allowlisted non-secret settings — yes. Anything describing
    their data — no, and no amount of usefulness changes that.
────────────────────────────────────────────────────────────────────────────

    python3 kit/report/vexa_state_report.py --namespace vexa [--dry-run]

Exit codes: 0 written · 2 usage · 3 redaction leak (the file is kept so it can
be inspected and reported, and it must not be sent). An unreadable resource is
NOT a usage error: it degrades to `absent` with a reason and still writes.
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import traceback

HERE = pathlib.Path(__file__).resolve().parent
KIT = HERE.parent
REPO = KIT.parent

TOOL = "vexa-state-report"
TOOL_VERSION = "0.4.0"
SCHEMA_VERSION = 4
OUTPUT_NAME = "state-report.yaml"


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

# Settings that describe HOW THE DEPLOYMENT IS SHAPED — the model, the device,
# the concurrency. An allowlist, not a denylist: everything else is dropped
# before it is written down, so there is nothing left to redact. A name
# matching this AND matching SECRET_KEY_RE is still dropped — the refusal
# outranks the allowlist, which is why MODEL_API_KEY is absent and not
# REDACTED.
ENV_ALLOW_RE = re.compile(
    r"(model|whisper|language|^lang$|_lang|beam|device|cuda|gpu|cpu_threads|"
    r"compute_type|precision|quantiz|vad|replica|scale|concurrency|workers|"
    r"num_workers|batch|chunk|sample_rate|inference|engine|backend)",
    re.IGNORECASE)

# Names that say WHERE a component is, without saying how to authenticate to
# it. The NAME is recorded; the value never is, whether it is inline or comes
# from a Secret. This is how the wiring block can say "the database is
# addressed by DATABASE_URL" while carrying no DSN.
ADDRESS_ENV_RE = re.compile(
    r"(_host$|_hosts$|_url$|_uri$|_dsn$|_addr|_endpoint|_port$|_service$|"
    r"^database|^postgres|^pg_|^redis|_server$)", re.IGNORECASE)


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
        # env-var idiom: {FOO_TOKEN: ...} and [{name: FOO_TOKEN, value: ...}] —
        # in the second the secret is named by a sibling key, not by the key
        # holding it.
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


def scan_text_for_leaks(text: str, secrets) -> list:
    """Return the INDEX of each withheld value that survived — never the value.

    Naming the value in the failure message would put the credential into a
    terminal, a CI log and a screenshot, which is the thing this file exists to
    avoid. The scan runs on the rendered document, so what is checked is what
    would actually be written rather than what we believe we assembled.
    """
    candidates = sorted(s for s in secrets if len(s) >= MIN_LEAK_SCAN_LEN)
    return [i for i, secret in enumerate(candidates) if secret in text]


def env_allowed(name: str) -> bool:
    if SECRET_KEY_RE.search(name or ""):
        return False                    # the refusal outranks the allowlist
    return bool(ENV_ALLOW_RE.search(name or ""))


# ── the YAML writer ─────────────────────────────────────────────────────────
#
# Hand-written, and deliberately: this tool is one stdlib-only file an operator
# can copy to a jump box, and a PyYAML dependency would be a thing to install
# before they could look at their own cluster. It also lets the document carry
# COMMENTS, which is the whole reason the format is YAML — the explanation of a
# block sits above the block, in the same file, and cannot drift from it.

# Anything that would change meaning, or could be read as a number, a boolean
# or a YAML indicator, gets quoted. Conservative on purpose: a wrongly quoted
# string is ugly, a wrongly unquoted one is a parse error in somebody else's
# pipeline.
YAML_BARE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9 _.,/@()+·—><=%-]*$")
YAML_RESERVED = {"true", "false", "null", "yes", "no", "on", "off", "y", "n", "~"}


def _scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if (text and YAML_BARE_RE.match(text) and text.lower() not in YAML_RESERVED
            and ": " not in text and " #" not in text and not text.endswith(":")
            and text == text.strip()):
        return text
    return "'%s'" % text.replace("'", "''")


# A sentence of explanation is worth more than a column limit, but a 300-char
# line in a document somebody is meant to READ is not. Long prose becomes a
# folded block, which YAML rejoins into one string on load: the reader sees
# paragraphs, the parser sees the same value.
FOLD_OVER = 88


def _fold(prefix, text, indent):
    pad = " " * (indent + 2)
    lines, line = ["%s >-" % prefix], ""
    for word in str(text).split():
        if line and len(pad) + len(line) + 1 + len(word) > 78:
            lines.append(pad + line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        lines.append(pad + line)
    return lines


def _long(value):
    return isinstance(value, str) and len(value) > FOLD_OVER and "\n" not in value


def _verbatim(value):
    return isinstance(value, str) and "\n" in value


def _block(prefix, text, indent):
    """A LITERAL block scalar — the only honest way to carry a receipt whole.

    A multi-line string quoted inline is not a document a person can read, and
    at some indentations it is not even parseable. `|` keeps the lines exactly
    as they are, and YAML hands back the identical string on load, so a receipt
    pasted into this file is still the receipt.

    Two details that are not decoration. The chomping indicator records whether
    the text ended in a newline, so a round trip is byte-exact rather than
    nearly. And a first line that begins with a space needs an EXPLICIT
    indentation indicator (`|2`), because YAML would otherwise read that space
    as the block's own indentation and silently eat one from every line.
    """
    body = text.split("\n")
    if body and body[-1] == "":
        body.pop()                                  # trailing newline: clip it
        head = "|"
    else:
        head = "|-"
    if body and body[0][:1] == " ":
        head = head[0] + "2" + head[1:]
    pad = " " * (indent + 2)
    return ["%s %s" % (prefix, head)] + [(pad + line) if line else "" for line in body]


def _yaml(value, indent=0):
    """Emit a value. Empty containers stay inline so a gap reads as a gap."""
    pad = " " * indent
    if isinstance(value, dict):
        if not value:
            return ["{}"]
        lines = []
        for k, v in value.items():
            key = "%s%s" % (pad, _scalar(k))
            if isinstance(v, (dict, list)) and v:
                lines.append(key + ":")
                lines += _yaml(v, indent + 2)
            elif isinstance(v, (dict, list)):
                lines.append("%s: %s" % (key, "{}" if isinstance(v, dict) else "[]"))
            elif _verbatim(v):
                lines += _block(key + ":", v, indent)
            elif _long(v):
                lines += _fold(key + ":", v, indent)
            else:
                lines.append("%s: %s" % (key, _scalar(v)))
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict) and item:
                block = _yaml(item, indent + 2)
                lines.append("%s- %s" % (pad, block[0].strip()))
                lines += block[1:]
            elif isinstance(item, (dict, list)):
                lines.append("%s- %s" % (pad, "{}" if isinstance(item, dict) else "[]"))
            elif _verbatim(item):
                lines += _block("%s-" % pad, item, indent)
            elif _long(item):
                lines += _fold("%s-" % pad, item, indent)
            else:
                lines.append("%s- %s" % (pad, _scalar(item)))
        return lines
    return [pad + _scalar(value)]


def comment(text, width=76):
    """Wrap PARAGRAPHS into `# ` lines — a blank line separates them.

    Wrapping each source line on its own would re-wrap the docstring's own
    line breaks into orphans, which is how a carefully written paragraph turns
    into a ransom note.
    """
    out = []
    for para in re.split(r"\n\s*\n", text.strip("\n")):
        if not para.strip():
            out.append("#")
            continue
        if out:
            out.append("#")
        line = ""
        for word in para.split():
            if line and len(line) + 1 + len(word) > width:
                out.append("# " + line)
                line = word
            else:
                line = (line + " " + word).strip()
        if line:
            out.append("# " + line)
    return out


# ── the only reader ─────────────────────────────────────────────────────────


class Kube:
    """The narrowest kubectl wrapper that does the job — every call is a read.

    THERE IS NO SECOND READER. This class is the entire surface this tool has
    against a customer's estate. If you are looking for the database client,
    there is not one, and there is no flag that would take a password. A
    failure returns a reason rather than raising, so a cluster that grants less
    than the full read still produces the sections it can, with the gaps named.
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

    def get_argv(self, resource, namespace=True):
        """The exact command `get` will run. Split out so --dry-run prints the
        real thing rather than a second, drifting description of it."""
        cmd = self.base() + ["get", resource]
        if namespace:
            cmd += ["-n", self.namespace]
        return cmd + ["-o", "json"]

    def version_argv(self):
        return self.base() + ["version", "-o", "json"]

    def get(self, resource, namespace=True, timeout=60):
        cmd = self.get_argv(resource, namespace=namespace)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            return None, "kubectl get %s: %s" % (resource, type(e).__name__)
        if r.returncode != 0:
            # stderr is NOT carried into the report. It is a cluster's own
            # message about a cluster's own objects and routinely names hosts
            # and users; this document promises not to carry that. The reason
            # says what failed, and the operator has their own terminal.
            return None, "kubectl get %s exited %d" % (resource, r.returncode)
        try:
            return json.loads(r.stdout), None
        except ValueError:
            return None, "kubectl get %s returned unparseable json" % resource

    def server_version(self):
        try:
            r = subprocess.run(self.version_argv(), capture_output=True, text=True,
                               timeout=60)
            return json.loads(r.stdout).get("serverVersion", {}).get("gitVersion"), None
        except Exception:                                            # noqa: BLE001
            return None, "kubectl version did not answer"


class Ctx:
    """Everything a collector may read, and the only two things it may write.

    `withheld` is the set of values we SAW and chose not to record. Feeding it
    to the redaction self-check is what makes the allowlist checkable rather
    than merely claimed: if one of them appears anywhere in the finished
    document, the run exits 3 and says so.
    """

    def __init__(self, kube, args):
        self.kube, self.args = kube, args
        self.withheld = set()
        self.sections = {}
        self.gaps = []
        self.unowned = None
        self._pods = None

    def absent(self, out, what, reason):
        """Record a gap once, centrally. Collectors never keep their own absent
        list: one place in the document to look for what could not be read."""
        self.gaps.append({"what": what, "reason": reason})
        return out

    def pods(self):
        """Pods are read once and reused. Four sections need them, and asking a
        customer's API server for the same list four times is rude."""
        if self._pods is None:
            doc, err = self.kube.get("pods")
            self._pods = ((doc or {}).get("items", []), err)
        return self._pods


# ── shared shapes ───────────────────────────────────────────────────────────

GPU_RESOURCES = ("nvidia.com/gpu", "amd.com/gpu", "gpu.intel.com/i915", "habana.ai/gaudi")


def _res(block):
    """`{"cpu": "2", "memory": "8Gi"}` -> `"cpu 2 · memory 8Gi"`, or None.

    One line rather than a nested block, and deliberately: this document is
    read end to end by a person deciding whether to send it, and five lines of
    YAML per resource block is how a document stops being read.
    """
    if not block:
        return None
    return " · ".join("%s %s" % (k, v) for k, v in sorted(block.items()))


def _image_parts(image):
    """(registry host, repository, tag). The host is the registry-reachability
    fact, so it is split out rather than left buried inside a string."""
    ref = (image or "").split("@")[0]
    tag = ref.rsplit(":", 1)[-1] if ":" in ref.rsplit("/", 1)[-1] else None
    repo = ref[:-(len(tag) + 1)] if tag else ref
    head = repo.split("/", 1)[0]
    host = head if ("." in head or ":" in head or head == "localhost") else "docker.io"
    return host, repo, tag


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
        if kind == "Job":
            # A per-meeting bot Job is NAMED after the meeting, and stripping the
            # last segment still leaves most of that id in the document. A meeting
            # id is the one thing this report will not carry, so a Job-owned pod is
            # grouped as unowned: its image is still reported, its name never is.
            return None
        if kind == "ReplicaSet":
            return name.rsplit("-", 1)[0] if "-" in name else name
        if kind in ("StatefulSet", "DaemonSet"):
            return name
    return None


# ── 1 · platform ────────────────────────────────────────────────────────────

# providerID is `<scheme>://<instance-id>`. The scheme says which cloud, which
# is shape; the instance id is inventory and is dropped at the split.
PROVIDER_NAMES = {
    "lke": "Linode LKE", "linode": "Linode", "aws": "AWS", "gce": "Google Cloud",
    "azure": "Azure", "openstack": "OpenStack", "vsphere": "vSphere",
    "hcloud": "Hetzner", "digitalocean": "DigitalOcean", "ibm": "IBM Cloud",
    "kind": "kind (local)", "k3s": "k3s",
}


def _nodes(ctx, out):
    """Nodes grouped by SHAPE, and deliberately not by name.

    We need to know there are three 16-core GPU nodes; we do not need to know
    what they are called, and node names in a document that leaves a perimeter
    are inventory. Grouping is the honest form of the same fact and drops the
    names as a consequence rather than as a promise.
    """
    doc, err = ctx.kube.get("nodes", namespace=False)
    if not doc:
        ctx.absent(out, "node shapes", (err or "not readable")
                   + " — nodes are cluster-scoped and need a ClusterRole. Skip it: "
                     "every other section is unaffected.")
        return None, None
    classes, providers = {}, set()
    for n in doc.get("items", []):
        labels = (n.get("metadata") or {}).get("labels") or {}
        status = n.get("status") or {}
        cap = status.get("capacity") or {}
        alloc = status.get("allocatable") or {}
        info = status.get("nodeInfo") or {}
        provider = str((n.get("spec") or {}).get("providerID") or "")
        if "://" in provider:
            providers.add(provider.split("://", 1)[0])
        gpu = {}
        for name in GPU_RESOURCES:
            if alloc.get(name) or cap.get(name):
                gpu[name] = alloc.get(name) or cap.get(name)
        if labels.get("nvidia.com/gpu.product"):
            gpu["product"] = labels["nvidia.com/gpu.product"]
        shape = {
            "instance_type": labels.get("node.kubernetes.io/instance-type")
            or labels.get("beta.kubernetes.io/instance-type"),
            "region": labels.get("topology.kubernetes.io/region"),
            "capacity": _res({k: v for k, v in cap.items()
                              if k in ("cpu", "memory", "pods")}),
            "gpu": _res(gpu) if gpu else None,
            "arch": info.get("architecture"),
            "os": info.get("osImage"),
            "kubelet": info.get("kubeletVersion"),
            "runtime": info.get("containerRuntimeVersion"),
        }
        key = json.dumps(shape, sort_keys=True)
        classes.setdefault(key, dict(count=0, **shape))
        classes[key]["count"] += 1
    rows = sorted(classes.values(), key=lambda r: (-r["count"], str(r["instance_type"])))
    cloud = PROVIDER_NAMES.get(sorted(providers)[0], sorted(providers)[0]) \
        if providers else None
    return rows, cloud


def collect_platform(ctx):
    """Kubernetes or OpenShift, its version, the cloud underneath, the shapes
    available to schedule on, and the storage this cluster offers."""
    out = {}

    version, err = ctx.kube.server_version()
    if version:
        out["kubernetes"] = version
    else:
        ctx.absent(out, "kubernetes version", err)

    # OpenShift answers this and Kubernetes does not, so a successful read is
    # the distribution and a failed one is not evidence of anything else — it
    # is also what a missing ClusterRole looks like. Said in the document
    # rather than left for a reader to assume.
    out["distribution"] = "Kubernetes"
    out["distribution_note"] = ("clusterversion.config.openshift.io was not readable, "
                                "which is what plain Kubernetes and a missing "
                                "ClusterRole both look like")
    cv, _ = ctx.kube.get("clusterversions.config.openshift.io", namespace=False)
    if cv and cv.get("items"):
        out["distribution"] = "OpenShift"
        out["distribution_version"] = ((cv["items"][0].get("status") or {})
                                       .get("desired") or {}).get("version")
        out.pop("distribution_note")

    nodes, cloud = _nodes(ctx, out)
    out["cloud"] = cloud
    if cloud is None:
        out["cloud_note"] = "no node providerID was readable; not guessed"
    if nodes is not None:
        out["node_shapes_note"] = "grouped by shape; node names are not collected"
        out["node_shapes"] = nodes

    doc, err = ctx.kube.get("storageclasses.storage.k8s.io", namespace=False)
    if doc is None:
        ctx.absent(out, "storage classes", (err or "not readable")
                   + " — cluster-scoped, needs a ClusterRole")
    else:
        out["storage_classes"] = [
            " · ".join(x for x in [
                (c.get("metadata") or {}).get("name"), c.get("provisioner"),
                c.get("reclaimPolicy"),
                "DEFAULT" if ((c.get("metadata") or {}).get("annotations") or {}).get(
                    "storageclass.kubernetes.io/is-default-class") == "true" else None,
            ] if x) for c in doc.get("items", [])]

    doc, err = ctx.kube.get("persistentvolumeclaims")
    if doc is None:
        ctx.absent(out, "volume claims", err or "not readable")
    else:
        out["volumes"] = [
            " · ".join(x for x in [
                (c.get("metadata") or {}).get("name"),
                ((c.get("status") or {}).get("capacity") or {}).get("storage")
                or (((c.get("spec") or {}).get("resources") or {}).get("requests")
                    or {}).get("storage"),
                (c.get("spec") or {}).get("storageClassName"),
                (c.get("status") or {}).get("phase"),
            ] if x) for c in doc.get("items", [])]
    return out


# ── 2 · workloads: versions, resources and the settings they carry ──────────

WORKLOAD_KINDS = (
    ("deployments.apps", "Deployment"),
    ("statefulsets.apps", "StatefulSet"),
    ("daemonsets.apps", "DaemonSet"),
    ("cronjobs.batch", "CronJob"),
)


def _chart_of(meta):
    """Which chart at which version put this here — one string, not nine keys.
    The rest of a customer's labels are theirs and are not read."""
    labels = dict((meta.get("labels") or {}), **(meta.get("annotations") or {}))
    return labels.get("helm.sh/chart") or labels.get("app.kubernetes.io/version") \
        or labels.get("argocd.argoproj.io/instance")


def _pod_template(obj, kind):
    spec = obj.get("spec") or {}
    if kind == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def _settings(container, withheld):
    """The customised settings on a container — allowlist first.

    Returns (visible settings, names that are provided from elsewhere). A value
    not on the allowlist is added to `withheld` and never written; a value that
    comes from a Secret or ConfigMap has its NAME recorded and nothing else, so
    the document can say what the deployment expects to be given without
    carrying it.

    THE KEY THIS LANDS UNDER IS `provided_externally`, NOT `from_secret_...`.
    The redaction rule is deliberately blunt — anything under a key matching
    password|token|secret|key|apikey loses its value — so a field NAMED after
    secrets gets emptied by it, which destroys the one piece of wiring that was
    safe to keep and poisons the leak scan with a value that is also recorded
    (correctly) elsewhere. Found by the leak scan itself, which is what it is
    for.
    """
    visible, external = {}, []
    for e in (container.get("env") or []):
        name = e.get("name") or ""
        if "valueFrom" in e:
            external.append("%s (from %s)" % (name, next(iter(e["valueFrom"] or {}),
                                                         "unknown")))
            continue
        value = e.get("value")
        if env_allowed(name):
            visible[name] = value
        elif isinstance(value, str) and value:
            withheld.add(value)
    return (visible or None), (external or None)


def _digests(ctx, out):
    """What is ACTUALLY running, read from pods rather than from the spec.

    The spec says what should be running; the pods say what is. Drift between
    the two is the single most useful thing a state report can carry, and
    reading the spec for both sides of that comparison would make it
    structurally undetectable. This is item 4 — the digest is what says 0.10
    and not "roughly 0.10".
    """
    pods, err = ctx.pods()
    if not pods:
        ctx.absent(out, "running image digests", err or "pods not readable")
        return None
    by_owner = {}
    for p in pods:
        owner = _owner_of(p) or "(unowned)"
        for cs in ((p.get("status") or {}).get("containerStatuses") or []):
            image_id = cs.get("imageID") or ""
            if "@sha256:" in image_id:
                by_owner.setdefault(owner, {})[cs.get("name")] = image_id.rsplit("@", 1)[1]
    return by_owner


def collect_workloads(ctx):
    """Every workload: chart, replicas, the image and digest actually running,
    the requests and limits each container declares, and its settings.

    Returns THE LIST, not a dict wrapping it — `workloads: workloads:` is a
    nesting level that says nothing, in a document whose budget is the point.
    The per-meeting pods that belong to no workload are stashed on ctx and get
    their own block, because they are a different fact.
    """
    out = {}
    digests = _digests(ctx, out)
    rows = []
    for resource, kind in WORKLOAD_KINDS:
        doc, err = ctx.kube.get(resource)
        if doc is None:
            ctx.absent(out, resource, err or "not readable")
            continue
        for obj in doc.get("items", []):
            meta, spec, status = (obj.get("metadata") or {}, obj.get("spec") or {},
                                  obj.get("status") or {})
            name = meta.get("name")
            template = _pod_template(obj, kind)
            row = {"kind": kind, "name": name, "chart": _chart_of(meta)}
            if kind in ("Deployment", "StatefulSet"):
                row["replicas"] = "%s ready of %s desired" % (
                    status.get("readyReplicas") or 0, spec.get("replicas"))
            elif kind == "DaemonSet":
                row["replicas"] = "%s ready of %s scheduled" % (
                    status.get("numberReady") or 0, status.get("desiredNumberScheduled"))
            elif kind == "CronJob":
                row["schedule"] = spec.get("schedule")
                row["suspended"] = bool(spec.get("suspend"))
            # NAMED `..._credentials`, not `..._secrets`, and that is not
            # squeamishness: the redaction rule is deliberately blunt and
            # empties anything under a key matching
            # password|token|secret|key|apikey, so a field NAMED after secrets
            # loses the very names that make registry reachability readable.
            # Two fields have now been caught by exactly that, both by the leak
            # scan, which is what it is for.
            pull = [s.get("name") for s in (template.get("imagePullSecrets") or [])]
            if pull:
                row["image_pull_credentials"] = pull
            containers = []
            for c in (template.get("containers") or []) + \
                     (template.get("initContainers") or []):
                res = c.get("resources") or {}
                host, _, tag = _image_parts(c.get("image"))
                settings, external = _settings(c, ctx.withheld)
                item = {"name": c.get("name"), "image": c.get("image"),
                        "registry": host, "tag": tag}
                digest = (digests or {}).get(name, {}).get(c.get("name"))
                if digest:
                    item["running_digest"] = digest
                item["requests"] = _res(res.get("requests"))
                item["limits"] = _res(res.get("limits"))
                if settings:
                    item["settings"] = settings
                if external:
                    item["provided_externally"] = external
                containers.append(item)
            row["containers"] = containers
            rows.append(row)
    if not rows:
        ctx.absent(out, "workloads", "no Deployment, StatefulSet, DaemonSet or CronJob "
                                     "was readable in namespace %r" % ctx.kube.namespace)
    # Bot pods are spawned per meeting and belong to no Deployment. They are
    # the most upgrade-sensitive image in the estate, so losing them to a
    # grouping convention would be the wrong tidy. They stay under `(unowned)`
    # rather than under their pod names: a per-meeting pod is NAMED after the
    # meeting, and a meeting id is the one thing this document promises not to
    # carry.
    ctx.unowned = {k: v for k, v in (digests or {}).items()
                   if k not in {r["name"] for r in rows}} or None
    return sorted(rows, key=lambda r: (r["kind"], str(r["name"])))


def collect_unowned(ctx):
    """Images running under no workload — emitted only when there are any."""
    return getattr(ctx, "unowned", None)


# ── 3 · resources: quotas, LimitRanges, and who declares nothing ────────────


def collect_resources(ctx):
    """Namespace quotas and LimitRanges, and which containers declare no
    resources of their own.

    THIS SECTION EXISTS BECAUSE IT BROKE A REAL UPGRADE. Bot pods are created
    per meeting and declare no requests or limits. In a namespace with a
    ResourceQuota that covers cpu or memory, Kubernetes REFUSES a pod that
    declares none — unless a LimitRange supplies a default. The estate ran fine
    until the quota was there, and then bots simply stopped being admitted.
    Neither half of that is visible from a workload list, which is why the
    quota, the LimitRange and the containers declaring nothing are collected
    together and reported together.

    And it reads PODS, not only workload templates: the pod that broke it
    belonged to no Deployment, so a scan of templates would have reported a
    clean namespace and missed the only container that mattered.
    """
    out = {}
    doc, err = ctx.kube.get("resourcequotas")
    quotas = None
    if doc is None:
        ctx.absent(out, "resource quotas", err or "not readable")
    else:
        quotas = [{"name": (q.get("metadata") or {}).get("name"),
                   "hard": _res((q.get("status") or {}).get("hard")
                                or (q.get("spec") or {}).get("hard")),
                   "used": _res((q.get("status") or {}).get("used"))}
                  for q in doc.get("items", [])]
        out["quotas"] = quotas

    doc, err = ctx.kube.get("limitranges")
    ranges = None
    if doc is None:
        ctx.absent(out, "limit ranges", err or "not readable")
    else:
        ranges = [{"name": (lr.get("metadata") or {}).get("name"),
                   "limits": (lr.get("spec") or {}).get("limits")}
                  for lr in doc.get("items", [])]
        out["limit_ranges"] = ranges

    undeclared, seen = [], set()
    for p in ctx.pods()[0]:
        owner = _owner_of(p) or "(unowned — created directly, e.g. a per-meeting bot)"
        for c in ((p.get("spec") or {}).get("containers") or []):
            res = c.get("resources") or {}
            key = "%s / %s" % (owner, c.get("name"))
            if res.get("requests") or res.get("limits") or key in seen:
                continue
            seen.add(key)
            undeclared.append(key)
    out["containers_declaring_no_resources"] = undeclared

    covers_compute = any(
        re.match(r"(.*\.)?(cpu|memory)$", part.strip().split(" ")[0])
        for q in (quotas or []) for part in (q.get("hard") or "").split("·"))
    if covers_compute and undeclared and not ranges:
        out["finding"] = (
            "A ResourceQuota covers cpu or memory here, %d container(s) declare neither "
            "request nor limit, and no LimitRange supplies a default. Kubernetes refuses "
            "such a pod outright. Vexa's per-meeting bot pods are in that shape by "
            "design, so this is the exact condition that stops bots being admitted."
            % len(undeclared))
    return out


# ── 4 · wiring: which components exist, and how they are connected ──────────

COMPONENT_IMAGES = (
    ("database", re.compile(r"(^|/)(postgres|postgresql|timescale|citus|pgbouncer)",
                            re.IGNORECASE)),
    ("redis", re.compile(r"(^|/)(redis|valkey)", re.IGNORECASE)),
)
COMPONENT_ENV = {
    "database": re.compile(r"postgres|^pg_|database|^db_", re.IGNORECASE),
    "redis": re.compile(r"redis|valkey", re.IGNORECASE),
}
DEVICE_ENV_RE = re.compile(r"device|cuda|gpu", re.IGNORECASE)
MODEL_ENV_RE = re.compile(r"model|whisper", re.IGNORECASE)


def _addressed_by(ctx, component):
    """The NAMES of the settings that point at a component — never the values.

    "Addressed by DATABASE_URL, from a Secret" is the wiring fact. The DSN is
    not, and is not read.
    """
    pattern = COMPONENT_ENV[component]
    hits = []
    for p in ctx.pods()[0]:
        for c in ((p.get("spec") or {}).get("containers") or []):
            for e in (c.get("env") or []):
                name = e.get("name") or ""
                if not (ADDRESS_ENV_RE.search(name) and pattern.search(name)):
                    continue
                if SECRET_KEY_RE.search(name):
                    # A password is not an address. Its name is still reported,
                    # under the container that declares it.
                    continue
                if "valueFrom" in e:
                    row = "%s (from %s)" % (name, next(iter(e["valueFrom"] or {}),
                                                       "unknown"))
                elif env_allowed(name):
                    row = "%s = %s" % (name, e.get("value"))
                else:
                    row = "%s (inline value, not on the allowlist — not collected)" % name
                if row not in hits:
                    hits.append(row)
    return hits


def collect_wiring(ctx):
    """Which components exist and how they are connected.

    The database and transcription especially: in-cluster or external, how each
    is addressed, its version, GPU or CPU. Every fact here is read from the
    cluster. Nothing connects to anything, and no value that could be a
    credential is recorded — only the NAME of the setting that carries it.
    """
    out = {}
    workloads = ctx.sections.get("workloads") or []

    for name, pattern in COMPONENT_IMAGES:
        found = None
        for w in workloads:
            for c in (w.get("containers") or []):
                _, repo, _ = _image_parts(c.get("image"))
                if pattern.search(repo) and found is None:
                    found = {"where": "in-cluster", "workload": w.get("name"),
                             "version": c.get("tag"), "image": c.get("image"),
                             "resources": c.get("requests")}
        if found is None:
            found = {"where": "external or managed", "version": None,
                     "note": "not running in this namespace. Nothing here connects to "
                             "it, so its version is not known — a gap, not a zero."}
        found["addressed_by"] = _addressed_by(ctx, name) or None
        out[name] = found

    # Transcription is the one runtime fact the shipped bundle must fit: a build
    # for a CPU box, delivered to an estate running a GPU model at a different
    # beam size, is a build for a different deployment.
    match = re.compile(ctx.args.transcription_match, re.IGNORECASE)
    transcription = []
    for w in workloads:
        for c in (w.get("containers") or []):
            if not (match.search(w.get("name") or "")
                    or match.search(c.get("image") or "")):
                continue
            settings = c.get("settings") or {}
            device = next(("%s = %s" % (k, v) for k, v in settings.items()
                           if DEVICE_ENV_RE.search(k)), None)
            if device is None and "gpu" in (c.get("requests") or "").lower():
                device = "gpu (from the resource request; no explicit setting)"
            model = next(("%s = %s" % (k, v) for k, v in settings.items()
                          if MODEL_ENV_RE.search(k)), None)
            transcription.append({
                "workload": w.get("name"), "container": c.get("name"),
                "replicas": w.get("replicas"),
                "device": device or "not stated — NOT assumed to be CPU",
                "model": model or "not stated",
                "requests": c.get("requests"), "limits": c.get("limits"),
            })
    out["transcription"] = transcription
    if not transcription:
        ctx.absent(out, "transcription", "no workload matched %r — widen it with "
                                         "--transcription-match. ABSENT, not 'CPU'."
                   % ctx.args.transcription_match)

    doc, err = ctx.kube.get("services")
    if doc is None:
        ctx.absent(out, "services", err or "not readable")
    else:
        out["services_note"] = "type and ports; addresses are not collected"
        out["services"] = [
            "%s · %s · %s" % ((s.get("metadata") or {}).get("name"),
                              (s.get("spec") or {}).get("type"),
                              ",".join("%s/%s" % (p.get("port"), p.get("protocol"))
                                       for p in ((s.get("spec") or {}).get("ports") or [])))
            for s in doc.get("items", [])]

    doc, err = ctx.kube.get("ingresses.networking.k8s.io")
    if doc is None:
        ctx.absent(out, "ingresses", err or "not readable")
    else:
        out["ingresses_note"] = "class, TLS and backends; hostnames are not collected"
        out["ingresses"] = [
            "%s · class %s · %s · %d rule(s) to %s" % (
                (i.get("metadata") or {}).get("name"),
                (i.get("spec") or {}).get("ingressClassName") or "unset",
                "TLS" if (i.get("spec") or {}).get("tls") else "no TLS",
                len((i.get("spec") or {}).get("rules") or []),
                ", ".join(sorted({((path.get("backend") or {}).get("service") or {}).get("name")
                                  for rule in ((i.get("spec") or {}).get("rules") or [])
                                  for path in (((rule.get("http") or {}).get("paths")) or [])}
                                 - {None})) or "none")
            for i in doc.get("items", [])]
    return out


# ── 5 · registry reachability ───────────────────────────────────────────────


def collect_registry(ctx):
    """Where images come FROM, stated as observed and never as inferred.

    A corporate mirror is the difference between an upgrade that pulls and one
    that sits in ImagePullBackOff, and it is not something to assume either
    way. Three observations, each labelled: the registry hosts actually
    referenced, whether any pull secret is attached, and any cluster mirror
    configuration that happens to be readable.
    """
    out = {}
    workloads = ctx.sections.get("workloads") or []
    hosts, secrets = {}, set()
    for w in workloads:
        for c in (w.get("containers") or []):
            if c.get("registry"):
                hosts[c["registry"]] = hosts.get(c["registry"], 0) + 1
        secrets.update(n for n in (w.get("image_pull_credentials") or []) if n)
    out["registries_referenced"] = ["%s (%d containers)" % (h, n)
                                    for h, n in sorted(hosts.items())] or None
    out["image_pull_credentials"] = sorted(secrets) or None
    if secrets:
        out["image_pull_credentials_note"] = (
            "the NAMES of the imagePullSecrets referenced; nothing in them is read")

    doc, err = ctx.kube.get("imagedigestmirrorsets.config.openshift.io", namespace=False)
    if doc is None:
        out["cluster_mirror_config"] = None
        out["cluster_mirror_note"] = (
            "ImageDigestMirrorSet is an OpenShift, cluster-scoped resource and was not "
            "readable (%s) — which is what a non-OpenShift cluster and a missing "
            "ClusterRole both look like. A mirror configured at the container runtime "
            "would not be visible to any kubectl read either." % (err or "not readable"))
    else:
        out["cluster_mirror_config"] = [
            {"name": (m.get("metadata") or {}).get("name"),
             "mirrors": (m.get("spec") or {}).get("imageDigestMirrors")}
            for m in doc.get("items", [])] or None

    public = ("docker.io", "ghcr.io", "quay.io", "registry.k8s.io", "gcr.io")
    private = sorted(h for h in hosts if h not in public)
    if private:
        out["reachability"] = (
            "images come from %s, which is not a registry we publish to — this cluster "
            "is served by a mirror or a private registry" % ", ".join(private))
    elif hosts:
        out["reachability"] = (
            "every image reference points at a public registry (%s)%s. Whether the pull "
            "goes direct or through a transparent proxy is not observable from here."
            % (", ".join(sorted(hosts)),
               "" if not secrets else ", with %d pull secret(s) attached" % len(secrets)))
    else:
        ctx.absent(out, "registry reachability", "no image reference was readable")
        out["reachability"] = None
    return out


# ── the document ────────────────────────────────────────────────────────────
#
# One entry per block of state-report.yaml: the key, the collector, and the
# comment a human reads ABOVE it. The comment lives here, beside the collector
# it describes, so a section and its explanation cannot drift apart — which is
# the whole reason this file is YAML and not JSON.

SECTIONS = (
    ("platform", collect_platform, """
1 · PLATFORM — what this runs on. Distribution and version, the cloud
underneath (read from the node providerID scheme; the instance ids are
dropped), the node shapes available to schedule on, and the storage classes
and volumes this cluster already has. Node NAMES are not collected: shapes
are grouped, which is the same fact without the inventory.
"""),
    ("workloads", collect_workloads, """
2 · VERSIONS AND VALUES — every workload, the image and the digest ACTUALLY
running, replicas, the requests and limits each container declares, and the
settings it carries. The digest is what says 0.10 exactly rather than roughly.
Settings are allowlist-first: a name matching password|token|secret|key|apikey
is dropped, and so is anything not on the allowlist, so what is here is the
customisation and nothing else. `provided_externally` names the settings that
come from a Secret or ConfigMap — the name only, never the value.
"""),
    ("running_outside_any_workload", collect_unowned, """
2b · IMAGES RUNNING UNDER NO WORKLOAD. Vexa creates a bot pod per meeting and
it belongs to no Deployment, so it would vanish from a workload list — and it
is the most upgrade-sensitive image in the estate. Grouped under `(unowned)`
rather than listed by pod name, because a per-meeting pod is NAMED after the
meeting and a meeting id is the one thing this document will not carry.
"""),
    ("resources", collect_resources, """
3 · RESOURCES — the namespace's quotas and LimitRanges, and the containers
that declare no resources of their own. This is here because it broke a real
upgrade: a ResourceQuota covering cpu or memory makes Kubernetes refuse any
pod that declares neither request nor limit, unless a LimitRange supplies a
default. Vexa's per-meeting bot pods declare none by design. `finding` below
is present only when all three conditions hold at once.
"""),
    ("wiring", collect_wiring, """
4 · WIRING — which components exist and how they are connected. The database
and transcription especially: in-cluster or external, how each is ADDRESSED
(the setting's name, never its value), version, and GPU or CPU. Every fact
here was read from the cluster. Nothing connected to the database.
"""),
    ("registry", collect_registry, """
5 · REGISTRY — where images actually come from, so an upgrade does not sit in
ImagePullBackOff behind a corporate mirror. Observed from image references,
pull secrets and any readable mirror configuration. Stated as observed, never
inferred.
"""),
)

HEADER = """
%s %s — the shape of this deployment's environment.

WHAT THIS IS. The output of one read-only `kubectl get` sweep of a single
namespace. No database connection, no pods/exec, no credentials of any kind,
no SQL. Run `--dry-run` to see every command that produced it.

WHY IT EXISTS. You already run Vexa. This says what shape your environment is,
so what gets built for you works with what you already have and asks for
nothing you do not.

WHAT IS NOT IN IT. No schema, no rows, no counts, no meeting content, no
transcripts. No credentials, and no Secret or ConfigMap values — where a
setting comes from one, only its name is recorded. No node names, no service
addresses, no ingress hostnames.

IT HAS NOT BEEN SENT ANYWHERE. The tool that wrote it has no transmit path:
no --submit, no destination, no endpoint. Read it, then send it by hand — or
do not.
"""

FOOTER_COMMENTS = {
    "absent": """
WHAT COULD NOT BE READ. Recorded rather than defaulted to zero or to an empty
list: a fabricated zero in a document whose whole purpose is to say what you
already have is worse than a stated gap. An empty list here means everything
was readable.
""",
    "refuses": """
WHAT THE TOOL REFUSES, each enforced by code rather than intent. Read the
source: it is one file, Apache-2.0, and `--dry-run` prints every command.
""",
    "redaction": """
THE REDACTION SELF-CHECK. `withheld_values` counts the values this run SAW and
chose not to record. The finished document is then scanned for every one of
them; `verified: true` means none survived. A survivor exits 3 and names the
count, never the value.
""",
}


def render_yaml(report):
    """The whole document: header comment, then one commented block per section.

    Comments are emitted from SECTIONS, so the prose that explains a block and
    the code that produces it live next to each other and move together.
    """
    lines = comment(HEADER.strip("\n") % (TOOL, TOOL_VERSION)) + [""]
    head = {k: report[k] for k in ("tool", "tool_version", "schema_version",
                                  "generated_at", "namespace", "read_with", "kit")
            if k in report}
    lines += _yaml(head)
    for key, _, note in SECTIONS:
        if report.get(key) is None:
            continue
        lines += ["", ""] + comment(note) + ["%s:" % key] + _yaml(report[key], 2)
    for key, note in FOOTER_COMMENTS.items():
        if key not in report:
            continue
        value = report[key]
        lines += ["", ""] + comment(note)
        if isinstance(value, (dict, list)) and value:
            lines += ["%s:" % key] + _yaml(value, 2)
        else:
            lines += _yaml({key: value})
    return "\n".join(lines) + "\n"


# ── --dry-run ───────────────────────────────────────────────────────────────
#
# THE FLAG THAT MAKES THE REST OF THIS FILE BELIEVABLE.
#
# The safety properties here are enforced in code — read-only `get`, an
# allowlist in front of every setting, no database client at all, no transmit
# path. None of it was VISIBLE at the moment an operator has to decide, which
# is before the first command. So the honest answer to "what will this do to my
# cluster?" was: read a thousand lines of Python, or trust us. This flag is the
# third answer.
#
# It connects to nothing, writes nothing, exits 0, and prints every command the
# real run would issue — built from the SAME argv builder the run uses, never
# from a second description of it. A hand-maintained "here is what it does"
# section would drift on the first collector somebody adds, and it would drift
# silently, which is the failure mode this whole tool exists to refuse. The
# test suite records what a real run executes and compares it to this list.


def _self_path():
    """How the docs spell this command, when this file is still in the kit."""
    here = pathlib.Path(__file__).resolve()
    try:
        return str(here.relative_to(REPO))
    except ValueError:
        return here.name


def cluster_reads(kube):
    """Every kubectl invocation a run makes, in the order it makes them."""
    ns = kube.namespace
    return [
        ("the Kubernetes version", kube.version_argv()),
        ("pods — read once, for digests, settings, wiring and resources",
         kube.get_argv("pods")),
        ("whether this is OpenShift, and which version",
         kube.get_argv("clusterversions.config.openshift.io", namespace=False)),
        ("nodes — grouped by shape; node NAMES are never collected",
         kube.get_argv("nodes", namespace=False)),
        ("storage classes — what this cluster can offer",
         kube.get_argv("storageclasses.storage.k8s.io", namespace=False)),
        ("volume claims — what is already used, and how big",
         kube.get_argv("persistentvolumeclaims")),
    ] + [("%ss in namespace %s" % (kind.lower(), ns), kube.get_argv(resource))
         for resource, kind in WORKLOAD_KINDS] + [
        ("resource quotas — the thing that stops bot pods being admitted",
         kube.get_argv("resourcequotas")),
        ("limit ranges — whether a default covers pods that declare nothing",
         kube.get_argv("limitranges")),
        ("services — type and ports; addresses are never collected",
         kube.get_argv("services")),
        ("ingresses — class and TLS; hostnames are never collected",
         kube.get_argv("ingresses.networking.k8s.io")),
        ("image mirror configuration, where the cluster exposes any",
         kube.get_argv("imagedigestmirrorsets.config.openshift.io", namespace=False)),
    ]


def dry_run(a, kube, argv=None):
    """Print exactly what a real run would do, having done none of it."""
    reads = cluster_reads(kube)
    out_path = pathlib.Path(a.out).resolve()
    if out_path.is_dir() or not out_path.suffix:
        out_path = out_path / OUTPUT_NAME
    lines = [
        "%s %s — DRY RUN. Nothing below was executed." % (TOOL, TOOL_VERSION),
        "",
        "This is the complete list of what a real run would do. This run connected to",
        "nothing, read nothing and wrote nothing, and it is safe to paste whole into a",
        "change ticket. Run it again without --dry-run to do the work.",
        "",
        "INVOCATION",
        "  python3 %s %s" % (_self_path(),
                             " ".join(argv if argv is not None else sys.argv[1:])),
        "",
        "WHAT IT READS — %d commands, every one a read" % len(reads),
    ]
    for note, cmd in reads:
        lines.append("  %s" % " ".join(cmd))
        lines.append("      %s" % note)
    lines += [
        "",
        "  That is the complete list. kubectl is invoked with no other verb: no exec,",
        "  no apply, no patch, no delete, no port-forward, no logs.",
        "",
        "  Nothing else is contacted. There is no database client in this tool, no SQL,",
        "  and no flag that would take a password. Four of the reads above are",
        "  cluster-scoped — nodes, storage classes, and the two OpenShift resources. If",
        "  you cannot grant those, they are recorded as absent and the rest still runs.",
        "",
        "WHAT IT WRITES — one file, and nothing else",
        "",
        "  %s" % out_path,
        "      Roughly 150-250 lines of commented YAML: platform and version, component",
        "      wiring for the database and transcription, per-container resources, the",
        "      namespace's quotas and LimitRanges, the image tags and digests actually",
        "      running, the settings this deployment has customised, and where its",
        "      images come from. Each block carries a plain-English comment above it.",
        "",
        "  No directory, no archive, nothing to extract. Nothing outside that one path",
        "  is created, moved or deleted.",
        "",
        "WHAT IT WILL NOT DO",
        "  Send anything. There is no --submit, no destination flag and no network",
        "      client in the source; the test suite fails the build if one appears.",
        "  Touch your database. It holds no database client and opens no connection;",
        "      engine and version are read from what is running, like everything else.",
        "  Read a Secret or a ConfigMap. Where a setting comes from one, only its name",
        "      is recorded — never the value.",
        "  Copy your configuration wholesale. Settings are captured from a fixed",
        "      allowlist in the source; a name matching password|token|secret|key|apikey",
        "      is dropped even when it matches that allowlist.",
    ]
    print("\n".join(lines))
    return 0


# ── the run ─────────────────────────────────────────────────────────────────


def git_revision():
    """Which kit produced this report — or an honest null.

    Two sources, and the second exists because of the first's blind spot: on a
    workstation the kit is a git checkout, and inside the kit runtime image
    there is neither a .git nor a git binary, both left out on purpose.
    """
    for args in (["describe", "--tags", "--always", "--dirty"],):
        try:
            r = subprocess.run(["git", "-C", str(REPO), *args],
                               capture_output=True, text=True)
        except OSError:
            break
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    stamp = REPO / "KIT_REVISION"
    if stamp.is_file():
        for line in stamp.read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "describe" and value.strip() not in ("", "unknown"):
                return value.strip()
    return None


def run_collectors(ctx):
    """Run every collector; a broken one costs its own section and nothing else.

    This is the contribute-back property in one function. A collector written
    for an estate nobody here has seen WILL raise somewhere eventually, and the
    operator running it should still get the other sections plus a line naming
    which collector failed — not a traceback and an empty file.
    """
    for key, fn, _ in SECTIONS:
        try:
            ctx.sections[key] = fn(ctx)
        except SystemExit:
            raise
        except Exception as e:                                       # noqa: BLE001
            print("!! collector %s (%s) failed: %s: %s"
                  % (fn.__name__, key, type(e).__name__, e))
            print("   every other section still ran. This is a bug worth a PR — the "
                  "traceback tail is in the report.")
            ctx.sections[key] = {
                "collector_failed": "%s raised %s: %s" % (fn.__name__,
                                                          type(e).__name__, e),
                "traceback_tail": traceback.format_exc().strip().splitlines()[-3:],
            }
    return ctx.sections


def build(a):
    kube = Kube(a.namespace, kubeconfig=a.kubeconfig, context=a.context)
    ctx = Ctx(kube, a)

    print("== %s %s — a read-only kubectl get, and nothing else" % (TOOL, TOOL_VERSION))
    print("   namespace: %s" % a.namespace)

    sections = run_collectors(ctx)

    report = {
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": utcnow(),
        "namespace": a.namespace,
        "read_with": "kubectl get -o json, read-only. Nothing else was contacted.",
        "kit": git_revision(),
    }
    report.update(redact(sections, removed=ctx.withheld))
    report["absent"] = ctx.gaps
    report["refuses"] = [
        "transmit: there is no submit path in this tool",
        "write: every call is kubectl get or kubectl version; no other verb exists here",
        "connect: no database client, no SQL, no flag that would take a password",
        "content: no schema, no rows, no counts, no meeting data, no Secret values",
    ]
    report["redaction"] = {
        "rule": "values under keys matching password|token|secret|key|apikey become "
                "REDACTED; settings capture is allowlist-first, so most values are "
                "never written rather than redacted after",
        "withheld_values": len(ctx.withheld),
        "verified": None,
        "leaks": None,
    }

    # VERIFY THE DOCUMENT, NOT THE INTENTION. The scan runs on the rendered
    # text, so what is checked is exactly the bytes that will be written — and
    # then the verdict goes back into the document and it is rendered again,
    # which is why this happens twice.
    if not a.verify_redaction:
        report["redaction"]["verified"] = False
        report["redaction"]["note"] = "--no-verify-redaction: NOT checked"
        leaks = []
    else:
        leaks = scan_text_for_leaks(render_yaml(report), ctx.withheld)
        report["redaction"]["verified"] = not leaks
        report["redaction"]["leaks"] = len(leaks)

    text = render_yaml(report)
    out_path = pathlib.Path(a.out).resolve()
    if out_path.is_dir() or not out_path.suffix:
        out_path = out_path / OUTPUT_NAME
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text)
    return out_path, text, leaks


def render(path, text, leaks):
    print("\n%s   (%d lines)" % (path, len(text.splitlines())))
    if leaks:
        print("\n!! REDACTION FAILED — %d withheld value(s) survived into the report."
              % len(leaks))
        print("   The file was written so you can inspect it. DO NOT SEND IT.")
        print("   Report the finding to Vexa without attaching it.")
        return 3
    print("\nRead it — it is one file and it explains itself. Then send it by hand,")
    print("or do not: nothing here transmits, and nothing will.")
    return 0


# Each claim below is enforced by a named thing in this file rather than by
# intent, and each is checkable in the source in under a minute. `--dry-run`
# prints the commands; the test suite fails the build if a transmit path, a
# second reader or a non-`get` verb appears.
EPILOGUE = """what this is, in one sentence

  A read-only `kubectl get` sweep of one namespace, written to one file. No
  database connection, no pods/exec, no credentials of any kind, no SQL.

why we ask for it

  You already run Vexa. This reads the shape of the environment it runs in, so
  what we build for you works with what you already have and asks for nothing
  you do not. If you are on 0.10, that is what tells us you are ready for 0.12.

what it collects

  1 platform    Kubernetes or OpenShift, version, cloud, node shapes, storage
  2 wiring      which components exist and how they are connected — database
                and transcription especially: in-cluster or external, how each
                is addressed, versions, GPU or CPU
  3 resources   requests and limits per container, and the namespace's
                ResourceQuotas and LimitRanges
  4 versions    image tags and digests actually running
  5 values      the settings this deployment has customised
  6 registry    Docker Hub or a mirror — as observed, never inferred

what you get

  state-report.yaml — one file, roughly 150-250 lines, every block carrying a
  plain-English comment above it. No directory, no archive, nothing to extract.
  You are meant to read all of it before any of it is sent.

what it enforces, and where to check it

  reads only    every call is `kubectl get -o json` or `kubectl version -o json`
                (Kube — there is no other verb anywhere in the file)
  no database   no client, no SQL, no flag that takes a password; engine and
                version are read from what is running (collect_wiring)
  allowlist     a setting is dropped unless its name matches the allowlist, and
                dropped anyway if it matches password|token|secret|key|apikey
                (env_allowed)
  no transmit   no --submit, no destination, no network client

  START WITH --dry-run. It connects to nothing and prints every command it would
  run, and what it would write."""


def main(argv=None):
    ap = argparse.ArgumentParser(prog=TOOL, description=__doc__, epilog=EPILOGUE,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--namespace", required=True,
                    help="the namespace the Vexa workloads run in")
    ap.add_argument("--dry-run", action="store_true",
                    help="print every kubectl command a real run would issue and what it "
                         "would write, then exit 0 having connected to nothing and "
                         "written nothing. Paste it into a change ticket.")
    ap.add_argument("--kubeconfig")
    ap.add_argument("--context")
    ap.add_argument("--out", default=".",
                    help="a directory to write %s into, or a filename to write "
                         "(default: the current directory)" % OUTPUT_NAME)
    ap.add_argument("--transcription-match", default="whisper|transcri|asr|diariz|stt",
                    help="regex matching the transcription workloads whose runtime shape "
                         "is captured (default 'whisper|transcri|asr|diariz|stt')")
    ap.add_argument("--verify-redaction", dest="verify_redaction", action="store_true",
                    default=True,
                    help="scan the finished report and refuse to finish if a withheld "
                         "value survived (default; exit 3)")
    ap.add_argument("--no-verify-redaction", dest="verify_redaction", action="store_false")
    a = ap.parse_args(argv)

    kube = Kube(a.namespace, kubeconfig=a.kubeconfig, context=a.context)
    if a.dry_run:
        return dry_run(a, kube, argv=argv)

    path, text, leaks = build(a)
    return render(path, text, leaks)


if __name__ == "__main__":
    sys.exit(main())
