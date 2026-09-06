#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# kit/platform/render.sh, offline. No network, no cluster: the upstream halves
# come from fixtures, and what is under test is the pack this repository adds
# around them.
#
#   1  DETERMINISM. Same inputs, two directories, byte-identical files. A pack
#      a platform team is asked to re-review must differ only when something
#      real about it differs, so a timestamp or a path in the header is a bug.
#   2  THE OBJECT SET. Every one of the five things measured Forbidden for a
#      tenant on 2026-09-06 is present, once, with the right names — and
#      Kyverno's ClusterPolicy CRD comes BEFORE the two ClusterPolicies that
#      need it.
#   3  NO UNSUBSTITUTED PLACEHOLDER. A leftover ${...} applies as a literal
#      and is the difference between a policy that pins your key and one that
#      pins the string ${CHANNEL_PUBLIC_KEY_INDENTED}.
#   4  THE CEILING IS THE CHART'S. LimitRange max equals the largest container
#      limit, the quota clears the delivered set, and --chart-values recomputes
#      both from a real values file.
#   5  THE PACK CANNOT DRIFT FROM THE INSTALLER. The two ClusterPolicies are
#      diffed against what kit/install.sh renders from the same inputs.
#   6  REFUSALS. Missing key, unknown provider, --uid-range off OpenShift.
#   7  LINT, when a linter is on this machine (kubeconform, or kubectl against
#      a reachable cluster). Skipped loudly otherwise — the load-bearing
#      validation is a server-side apply on a real cluster, not this.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(dirname "$HERE")"
KIT="$(dirname "$PLATFORM")"
FIX="$HERE/fixtures"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

cat > "$TMP/channel.pub" <<'EOF'
-----BEGIN PUBLIC KEY-----
FIXTUREKEYNOTAREALCHANNELKEYFIXTUREKEYNOTAREALCHANNELKEYFIXTURE=
-----END PUBLIC KEY-----
EOF

render() {
  bash "$PLATFORM/render.sh" \
    --channel fixture-stable --channel-pubkey "$TMP/channel.pub" \
    --argocd-manifest "$FIX/argocd-install.yaml" \
    --kyverno-manifest "$FIX/kyverno-install.yaml" "$@"
}

# 0 · every file the renderer needs is actually COMMITTED ----------------------
# chart-sizing.env matched the repository's `*.env` ignore rule, `git add -A`
# skipped it without a word, and the pack failed to render on the next machine
# that cloned the tree. A test that only reads the working directory cannot see
# that, so this one asks git.
if git -C "$PLATFORM" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  for needed in chart-sizing.env render.sh extract-crds.py read-chart-sizing.py; do
    git -C "$PLATFORM" ls-files --error-unmatch "$needed" >/dev/null 2>&1 \
      || fail "kit/platform/$needed is not tracked by git — a clone cannot render the pack"
  done
fi

# 1 · determinism ---------------------------------------------------------------
mkdir -p "$TMP/a" "$TMP/b"
for d in a b; do
  render --provider openshift --project vexa-app --out "$TMP/$d/platform-openshift.yaml" >/dev/null \
    || fail "render.sh failed for provider openshift"
done
cmp -s "$TMP/a/platform-openshift.yaml" "$TMP/b/platform-openshift.yaml" \
  || fail "two renders of the same inputs differ — something non-deterministic is in the output"

PACK="$TMP/a/platform-openshift.yaml"

# 2/3/4 · the object set, the placeholders, the ceiling ------------------------
python3 - "$PACK" "$PLATFORM/chart-sizing.env" <<'PYEOF' || exit 1
import sys, yaml
pack = open(sys.argv[1], encoding="utf-8").read()

problems = []
# Comment lines are exempt: kit/policy/ explains its own ${...} placeholders in
# a comment, and that sentence is not a leftover. A placeholder in a VALUE is.
leftover = sorted({line.strip() for line in pack.splitlines()
                   if "${" in line and not line.lstrip().startswith("#")})
if leftover:
    problems.append("unsubstituted placeholder(s): " + "; ".join(leftover[:5]))

docs = [d for d in yaml.safe_load_all(pack) if d]
by_kind = {}
for d in docs:
    by_kind.setdefault(d["kind"], []).append(d)
names = lambda kind: sorted(d["metadata"]["name"] for d in by_kind.get(kind, []))


def want(kind, expected):
    got = names(kind)
    if got != sorted(expected):
        problems.append(f"{kind}: expected {sorted(expected)}, got {got}")


# 1 · the Argo CRDs, and ONLY the argoproj.io ones
crds = names("CustomResourceDefinition")
for n in ("applications.argoproj.io", "applicationsets.argoproj.io", "appprojects.argoproj.io"):
    if n not in crds:
        problems.append(f"missing Argo CRD {n}")
if "widgets.example.com" in crds:
    problems.append("the extractor kept a CRD from another group")

# 2 · Kyverno and the two ClusterPolicies, in that order
if "clusterpolicies.kyverno.io" not in crds:
    problems.append("Kyverno's ClusterPolicy CRD is not in the pack")
want("ClusterPolicy", ["vexa-require-digest-pinning", "vexa-verify-channel-signature"])
kinds = [d["kind"] for d in docs]
if "ClusterPolicy" in kinds:
    crd_at = max(i for i, d in enumerate(docs)
                 if d["kind"] == "CustomResourceDefinition"
                 and d["metadata"]["name"] == "clusterpolicies.kyverno.io")
    if crd_at > min(i for i, d in enumerate(docs) if d["kind"] == "ClusterPolicy"):
        problems.append("a ClusterPolicy is ordered before the CRD that defines it")

# 3 · the read ClusterRole and its binding
if "vexa-argocd-cluster-cache-reader" not in names("ClusterRole"):
    problems.append("the read ClusterRole is missing")
if "vexa-argocd-cluster-cache-reader" not in names("ClusterRoleBinding"):
    problems.append("the read ClusterRoleBinding is missing")
for role in by_kind.get("ClusterRole", []):
    if role["metadata"]["name"] == "vexa-argocd-cluster-cache-reader":
        verbs = sorted({v for rule in role["rules"] for v in rule["verbs"]})
        if verbs != ["get", "list", "watch"]:
            problems.append(f"the read ClusterRole is not read-only: {verbs}")

# 4 · the projects, with PSA labels
projects = [d for d in by_kind.get("Namespace", []) if d["metadata"]["name"].startswith("vexa-app")]
if sorted(d["metadata"]["name"] for d in projects) != ["vexa-app", "vexa-app-prod"]:
    problems.append("the two projects are not both in the pack")
for ns in projects:
    labels = ns["metadata"].get("labels") or {}
    for key in ("pod-security.kubernetes.io/enforce",
                "pod-security.kubernetes.io/audit",
                "pod-security.kubernetes.io/warn"):
        if key not in labels:
            problems.append(f"{ns['metadata']['name']} carries no {key}")

# 5 · the ceiling and the quota, against the chart's own recorded figures
recorded = {}
for line in open(sys.argv[2], encoding="utf-8"):
    if "=" in line and not line.startswith("#"):
        k, v = line.strip().split("=", 1)
        recorded[k] = v

def mib(q):
    q = str(q)
    return int(q[:-2]) * 1024 if q.endswith("Gi") else int(q[:-2])

ceiling = mib(recorded["CHART_MAX_CONTAINER_MEMORY"])
for lr in by_kind.get("LimitRange", []):
    container = [i for i in lr["spec"]["limits"] if i["type"] == "Container"]
    if not container:
        problems.append(f"LimitRange {lr['metadata']['namespace']} has no Container limits")
        continue
    item = container[0]
    if mib(item["max"]["memory"]) < ceiling:
        problems.append(f"LimitRange max {item['max']['memory']} is BELOW the chart's largest "
                        f"container limit {recorded['CHART_MAX_CONTAINER_MEMORY']} — this is the "
                        f"exact refusal the 2026-09-06 rehearsal hit")
    # 'max' without 'default' rejects every container that declares none,
    # which on a shared project means Argo CD's own pods.
    if "default" not in item or "defaultRequest" not in item:
        problems.append("LimitRange sets max with no default/defaultRequest — "
                        "upstream Argo declares no resources and would be refused")

for q in by_kind.get("ResourceQuota", []):
    hard = q["spec"]["hard"]
    if mib(hard["limits.memory"]) < int(recorded["CHART_SUM_LIMITS_MEMORY_MI"]):
        problems.append("the quota does not cover the delivered set's own declared limits")
    if mib(hard["limits.memory"]) < ceiling:
        problems.append("the quota is below a single container's limit")

if problems:
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    sys.exit(1)
print(f"  object set OK — {len(docs)} documents, "
      f"{len(crds)} CRDs, {len(by_kind.get('ClusterPolicy', []))} ClusterPolicies, "
      f"{len(projects)} projects")
PYEOF

# 4b · --chart-values recomputes, and the arithmetic is the fixture's ----------
SIZING=$(python3 "$PLATFORM/read-chart-sizing.py" "$FIX/chart-values.yaml")
expect_sizing() {
  printf '%s\n' "$SIZING" | grep -qx "$1" || fail "read-chart-sizing: expected '$1', got: $(printf '%s\n' "$SIZING" | tr '\n' ' ')"
}
expect_sizing "CHART_MAX_CONTAINER_MEMORY=3Gi"
expect_sizing "CHART_MAX_CONTAINER_NAME=big"
expect_sizing "CHART_CONTAINERS=3"
expect_sizing "CHART_SUM_LIMITS_MEMORY_MI=4352"
expect_sizing "CHART_SUM_REQUESTS_MEMORY_MI=896"
expect_sizing "CHART_SUM_LIMITS_CPU_M=2600"
expect_sizing "CHART_SUM_REQUESTS_CPU_M=350"
expect_sizing "CHART_SPAWNED_BOT_MEMORY_MI=3000"
expect_sizing "CHART_SPAWNED_BOT_CPU_M=2000"
expect_sizing "CHART_SPAWNED_WORKER_CPU_M=250"

# and the ceiling in a pack rendered from that file is the file's, not the record's
render --provider kubernetes --project vexa-k8s --chart-values "$FIX/chart-values.yaml" \
  --out "$TMP/chartvalues.yaml" >/dev/null || fail "render.sh --chart-values failed"
grep -q "memory: 3Gi" "$TMP/chartvalues.yaml" \
  || fail "--chart-values did not carry the fixture's 3Gi ceiling into the LimitRange"

# an explicit override wins over both
render --provider kubernetes --project vexa-k8s --memory-ceiling 8Gi --out "$TMP/ceiling.yaml" >/dev/null
grep -q "memory: 8Gi" "$TMP/ceiling.yaml" || fail "--memory-ceiling was not honoured"

# 5 · the pack's ClusterPolicies are what install.sh renders -------------------
# Same file, same substitution, same key. If they ever diverge, a subscriber's
# admission gate and their platform team's admission gate are two different
# policies with one name.
cat > "$TMP/kubectl" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in namespace) echo "kind: Namespace";; esac; done
exit 0
EOF
chmod +x "$TMP/kubectl"
PATH="$TMP:$PATH" bash "$KIT/install.sh" --provider generic --registry reg.example:5000 \
  --channel fixture-stable --channel-pubkey "$TMP/channel.pub" \
  --staging-ns vexa-app --prod-ns vexa-app-prod \
  --skip-preflight --dry-run > "$TMP/install-dry-run.txt" 2>&1 \
  || fail "install.sh --dry-run failed while checking policy parity"

python3 - "$PACK" "$TMP/install-dry-run.txt" <<'PYEOF' || exit 1
import re, sys, yaml

pack = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8"))
        if d and d.get("kind") == "ClusterPolicy"]

# install.sh --dry-run interleaves rendered objects with its own progress
# lines: a "--- would apply:" marker introduces each render, then a "== "
# section header or an indented note resumes the narration. The renders carry
# no trailing newline, so the next "== " can land on the SAME line as the last
# key of an object — cut on the marker wherever it is, not only at a line
# start, or the last value silently absorbs a sentence of English.
# Exactly three or exactly five spaces: install.sh's two note indents. The
# rendered YAML steps in twos, so no line of a policy is ever odd-indented.
NARRATION = re.compile(r"\n {3}\S|\n {5}\S|== ")
installer = []
for chunk in open(sys.argv[2], encoding="utf-8").read().split("--- would apply:")[1:]:
    cut = NARRATION.search(chunk)
    body = chunk[:cut.start()] if cut else chunk
    try:
        installer += [d for d in yaml.safe_load_all(body)
                      if isinstance(d, dict) and d.get("kind") == "ClusterPolicy"]
    except yaml.YAMLError:
        continue

if len(installer) != 2:
    print(f"FAIL: install.sh --dry-run rendered {len(installer)} ClusterPolicies, expected 2",
          file=sys.stderr)
    sys.exit(1)
by_name = lambda ds: {d["metadata"]["name"]: d for d in ds}
if by_name(pack) != by_name(installer):
    print("FAIL: the pack's ClusterPolicies differ from what install.sh renders", file=sys.stderr)
    for name in sorted(by_name(pack)):
        if by_name(pack)[name] != by_name(installer).get(name):
            print(f"       diverged: {name}", file=sys.stderr)
    sys.exit(1)
print("  ClusterPolicy parity OK — the pack and install.sh render the same two policies")
PYEOF

# 6 · refusals -----------------------------------------------------------------
set +e
OUT=$(bash "$PLATFORM/render.sh" --provider openshift --project p --channel c 2>&1); RC=$?
set -e
[ "$RC" = 2 ] || fail "render.sh without --channel-pubkey exited $RC, expected 2"
echo "$OUT" | grep -q "channel.pub" || fail "the missing-key refusal does not say where the key comes from"

set +e
OUT=$(bash "$PLATFORM/render.sh" --provider eks --project p --channel c \
        --channel-pubkey "$TMP/channel.pub" 2>&1); RC=$?
set -e
[ "$RC" = 2 ] || fail "an unknown --provider exited $RC, expected 2"
echo "$OUT" | grep -q "kubernetes" || fail "the unknown-provider refusal does not name the generic pack"

set +e
OUT=$(bash "$PLATFORM/render.sh" --provider kubernetes --project p --channel c \
        --channel-pubkey "$TMP/channel.pub" --uid-range 1000/10 2>&1); RC=$?
set -e
[ "$RC" = 2 ] || fail "--uid-range on --provider kubernetes exited $RC, expected 2"

# the generic pack carries no OpenShift annotation
render --provider kubernetes --project vexa-k8s --out "$TMP/k8s.yaml" >/dev/null
grep -q "openshift.io/" "$TMP/k8s.yaml" && fail "the kubernetes pack carries OpenShift annotations"

# 7 · lint ---------------------------------------------------------------------
if command -v kubeconform >/dev/null 2>&1; then
  kubeconform -ignore-missing-schemas -summary "$PACK" \
    || fail "kubeconform rejected the rendered pack"
elif command -v kubectl >/dev/null 2>&1 && kubectl version >/dev/null 2>&1; then
  kubectl apply --dry-run=client -f "$PACK" >/dev/null \
    || fail "kubectl --dry-run=client rejected the rendered pack"
  echo "  linted with kubectl --dry-run=client"
else
  echo "  LINT SKIPPED: no kubeconform, and no kubectl with a reachable cluster."
  echo "  (kubectl --dry-run=client needs a server for discovery, so it is not an offline linter.)"
  echo "  The structural checks above still ran; a server-side apply on a real cluster is the"
  echo "  validation that matters and it is a receipt, not a unit test."
fi

echo "PASS: platform pack (determinism, object set, ceiling from the chart, policy parity, refusals)"
