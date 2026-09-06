#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# render.sh — the platform pack: every cluster-scoped object the kit needs,
# as ONE file a platform team applies once.
#
# The subscriber is supposed to deliver a generic environment, a transcription
# endpoint, a mailbox and the ports. Our machinery installs itself, from
# kit/install.sh, when that one run holds cluster rights. Where it does not —
# the app team holds a project and a separate department runs the cluster —
# five things are Forbidden to a tenant, each measured by attempting the verb
# on 2026-09-06:
#
#   1  the Argo CD CRDs                     CRDs are cluster-scoped
#   2  Kyverno + the two ClusterPolicies     cluster-scoped
#   3  a cluster-scoped READ ClusterRole     without it a namespace-scoped Argo
#      for the Argo application-controller   NEVER syncs: its cluster cache
#                                            fails on volumeattachments and
#                                            every Application sits Unknown
#   4  the project(s), with SCC annotations  namespaces are cluster-scoped
#      and PSA labels
#   5  a LimitRange ceiling >= the largest   project admin is READ-ONLY on
#      container limit in the chart          quota and limits
#
# This script renders those five as one `platform-<provider>.yaml`. Nothing in
# it is invented: the Argo CRDs and Kyverno come verbatim from the SAME pinned
# upstream manifests kit/install.sh applies, the two ClusterPolicies come from
# kit/policy/ through the same substitution install.sh performs, and the
# memory ceiling is read from the chart (kit/platform/chart-sizing.env records
# where, and --chart-values recomputes it from a real file).
#
# The render is a pure function of its inputs — no timestamp, no hostname, no
# run id — so two renders of the same inputs are byte-identical. That is a
# test (kit/platform/tests/test_render.sh), not an aspiration: a pack a
# platform team is asked to re-review should differ only when something real
# about it differs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"

usage() {
  cat <<EOF
usage: render.sh --provider <openshift|kubernetes> --project <name> \\
                 --channel <name> --channel-pubkey <path> [options]

required
  --provider        openshift | kubernetes. 'kubernetes' is the generic pack
                    for every other platform (EKS, AKS, GKE, LKE, on-prem):
                    identical objects, minus the OpenShift SCC annotations.
  --project         the project/namespace the staging tier deploys into. This
                    is the name your platform team creates.
  --channel         channel name, e.g. acme-stable. Recorded on every object
                    as an annotation so the pack's provenance is readable in
                    the cluster afterwards.
  --channel-pubkey  the cosign public key from your onboarding mail. The
                    signature ClusterPolicy pins it, exactly as install.sh
                    does; a pack without it could not be applied.

options
  --prod-project    the production project (default: <project>-prod)
  --signature-repository  OCI repo the image signatures live in (default:
                    alongside each image, cosign's own convention)
  --uid-range START/SIZE  OpenShift only. Pin the project's SCC UID range
                    instead of letting OpenShift allocate one on creation.
                    Omitted by default: OpenShift assigns the range itself,
                    and a range invented here would be a fabricated
                    constraint. See kit/platform/README.md.
  --app-team-subject KIND/NAME  bind ONE app-team identity to BOTH projects,
                    e.g. Group/vexa-app-team, User/…, ServiceAccount/… (which
                    is taken to live in the staging project unless you write
                    ServiceAccount/NAMESPACE/NAME). Omitted by default: most
                    platform teams grant project access through their own
                    mechanism (\`oc adm policy\`), and this pack should not
                    presume it.
  --app-team-role   the ClusterRole the binding above references (default:
                    admin — OpenShift's project admin)
  --argo-namespace  namespace holding the argocd-application-controller
                    ServiceAccount the read ClusterRole is bound to
                    (default: <project>, the namespace-scoped Argo shape)
  --argo-sa         that ServiceAccount's name (default:
                    argocd-application-controller)

sizing — every number below is derived and printed; --print-plan shows the
arithmetic and writes nothing
  --chart-values FILE  recompute the ceiling and the quota from a real Vexa
                    chart values.yaml instead of the recorded figures in
                    kit/platform/chart-sizing.env (needs PyYAML)
  --memory-ceiling SIZE  set the LimitRange max.memory outright. It is a
                    FLOOR, not a target: below the chart's largest container
                    limit the delivered set is refused at admission.
  --concurrent-bots N     meeting bots to budget quota for (default 4)
  --concurrent-workers N  agent workers to budget quota for (default 2)
  --quota-memory, --quota-cpu, --quota-pods, --quota-pvc  override a computed
                    ResourceQuota line (e.g. --quota-memory 64Gi)

sources
  --argocd-manifest FILE   read the pinned Argo CD manifest from a file
                    instead of fetching it. For air-gapped renders and for
                    tests; the pinned URL is printed either way.
  --kyverno-manifest FILE  the same for Kyverno.

output
  --out FILE        default: platform-<provider>.yaml in the current directory
  --print-plan      print the object list and the sizing arithmetic, write
                    nothing, exit 0
EOF
  exit 2
}

PROVIDER="" PROJECT="" CHANNEL="" PUBKEY="" PROD_PROJECT="" SIG_REPO=""
UID_RANGE="" APP_TEAM_SUBJECT="" APP_TEAM_ROLE=admin
ARGO_NS="" ARGO_SA=argocd-application-controller
CHART_VALUES="" MEMORY_CEILING="" CONCURRENT_BOTS=4 CONCURRENT_WORKERS=2
QUOTA_MEMORY="" QUOTA_CPU="" QUOTA_PODS="" QUOTA_PVC=""
ARGOCD_MANIFEST="" KYVERNO_MANIFEST="" OUT="" PRINT_PLAN=false

while [ $# -gt 0 ]; do
  case "$1" in
    --provider) PROVIDER=$2; shift 2;;
    --project) PROJECT=$2; shift 2;;
    --channel) CHANNEL=$2; shift 2;;
    --channel-pubkey) PUBKEY=$2; shift 2;;
    --prod-project) PROD_PROJECT=$2; shift 2;;
    --signature-repository) SIG_REPO=$2; shift 2;;
    --uid-range) UID_RANGE=$2; shift 2;;
    --app-team-subject) APP_TEAM_SUBJECT=$2; shift 2;;
    --app-team-role) APP_TEAM_ROLE=$2; shift 2;;
    --argo-namespace) ARGO_NS=$2; shift 2;;
    --argo-sa) ARGO_SA=$2; shift 2;;
    --chart-values) CHART_VALUES=$2; shift 2;;
    --memory-ceiling) MEMORY_CEILING=$2; shift 2;;
    --concurrent-bots) CONCURRENT_BOTS=$2; shift 2;;
    --concurrent-workers) CONCURRENT_WORKERS=$2; shift 2;;
    --quota-memory) QUOTA_MEMORY=$2; shift 2;;
    --quota-cpu) QUOTA_CPU=$2; shift 2;;
    --quota-pods) QUOTA_PODS=$2; shift 2;;
    --quota-pvc) QUOTA_PVC=$2; shift 2;;
    --argocd-manifest) ARGOCD_MANIFEST=$2; shift 2;;
    --kyverno-manifest) KYVERNO_MANIFEST=$2; shift 2;;
    --out) OUT=$2; shift 2;;
    --print-plan) PRINT_PLAN=true; shift;;
    -h|--help) usage;;
    *) echo "render.sh: unknown argument '$1'" >&2; usage;;
  esac
done

[ -n "$PROVIDER" ] && [ -n "$PROJECT" ] && [ -n "$CHANNEL" ] || usage
case "$PROVIDER" in
  openshift|kubernetes) ;;
  *) echo "render.sh: --provider takes openshift or kubernetes, not '$PROVIDER'." >&2
     echo "  Every non-OpenShift platform uses the 'kubernetes' pack." >&2; exit 2;;
esac
if [ -z "$PUBKEY" ]; then
  cat >&2 <<'EOF'
render.sh: --channel-pubkey is required.

  The pack carries the channel-signature ClusterPolicy, and that policy pins
  your channel's cosign public key inline — the same key kit/install.sh pins,
  filled the same way. A pack rendered without it would not be applyable, and
  a pack that silently dropped the policy would hand your platform team four
  of the five objects while reporting five.

  The key arrives in your onboarding mail as `channel.pub`. It is public: it
  is verification material, not a secret.
EOF
  exit 2
fi
[ -f "$PUBKEY" ] || { echo "render.sh: --channel-pubkey '$PUBKEY' is not a file" >&2; exit 2; }
if [ -n "$UID_RANGE" ]; then
  [ "$PROVIDER" = openshift ] || { echo "render.sh: --uid-range applies to --provider openshift only" >&2; exit 2; }
  echo "$UID_RANGE" | grep -Eq '^[0-9]+/[0-9]+$' || { echo "render.sh: --uid-range wants START/SIZE, e.g. 1000600000/10000" >&2; exit 2; }
fi

PROD_PROJECT=${PROD_PROJECT:-${PROJECT}-prod}
ARGO_NS=${ARGO_NS:-$PROJECT}
OUT=${OUT:-platform-${PROVIDER}.yaml}
# The header quotes the file's own name in the apply line, so it is the
# BASENAME: rendering the same inputs into two directories must produce two
# byte-identical files, and a path in the header would break that for no gain
# to the reader, who has the file in front of them.
OUT_NAME=$(basename "$OUT")

# Computed KEY=VALUE blocks are written here and sourced from a real file:
# `source <(...)` silently sets nothing under bash 3.2, which ships as
# /bin/bash on macOS, and the failure surfaces later as an unbound variable in
# a line that looks unrelated.
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# The pins come from the SAME provider profile install.sh sources, so the pack
# and the installer can never disagree about which Argo CD and which Kyverno
# this is. 'kubernetes' reads the generic profile.
KIT_PROVIDER=$PROVIDER
[ "$PROVIDER" = kubernetes ] && KIT_PROVIDER=generic
PROFILE="$KIT/providers/$KIT_PROVIDER/profile.env"
[ -f "$PROFILE" ] || { echo "render.sh: no provider profile at $PROFILE" >&2; exit 2; }
# shellcheck disable=SC1090
source "$PROFILE"
ARGOCD_URL="https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/install.yaml"
KYVERNO_URL="https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/install.yaml"

# --- sizing -------------------------------------------------------------------
if [ ! -f "$HERE/chart-sizing.env" ]; then
  echo "render.sh: kit/platform/chart-sizing.env is missing." >&2
  echo "  It holds the chart's own resource figures — the memory ceiling among them — and" >&2
  echo "  this script will not invent them. If this is a clone, the file was probably" >&2
  echo "  swallowed by the repository's \`*.env\` ignore rule; it carries an exception." >&2
  exit 1
fi
# shellcheck disable=SC1091
source "$HERE/chart-sizing.env"
SIZING_SOURCE="kit/platform/chart-sizing.env (recorded from $CHART_MAX_CONTAINER_NAME in the Vexa chart)"
if [ -n "$CHART_VALUES" ]; then
  [ -f "$CHART_VALUES" ] || { echo "render.sh: --chart-values '$CHART_VALUES' is not a file" >&2; exit 2; }
  python3 "$HERE/read-chart-sizing.py" "$CHART_VALUES" > "$TMP/recomputed.env" || exit 1
  # shellcheck disable=SC1091
  source "$TMP/recomputed.env"
  SIZING_SOURCE="$CHART_VALUES (read at render time by --chart-values)"
fi

CEILING=${MEMORY_CEILING:-$CHART_MAX_CONTAINER_MEMORY}

# The LimitRange defaults exist for ONE reason: upstream Argo CD declares no
# resources at all, and a LimitRange that sets `max` without a `default`
# REJECTS every container that declares none. The delivered chart declares all
# 13, so no delivered container is ever assigned a default — which is what
# keeps this clear of the 64Mi-squeeze class the preflight's P2 is anchored to.
LR_DEFAULT_MEMORY_MI=512
LR_DEFAULT_CPU_M=1000
LR_DEFAULT_REQUEST_MEMORY_MI=64
LR_DEFAULT_REQUEST_CPU_M=10

plan() {
  python3 - "$@" <<'PYEOF'
import math, sys
(sum_lim_mem, sum_req_mem, sum_lim_cpu, sum_req_cpu, containers, pvcs,
 bot_mem, bot_cpu, wrk_mem, wrk_cpu, bots, workers, argo_pods,
 d_mem, d_cpu, dr_mem, dr_cpu) = (int(x) for x in sys.argv[1:18])

lim_mem = sum_lim_mem + bots * bot_mem + workers * wrk_mem + argo_pods * d_mem
req_mem = sum_req_mem + bots * bot_mem + workers * wrk_mem + argo_pods * dr_mem
lim_cpu = sum_lim_cpu + bots * bot_cpu + workers * wrk_cpu + argo_pods * d_cpu
req_cpu = sum_req_cpu + bots * bot_cpu + workers * wrk_cpu + argo_pods * dr_cpu
# Rolling updates double a Deployment's pods for the length of the roll; a
# quota that fits the steady state and not the roll wedges the first upgrade.
pods = (containers + argo_pods) * 2 + bots + workers
gi = lambda mi: math.ceil(mi / 1024)
print(f"QUOTA_LIMITS_MEMORY_GI={gi(lim_mem)}")
print(f"QUOTA_REQUESTS_MEMORY_GI={gi(req_mem)}")
print(f"QUOTA_LIMITS_CPU={math.ceil(lim_cpu / 1000)}")
print(f"QUOTA_REQUESTS_CPU={math.ceil(req_cpu / 1000)}")
print(f"QUOTA_PODS_CALC={pods}")
print(f"QUOTA_PVC_CALC={pvcs * 2}")
print(f"WHY_LIMITS_MEMORY={sum_lim_mem}Mi chart + {bots}x{bot_mem}Mi bots + "
      f"{workers}x{wrk_mem}Mi workers + {argo_pods}x{d_mem}Mi argo = {lim_mem}Mi")
print(f"WHY_REQUESTS_MEMORY={sum_req_mem}Mi chart + {bots}x{bot_mem}Mi bots + "
      f"{workers}x{wrk_mem}Mi workers + {argo_pods}x{dr_mem}Mi argo = {req_mem}Mi")
print(f"WHY_LIMITS_CPU={sum_lim_cpu}m chart + {bots}x{bot_cpu}m bots + "
      f"{workers}x{wrk_cpu}m workers + {argo_pods}x{d_cpu}m argo = {lim_cpu}m")
print(f"WHY_PODS=({containers} chart + {argo_pods} argo) x2 for rolling "
      f"updates + {bots} bots + {workers} workers = {pods}")
PYEOF
}

plan "$CHART_SUM_LIMITS_MEMORY_MI" "$CHART_SUM_REQUESTS_MEMORY_MI" \
  "$CHART_SUM_LIMITS_CPU_M" "$CHART_SUM_REQUESTS_CPU_M" "$CHART_CONTAINERS" "$CHART_PVCS" \
  "$CHART_SPAWNED_BOT_MEMORY_MI" "$CHART_SPAWNED_BOT_CPU_M" \
  "$CHART_SPAWNED_WORKER_MEMORY_MI" "$CHART_SPAWNED_WORKER_CPU_M" \
  "$CONCURRENT_BOTS" "$CONCURRENT_WORKERS" "$ARGO_PODS" \
  "$LR_DEFAULT_MEMORY_MI" "$LR_DEFAULT_CPU_M" \
  "$LR_DEFAULT_REQUEST_MEMORY_MI" "$LR_DEFAULT_REQUEST_CPU_M" > "$TMP/plan.env"
grep -E '^QUOTA_' "$TMP/plan.env" > "$TMP/quota.env"
# shellcheck disable=SC1091
source "$TMP/quota.env"
WHY_LIMITS_MEMORY=$(sed -n 's/^WHY_LIMITS_MEMORY=//p' "$TMP/plan.env")
WHY_REQUESTS_MEMORY=$(sed -n 's/^WHY_REQUESTS_MEMORY=//p' "$TMP/plan.env")
WHY_LIMITS_CPU=$(sed -n 's/^WHY_LIMITS_CPU=//p' "$TMP/plan.env")
WHY_PODS=$(sed -n 's/^WHY_PODS=//p' "$TMP/plan.env")

Q_MEMORY=${QUOTA_MEMORY:-${QUOTA_LIMITS_MEMORY_GI}Gi}
Q_REQ_MEMORY=${QUOTA_REQUESTS_MEMORY_GI}Gi
Q_CPU=${QUOTA_CPU:-$QUOTA_LIMITS_CPU}
Q_REQ_CPU=$QUOTA_REQUESTS_CPU
Q_PODS=${QUOTA_PODS:-$QUOTA_PODS_CALC}
Q_PVC=${QUOTA_PVC:-$QUOTA_PVC_CALC}

if $PRINT_PLAN; then
  cat <<EOF
platform pack plan — nothing written

  provider            $PROVIDER (kit profile: $KIT_PROVIDER)
  projects            $PROJECT (staging) · $PROD_PROJECT (production)
  channel             $CHANNEL
  Argo CD             $ARGOCD_VERSION — CRDs only, from $ARGOCD_URL
  Kyverno             $KYVERNO_VERSION — whole install, from $KYVERNO_URL
  read ClusterRole    bound to $ARGO_NS/$ARGO_SA

  sizing read from    $SIZING_SOURCE
  LimitRange max      ${CEILING}   <- the largest container limit in the chart
                      ($CHART_MAX_CONTAINER_NAME). A FLOOR, not a target:
                      below it the delivered set is refused at admission.
  quota limits.mem    ${Q_MEMORY}   $WHY_LIMITS_MEMORY
  quota requests.mem  ${Q_REQ_MEMORY}   $WHY_REQUESTS_MEMORY
  quota limits.cpu    ${Q_CPU}   $WHY_LIMITS_CPU
  quota pods          ${Q_PODS}   $WHY_PODS
EOF
  exit 0
fi

# --- the upstream halves, verbatim -------------------------------------------
fetch() {   # $1 = local file or empty, $2 = url, $3 = label
  if [ -n "$1" ]; then
    [ -f "$1" ] || { echo "render.sh: $3 manifest '$1' is not a file" >&2; exit 2; }
    cat "$1"
  else
    curl -fsSL "$2" || { echo "render.sh: could not fetch the pinned $3 manifest from $2" >&2
                         echo "  Air-gapped? Mirror it and pass --${3}-manifest <file>." >&2; exit 1; }
  fi
}

fetch "$ARGOCD_MANIFEST" "$ARGOCD_URL" argocd > "$TMP/argocd.yaml"
fetch "$KYVERNO_MANIFEST" "$KYVERNO_URL" kyverno > "$TMP/kyverno.yaml"

# Split on document boundaries and keep the CustomResourceDefinition documents
# BYTE FOR BYTE. Re-emitting them through a YAML parser would produce objects
# that are equivalent but not identical, and "identical to upstream v3.5.1" is
# exactly the property a platform team reviewing this file wants to check.
python3 "$HERE/extract-crds.py" "$TMP/argocd.yaml" argoproj.io > "$TMP/argocd-crds.yaml"
grep -c '^kind: CustomResourceDefinition' "$TMP/argocd-crds.yaml" > "$TMP/crd-count"
CRD_COUNT=$(cat "$TMP/crd-count")
[ "$CRD_COUNT" = 3 ] || { echo "render.sh: expected 3 Argo CRDs in $ARGOCD_VERSION, found $CRD_COUNT" >&2; exit 1; }

# --- the two ClusterPolicies -------------------------------------------------
# Filled the way kit/install.sh step 4 fills them, from the same file, so the
# pack cannot drift from the installer. test_render.sh diffs the two renders.
PUBKEY_INDENTED=$(sed 's/^/                      /' "$PUBKEY")
STAGING_NAMESPACE=$PROJECT PROD_NAMESPACE=$PROD_PROJECT \
SIGNATURE_REPOSITORY=$SIG_REPO PUBKEY_INDENTED=$PUBKEY_INDENTED \
python3 - "$KIT/policy/kyverno-vexa-admission.yaml" > "$TMP/policy.yaml" <<'PYEOF'
import os, sys
text = open(sys.argv[1]).read()
text = text.replace("${STAGING_NAMESPACE}", os.environ["STAGING_NAMESPACE"])
text = text.replace("${PROD_NAMESPACE}", os.environ["PROD_NAMESPACE"])
text = text.replace("${CHANNEL_PUBLIC_KEY_INDENTED}", os.environ["PUBKEY_INDENTED"])
sig_repo = os.environ["SIGNATURE_REPOSITORY"]
if sig_repo:
    text = text.replace("${SIGNATURE_REPOSITORY}", sig_repo)
else:
    text = "\n".join(l for l in text.splitlines() if "${SIGNATURE_REPOSITORY}" not in l)
sys.stdout.write(text)
PYEOF
PUBKEY_SHA=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$PUBKEY")

# --- SCC annotations ----------------------------------------------------------
scc_annotations() {
  if [ -n "$UID_RANGE" ]; then
    local start=${UID_RANGE%%/*} size=${UID_RANGE##*/}
    cat <<EOF
    openshift.io/sa.scc.uid-range: "${UID_RANGE}"
    openshift.io/sa.scc.supplemental-groups: "${UID_RANGE}"
EOF
    echo "    # pinned by --uid-range: SCC admission assigns UIDs from ${start} for ${size}"
  else
    cat <<'EOF'
    # SCC annotations: OpenShift's project lifecycle sets these ITSELF at
    # creation — openshift.io/sa.scc.uid-range, .supplemental-groups, .mcs —
    # and restricted-v2 then assigns every container a UID from that range.
    # They are deliberately not written here: a range invented by a renderer
    # is a fabricated constraint, and one that collides with another project's
    # is worse than none. Pin them only if your estate pins ranges by policy:
    #   render.sh --uid-range <START>/<SIZE>
    # The kit's preflight (P4) reads uid-range off the live namespace, so it
    # works either way.
EOF
  fi
}

app_team_binding() {   # $1 = namespace
  [ -n "$APP_TEAM_SUBJECT" ] || return 0
  local kind=${APP_TEAM_SUBJECT%%/*} rest=${APP_TEAM_SUBJECT#*/}
  local subject sa_ns sa_name
  case "$kind" in
    Group|User) subject="- {apiGroup: rbac.authorization.k8s.io, kind: ${kind}, name: ${rest}}";;
    ServiceAccount)
      # ONE identity, BOTH projects. Resolving a ServiceAccount's namespace to
      # "whichever project this binding is in" would name two different
      # accounts and give the app team admin on staging and nothing on
      # production — which is not a team, it is two. The default namespace is
      # therefore the staging project for both bindings;
      # ServiceAccount/<ns>/<name> says otherwise.
      if [ "$rest" != "${rest#*/}" ]; then sa_ns=${rest%%/*}; sa_name=${rest#*/}
      else sa_ns=$PROJECT; sa_name=$rest; fi
      subject="- {kind: ServiceAccount, name: ${sa_name}, namespace: ${sa_ns}}";;
    *) echo "render.sh: --app-team-subject wants Group/NAME, User/NAME, ServiceAccount/NAME or ServiceAccount/NAMESPACE/NAME" >&2; exit 2;;
  esac
  cat <<EOF
---
# The app team's own grant inside the project. Everything after this pack is
# applied is theirs to do with it, and nothing they do reaches the cluster.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vexa-app-team
  namespace: $1
  annotations:
    vexa.ai/platform-pack: "$CHANNEL"
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ${APP_TEAM_ROLE}}
subjects:
${subject}
EOF
}

namespace_annotations() {   # $1 = tier
  echo "    vexa.ai/platform-pack: \"$CHANNEL\""
  echo "    vexa.ai/tier: \"$1\""
  if [ "$PROVIDER" = openshift ]; then
    echo "    openshift.io/description: \"Vexa $1 — channel $CHANNEL\""
    scc_annotations
  fi
}

project() {   # $1 = namespace  $2 = tier
  cat <<EOF
---
apiVersion: v1
kind: Namespace
metadata:
  name: $1
  annotations:
$(namespace_annotations "$2")
  labels:
    # PSA is validating, never mutating: where a cluster enforces Pod Security
    # 'restricted' it requires runAsNonRoot, which SCC does NOT set — so
    # SCC-clean is not PSA-clean and the delivered set must satisfy the union.
    # 'baseline' is what the delivered set is proven against today; raise it to
    # 'restricted' when your estate requires it and read
    # kit/providers/openshift/README.md first.
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# The ceiling, and it is the object the 2026-09-06 rehearsal died on:
# 'maximum memory usage per Container is 2560Mi, but limit is 4Gi'. A ceiling
# sized for the meeting bot's 2Gi memory-backed /dev/shm does not clear the
# delivered set — ${CHART_MAX_CONTAINER_NAME} asks ${CHART_MAX_CONTAINER_MEMORY}.
apiVersion: v1
kind: LimitRange
metadata:
  name: vexa-limits
  namespace: $1
  annotations:
    vexa.ai/platform-pack: "$CHANNEL"
    vexa.ai/memory-ceiling-source: "${SIZING_SOURCE}"
spec:
  limits:
    - type: Container
      max:
        memory: ${CEILING}
      # Applied only to a container that declares nothing. All 13 delivered
      # containers declare requests AND limits; these exist because upstream
      # Argo CD declares none, and a LimitRange with 'max' and no 'default'
      # refuses such a container outright.
      default:
        cpu: ${LR_DEFAULT_CPU_M}m
        memory: ${LR_DEFAULT_MEMORY_MI}Mi
      defaultRequest:
        cpu: ${LR_DEFAULT_REQUEST_CPU_M}m
        memory: ${LR_DEFAULT_REQUEST_MEMORY_MI}Mi
---
# Sized for the delivered set PLUS the pods the runtime spawns at meeting time
# (they are not in the chart, they carry request == limit, and a quota that
# forgets them refuses the meeting rather than the install) PLUS Argo CD if it
# shares the project.
apiVersion: v1
kind: ResourceQuota
metadata:
  name: vexa-quota
  namespace: $1
  annotations:
    vexa.ai/platform-pack: "$CHANNEL"
    vexa.ai/quota-limits-memory: "${WHY_LIMITS_MEMORY}"
    vexa.ai/quota-limits-cpu: "${WHY_LIMITS_CPU}"
    vexa.ai/quota-pods: "${WHY_PODS}"
spec:
  hard:
    limits.memory: ${Q_MEMORY}
    requests.memory: ${Q_REQ_MEMORY}
    limits.cpu: "${Q_CPU}"
    requests.cpu: "${Q_REQ_CPU}"
    pods: "${Q_PODS}"
    persistentvolumeclaims: "${Q_PVC}"
$(app_team_binding "$1")
EOF
}

# --- write it ----------------------------------------------------------------
{
cat <<EOF
# SPDX-License-Identifier: Apache-2.0
# Vexa platform pack — $PROVIDER
#
# Every cluster-scoped object the Vexa delivery kit needs, as one file. Apply
# it ONCE, with cluster rights. After that the app team installs, subscribes,
# upgrades and reports entirely inside their own project, and never comes back
# to you for a cluster-scoped act.
#
#   kubectl apply --server-side --force-conflicts -f $OUT_NAME
#
# --server-side is not optional: the Argo ApplicationSet CRD is larger than the
# 256KB last-applied annotation client-side apply writes, and a plain
# \`apply -f\` fails on it. The two ClusterPolicies at the foot of this file
# need Kyverno's own CRD to exist first; if your first apply reports
# 'no matches for kind ClusterPolicy', run the same command again — every
# object here is idempotent.
#
# WHAT IS IN IT
#   Argo CD $ARGOCD_VERSION CRDs ($CRD_COUNT)   verbatim from the pinned upstream manifest
#     $ARGOCD_URL
#   Kyverno $KYVERNO_VERSION                verbatim from the pinned upstream release
#     $KYVERNO_URL
#   ClusterRole + binding           cluster-scoped READ for the Argo
#                                   application-controller. Without it a
#                                   namespace-scoped Argo never syncs.
#   $PROJECT / $PROD_PROJECT
#                                   the projects, with PSA labels, the memory
#                                   ceiling and the quota
#   2 ClusterPolicies               digest pinning and channel-signature
#                                   verification, from kit/policy/, pinning
#                                   the channel key sha256:$PUBKEY_SHA
#
# WHAT IT DOES NOT DO
#   It installs no Vexa workload and grants nothing to Vexa. It creates no
#   credential. Nothing in it calls out; the pinned upstream manifests above
#   are the only fetch, and it happened on the machine that rendered this.
#
# Rendered by kit/platform/render.sh from Vexa-ai/vexa-delivery. The render is
# a pure function of its inputs — no timestamps — so re-rendering the same
# inputs produces this file byte for byte. Full explanation of every object:
# kit/platform/README.md.
EOF
echo "---"
cat "$TMP/argocd-crds.yaml"
echo "---"
cat "$TMP/kyverno.yaml"
cat <<EOF
---
# Argo CD's cluster cache loads the initial state of EVERY cluster-scoped
# resource kind before it syncs anything, and that load is not gated by
# resource.inclusions / resource.exclusions — both were set on 2026-09-06 and
# neither helped. Without this grant a namespace-scoped Argo sits on
#   failed to load initial state of resource VolumeAttachment.storage.k8s.io:
#   volumeattachments.storage.k8s.io is forbidden ... at the cluster scope
# and every Application stays Unknown. Read-only: get, list, watch. It grants
# no write anywhere in the cluster.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vexa-argocd-cluster-cache-reader
  annotations:
    vexa.ai/platform-pack: "$CHANNEL"
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vexa-argocd-cluster-cache-reader
  annotations:
    vexa.ai/platform-pack: "$CHANNEL"
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: vexa-argocd-cluster-cache-reader}
subjects:
  - {kind: ServiceAccount, name: ${ARGO_SA}, namespace: ${ARGO_NS}}
EOF
project "$PROJECT" staging
project "$PROD_PROJECT" production
echo "---"
cat "$TMP/policy.yaml"
} > "$OUT"

BYTES=$(wc -c < "$OUT" | tr -d ' ')
DOCS=$(grep -c '^---$' "$OUT" || true)
cat <<EOF
wrote $OUT ($BYTES bytes, $DOCS documents)

  Argo CD $ARGOCD_VERSION      $CRD_COUNT CRDs, verbatim
  Kyverno $KYVERNO_VERSION      whole upstream install, verbatim
  read ClusterRole      vexa-argocd-cluster-cache-reader -> ${ARGO_NS}/${ARGO_SA}
  projects              $PROJECT · $PROD_PROJECT
  memory ceiling        $CEILING  (largest container limit in the chart: $CHART_MAX_CONTAINER_NAME)
                        source: $SIZING_SOURCE
  quota                 limits.memory $Q_MEMORY · limits.cpu $Q_CPU · pods $Q_PODS
  channel key           sha256:$PUBKEY_SHA

hand it to your platform team with one line:

  kubectl apply --server-side --force-conflicts -f $OUT

then, in the project and with no cluster rights:

  ./kit/install.sh --provider $KIT_PROVIDER --cluster-scope platform-pack \\
    --registry <your registry> --channel $CHANNEL --channel-pubkey <channel.pub> \\
    --staging-ns $PROJECT --prod-ns $PROD_PROJECT
EOF
