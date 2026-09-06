#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# vexa-kit install — "bring your own cluster, run this command."
#
# One idempotent entrypoint that takes a conformant cluster to a subscribed
# one: preflight -> pinned Argo CD -> pinned Kyverno -> admission policy ->
# channel subscription (ApplicationSet). Provider differences live in
# kit/providers/<name>/profile.env, never in this script's logic.
#
# Everything installed is stock upstream (Argo CD, Kyverno) plus rendered
# configuration; nothing phones home; the cluster pulls, verifies, applies.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
usage: install.sh --provider <name> --registry <host[:port]> --channel <name> \\
                  --channel-pubkey <path> [options]

required
  --provider        one of: $(find "$HERE/providers" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | tr '\n' ' ')
  --registry        channel registry host[:port]
  --channel         channel name, e.g. acme-stable
  --channel-pubkey  cosign public key the admission policy pins

options
  --customer-values customer-local values file injected into the subscription
                    (default: profiles/vexa/customer-values.example.yaml)
  --manifests       rendered manifests of the delivered set, handed to the
                    preflight so P2/P3 check EVERY workload's declared
                    resources against your LimitRange and quota — not just the
                    synthetic bot profile. Without it the installer renders the
                    chart itself with 'helm template'; if that is not possible
                    it says so and the preflight checks the bot alone.
  --staging-ns      namespace the staging Application deploys into
                    (default vexa-staging)
  --prod-ns         namespace the production Application deploys into
                    (default vexa-prod)
  --prod-pin        channel position prod follows. The production Application
                    is created either way; with no pin it is parked at
                    'UNPINNED', a position that resolves to nothing, so it
                    syncs nothing until you move the pin. Moving it is YOUR
                    gate.
  --signature-repository  OCI repo where cosign signatures live (default:
                    alongside each image)
  --claim-code CODE claim the channel credential with the six digits read to you
                    on a call, INSTEAD of --registry-user plus VEXA_CHANNEL_PASS.
                    Written 123 456 and typed either way: 123456, or '123 456'
                    in quotes. The credential is fetched from the channel edge
                    over TLS, used for every registry secret this script writes,
                    and also written to the station credential Secret in
                    --prod-ns. It never appears on your screen, in your shell
                    history or in a file. The code is single-use and lives ~15
                    minutes.
  --claim-edge URL  claim endpoint (default https://<registry>/claim — the claim
                    service is behind the same edge as the registry, so it is
                    the host you already allowed through your firewall)
  --station NAME    your station name, which the claim is bound to
                    (default: the channel name)
  --registry-user   username for an AUTHENTICATED channel registry. The
                    password is read from the VEXA_CHANNEL_PASS environment
                    variable, never from argv. Required whenever your channel
                    registry needs credentials to pull: without it Argo CD's
                    repo-server gets 401 and the subscription never syncs.
                    Kyverno also receives it; against channel.vexa.ai the
                    signature read paths are anonymous so it is not needed
                    for admission, but it is needed if you mirror the channel
                    into your own authenticated registry. Use this OR
                    --claim-code, not both.
  --chart-name NAME  chart to install from the channel (default: vexa). An
                    estate channel serves the vexa-platform chart.
  --release-name N  Helm release name (default: vexa). MUST match the existing
                    release when adopting a live cluster — Helm keys its release
                    Secret on this and a mismatch installs a second copy.
  --registry-ca     PEM file of the registry's CA (corporate/self-signed):
                    mounted into Kyverno as a trust bundle
  --registry-insecure  registry TLS cert is not trusted by Argo CD (self-signed
                    test rigs): marks the Argo repo secrets insecure. Argo has
                    no CA-bundle path for OCI repos, so --registry-ca alone
                    covers Kyverno but not Argo; without this flag a self-signed
                    registry fails repo-server with "x509: certificate signed by
                    unknown authority" (M2 receipt §3)
  --verifier-image  station verifier image; setting it turns the chart-side
                    PreSync verify gate on (default: off)
  --kubeconfig      kubeconfig path (default: ambient)
  --plain-http      registry is plain HTTP (test rigs only; implies insecure)
  --argocd MODE     what to do about Argo CD: auto (default) | adopt | install |
                    skip. auto DETECTS an existing install first: absent ->
                    install the pin; present at the pinned version -> ADOPT it
                    and write nothing; present at another version -> REFUSE and
                    say so, before a single object is applied. adopt takes an
                    existing install whatever version it is; install always
                    applies the upstream manifests; skip leaves Argo entirely
                    alone (you install it, we subscribe to it).
  --kyverno MODE    the same four modes for Kyverno.
  --cluster-scope   who owns the cluster-scoped objects:
                      installer      (default) this run creates them. Needs
                                     cluster rights, which is how our own
                                     cluster went in.
                      platform-pack  your platform team already applied
                                     kit/platform's platform-<provider>.yaml.
                                     This run then does namespace-scoped work
                                     only: it installs no Argo CD, no Kyverno
                                     and no ClusterPolicy, and it creates no
                                     namespace. It CHECKS the pack landed
                                     first and refuses by name if it did not.
  --skip-preflight  do not run the conformance preflight (NOT recommended)
  --dry-run         render everything, apply nothing
EOF
  exit 2
}

PROVIDER="" REGISTRY="" CHANNEL="" PUBKEY="" SIG_REPO="" REGISTRY_CA="" REGISTRY_USER=""
CUSTOMER_VALUES="" VERIFIER_IMAGE="" MANIFESTS=""
CLAIM_CODE="" CLAIM_EDGE="" STATION="" STATION_SECRET=vexa-station-credential
# The chart the subscription installs and the Helm release name it installs
# under. Both were hardcoded to "vexa". ADOPTION MAKES THAT FATAL: taking
# ownership of an existing release means matching the name that release
# ALREADY HAS, and ours is `vexa-platform`. A release name is not a preference
# — Helm keys its release Secret on it, and Argo's ownership metadata derives
# from it, so a mismatch does not adopt, it installs a SECOND copy alongside.
CHART_NAME=vexa RELEASE_NAME=vexa
STAGING_NS=vexa-staging PROD_NS=vexa-prod PROD_PIN=""
KUBECONFIG_ARG=() PLAIN_HTTP=false REGISTRY_INSECURE=false SKIP_PREFLIGHT=false DRY_RUN=false
ARGOCD_MODE=auto KYVERNO_MODE=auto
CLUSTER_SCOPE=installer

while [ $# -gt 0 ]; do
  case "$1" in
    --provider) PROVIDER=$2; shift 2;;
    --registry) REGISTRY=$2; shift 2;;
    --channel) CHANNEL=$2; shift 2;;
    --channel-pubkey) PUBKEY=$2; shift 2;;
    --signature-repository) SIG_REPO=$2; shift 2;;
    --registry-user) REGISTRY_USER=$2; shift 2;;
    --claim-code) CLAIM_CODE=$2; shift 2;;
    --claim-edge) CLAIM_EDGE=$2; shift 2;;
    --station) STATION=$2; shift 2;;
    --registry-ca) REGISTRY_CA=$2; shift 2;;
    --chart-name) CHART_NAME=$2; shift 2;;
    --release-name) RELEASE_NAME=$2; shift 2;;
    --customer-values) CUSTOMER_VALUES=$2; shift 2;;
    --manifests) MANIFESTS=$2; shift 2;;
    --contract) CONTRACT=$2; shift 2;;
    --contract-prod) CONTRACT_PROD=$2; shift 2;;
    --verifier-image) VERIFIER_IMAGE=$2; shift 2;;
    --staging-ns) STAGING_NS=$2; shift 2;;
    --prod-ns) PROD_NS=$2; shift 2;;
    --prod-pin) PROD_PIN=$2; shift 2;;
    --kubeconfig) KUBECONFIG_ARG=(--kubeconfig "$2"); shift 2;;
    --cluster-scope) CLUSTER_SCOPE=$2; shift 2;;
    --plain-http) PLAIN_HTTP=true; shift;;
    --argocd) ARGOCD_MODE=$2; shift 2;;
    --kyverno) KYVERNO_MODE=$2; shift 2;;
    --registry-insecure) REGISTRY_INSECURE=true; shift;;
    --skip-preflight) SKIP_PREFLIGHT=true; shift;;
    --dry-run) DRY_RUN=true; shift;;
    *) usage;;
  esac
done
if [ -z "$PROVIDER" ] || [ -z "$REGISTRY" ] || [ -z "$CHANNEL" ] || [ -z "$PUBKEY" ]; then
  usage
fi

for mode_pair in "--argocd:$ARGOCD_MODE" "--kyverno:$KYVERNO_MODE"; do
  case "${mode_pair#*:}" in
    auto|adopt|install|skip) ;;
    *) echo "install.sh: ${mode_pair%%:*} takes auto|adopt|install|skip, not '${mode_pair#*:}'"; exit 2;;
  esac
done

if [ -n "$REGISTRY_USER" ] && [ -n "$CLAIM_CODE" ]; then
  echo "install.sh: --registry-user and --claim-code are two ways to get the same"
  echo "  credential. Pass one. --claim-code fetches it; --registry-user says you"
  echo "  already have it in VEXA_CHANNEL_PASS."
  exit 2
fi
case "$CLUSTER_SCOPE" in
  installer|platform-pack) ;;
  *) echo "install.sh: --cluster-scope takes installer or platform-pack, not '$CLUSTER_SCOPE'"; exit 2;;
esac
PACK_SCOPE=false; [ "$CLUSTER_SCOPE" = platform-pack ] && PACK_SCOPE=true

if [ -n "$REGISTRY_USER" ] && [ -z "${VEXA_CHANNEL_PASS:-}" ]; then
  echo "install.sh: --registry-user given but VEXA_CHANNEL_PASS is not set."
  echo "  export VEXA_CHANNEL_PASS=... (the password never goes on the command line)"
  exit 2
fi

PROFILE="$HERE/providers/$PROVIDER/profile.env"
[ -f "$PROFILE" ] || { echo "unknown provider '$PROVIDER' (no $PROFILE)"; exit 2; }
# shellcheck disable=SC1090
source "$PROFILE"
echo "== provider profile: $PROVIDER (tested: ${PROFILE_TESTED:-no})"
[ "${PROFILE_TESTED:-no}" = "yes" ] || echo "   NOTE: this profile is declared, not yet exercised end-to-end; expect deltas."

ARGOCD_NS=${ARGOCD_NAMESPACE:-argocd}
KYVERNO_NS=${KYVERNO_NAMESPACE:-kyverno}

# --cluster-scope platform-pack IS the namespace-scoped-Argo shape: the app
# team holds a project, Argo lives in it, and the pack's ClusterRoleBinding
# binds the application-controller ServiceAccount there by default. Leaving
# ARGOCD_NS at `argocd` made every pack-mode run die at step 5 on
#   secrets "vexa-channel-registry" is forbidden ... in the namespace "argocd"
# — measured on the rig, 2026-09-06. Set ARGOCD_NAMESPACE (or the provider
# profile's) to override; it still wins, because this only fills a blank.
if $PACK_SCOPE && [ -z "${ARGOCD_NAMESPACE:-}" ]; then
  ARGOCD_NS=$STAGING_NS
  echo "== Argo CD namespace: ${ARGOCD_NS} (the project — this is the namespace-scoped shape)"
  echo "   export ARGOCD_NAMESPACE=... if your Argo lives elsewhere"
fi

# ${arr[@]+"${arr[@]}"} — empty-array expansion is "unbound" under set -u on bash 3.2 (macOS
# default), so a run without --kubeconfig crashed at the first kubectl call
kc() { kubectl ${KUBECONFIG_ARG[@]+"${KUBECONFIG_ARG[@]}"} "$@"; }
# THE DRY RUN MUST NOT PRINT A CREDENTIAL, and on 2026-09-06 it printed the
# registry password in cleartext inside the rendered Argo repository Secret. The
# Harbor robot credential that render burned was rotated the same hour. A render
# an operator cannot save, paste into a ticket, or leave in scrollback is not a
# review artifact, so redaction is not a courtesy here — it is what makes
# --dry-run usable for the thing it exists for.
#
# The SHAPE survives and only the value goes: a reviewer needs to see that a
# repository Secret carrying a username exists, never what the password is. The
# channel PUBLIC key is deliberately not touched — it is public, and whether the
# right key landed is exactly what a reviewer is checking.
redact_secrets() {
  VEXA_REDACT_PASS="${VEXA_CHANNEL_PASS:-}" python3 -c '
import base64, os, re, sys
text = sys.stdin.read()
pw = os.environ.get("VEXA_REDACT_PASS") or ""
if pw:
    # the literal, and the two encodings kubectl puts it through on the way
    # into a dockerconfigjson Secret
    for form in (pw, base64.b64encode(pw.encode()).decode()):
        text = text.replace(form, "REDACTED")
# ...and the carriers, replaced wholesale rather than searched inside: a base64
# blob that DECODES to a credential is a credential.
text = re.sub(r"(?mi)^(\s*(?:\.dockerconfigjson|password|token|auth)\s*:\s*)\S.*$",
              r"\1REDACTED", text)
sys.stdout.write(text)
'
}

apply() {
  if $DRY_RUN; then echo "--- would apply:"; redact_secrets; else kc apply -f -; fi
}

# THE CHANNEL PASSWORD NEVER REACHES A CHILD PROCESS'S ARGV.
#
# `kubectl create secret docker-registry --docker-password="$VEXA_CHANNEL_PASS"`
# put it there three times: the Kyverno credential, the kubelet pull Secret and
# the verifier's Secret. Argv is world-readable in /proc and in `ps` output for
# the life of the process — on a shared jump host that IS the exposure — and two
# of the three ran under `--dry-run` as well, inside the command #28 hardened so
# that a render carries no credential. The kit already refused this shape
# elsewhere and said why: `kit/claim.sh` § `vexa_claim_write_secret`.
#
# So the Secret is RENDERED here and applied from stdin, which is what
# `/install` promises: "the password is read from the environment, never from
# argv". The value moves shell variable -> printf (a bash BUILTIN: no exec, so
# nothing appears in a process listing) -> pipe -> python's stdin -> base64 in
# the manifest. It is never an argument to anything and never touches disk.
#
# The object is the one kubectl would have built: the same `auths` map, the same
# three keys in the same order, `email` omitted when empty exactly as kubectl
# omits it, and compact separators so the encoded blob matches Go's
# json.Marshal. Checked against `kubectl create secret docker-registry
# --dry-run=client -o yaml` on v1.34.1 with a password carrying a quote and a
# backslash; the one difference left is Go's HTML-escaping of < > & inside a
# string, which decodes to the same bytes.
#
# Under --dry-run `redact_secrets` replaces the whole .dockerconfigjson line,
# because a base64 blob that decodes to a credential is a credential.
render_registry_secret() {
  local ns=$1 name=$2 blob
  blob=$(printf '%s' "${VEXA_CHANNEL_PASS:-}" \
    | VEXA_DR_SERVER="$REGISTRY" VEXA_DR_USER="$REGISTRY_USER" python3 -c '
import base64, json, os, sys
pw = sys.stdin.read()
server, user = os.environ["VEXA_DR_SERVER"], os.environ["VEXA_DR_USER"]
auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
cfg = {"auths": {server: {"username": user, "password": pw, "auth": auth}}}
sys.stdout.write(base64.b64encode(
    json.dumps(cfg, separators=(",", ":")).encode()).decode())
')
  cat <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${name}
  namespace: ${ns}
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: ${blob}
EOF
}

# `apply >/dev/null` silences the one-line confirmation a REAL apply prints.
# Under --dry-run it silenced the RENDER: the rehearsal's dry run emitted 0
# ConfigMaps and 2 Secrets where a real run writes 2 contract ConfigMaps, 2
# pubkey Secrets, 2 kubelet pull Secrets and 2 repo Secrets. Six objects a
# reviewing subscriber never saw, in the command whose whole promise is "render
# everything, apply nothing".
apply_quiet() {
  if $DRY_RUN; then apply; else apply >/dev/null; fi
}

# 0 · ADOPTION PLAN — decided BEFORE a single object is written ----------------
#
# The rehearsal that produced this section ran the installer as a namespace-
# scoped tenant against a cluster that ALREADY had Argo CD v3.5.1 and Kyverno
# v1.19.0 — exactly the pinned versions. A server-side dry-run measured what
# the unconditional steps 2 and 3 below would have done: 49 objects
# `serverside-applied` and 9 `Forbidden`. Among the 49, `argocd-dex-server` and
# `argocd-application-controller` — re-adding the upstream hard-coded UIDs
# (dex 1001, redis 999) that the cluster's own SCC then rejects. So a real run
# HALF-LANDS: it breaks a working Argo, is Forbidden on the cluster-scoped
# nine, `set -e` stops the script, and the operator is left with a broken Argo
# and no subscription.
#
# Both halves of that are fixed here, and both are refusals rather than
# repairs, because the only safe thing to do with a component somebody else
# already owns is to leave it alone and say so:
#
#   1. DETECT what is already installed and compare it with the pin. Present at
#      the pinned version -> ADOPT (write nothing). Present at another version
#      -> REFUSE, naming both versions. Absent -> install.
#   2. Before installing, SERVER-SIDE DRY-RUN the upstream manifest. Any
#      Forbidden means this credential cannot complete the install, so the
#      install does not start. A refusal that costs nothing is the whole point
#      of asking first.

# The deployment that identifies each component, and the image whose tag
# carries its version. Argo is looked for under both its upstream name and the
# OpenShift GitOps operator's, because on OpenShift the house Argo is the
# operator's and it is the one that must be adopted rather than duplicated.
detect_component() {   # $1 = namespace, $2.. = candidate deployment names
  local ns=$1; shift
  local d img
  for d in "$@"; do
    img=$(kc -n "$ns" get deploy "$d" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)
    if [ -n "$img" ]; then
      case "$img" in
        *@sha256:*) echo "$d unknown";;         # digest-pinned: no version to read
        *:*)        echo "$d ${img##*:}";;
        *)          echo "$d unknown";;
      esac
      return 0
    fi
  done
  echo "- absent"
}

# A namespace is created by this installer under --cluster-scope installer and
# by the platform pack under --cluster-scope platform-pack. One creator, and
# the other verifies — never both, because a `create namespace` from a tenant
# is Forbidden and would stop the script on a namespace that already exists.
#
# `quiet` as the second argument routes the create through apply_quiet rather
# than apply: silent on a REAL run, still RENDERED under --dry-run. That is the
# distinction apply_quiet exists to hold, and a bare `>/dev/null` on the call
# would take the render away again.
ensure_namespace() {   # $1 = namespace  $2 = "quiet" to route through apply_quiet
  if $PACK_SCOPE; then
    $DRY_RUN && return 0
    kc get namespace "$1" >/dev/null 2>&1 && return 0
    echo "install.sh: namespace '$1' does not exist and --cluster-scope platform-pack says the"
    echo "  platform pack owns it. Either it was not applied, or --staging-ns/--prod-ns name"
    echo "  something the pack did not create."
    exit 3
  fi
  if [ "${2:-}" = quiet ]; then
    kc create namespace "$1" --dry-run=client -o yaml | apply_quiet
  else
    kc create namespace "$1" --dry-run=client -o yaml | apply
  fi
}


# 0 · IS THE PLATFORM PACK ACTUALLY HERE --------------------------------------
#
# Under --cluster-scope platform-pack this run installs nothing cluster-scoped,
# so it must find out FIRST whether the five things the pack carries are
# present — and refuse before it writes anything if they are not. A run that
# proceeds without them does not fail: it succeeds, and then the Applications
# sit Unknown on a cluster cache they cannot load, or every pod is admitted
# with no signature check at all. Both are worse than a refusal.
#
# The check has three outcomes per object, not two, and the third is the one
# this shape makes unavoidable:
#
#   present    read it, it is there.
#   ABSENT     NotFound. Refuse, naming the pack and the render command.
#   UNKNOWN    Forbidden. A namespace-scoped credential cannot read a
#              cluster-scoped object — which is the whole premise of this mode
#              — so "cannot read it" is NOT "it is missing". Reported and
#              carried on with, never silently upgraded to either answer.
#
# API KINDS are the exception and the reason this works at all: discovery is
# open to any authenticated user, so whether the CRDs landed is a question a
# tenant CAN answer. Absent kinds are therefore a hard refusal even here.
PACK_UNKNOWN=()
PACK_MISSING=()

pack_kind_present() {   # $1 = fully qualified resource, e.g. applications.argoproj.io
  kc api-resources --api-group="${1#*.}" -o name 2>/dev/null | grep -qx "$1"
}

pack_object_present() {   # $1 = kind  $2 = name
  local out rc=0
  out=$(kc get "$1" "$2" -o name 2>&1) || rc=$?
  if [ "$rc" = 0 ]; then return 0; fi
  case "$out" in
    *[Ff]orbidden*) PACK_UNKNOWN+=("$1/$2"); return 0;;
    *) PACK_MISSING+=("$1/$2"); return 1;;
  esac
}

# The projects are the exception to the UNKNOWN rule, and the rig proved why on
# 2026-09-06: `kubectl -n vexa-pack get limitrange` as a tenant scoped to
# another namespace returns FORBIDDEN, not NotFound — RBAC is evaluated before
# existence, so a namespace that does not exist and one you may not read are
# the same answer. Reporting that as UNKNOWN passed a check on two projects
# that were not there.
#
# But a tenant IS supposed to be able to read its own project — holding these
# two is the entire premise of this mode. So here Forbidden is a STOP, and the
# message names both readings rather than picking one.
pack_namespaced_present() {   # $1 = namespace  $2 = kind
  local out rc=0
  out=$(kc -n "$1" get "$2" -o name 2>&1) || rc=$?
  if [ "$rc" = 0 ] && [ -n "$out" ]; then return 0; fi
  case "$out" in
    *[Ff]orbidden*)
      PACK_MISSING+=("$2 in $1 — Forbidden: either the project does not exist, or this credential is not the app team's in it")
      return 1;;
    *) PACK_MISSING+=("$2 in $1"); return 1;;
  esac
}

check_platform_pack() {
  echo "== platform pack (--cluster-scope platform-pack): checking it landed before writing anything"
  for kind in applications.argoproj.io applicationsets.argoproj.io appprojects.argoproj.io \
              clusterpolicies.kyverno.io; do
    pack_kind_present "$kind" || PACK_MISSING+=("CRD $kind")
  done
  pack_object_present clusterpolicy vexa-require-digest-pinning || true
  pack_object_present clusterpolicy vexa-verify-channel-signature || true
  pack_object_present clusterrole vexa-argocd-cluster-cache-reader || true
  pack_object_present clusterrolebinding vexa-argocd-cluster-cache-reader || true
  for ns in "$STAGING_NS" "$PROD_NS"; do
    pack_namespaced_present "$ns" limitrange || true
    pack_namespaced_present "$ns" resourcequota || true
    # Namespaced, but still not a tenant's to create: RBAC escalation
    # prevention refuses a grant wider than the grantor's own. Without it Argo
    # cannot manage what the chart renders, and the app team is Forbidden on
    # the ApplicationSet that IS the subscription — the last step of their own
    # install, measured on the rig 2026-09-06.
    pack_namespaced_present "$ns" role/vexa-argocd-project-admin || true
    pack_namespaced_present "$ns" role/vexa-app-team-argo || true
  done

  if [ ${#PACK_UNKNOWN[@]} -gt 0 ]; then
    echo "   UNKNOWN (this credential may not read cluster-scoped objects; not a finding):"
    printf '     %s\n' "${PACK_UNKNOWN[@]}"
  fi
  if [ ${#PACK_MISSING[@]} -eq 0 ]; then
    echo "   the pack is here. Everything from here on is namespace-scoped."
    return 0
  fi

  cat >&2 <<EOF

REFUSING — nothing has been applied.

  --cluster-scope platform-pack says your platform team applied the Vexa
  platform pack, and these objects are not in the cluster:

$(printf '      %s\n' "${PACK_MISSING[@]}")

  This installer will not create them: under this flag it holds no cluster
  rights, and a run that continued would report success while the subscription
  could never sync and nothing would verify a signature.

  The pack is one file, and applying it is one act:

      ./kit/platform/render.sh --provider ${PROVIDER} --project ${STAGING_NS} \\
        --prod-project ${PROD_NS} --channel ${CHANNEL} --channel-pubkey ${PUBKEY}

      # then, by someone with cluster rights, ONCE:
      kubectl apply --server-side --force-conflicts -f platform-${PROVIDER}.yaml

  What it contains and why each object is there: kit/platform/README.md.

  If you DO hold cluster rights, drop the flag and this installer creates them
  itself — that is the default.
EOF
  exit 3
}

if $PACK_SCOPE && ! $DRY_RUN; then check_platform_pack; fi


# What auto does with what it found. Prints the chosen action on stdout and the
# human sentence on stderr, so the caller can capture one without losing the
# other.
plan_component() {   # $1 = label  $2 = mode  $3 = pinned version  $4 = found deploy  $5 = found version
  local label=$1 mode=$2 pin=$3 found_deploy=$4 found=$5
  case "$mode" in
    skip)
      echo >&2 "   $label: --$label skip — not touched, not checked. Yours to install."
      echo skip; return 0;;
    install)
      echo >&2 "   $label: --$label install — applying the pinned upstream manifests${found:+ over the existing $found_deploy $found}."
      echo install; return 0;;
  esac
  if [ "$found" = "absent" ]; then
    echo >&2 "   $label: not present — installing $pin"
    echo install; return 0
  fi
  if [ "$mode" = "adopt" ]; then
    if [ "$found" = "$pin" ]; then
      echo >&2 "   $label: ADOPTING the existing $found_deploy — it is already $pin. Nothing is applied."
    else
      echo >&2 "   $label: ADOPTING the existing $found_deploy ($found) though the pin is $pin — versions differ, adopted on your say-so. Nothing is applied."
    fi
    echo adopt; return 0
  fi
  if [ "$found" = "$pin" ]; then
    echo >&2 "   $label: ADOPTING the existing $found_deploy — it is already $pin. Nothing is applied."
    echo adopt; return 0
  fi
  echo refuse
  return 0
}

refuse_version() {   # $1 = label  $2 = pin  $3 = found deploy  $4 = found version
  cat >&2 <<EOF

REFUSING — nothing has been applied.

  $1 is already installed in this cluster ($3), and it is not the version this
  kit pins:

      installed: $4
      pinned:    $2

  Installing over it would overwrite a component somebody else owns, and on a
  cluster where this credential is namespace-scoped it would half-land: the
  namespaced objects written, the cluster-scoped ones Forbidden, and the script
  stopped in between. So it does not start.

  Three ways forward, and they are yours to choose:

    --$1 adopt     take the installed $4 as it is. The kit writes nothing to it
                   and subscribes against it. Its behaviour at that version is
                   not what we pinned; that is the trade.
    --$1 skip      leave it entirely alone and do not check it either.
    --$1 install   apply the pinned manifests over it anyway. Read the paragraph
                   above before you do.
EOF
  exit 3
}

# Ask the API server what this credential could actually write, and refuse
# BEFORE writing any of it. `--dry-run=server` runs the full admission path —
# RBAC included — so a Forbidden here is the same Forbidden the real apply
# would hit, minus the 49 objects that would already be on disk by then.
precheck_apply() {   # $1 = label  $2 = manifest url  $3.. = extra kubectl args
  local label=$1 url=$2; shift 2
  local out rc=0
  out=$(kc apply --server-side --force-conflicts --dry-run=server "$@" -f "$url" 2>&1) || rc=$?
  local forbidden
  forbidden=$(printf '%s\n' "$out" | grep -i -c 'forbidden' || true)
  if [ "$rc" -ne 0 ] || [ "$forbidden" -gt 0 ]; then
    cat >&2 <<EOF

REFUSING — nothing has been applied.

  A server-side dry-run of the $label install came back with $forbidden
  Forbidden object(s) (kubectl exit $rc). This credential cannot complete the
  install, and a partial one is worse than none: the objects it CAN write land,
  the rest are refused, and the cluster is left with a half-installed component
  and no subscription. That is the failure this check exists to prevent.

  What the API server said:

$(printf '%s\n' "$out" | grep -i 'forbidden' | sed 's/^/      /' | head -20)

  This is a one-time platform-team ask, not something to work around: have
  someone with cluster scope install $label, then re-run with
  \`--$label adopt\` (or \`--$label skip\`) and the rest of this installer is
  namespace-scoped work your own credential can do.
EOF
    exit 3
  fi
}

# WHAT THE PLAN IS UNDER --cluster-scope platform-pack: nothing to plan. Argo CD
# and Kyverno belong to the platform team, this credential cannot read them, and
# a detection that came back "absent" out of a Forbidden read would plan exactly
# the install this mode exists not to do. check_platform_pack above has already
# decided whether they are here, and refused by name if they were not.
if $PACK_SCOPE; then
ARGOCD_ACTION=pack;  ARGOCD_DEPLOY=-; ARGOCD_HAVE=unknown
KYVERNO_ACTION=pack; KYVERNO_DEPLOY=-; KYVERNO_HAVE=unknown
echo "== Argo CD and Kyverno: the platform pack owns both (--cluster-scope platform-pack)"
else
ARGOCD_FOUND=$(detect_component "$ARGOCD_NS" argocd-server openshift-gitops-server)
KYVERNO_FOUND=$(detect_component "$KYVERNO_NS" kyverno-admission-controller kyverno)
ARGOCD_DEPLOY=${ARGOCD_FOUND%% *}; ARGOCD_HAVE=${ARGOCD_FOUND##* }
KYVERNO_DEPLOY=${KYVERNO_FOUND%% *}; KYVERNO_HAVE=${KYVERNO_FOUND##* }

echo "== what is already here (checked before anything is written)"
ARGOCD_ACTION=$(plan_component argocd "$ARGOCD_MODE" "$ARGOCD_VERSION" "$ARGOCD_DEPLOY" "$ARGOCD_HAVE")
[ "$ARGOCD_ACTION" = refuse ] && refuse_version argocd "$ARGOCD_VERSION" "$ARGOCD_DEPLOY" "$ARGOCD_HAVE"
KYVERNO_ACTION=$(plan_component kyverno "$KYVERNO_MODE" "$KYVERNO_VERSION" "$KYVERNO_DEPLOY" "$KYVERNO_HAVE")
[ "$KYVERNO_ACTION" = refuse ] && refuse_version kyverno "$KYVERNO_VERSION" "$KYVERNO_DEPLOY" "$KYVERNO_HAVE"
fi

# 0 · claim the credential ----------------------------------------------------
#
# FIRST, before preflight and before a byte of Argo CD is fetched. A claim code
# lives about fifteen minutes and the installs below take longer than that, so a
# claim attempted at the point of first use would routinely expire mid-install —
# after Argo and Kyverno are already down, which is the worst moment to need a
# second phone call.
#
# The exchange lives in kit/claim.sh and is SOURCED, not run: there is one
# implementation of it, and the credential exists in exactly one place — a shell
# variable in this process. Shelling out would mean getting the value back
# through stdout, a file, or a child's environment, and each of those is a way
# of writing it down.
if [ -n "$CLAIM_CODE" ]; then
  CLAIM_EDGE=${CLAIM_EDGE:-https://${REGISTRY}/claim}
  STATION=${STATION:-$CHANNEL}
  if $DRY_RUN; then
    # A dry run must NOT spend the code. Rehearsing an install is exactly when
    # an operator has not yet been given a fresh one, and a rehearsal that
    # burned it would be a trap: the real run would then fail with the generic
    # refusal, saying nothing about why.
    echo "== claim code: NOT spent (dry run). The real run posts to $CLAIM_EDGE"
    echo "   as station '$STATION'. Rehearse the exchange itself with:"
    echo "     ./kit/claim.sh --code <code> --edge $CLAIM_EDGE --station $STATION \\"
    echo "       --namespace $PROD_NS --dry-run"
    REGISTRY_USER="<claimed-at-run-time>"
    VEXA_CHANNEL_PASS="<claimed-at-run-time>"
  else
    echo "== claiming the channel credential from $CLAIM_EDGE (station $STATION)"
    # shellcheck source=claim.sh disable=SC1091
    source "$HERE/claim.sh"
    # The exit code is the claim's, not a flat 1: 3 means nothing answered at
    # --claim-edge (a different problem, with a different fix, than a code the
    # service refused). claim.sh's usage lists both.
    CLAIM_RC=0; vexa_claim_fetch "$CLAIM_CODE" "$CLAIM_EDGE" "$STATION" || CLAIM_RC=$?
    [ "$CLAIM_RC" -eq 0 ] || exit "$CLAIM_RC"
    REGISTRY_USER=$VEXA_CLAIM_USER
    VEXA_CHANNEL_PASS=$VEXA_CLAIM_PASS
    echo "   claimed; the code is now spent"

    # The station credential Secret, in the prod namespace — the one object the
    # station bundle expects an operator to bring (station/README.md). It is the
    # SAME credential: the receipt sender pushes the station's report back to the
    # channel with it, and everything below pulls from the channel with it.
    kc create namespace "$PROD_NS" --dry-run=client -o yaml | kc apply -f - >/dev/null
    vexa_claim_write_secret "$PROD_NS" "$STATION_SECRET" \
      "$VEXA_CLAIM_USER" "$VEXA_CLAIM_PASS" \
      ${KUBECONFIG_ARG[@]+"${KUBECONFIG_ARG[@]}"}
    echo "   $PROD_NS: $STATION_SECRET (keys username, password)"
  fi
fi

# 1 · preflight ---------------------------------------------------------------
#
# THE PREFLIGHT MUST BE GIVEN THE DELIVERED SET. Until the bbb rehearsal this
# call passed --namespace and nothing else, so `objects = []` and P2/P3
# evaluated ONLY the synthetic bot profile — never the chart. P2's own anchor is
# vexa#1005, "a customer LimitRange squeezed undeclared bots to 64Mi"; the same
# class then happened at sync time, to postgres, because the check ran against
# nothing: the chart's own postgres asks for a 4Gi limit and the project's
# LimitRange ceiling was 2560Mi, sized for the bot's /dev/shm. Admission refused
# it, after the install, with the preflight green.
CV_FILE=${CUSTOMER_VALUES:-$HERE/profiles/vexa/customer-values.example.yaml}
if ! $SKIP_PREFLIGHT; then
  echo "== preflight (conformance before anything is installed)"
  PF_MANIFESTS="$MANIFESTS"
  if [ -z "$PF_MANIFESTS" ]; then
    # Render the chart ourselves. Anonymously and with whatever OCI credential
    # `helm registry login` already left on this machine — the password is NOT
    # put on helm's argv, where it would land in the process list and the shell
    # history of the same run that refuses to print it.
    RENDER_DIR=$(mktemp -d); RENDER="$RENDER_DIR/rendered.yaml"
    HELM_EXTRA=()
    $PLAIN_HTTP && HELM_EXTRA+=(--plain-http)
    $REGISTRY_INSECURE && HELM_EXTRA+=(--insecure-skip-tls-verify)
    if command -v helm >/dev/null 2>&1 && \
       helm template "$RELEASE_NAME" "oci://${REGISTRY}/vexa/channel/${CHANNEL}/charts/${CHART_NAME}" \
         --namespace "$STAGING_NS" --values "$CV_FILE" \
         ${HELM_EXTRA[@]+"${HELM_EXTRA[@]}"} > "$RENDER" 2>"$RENDER_DIR/err"; then
      PF_MANIFESTS="$RENDER"
      echo "   rendered the delivered chart for the preflight: $PF_MANIFESTS"
    else
      cat <<EOF
   WARNING the delivered chart was NOT rendered, so the preflight below checks
           only the dynamic bot profile. P2 (LimitRange) and P3 (quota) will not
           see a single workload the channel actually delivers — which is how a
           4Gi postgres limit got past a 2560Mi ceiling in the 2026-09-06
           rehearsal and was refused at admission instead.
           Reason: $( command -v helm >/dev/null 2>&1 && head -1 "$RENDER_DIR/err" 2>/dev/null || echo "helm is not on PATH" )
           Fix it either way, and re-run:
             helm registry login ${REGISTRY}          # then re-run this installer
             # or render it yourself and hand it over:
             helm template ${RELEASE_NAME} oci://${REGISTRY}/vexa/channel/${CHANNEL}/charts/${CHART_NAME} \\
               --values ${CV_FILE} > rendered.yaml
             $0 ... --manifests rendered.yaml
EOF
    fi
  fi
  PF_ARGS=(--namespace "$STAGING_NS")
  [ -n "$PF_MANIFESTS" ] && PF_ARGS+=(--manifests "$PF_MANIFESTS")
  PF_ARGS+=(${KUBECONFIG_ARG[@]+"${KUBECONFIG_ARG[@]}"})
  echo "   vexa_preflight.py ${PF_ARGS[*]}"
  # Exit 4 is NOT a failure: it means nothing failed and some check could not be
  # evaluated, because this credential is not allowed to make the read. Treating
  # it as failure would print `preflight FAILED` over checks that never ran —
  # the exact lie #28 removed from the check itself. Treating it as success
  # would hide it, which is what it did until now. So: name it and continue.
  PF_RC=0
  python3 "$HERE/preflight/vexa_preflight.py" "${PF_ARGS[@]}" || PF_RC=$?
  case "$PF_RC" in
    0) ;;
    4) echo "   NOTE preflight found nothing wrong, and some checks were NOT EVALUATED (exit 4) —"
       echo "        this credential could not make the reads they need. That is not a verdict on"
       echo "        your cluster. To turn them into answers, run it once with a credential that"
       echo "        can read cluster scope and keep the result:"
       echo "          python3 kit/preflight/vexa_preflight.py --namespace $STAGING_NS --dump-snapshot snap.json"
       echo "          python3 kit/preflight/vexa_preflight.py --namespace $STAGING_NS --snapshot snap.json"
       echo "        The install continues.";;
    *) echo "preflight FAILED — fix the findings (or rerun with --skip-preflight to proceed anyway, on your own head)"; exit 1;;
  esac
else
  echo "== preflight SKIPPED by flag"
fi

# 2 · Argo CD (pinned, the one already here, or the platform team’s) -------
ARGOCD_URL="https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/install.yaml"
case "$ARGOCD_ACTION" in
  pack)  echo "== Argo CD: the platform pack carries its CRDs; installing Argo itself is yours"
         echo "   (nothing applied here — this run holds no cluster rights)";;
  skip)  echo "== Argo CD: skipped by flag (namespace ${ARGOCD_NS} assumed to hold your own)";;
  adopt) echo "== Argo CD ${ARGOCD_HAVE}: ADOPTED in namespace ${ARGOCD_NS} — nothing applied to it";;
  *)     echo "== Argo CD ${ARGOCD_VERSION} into namespace ${ARGOCD_NS}";;
esac
if [ "$ARGOCD_ACTION" = install ]; then
ensure_namespace "$ARGOCD_NS"
if ! $DRY_RUN; then
  precheck_apply argocd "$ARGOCD_URL" -n "$ARGOCD_NS"
  # --server-side: the ApplicationSet CRD exceeds the 256KB last-applied
  # annotation limit under client-side apply (same failure class the argocd
  # spike hit, finding 6)
  kc apply --server-side --force-conflicts -n "$ARGOCD_NS" -f "$ARGOCD_URL" >/dev/null
  kc -n "$ARGOCD_NS" rollout status deploy/argocd-repo-server --timeout=300s
  kc -n "$ARGOCD_NS" rollout status deploy/argocd-applicationset-controller --timeout=300s

  # -------------------------------------------------------------------------
  # resourceTrackingMethod: annotation — SET BEFORE ANY APPLICATION EXISTS.
  #
  # Argo's default tracking method is `label`: it stamps
  # app.kubernetes.io/instance on every resource it manages. On a GREENFIELD
  # install that is merely a label. On an ADOPTION it is a wall, because that
  # same label is inside `spec.selector.matchLabels` of Deployments the Vexa
  # chart already rendered — and selectors are IMMUTABLE. Argo tries to write
  # the label, the API server rejects the update as an immutable-field change,
  # and the Application sits permanently OutOfSync on a resource it cannot fix.
  # The only exits are recreating the workload (a restart, which is exactly
  # what adoption must not cause) or flipping this setting afterwards and
  # cleaning up half-stamped resources.
  #
  # `annotation` puts the tracking id in argocd.argoproj.io/tracking-id, an
  # annotation, which is mutable. Nothing about the workload changes.
  #
  # It is set HERE, not later, because changing it after Applications exist
  # means every already-tracked resource carries the old marker.
  kc -n "$ARGOCD_NS" patch configmap argocd-cm --type merge \
     -p '{"data":{"application.resourceTrackingMethod":"annotation"}}' >/dev/null
  kc -n "$ARGOCD_NS" rollout restart deploy/argocd-server statefulset/argocd-application-controller >/dev/null 2>&1 || \
    kc -n "$ARGOCD_NS" rollout restart deploy/argocd-server deploy/argocd-application-controller >/dev/null 2>&1 || true
  echo "   resourceTrackingMethod=annotation (adoption-safe; label tracking cannot write into immutable selectors)"
fi
fi

# An ADOPTED Argo is somebody else's, and the tracking method is a cluster-wide
# setting that restarts its controller. We READ it and, if it is wrong, say so
# with the two commands — we do not restart a controller managing Applications
# we know nothing about.
if [ "$ARGOCD_ACTION" = adopt ] && ! $DRY_RUN; then
  TRACKING=$(kc -n "$ARGOCD_NS" get configmap argocd-cm \
    -o jsonpath='{.data.application\.resourceTrackingMethod}' 2>/dev/null || true)
  if [ "$TRACKING" = "annotation" ]; then
    echo "   resourceTrackingMethod=annotation already set on the adopted Argo"
  else
    cat <<EOF
   NOTE the adopted Argo tracks resources by '${TRACKING:-label (the default)}', not by annotation.
   Label tracking writes app.kubernetes.io/instance into spec.selector, which is IMMUTABLE on a
   Deployment the chart already rendered — the Application then sits permanently OutOfSync on a
   resource it cannot fix. This installer does NOT change it: it restarts a controller that is
   managing Applications it knows nothing about. Run these two yourself, before the first sync:
     kubectl -n ${ARGOCD_NS} patch configmap argocd-cm --type merge -p '{"data":{"application.resourceTrackingMethod":"annotation"}}'
     kubectl -n ${ARGOCD_NS} rollout restart deploy/argocd-server statefulset/argocd-application-controller
EOF
  fi
fi

# 3 · Kyverno (pinned, the one already here, or the platform team’s) ------
KYVERNO_URL="https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/install.yaml"
case "$KYVERNO_ACTION" in
  pack)
    echo "== Kyverno: installed by the platform pack (${KYVERNO_VERSION}) — not touched here"
    # A flag that silently does nothing is worse than a flag that is refused. Each
    # of these has a KYVERNO-SIDE half that lives in a namespace this run cannot
    # write, so say which half did not happen and who has to do it.
    if [ -n "$REGISTRY_CA" ]; then
      echo "   NOTE --registry-ca does NOT reach Kyverno here. Argo gets the registry through its"
      echo "        own repo secret below, but Kyverno needs the CA as a trust bundle to FETCH"
      echo "        SIGNATURES, and its namespace is the platform team's. Without it every image"
      echo "        is denied with 'no signatures found' — which reads identically to an unsigned"
      echo "        image. Ask them to mount the CA into kyverno-admission-controller."
    fi
    if [ -n "$REGISTRY_USER" ]; then
      echo "   NOTE Kyverno is not given the channel credential here (same reason). Against a"
      echo "        channel whose signature paths are anonymous this changes nothing; against"
      echo "        your own authenticated mirror, signature verification fails closed until"
      echo "        the platform team wires --imagePullSecrets into the controller."
    fi
    if $PLAIN_HTTP; then
      echo "   NOTE --plain-http does not reach Kyverno's --allowInsecureRegistry here."
    fi
    ;;
  skip)  echo "== Kyverno: skipped by flag. The channel’s admission policy still lands in step 4;"
         echo "   it needs a Kyverno in this cluster to have any effect.";;
  adopt) echo "== Kyverno ${KYVERNO_HAVE}: ADOPTED in namespace ${KYVERNO_NS} — the install is not re-applied";;
  *)     echo "== Kyverno ${KYVERNO_VERSION} into namespace ${KYVERNO_NS}";;
esac
if [ "$KYVERNO_ACTION" != skip ] && [ "$KYVERNO_ACTION" != pack ] && ! $DRY_RUN; then
  if [ "$KYVERNO_ACTION" = install ]; then
    precheck_apply kyverno "$KYVERNO_URL"
    kc apply --server-side --force-conflicts -f "$KYVERNO_URL" >/dev/null
    kc -n "$KYVERNO_NS" rollout status deploy/kyverno-admission-controller --timeout=300s
  fi
  if $PLAIN_HTTP; then
    # test rigs only; the upstream manifest carries --allowInsecureRegistry=false,
    # so rewrite the args (a blind append leaves both values in place)
    echo "   (test rig) allowing insecure registry in kyverno admission controller"
    kc -n "$KYVERNO_NS" get deploy kyverno-admission-controller -o json \
      | jq '.spec.template.spec.containers[0].args |= (map(select(startswith("--allowInsecureRegistry=") | not)) + ["--allowInsecureRegistry=true"])' \
      | kc apply --server-side --force-conflicts -f - >/dev/null
    kc -n "$KYVERNO_NS" rollout status deploy/kyverno-admission-controller --timeout=180s
  fi
  if [ -n "$REGISTRY_USER" ]; then
    # Kyverno fetches signatures from the channel itself. On a signature
    # repository that requires credentials that fetch is a 401 and the
    # verifyImages rule fails closed — reported as 'no signatures found',
    # which is byte-identical to its report on a genuinely unsigned image.
    # Kyverno reads registry credentials only from secrets named on the
    # controller's own flag; there is no other path in.
    #
    # channel.vexa.ai serves the signature read paths ANONYMOUSLY (see
    # docs/receipts/2026-08-25-kyverno-authenticated-channel.md), so against
    # our own channel this credential is not required for signature
    # verification. It is kept, and still applied, for two cases that are
    # real today:
    #   * a customer who mirrors the channel into their own authenticated
    #     registry (Harbor, Artifactory, ECR) and points
    #     --signature-repository at it;
    #   * the day Vexa's images are mirrored into the channel — Kyverno then
    #     needs read access for digest resolution, which no amount of
    #     anonymous signature serving covers.
    #
    # The flag form: BOTH '<ns>/<name>' and a bare '<name>' were measured
    # working on Kyverno 1.19.0 against channel.vexa.ai on 2026-08-25 (the
    # controller sent Authorization and got 200 in both). The earlier note in
    # PR vexa-delivery-internal#31's receipt that the namespaced form is silently ignored is
    # withdrawn — it was not the cause of that session's 401s.
    echo "   giving kyverno a credential for the channel registry"
    render_registry_secret "$KYVERNO_NS" channel-registry-creds | kc apply -f - >/dev/null
    kc -n "$KYVERNO_NS" get deploy kyverno-admission-controller -o json \
      | jq --arg s "$KYVERNO_NS/channel-registry-creds" \
        '.spec.template.spec.containers[0].args |= (map(select(startswith("--imagePullSecrets=") | not)) + ["--imagePullSecrets=" + $s])' \
      | kc apply --server-side --force-conflicts -f - >/dev/null
    kc -n "$KYVERNO_NS" rollout status deploy/kyverno-admission-controller --timeout=180s
  fi
  if [ -n "$REGISTRY_CA" ]; then
    # registries behind a corporate CA: give Kyverno a trust bundle
    # (Mozilla roots + the corporate CA) so signature fetch and digest
    # resolution both keep working. Argo trusts the registry via the repo
    # secret; nodes need the CA in their own containerd trust (provider docs).
    echo "   trusting registry CA in kyverno admission controller"
    TMP_BUNDLE=$(mktemp)
    curl -fsS https://curl.se/ca/cacert.pem -o "$TMP_BUNDLE"
    cat "$REGISTRY_CA" >> "$TMP_BUNDLE"
    kc -n "$KYVERNO_NS" create configmap channel-registry-ca \
      --from-file=ca-certificates.crt="$TMP_BUNDLE" --dry-run=client -o yaml | kc apply -f - >/dev/null
    rm -f "$TMP_BUNDLE"
    kc -n "$KYVERNO_NS" patch deploy kyverno-admission-controller --type=strategic -p \
      '{"spec":{"template":{"spec":{"volumes":[{"name":"ca-bundle","configMap":{"name":"channel-registry-ca"}}],"containers":[{"name":"kyverno","volumeMounts":[{"name":"ca-bundle","mountPath":"/etc/ssl/certs/ca-certificates.crt","subPath":"ca-certificates.crt"}]}]}}}}'
    kc -n "$KYVERNO_NS" rollout status deploy/kyverno-admission-controller --timeout=180s
  fi
fi

# The subscription render in step 6 reads these two out of the environment, and
# they used to be exported here, inside the admission-policy step — an implicit
# dependency that only surfaced when a mode skipped this step and step 6 died on
# KeyError: 'STAGING_NAMESPACE'. Exported once, above both, where they belong.
export STAGING_NAMESPACE=$STAGING_NS PROD_NAMESPACE=$PROD_NS

# 4 · admission policy --------------------------------------------------------
if $PACK_SCOPE; then
echo "== admission policy: the two ClusterPolicies came with the platform pack, pinning your"
echo "   channel key. They are cluster-scoped; this run neither writes nor re-renders them."
else
echo "== admission policy (digest pinning + channel signature)"
PUBKEY_INDENTED=$(sed 's/^/                      /' "$PUBKEY")
python3 - "$HERE/policy/kyverno-vexa-admission.yaml" <<PYEOF | apply
import os, sys
text = open(sys.argv[1]).read()
text = text.replace("\${STAGING_NAMESPACE}", os.environ["STAGING_NAMESPACE"])
text = text.replace("\${PROD_NAMESPACE}", os.environ["PROD_NAMESPACE"])
text = text.replace("\${CHANNEL_PUBLIC_KEY_INDENTED}", """$PUBKEY_INDENTED""")
sig_repo = "$SIG_REPO"
if sig_repo:
    text = text.replace("\${SIGNATURE_REPOSITORY}", sig_repo)
else:
    # default cosign convention: signatures alongside the image
    text = "\n".join(l for l in text.splitlines() if "\${SIGNATURE_REPOSITORY}" not in l)
sys.stdout.write(text)
PYEOF
fi

# 5 · registry access for Argo ------------------------------------------------
echo "== registering channel registry with Argo CD"
REGISTRY_CRED_FIELDS=""
if [ -n "$REGISTRY_USER" ]; then
  # An authenticated channel is the common shape; a repo secret without a
  # credential makes repo-server fail the pull with 401 and the Application
  # never leaves Unknown.
  REGISTRY_CRED_FIELDS="  username: ${REGISTRY_USER}"$'\n'"  password: ${VEXA_CHANNEL_PASS}"
fi
INSECURE_FIELDS=""
if $PLAIN_HTTP; then
  INSECURE_FIELDS=$'  insecure: "true"\n  forceHttpBasicAuth: "false"'
elif $REGISTRY_INSECURE; then
  # self-signed TLS: Argo has no per-repo CA-bundle knob for OCI repos, so the
  # repo secret itself must opt out of verification (M2 receipt §3 did this by
  # hand; encoding it here keeps a re-run from clobbering the fix)
  INSECURE_FIELDS=$'  insecure: "true"'
fi
apply <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: vexa-channel-registry
  namespace: ${ARGOCD_NS}
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  url: oci://${REGISTRY}/vexa/channel/${CHANNEL}
  name: vexa-channel-${CHANNEL}
  type: oci
${REGISTRY_CRED_FIELDS}
${INSECURE_FIELDS}
EOF

echo "== registering channel chart repository with Argo CD (helm OCI)"
apply <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: vexa-channel-charts
  namespace: ${ARGOCD_NS}
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  url: ${REGISTRY}/vexa/channel/${CHANNEL}/charts
  name: vexa-charts-${CHANNEL}
  type: helm
  enableOCI: "true"
${REGISTRY_CRED_FIELDS}
${INSECURE_FIELDS}
EOF

echo "== station contracts + channel key (what each environment verifies against)"
CONTRACT_FILE=${CONTRACT:-$HERE/verify/policy.example.yaml}
CONTRACT_PROD_FILE=${CONTRACT_PROD:-$CONTRACT_FILE}
for pair in "vexa-contract-staging:$CONTRACT_FILE:$STAGING_NS" "vexa-contract-prod:$CONTRACT_PROD_FILE:$PROD_NS"; do
  cmname=${pair%%:*}; rest=${pair#*:}; file=${rest%%:*}; ns=${rest##*:}
  ensure_namespace "$ns" quiet
  python3 - "$file" <<PYEOF2 > /tmp/vexa-contract.json
import json, sys, yaml
print(json.dumps(yaml.safe_load(open(sys.argv[1])) or {}))
PYEOF2
  kc -n "$ns" create configmap "$cmname" --from-file=contract.json=/tmp/vexa-contract.json \
    --dry-run=client -o yaml | apply_quiet
  kc -n "$ns" create secret generic vexa-channel-pubkey --from-file=channel.pub="$PUBKEY" \
    --dry-run=client -o yaml | apply_quiet
  echo "   $ns: $cmname ($(basename "$file")) + channel key"
done
rm -f /tmp/vexa-contract.json

# 6 · the subscription --------------------------------------------------------
echo "== channel subscription (ApplicationSet: staging follows 'current'; prod follows YOUR pin)"
echo "   customer values: $CV_FILE"
VERIFY_ENABLED=false; [ -n "$VERIFIER_IMAGE" ] && VERIFY_ENABLED=true

# --------------------------------------------------------------------------
# THE KUBELET PULL SECRET. Not the verifier's — the kubelet's.
#
# Found on the clean-pull proof, 2026-08-25, and invisible before it.
#
# Until the channel started carrying MIRRORED IMAGES, its only content was
# charts and entries, and those are fetched by Argo's repo-server using the
# `vexa-channel-registry` REPOSITORY SECRET in the argocd namespace. Images
# still came from Docker Hub, which needs no credential from us.
#
# The moment the channel serves the images too — the entire point of
# mirroring, and the only way a one-host-egress customer can install — the
# thing that pulls them is the KUBELET, in the workload namespace, and it
# reads `spec.imagePullSecrets`. There was no such Secret. Every pod came up
# `ImagePullBackOff` with:
#
#     FailedToRetrieveImagePullSecret: Unable to retrieve some image pull
#     secrets (vexa-channel-registry)
#     ... authorization failed: no basic auth credentials
#
# after a sync Argo reported as fully Succeeded, 115/115 Synced, because from
# Argo's side it WAS: it applied every object correctly. The failure is one
# layer below the layer that reports success — which is why it needed a
# greenfield pull to surface and would never have shown up in an adoption,
# where the images are already on the nodes.
#
# It is created unconditionally with --registry-user, NOT gated on the
# verifier being enabled. The two credentials answer to different consumers
# and one is not a substitute for the other.
#
# AND IT IS CALLED `vexa-channel-pull`, NOT `vexa-channel-registry` (2026-09-06).
# It carried the same name as the Argo REPOSITORY Secret above, and the two are
# different objects of different types — Opaque against
# kubernetes.io/dockerconfigjson. They never collided only because ARGOCD_NS
# defaults to `argocd` and this one lives in the workload namespace. On ONE
# PROJECT — the shape the openshift profile exists for — they are one object:
# the second create failed with
#
#     type: Invalid value: "kubernetes.io/dockerconfigjson": field is immutable
#
# and all nine ServiceAccounts were left pointing their imagePullSecrets at an
# Opaque Argo secret the kubelet cannot use. That is precisely the
# ImagePullBackOff the comment above was written to prevent, reintroduced by a
# namespace choice. A name that is only unique because of a default is not
# unique.
#
# CARRYING OVER AN EXISTING INSTALL: nothing to do by hand. The ServiceAccount
# patch below is a merge patch on a LIST, so it REPLACES the whole
# imagePullSecrets array — every account stops referring to the old name on the
# next run of this installer or of self-update.sh. The old Secret is then
# unreferenced and can be deleted at leisure; the migration note in
# kit/README.md gives the one command and says how to tell the two objects apart
# before you delete either.
# --------------------------------------------------------------------------
KUBELET_PULL_SECRET=vexa-channel-pull
if [ -n "$REGISTRY_USER" ]; then
  echo "== image-pull credential for the kubelet, in each workload namespace"
  for ns in "$STAGING_NS" "$PROD_NS"; do
    ensure_namespace "$ns" quiet
    render_registry_secret "$ns" "$KUBELET_PULL_SECRET" | apply_quiet
    echo "   $ns: $KUBELET_PULL_SECRET"

    # AND ATTACH IT TO THE SERVICE ACCOUNTS, which is not belt-and-braces.
    #
    # Four workloads in the real platform estate — caddy, capacity-resize,
    # collector-watchdog, system-host-labeler — render with NO
    # imagePullSecrets at all. That was correct as long as their images
    # (caddy, bitnami/kubectl) came from public Docker Hub and needed no
    # credential. Against an authenticated channel they cannot pull, and no
    # values overlay reaches them because the chart has no key to set.
    #
    # A pull secret on the ServiceAccount is applied by the kubelet to every
    # pod that uses that account, so it covers workloads whose chart forgot
    # one WITHOUT the chart having to be changed first. The chart should still
    # be fixed; this means a subscriber is not blocked until it is.
    #
    # It runs on every install because ServiceAccounts appear as the estate
    # syncs, not before it — so it is also re-run by self-update.
    #
    # A merge patch REPLACES a list, which is what carries an existing install
    # over: an account still pointing at the old `vexa-channel-registry` name
    # stops doing so here, without anyone having to find it first.
    for sa in $(kc -n "$ns" get serviceaccounts -o name 2>/dev/null); do
      kc -n "$ns" patch "$sa" --type merge \
        -p "{\"imagePullSecrets\":[{\"name\":\"$KUBELET_PULL_SECRET\"}]}" >/dev/null 2>&1 || true
    done
  done
fi

VERIFY_REGISTRY_SECRET=""
if [ -n "$REGISTRY_USER" ] && $VERIFY_ENABLED; then
  # the PreSync verifier pulls the channel entry itself; on an authenticated
  # channel it needs its own credential in each target namespace
  VERIFY_REGISTRY_SECRET=vexa-channel-registry-cred
  for ns in "$STAGING_NS" "$PROD_NS"; do
    render_registry_secret "$ns" "$VERIFY_REGISTRY_SECRET" | apply_quiet
  done
fi
VERIFY_INSECURE=false
if $PLAIN_HTTP || $REGISTRY_INSECURE; then VERIFY_INSECURE=true; fi
export ARGOCD_NAMESPACE=$ARGOCD_NS CHANNEL_NAME=$CHANNEL REGISTRY_HOST=$REGISTRY CV_FILE \
       VERIFY_ENABLED VERIFY_INSECURE VERIFIER_IMAGE VERIFY_REGISTRY_SECRET \
       CHART_NAME RELEASE_NAME
python3 - "$HERE/argocd/applicationset.yaml" <<PYEOF | apply
import os, sys, yaml
text = open(sys.argv[1]).read()
cv = yaml.safe_load(open(os.environ["CV_FILE"])) or {}
# An EMPTY customer-values file is not a mistake — it is the correct state for a
# subscriber that takes the published estate verbatim, which is exactly what the
# "channel is the only writer of cluster state" invariant asks for. yaml.safe_dump({})
# returns "{}", and "valuesObject: {}" followed by an indented "verify:" key is
# invalid YAML — so the most correct possible input crashed the installer.
cv_block = "" if not cv else "\n".join("            " + ln for ln in yaml.safe_dump(cv, sort_keys=False).splitlines())
subs = {
    "ARGOCD_NAMESPACE": os.environ["ARGOCD_NAMESPACE"],
    "STAGING_NAMESPACE": os.environ["STAGING_NAMESPACE"],
    "PROD_NAMESPACE": os.environ["PROD_NAMESPACE"],
    "CHANNEL_NAME": os.environ["CHANNEL_NAME"],
    "REGISTRY": os.environ["REGISTRY_HOST"],
    "PROD_PIN": "${PROD_PIN}" or "UNPINNED",
    "VERIFY_ENABLED": os.environ.get("VERIFY_ENABLED", "false"),
    "VERIFY_INSECURE": os.environ.get("VERIFY_INSECURE", "false"),
    "VERIFIER_IMAGE": os.environ.get("VERIFIER_IMAGE") or "UNSET",
    "VERIFY_REGISTRY_SECRET": os.environ.get("VERIFY_REGISTRY_SECRET", ""),
    "CHART_NAME": os.environ.get("CHART_NAME", "vexa"),
    "RELEASE_NAME": os.environ.get("RELEASE_NAME", "vexa"),
}
for k, v in subs.items():
    text = text.replace("\${%s}" % k, v)
text = text.replace("\${CUSTOMER_VALUES_OBJECT}\n", cv_block + "\n" if cv_block else "")
text = text.replace("\${CUSTOMER_VALUES_OBJECT}", cv_block)
sys.stdout.write(text)
PYEOF
if [ -z "$PROD_PIN" ]; then
  echo "   prod pin not set: the production Application tracks position 'UNPINNED' (a"
  echo "   non-existent tag — it will sync nothing). Set your pin when your gate passes;"
  echo "   the pin is the CHART VERSION, which carries no 'v' prefix:"
  echo "     kubectl -n ${ARGOCD_NS} patch applicationset vexa-channel-subscription --type=json \\"
  echo "       -p '[{\"op\":\"replace\",\"path\":\"/spec/generators/0/list/elements/1/position\",\"value\":\"X.Y.Z\"}]'"
fi

echo "== done. subscription state:"
$DRY_RUN || kc -n "$ARGOCD_NS" get applicationset,applications 2>/dev/null || true
