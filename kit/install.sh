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
  --staging-ns      namespace the staging Application deploys into
                    (default vexa-staging)
  --prod-ns         namespace the production Application deploys into
                    (default vexa-prod)
  --prod-pin        channel position prod follows      (default: none — prod
                    Application is created only when you set a pin; moving the
                    pin is YOUR gate)
  --signature-repository  OCI repo where cosign signatures live (default:
                    alongside each image)
  --registry-user   username for an AUTHENTICATED channel registry. The
                    password is read from the VEXA_CHANNEL_PASS environment
                    variable, never from argv. Required whenever your channel
                    registry needs credentials to pull: without it Argo CD's
                    repo-server gets 401 and the subscription never syncs.
                    Kyverno also receives it; against channel.vexa.ai the
                    signature read paths are anonymous so it is not needed
                    for admission, but it is needed if you mirror the channel
                    into your own authenticated registry.
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
  --skip-preflight  do not run the conformance preflight (NOT recommended)
  --dry-run         render everything, apply nothing
EOF
  exit 2
}

PROVIDER="" REGISTRY="" CHANNEL="" PUBKEY="" SIG_REPO="" REGISTRY_CA="" REGISTRY_USER=""
CUSTOMER_VALUES="" VERIFIER_IMAGE=""
# The chart the subscription installs and the Helm release name it installs
# under. Both were hardcoded to "vexa". ADOPTION MAKES THAT FATAL: taking
# ownership of an existing release means matching the name that release
# ALREADY HAS, and ours is `vexa-platform`. A release name is not a preference
# — Helm keys its release Secret on it, and Argo's ownership metadata derives
# from it, so a mismatch does not adopt, it installs a SECOND copy alongside.
CHART_NAME=vexa RELEASE_NAME=vexa
STAGING_NS=vexa-staging PROD_NS=vexa-prod PROD_PIN=""
KUBECONFIG_ARG=() PLAIN_HTTP=false REGISTRY_INSECURE=false SKIP_PREFLIGHT=false DRY_RUN=false

while [ $# -gt 0 ]; do
  case "$1" in
    --provider) PROVIDER=$2; shift 2;;
    --registry) REGISTRY=$2; shift 2;;
    --channel) CHANNEL=$2; shift 2;;
    --channel-pubkey) PUBKEY=$2; shift 2;;
    --signature-repository) SIG_REPO=$2; shift 2;;
    --registry-user) REGISTRY_USER=$2; shift 2;;
    --registry-ca) REGISTRY_CA=$2; shift 2;;
    --chart-name) CHART_NAME=$2; shift 2;;
    --release-name) RELEASE_NAME=$2; shift 2;;
    --customer-values) CUSTOMER_VALUES=$2; shift 2;;
    --contract) CONTRACT=$2; shift 2;;
    --contract-prod) CONTRACT_PROD=$2; shift 2;;
    --verifier-image) VERIFIER_IMAGE=$2; shift 2;;
    --staging-ns) STAGING_NS=$2; shift 2;;
    --prod-ns) PROD_NS=$2; shift 2;;
    --prod-pin) PROD_PIN=$2; shift 2;;
    --kubeconfig) KUBECONFIG_ARG=(--kubeconfig "$2"); shift 2;;
    --plain-http) PLAIN_HTTP=true; shift;;
    --registry-insecure) REGISTRY_INSECURE=true; shift;;
    --skip-preflight) SKIP_PREFLIGHT=true; shift;;
    --dry-run) DRY_RUN=true; shift;;
    *) usage;;
  esac
done
if [ -z "$PROVIDER" ] || [ -z "$REGISTRY" ] || [ -z "$CHANNEL" ] || [ -z "$PUBKEY" ]; then
  usage
fi

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

# ${arr[@]+"${arr[@]}"} — empty-array expansion is "unbound" under set -u on bash 3.2 (macOS
# default), so a run without --kubeconfig crashed at the first kubectl call
kc() { kubectl ${KUBECONFIG_ARG[@]+"${KUBECONFIG_ARG[@]}"} "$@"; }
apply() {
  if $DRY_RUN; then echo "--- would apply:"; cat; else kc apply -f -; fi
}

# 1 · preflight ---------------------------------------------------------------
if ! $SKIP_PREFLIGHT; then
  echo "== preflight (conformance before anything is installed)"
  python3 "$HERE/preflight/vexa_preflight.py" \
    --namespace "$STAGING_NS" ${KUBECONFIG_ARG[@]+"${KUBECONFIG_ARG[@]}"} \
    || { echo "preflight FAILED — fix the findings (or rerun with --skip-preflight to proceed anyway, on your own head)"; exit 1; }
else
  echo "== preflight SKIPPED by flag"
fi

# 2 · Argo CD (pinned) --------------------------------------------------------
echo "== Argo CD ${ARGOCD_VERSION} into namespace ${ARGOCD_NS}"
kc create namespace "$ARGOCD_NS" --dry-run=client -o yaml | apply
if ! $DRY_RUN; then
  # --server-side: the ApplicationSet CRD exceeds the 256KB last-applied
  # annotation limit under client-side apply (same failure class the argocd
  # spike hit, finding 6)
  kc apply --server-side --force-conflicts -n "$ARGOCD_NS" -f "https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/install.yaml" >/dev/null
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

# 3 · Kyverno (pinned) --------------------------------------------------------
echo "== Kyverno ${KYVERNO_VERSION} into namespace ${KYVERNO_NS}"
if ! $DRY_RUN; then
  kc apply --server-side --force-conflicts -f "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/install.yaml" >/dev/null
  kc -n "$KYVERNO_NS" rollout status deploy/kyverno-admission-controller --timeout=300s
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
    # PR #31's receipt that the namespaced form is silently ignored is
    # withdrawn — it was not the cause of that session's 401s.
    echo "   giving kyverno a credential for the channel registry"
    kc -n "$KYVERNO_NS" create secret docker-registry channel-registry-creds \
      --docker-server="$REGISTRY" --docker-username="$REGISTRY_USER" \
      --docker-password="$VEXA_CHANNEL_PASS" --dry-run=client -o yaml | kc apply -f - >/dev/null
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

# 4 · admission policy --------------------------------------------------------
echo "== admission policy (digest pinning + channel signature)"
PUBKEY_INDENTED=$(sed 's/^/                      /' "$PUBKEY")
export STAGING_NAMESPACE=$STAGING_NS PROD_NAMESPACE=$PROD_NS
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
  kc create namespace "$ns" --dry-run=client -o yaml | apply >/dev/null
  python3 - "$file" <<PYEOF2 > /tmp/vexa-contract.json
import json, sys, yaml
print(json.dumps(yaml.safe_load(open(sys.argv[1])) or {}))
PYEOF2
  kc -n "$ns" create configmap "$cmname" --from-file=contract.json=/tmp/vexa-contract.json \
    --dry-run=client -o yaml | apply >/dev/null
  kc -n "$ns" create secret generic vexa-channel-pubkey --from-file=channel.pub="$PUBKEY" \
    --dry-run=client -o yaml | apply >/dev/null
  echo "   $ns: $cmname ($(basename "$file")) + channel key"
done
rm -f /tmp/vexa-contract.json

# 6 · the subscription --------------------------------------------------------
echo "== channel subscription (ApplicationSet: staging follows 'current'; prod follows YOUR pin)"
CV_FILE=${CUSTOMER_VALUES:-$HERE/profiles/vexa/customer-values.example.yaml}
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
# --------------------------------------------------------------------------
if [ -n "$REGISTRY_USER" ]; then
  echo "== image-pull credential for the kubelet, in each workload namespace"
  for ns in "$STAGING_NS" "$PROD_NS"; do
    kc create namespace "$ns" --dry-run=client -o yaml | apply >/dev/null
    kc -n "$ns" create secret docker-registry vexa-channel-registry \
      --docker-server="$REGISTRY" --docker-username="$REGISTRY_USER" \
      --docker-password="$VEXA_CHANNEL_PASS" --dry-run=client -o yaml | apply >/dev/null
    echo "   $ns: vexa-channel-registry"

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
    for sa in $(kc -n "$ns" get serviceaccounts -o name 2>/dev/null); do
      kc -n "$ns" patch "$sa" --type merge \
        -p '{"imagePullSecrets":[{"name":"vexa-channel-registry"}]}' >/dev/null 2>&1 || true
    done
  done
fi

VERIFY_REGISTRY_SECRET=""
if [ -n "$REGISTRY_USER" ] && $VERIFY_ENABLED; then
  # the PreSync verifier pulls the channel entry itself; on an authenticated
  # channel it needs its own credential in each target namespace
  VERIFY_REGISTRY_SECRET=vexa-channel-registry-cred
  for ns in "$STAGING_NS" "$PROD_NS"; do
    kc -n "$ns" create secret docker-registry "$VERIFY_REGISTRY_SECRET" \
      --docker-server="$REGISTRY" --docker-username="$REGISTRY_USER" \
      --docker-password="$VEXA_CHANNEL_PASS" --dry-run=client -o yaml | apply >/dev/null
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
  echo "   non-existent tag — it will sync nothing). Set your pin when your gate passes:"
  echo "     kubectl -n ${ARGOCD_NS} patch applicationset vexa-channel-subscription --type=json \\"
  echo "       -p '[{\"op\":\"replace\",\"path\":\"/spec/generators/0/list/elements/1/position\",\"value\":\"vX.Y.Z\"}]'"
fi

echo "== done. subscription state:"
$DRY_RUN || kc -n "$ARGOCD_NS" get applicationset,applications 2>/dev/null || true
