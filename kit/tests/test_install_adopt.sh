#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install.sh adoption path — the bbb rehearsal's defect 1, offline.
#
# The rehearsal ran the installer as a namespace-scoped tenant against a cluster
# that ALREADY had Argo CD v3.5.1 and Kyverno v1.19.0 — the pinned versions. A
# server-side dry-run measured what steps 2 and 3 would have done: 49 objects
# applied, 9 Forbidden, dex and the application-controller among the 49, and
# `set -e` stopping the script in between. A broken Argo and no subscription.
#
# Five cases, each against a LOGGING stub kubectl, so what is asserted is what
# the installer actually executed rather than what it printed:
#
#   1. present at the pinned version   -> ADOPT: the upstream manifest is never
#                                        fetched, let alone applied
#   2. present at another version      -> REFUSE (exit 3) naming both versions,
#                                        with nothing applied at all
#   3. absent, but the credential is   -> REFUSE (exit 3) after the server-side
#      Forbidden on the install           dry-run and BEFORE the real apply
#   4. absent and permitted            -> install, exactly as before
#   5. --argocd skip                   -> not touched, not checked
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ARGO_MANIFEST="argo-cd/v3.5.1/manifests/install.yaml"
KYVERNO_MANIFEST="kyverno/releases/download/v1.19.0/install.yaml"

cat > "$TMP/kubectl" <<'EOF'
#!/usr/bin/env bash
# Logging stub. Every invocation is appended to $KUBECTL_LOG verbatim, so a test
# can assert on what ran rather than on what was echoed.
printf '%s\n' "$*" >> "$KUBECTL_LOG"
# `apply -f -` reads stdin; a stub that exits without draining it gives the
# renderer upstream a BrokenPipe and the run dies for the wrong reason.
case "$*" in *" -f -"*) cat >/dev/null;; esac
case "$*" in
  *"get deploy argocd-server -o jsonpath"*)
      [ -n "${STUB_ARGOCD_IMAGE:-}" ] && printf '%s' "$STUB_ARGOCD_IMAGE"; exit 0;;
  *"get deploy kyverno-admission-controller -o jsonpath"*)
      [ -n "${STUB_KYVERNO_IMAGE:-}" ] && printf '%s' "$STUB_KYVERNO_IMAGE"; exit 0;;
  *"get deploy "*"-o jsonpath"*) exit 0;;                       # the other candidates: absent
  *"get configmap argocd-cm"*) printf '%s' "${STUB_TRACKING:-}"; exit 0;;
  *--dry-run=server*)
      if [ -n "${STUB_FORBIDDEN:-}" ]; then
        echo 'customresourcedefinitions.apiextensions.k8s.io "applications.argoproj.io" is forbidden: User "tenant" cannot patch resource "customresourcedefinitions" in API group "apiextensions.k8s.io" at the cluster scope' >&2
        echo 'clusterroles.rbac.authorization.k8s.io "argocd-server" is forbidden: User "tenant" cannot get resource "clusterroles" at the cluster scope' >&2
        exit 1
      fi
      echo 'deployment.apps/argocd-server serverside-applied'; exit 0;;
  *"create namespace"*) echo "kind: Namespace"; exit 0;;
esac
exit 0
EOF
chmod +x "$TMP/kubectl"
export PATH="$TMP:$PATH"
echo "test-key-placeholder" > "$TMP/channel.pub"

fail() { echo "FAIL: $1" >&2; [ -f "$KUBECTL_LOG" ] && sed 's/^/    log| /' "$KUBECTL_LOG" >&2; exit 1; }

# Run install.sh for real (no --dry-run — the defect is in what a REAL run
# writes) against the stub, with a fresh log each time.
run() {
  KUBECTL_LOG="$TMP/log.$RANDOM"; export KUBECTL_LOG
  : > "$KUBECTL_LOG"
  set +e
  OUT=$(bash "$KIT/install.sh" --provider lke --registry reg.example:5000 \
    --channel acme-stable --channel-pubkey "$TMP/channel.pub" \
    --skip-preflight "$@" 2>&1)
  RC=$?
  set -e
}

# 1 · already installed at exactly the pin -> adopt, and touch nothing
STUB_ARGOCD_IMAGE=quay.io/argoproj/argocd:v3.5.1 \
STUB_KYVERNO_IMAGE=ghcr.io/kyverno/kyverno:v1.19.0 \
STUB_TRACKING=annotation run
[ "$RC" -eq 0 ] || fail "adoption of a pinned-version Argo/Kyverno exited $RC"
echo "$OUT" | grep -q "ADOPTED" || fail "an already-pinned Argo was not reported as adopted"
grep -q "$ARGO_MANIFEST" "$KUBECTL_LOG" && fail "adopted Argo, yet the upstream manifest was still applied"
grep -q "$KYVERNO_MANIFEST" "$KUBECTL_LOG" && fail "adopted Kyverno, yet the upstream manifest was still applied"
grep -q "applicationset" "$KUBECTL_LOG" || fail "adoption skipped the subscription too — the whole point is that it lands"

# 2 · installed at a DIFFERENT version -> refuse, having written nothing
STUB_ARGOCD_IMAGE=quay.io/argoproj/argocd:v2.11.0 \
STUB_KYVERNO_IMAGE=ghcr.io/kyverno/kyverno:v1.19.0 run
[ "$RC" -eq 3 ] || fail "a version mismatch exited $RC; expected the refusal code 3"
echo "$OUT" | grep -q "REFUSING" || fail "the mismatch refusal does not say it is refusing"
echo "$OUT" | grep -q "v2.11.0" || fail "the refusal does not name the version that is installed"
echo "$OUT" | grep -q "v3.5.1" || fail "the refusal does not name the version this kit pins"
grep -Eq '(^| )apply( |$)' "$KUBECTL_LOG" && fail "the refusal still applied something — it must refuse before any write"

# 2b · --argocd adopt takes it anyway, on the operator's say-so
STUB_ARGOCD_IMAGE=quay.io/argoproj/argocd:v2.11.0 \
STUB_KYVERNO_IMAGE=ghcr.io/kyverno/kyverno:v1.19.0 \
STUB_TRACKING=annotation run --argocd adopt
[ "$RC" -eq 0 ] || fail "--argocd adopt over a version mismatch exited $RC"
echo "$OUT" | grep -q "versions differ" || fail "adopting across a version delta did not say so"
grep -q "$ARGO_MANIFEST" "$KUBECTL_LOG" && fail "--argocd adopt still applied the upstream manifest"

# 2c · an adopted Argo tracking by label is REPORTED, never patched behind its owner's back
STUB_ARGOCD_IMAGE=quay.io/argoproj/argocd:v3.5.1 \
STUB_KYVERNO_IMAGE=ghcr.io/kyverno/kyverno:v1.19.0 run
[ "$RC" -eq 0 ] || fail "adoption with label tracking exited $RC"
echo "$OUT" | grep -q "resourceTrackingMethod" || fail "label tracking on an adopted Argo was not surfaced"
grep -q "rollout restart" "$KUBECTL_LOG" && fail "the installer restarted an adopted Argo's controller"

# 3 · absent, but this credential cannot complete the install -> refuse BEFORE writing
STUB_FORBIDDEN=1 run
[ "$RC" -eq 3 ] || fail "a Forbidden install exited $RC; expected the refusal code 3"
echo "$OUT" | grep -qi "forbidden" || fail "the refusal does not name what was Forbidden"
grep -q "dry-run=server" "$KUBECTL_LOG" || fail "no server-side dry-run ran; the refusal was not measured"
grep "$ARGO_MANIFEST" "$KUBECTL_LOG" | grep -qv "dry-run=server" \
  && fail "the upstream manifest was applied for real after a Forbidden dry-run — this is the 49-objects-9-Forbidden half-landing"

# 4 · greenfield and permitted -> install, unchanged
run
[ "$RC" -eq 0 ] || fail "a greenfield install exited $RC"
grep "$ARGO_MANIFEST" "$KUBECTL_LOG" | grep -qv "dry-run=server" || fail "greenfield did not install Argo CD"
grep "$KYVERNO_MANIFEST" "$KUBECTL_LOG" | grep -qv "dry-run=server" || fail "greenfield did not install Kyverno"

# 5 · --argocd skip / --kyverno skip -> not touched, not checked
run --argocd skip --kyverno skip
[ "$RC" -eq 0 ] || fail "--argocd skip --kyverno skip exited $RC"
grep -q "$ARGO_MANIFEST" "$KUBECTL_LOG" && fail "--argocd skip still applied Argo CD"
grep -q "$KYVERNO_MANIFEST" "$KUBECTL_LOG" && fail "--kyverno skip still applied Kyverno"

echo "PASS: install.sh adoption (adopt at pin, refuse on delta, refuse on Forbidden, install greenfield, skip)"
