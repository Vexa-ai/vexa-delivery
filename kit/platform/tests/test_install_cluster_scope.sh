#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install.sh --cluster-scope platform-pack, against a stub kubectl. Offline.
#
# The mode exists because a tenant cannot create the cluster-scoped objects,
# and the danger it guards against is not a crash — it is a SUCCESS. Without
# the check, a run against a cluster where the pack was never applied installs
# the subscription, prints "done", and leaves an Argo that can never sync and
# an admission gate that does not exist. So the tests are about what the run
# REFUSES, and about the third answer the shape forces:
#
#   1  nothing there            -> refuse, exit 3, naming the pack file and the
#                                  render command
#   2  everything there         -> proceed, and touch no cluster-scoped object:
#                                  no Argo install, no Kyverno install, no
#                                  ClusterPolicy, no namespace creation
#   3  Forbidden on the reads   -> UNKNOWN, reported, NOT a refusal. A
#                                  namespace-scoped credential cannot read a
#                                  cluster-scoped object, which is this mode's
#                                  premise; "cannot read it" is not "missing".
#   4  a namespace missing      -> refuse, naming that namespace
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$(dirname "$HERE")")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

echo "fixture-key" > "$TMP/channel.pub"

# A kubectl whose answers are set by the environment, so one stub covers every
# case. It also LOGS every invocation, which is how "touched no cluster-scoped
# object" is checked rather than assumed.
cat > "$TMP/kubectl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$KUBECTL_LOG"
# A real `kubectl apply -f -` READS its stdin. A stub that exits without
# reading closes the pipe under the renderer still writing into it, and the
# run dies on BrokenPipeError — a property of the stub, not of install.sh.
case "$*" in *"-f -"*) cat >/dev/null;; esac
case "$*" in
  *api-resources*argoproj.io*)
    [ "${PACK_CRDS:-yes}" = yes ] || exit 0
    printf 'applications.argoproj.io\napplicationsets.argoproj.io\nappprojects.argoproj.io\n'; exit 0;;
  *api-resources*kyverno.io*)
    [ "${PACK_CRDS:-yes}" = yes ] || exit 0
    echo 'clusterpolicies.kyverno.io'; exit 0;;
  "get clusterpolicy"*|"get clusterrole"*|"get clusterrolebinding"*)
    case "${PACK_CLUSTER_OBJECTS:-present}" in
      present) echo "$2/$3"; exit 0;;
      forbidden) echo 'Error from server (Forbidden): clusterpolicies.kyverno.io is forbidden: User "t" cannot get resource "clusterpolicies" at the cluster scope' >&2; exit 1;;
      *) echo 'Error from server (NotFound): the server could not find the requested resource' >&2; exit 1;;
    esac;;
  "get namespace"*)
    [ "${PACK_NAMESPACES:-present}" = present ] || { echo 'Error from server (NotFound)' >&2; exit 1; }
    echo "namespace/$3"; exit 0;;
  *"get limitrange"*|*"get resourcequota"*)
    [ "${PACK_NAMESPACES:-present}" = present ] || { echo 'Error from server (NotFound): namespaces "x" not found' >&2; exit 1; }
    echo "object/vexa"; exit 0;;
  *namespace*) echo "kind: Namespace";;
esac
exit 0
EOF
chmod +x "$TMP/kubectl"

run() {
  KUBECTL_LOG="$TMP/kubectl.log" PATH="$TMP:$PATH" \
    bash "$KIT/install.sh" --provider openshift --registry reg.example:5000 \
      --channel fixture-stable --channel-pubkey "$TMP/channel.pub" \
      --staging-ns vexa-app --prod-ns vexa-app-prod \
      --cluster-scope platform-pack --skip-preflight 2>&1
}

# 1 · nothing there ------------------------------------------------------------
: > "$TMP/kubectl.log"
set +e
OUT=$(PACK_CRDS=no PACK_CLUSTER_OBJECTS=missing PACK_NAMESPACES=missing run); RC=$?
set -e
[ "$RC" = 3 ] || fail "an empty cluster exited $RC under --cluster-scope platform-pack, expected 3"
echo "$OUT" | grep -q "platform-openshift.yaml" \
  || fail "the refusal does not name the pack file the platform team must apply"
echo "$OUT" | grep -q "kit/platform/render.sh" \
  || fail "the refusal does not give the render command"
echo "$OUT" | grep -q "applications.argoproj.io" \
  || fail "the refusal does not list the missing Argo CRDs"
grep -q "^apply" "$TMP/kubectl.log" && fail "the refusal applied something before refusing"

# 2 · everything there ---------------------------------------------------------
: > "$TMP/kubectl.log"
OUT=$(run) || fail "a cluster carrying the pack was refused"
echo "$OUT" | grep -q "the pack is here" || fail "the precheck did not confirm the pack"
grep -qE "^create namespace" "$TMP/kubectl.log" && fail "it created a namespace the pack owns"
grep -q "argo-cd/.*/manifests/install.yaml" "$TMP/kubectl.log" && fail "it applied upstream Argo CD"
grep -q "kyverno/releases" "$TMP/kubectl.log" && fail "it applied upstream Kyverno"
echo "$OUT" | grep -q "kind: ClusterPolicy" && fail "it re-rendered a ClusterPolicy the pack owns"
echo "$OUT" | grep -q "channel subscription" || fail "it did not get as far as the subscription"

# 3 · Forbidden is UNKNOWN, not missing ---------------------------------------
: > "$TMP/kubectl.log"
OUT=$(PACK_CLUSTER_OBJECTS=forbidden run) \
  || fail "a Forbidden READ was treated as a missing object and refused the install"
echo "$OUT" | grep -q "UNKNOWN" || fail "a Forbidden read was not reported as UNKNOWN"
echo "$OUT" | grep -q "vexa-require-digest-pinning" \
  || fail "the UNKNOWN list does not name what could not be read"

# 4 · a missing namespace is named --------------------------------------------
: > "$TMP/kubectl.log"
set +e
OUT=$(PACK_NAMESPACES=missing run); RC=$?
set -e
[ "$RC" = 3 ] || fail "a missing project exited $RC, expected 3"
echo "$OUT" | grep -q "vexa-app" || fail "the refusal does not name the missing project"

# 5 · the default is unchanged -------------------------------------------------
: > "$TMP/kubectl.log"
OUT=$(KUBECTL_LOG="$TMP/kubectl.log" PATH="$TMP:$PATH" \
  bash "$KIT/install.sh" --provider openshift --registry reg.example:5000 \
    --channel fixture-stable --channel-pubkey "$TMP/channel.pub" \
    --skip-preflight --dry-run 2>&1) || fail "the default scope stopped working"
echo "$OUT" | grep -q "kind: ClusterPolicy" \
  || fail "the default scope no longer renders the admission policy"

# 6 · an unknown value is refused ---------------------------------------------
set +e
OUT=$(bash "$KIT/install.sh" --provider openshift --registry reg.example:5000 \
  --channel c --channel-pubkey "$TMP/channel.pub" --cluster-scope whatever 2>&1); RC=$?
set -e
[ "$RC" = 2 ] || fail "--cluster-scope whatever exited $RC, expected 2"

echo "PASS: install.sh --cluster-scope platform-pack (refusal, UNKNOWN, no cluster-scoped writes)"
