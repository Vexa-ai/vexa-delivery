#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install.sh gives the preflight the delivered set — the bbb rehearsal's defect 3.
#
# The call was `vexa_preflight.py --namespace <ns> [--kubeconfig]` and nothing
# else, so `objects = []` and P2/P3 evaluated ONLY the synthetic bot profile.
# P2's own anchor is a LimitRange incident; the same class then happened at sync
# time, to postgres (limit 4Gi against a 2560Mi ceiling), because the check ran
# against nothing at all.
#
# Everything here is offline: a stub kubectl IS the cluster (a namespace, a
# LimitRange with a 2560Mi Container max, a default StorageClass, one node), and
# it converts the rendered fixture with a real YAML parse, which is what the
# preflight's own `kubectl create --dry-run=client` does on a live machine.
#
#   1. --manifests given          -> threaded, and P2 CATCHES the 4Gi postgres
#   2. no manifests, no helm      -> a warning that names what was not checked,
#                                    and the run continues (this is the silent
#                                    escape, now audible)
#   3. no --manifests, helm works -> the installer renders the chart itself and
#                                    threads that
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
FIXTURE="$HERE/fixtures/rendered-chart.yaml"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/kubectl" <<'EOF'
#!/usr/bin/env bash
# A stub cluster: one node, a namespace with no PSA label, a LimitRange whose
# Container max is the recorded 2560Mi, a default StorageClass, no quota and no
# NetworkPolicy. Plus the one conversion the preflight relies on.
case "$*" in *" -f -"*) cat >/dev/null;; esac
case "$*" in
  *jsonpath*) exit 0;;                                  # nothing already installed
  *"create --dry-run=client -o json -f "*)
      python3 -c '
import json,sys,yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d: print(json.dumps(d))
' "${@: -1}"; exit 0;;
  *"get nodes"*)
      echo '{"items":[{"metadata":{"name":"n1"},"spec":{"taints":[]},"status":{"allocatable":{"memory":"8Gi","cpu":"4"}}}]}'; exit 0;;
  *"get namespace"*)
      echo '{"metadata":{"name":"vexa-staging","labels":{},"annotations":{}}}'; exit 0;;
  *"get limitrange"*)
      echo '{"items":[{"metadata":{"name":"project-limits"},"spec":{"limits":[{"type":"Container","max":{"memory":"2560Mi"}}]}}]}'; exit 0;;
  *"get storageclass"*)
      echo '{"items":[{"metadata":{"name":"standard","annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}]}'; exit 0;;
  *"get resourcequota"*|*"get networkpolicy"*) echo '{"items":[]}'; exit 0;;
  *"version -o json"*) echo '{"serverVersion":{"minor":"31","gitVersion":"v1.31.0"}}'; exit 0;;
  *api-versions*) echo "v1"; exit 0;;
  *"create namespace"*) echo "kind: Namespace"; exit 0;;
esac
exit 0
EOF
chmod +x "$TMP/kubectl"
export PATH="$TMP:$PATH"
echo "test-key-placeholder" > "$TMP/channel.pub"

fail() { echo "FAIL: $1" >&2; printf '%s\n' "$OUT" | sed 's/^/    out| /' >&2; exit 1; }

run() {
  set +e
  OUT=$(bash "$KIT/install.sh" --provider lke --registry reg.example:5000 \
    --channel acme-stable --channel-pubkey "$TMP/channel.pub" \
    --argocd skip --kyverno skip "$@" 2>&1)
  RC=$?
  set -e
}

# 1 · the rendered set is threaded, and P2 sees it
run --manifests "$FIXTURE" --dry-run
echo "$OUT" | grep -q -- "--manifests $FIXTURE" \
  || fail "the preflight was not given --manifests"
echo "$OUT" | grep -q "vexa-vexa-postgres" \
  || fail "P2 never mentioned a workload from the rendered chart — it checked the bot profile alone"
echo "$OUT" | grep -q "2560Mi" \
  || fail "the LimitRange ceiling was not compared against the chart"
echo "$OUT" | grep -q "preflight FAILED" \
  || fail "a 4Gi limit under a 2560Mi ceiling did not fail the preflight"
[ "$RC" -eq 1 ] || fail "install.sh continued past a failed preflight (exit $RC)"

# 2 · nothing to render with: SAY SO, loudly, and name what went unchecked
PATH="$TMP:/usr/bin:/bin" run --dry-run          # no helm on this PATH
[ "$RC" -eq 0 ] || fail "the un-rendered run exited $RC; it is a warning, not a failure"
echo "$OUT" | grep -q "WARNING the delivered chart was NOT rendered" \
  || fail "the installer checked only the bot profile and did not say so"
echo "$OUT" | grep -q "helm is not on PATH" || fail "the warning does not say why it could not render"
echo "$OUT" | grep "vexa_preflight.py" | grep -q -- "--manifests" \
  && fail "a --manifests path was passed with nothing rendered"
echo "$OUT" | grep -q "vexa-vexa-postgres" \
  && fail "the chart was somehow checked; this case exists to pin the un-rendered behaviour"

# 3 · helm is here: the installer renders the chart itself
cat > "$TMP/helm" <<EOF
#!/usr/bin/env bash
[ "\$1" = template ] || exit 1
cat "$FIXTURE"
EOF
chmod +x "$TMP/helm"
run --dry-run
echo "$OUT" | grep -q "rendered the delivered chart for the preflight" \
  || fail "helm was available and the installer did not render the chart"
echo "$OUT" | grep -q "vexa-vexa-postgres" || fail "the self-rendered chart never reached P2"
[ "$RC" -eq 1 ] || fail "the self-rendered chart's LimitRange collision did not fail the preflight"

echo "PASS: install.sh --manifests (threaded, self-rendered, and loud when neither)"
