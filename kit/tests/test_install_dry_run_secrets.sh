#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# --dry-run renders everything and prints no credential — rehearsal defect 4.
#
# Two halves of one broken promise ("render everything, apply nothing"):
#
#   * it UNDER-RENDERED. `apply >/dev/null` in the contracts loop and the
#     pull-secret loop silenced the render as well as the apply: 0 ConfigMaps
#     and 2 Secrets emitted, where a real run writes 2 contract ConfigMaps, 2
#     pubkey Secrets, 2 kubelet pull Secrets and 2 repo Secrets. Six objects a
#     reviewing subscriber never saw.
#   * it LEAKED. The rendered Argo repository Secret carried the registry
#     password in cleartext. The Harbor robot credential it burned was rotated
#     the same hour.
#
# The stub kubectl below renders secrets the way the real one does — plaintext
# in the repo Secret's stringData, base64 in the pull Secret's
# .dockerconfigjson — so the greps here are looking at the shapes a real leak
# takes, not at a convenient stand-in.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# A password with the shape of a real Harbor robot secret, and nothing else in
# the render looks like it.
FIXTURE_PASS='Rh9x-fixture-robot-secret-2f7a'
B64_PASS=$(printf '%s' "$FIXTURE_PASS" | base64)

cat > "$TMP/kubectl" <<'EOF'
#!/usr/bin/env bash
# Renders the two secret shapes faithfully; everything else is inert.
case "$*" in *" -f -"*) cat >/dev/null;; esac
case "$*" in
  *jsonpath*) exit 0;;
  *"create secret docker-registry"*)
      name=""; server=""; user=""; pass=""
      prev=""
      for a in "$@"; do
        case "$a" in
          --docker-server=*) server=${a#*=};;
          --docker-username=*) user=${a#*=};;
          --docker-password=*) pass=${a#*=};;
          -*) ;;
          *) [ "$prev" = "docker-registry" ] && name=$a;;
        esac
        prev=$a
      done
      python3 -c '
import base64, json, sys
name, server, user, pw = sys.argv[1:5]
auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
blob = base64.b64encode(json.dumps(
    {"auths": {server: {"username": user, "password": pw, "auth": auth}}}).encode()).decode()
print(f"""apiVersion: v1
data:
  .dockerconfigjson: {blob}
kind: Secret
metadata:
  creationTimestamp: null
  name: {name}
type: kubernetes.io/dockerconfigjson""")
' "$name" "$server" "$user" "$pass"
      exit 0;;
  *"create secret generic"*)
      # --from-file=channel.pub=<path>
      f=""; name=""; prev=""
      for a in "$@"; do
        case "$a" in --from-file=*) f=${a#*=};; esac
        [ "$prev" = "generic" ] && name=$a
        prev=$a
      done
      python3 -c '
import base64, sys
name, spec = sys.argv[1], sys.argv[2]
key, _, path = spec.partition("=")
print(f"""apiVersion: v1
data:
  {key}: {base64.b64encode(open(path,"rb").read()).decode()}
kind: Secret
metadata:
  creationTimestamp: null
  name: {name}""")
' "$name" "$f"
      exit 0;;
  *"create configmap"*)
      f=""; name=""; prev=""
      for a in "$@"; do
        case "$a" in --from-file=*) f=${a#*=};; esac
        [ "$prev" = "configmap" ] && name=$a
        prev=$a
      done
      python3 -c '
import sys
name, spec = sys.argv[1], sys.argv[2]
key, _, path = spec.partition("=")
body = open(path).read().strip()
print(f"""apiVersion: v1
data:
  {key}: |
    {body}
kind: ConfigMap
metadata:
  creationTimestamp: null
  name: {name}""")
' "$name" "$f"
      exit 0;;
  *"create namespace"*)
      for a in "$@"; do prev_ns=${a}; done
      echo "apiVersion: v1"; echo "kind: Namespace"; echo "metadata:"; echo "  name: ns"
      exit 0;;
esac
exit 0
EOF
chmod +x "$TMP/kubectl"
export PATH="$TMP:$PATH"
echo "-----BEGIN PUBLIC KEY-----" > "$TMP/channel.pub"

fail() { echo "FAIL: $1" >&2; exit 1; }

export VEXA_CHANNEL_PASS="$FIXTURE_PASS"
OUT=$(bash "$KIT/install.sh" --provider lke --registry reg.example:5000 \
  --channel acme-stable --channel-pubkey "$TMP/channel.pub" \
  --registry-user robot-vexa --skip-preflight --dry-run \
  --argocd skip --kyverno skip 2>&1) || fail "install.sh --dry-run exited non-zero"

printf '%s' "$OUT" > "$TMP/render.txt"

# ── the leak ────────────────────────────────────────────────────────────────
# The one that reached the field: the password, verbatim, in the render.
grep -qF "$FIXTURE_PASS" "$TMP/render.txt" \
  && fail "the dry run printed the registry password in cleartext"
# ...and the two encodings kubectl puts it through on the way into a Secret.
grep -qF "$B64_PASS" "$TMP/render.txt" \
  && fail "the dry run printed the base64 of the registry password"
grep -qE '^\s*\.dockerconfigjson: [A-Za-z0-9+/=]{20,}' "$TMP/render.txt" \
  && fail "the dry run printed a dockerconfigjson blob — it decodes to the credential"
grep -q "REDACTED" "$TMP/render.txt" || fail "nothing was redacted; is the render reaching the filter at all?"

# The shape survives the redaction — a reviewer must still see WHAT exists.
grep -q "username: robot-vexa" "$TMP/render.txt" \
  || fail "redaction removed the username too; the shape is the point of the render"
grep -q "channel.pub:" "$TMP/render.txt" \
  || fail "the channel PUBLIC key was redacted — it is public, and it is what a reviewer checks"

# ── the under-render ────────────────────────────────────────────────────────
# What a real run writes, counted in what the dry run showed.
count() { grep -c "$1" "$TMP/render.txt" || true; }
[ "$(count '^kind: ConfigMap')" -ge 2 ] \
  || fail "expected both contract ConfigMaps in the render, saw $(count '^kind: ConfigMap')"
[ "$(count '^kind: Secret')" -ge 6 ] \
  || fail "expected 6 Secrets (2 repo, 2 pubkey, 2 kubelet pull), saw $(count '^kind: Secret')"
for obj in vexa-contract-staging vexa-contract-prod vexa-channel-pubkey \
           vexa-channel-registry vexa-channel-charts; do
  grep -q "name: $obj" "$TMP/render.txt" || fail "$obj is missing from the render"
done

echo "PASS: install.sh --dry-run (no credential printed, every object rendered)"
