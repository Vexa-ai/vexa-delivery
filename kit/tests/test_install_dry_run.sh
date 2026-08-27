#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Focused regression checks for kit/install.sh, run entirely offline:
# render everything with --dry-run and a stub kubectl, assert on the output.
#
#   1. Omitting --verifier-image must not crash (2026-08-23 field defect:
#      `set -u` hit "VERIFIER_IMAGE: unbound variable" at the subscription
#      render) and must render the verify gate off.
#   2. --registry-insecure must mark BOTH Argo repo secrets `insecure: "true"`
#      (M2 receipt §3 recorded this as a manual patch; a re-run of install.sh
#      used to clobber it).
#   3. --verifier-image set must flip the rendered gate on.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# stub kubectl: --dry-run=client renders pass through it; nothing may reach a cluster
cat > "$TMP/kubectl" <<'EOF'
#!/usr/bin/env bash
# minimal stub: echo a namespace render for `create namespace --dry-run=client`,
# swallow everything else. install.sh --dry-run never applies, so output shape
# only needs to be non-empty yaml where it is piped onward.
for a in "$@"; do
  case "$a" in
    namespace) echo "kind: Namespace";;
  esac
done
exit 0
EOF
chmod +x "$TMP/kubectl"
export PATH="$TMP:$PATH"

echo "test-key-placeholder" > "$TMP/channel.pub"

run() {
  bash "$KIT/install.sh" --provider lke --registry reg.example:5000 \
    --channel enterprise-stable --channel-pubkey "$TMP/channel.pub" \
    --skip-preflight --dry-run "$@" 2>&1
}

fail() { echo "FAIL: $1" >&2; exit 1; }

# 1 · no --verifier-image: must succeed, gate rendered off
OUT=$(run) || fail "install.sh --dry-run crashed without --verifier-image"
echo "$OUT" | grep -q "enabled: false" || fail "verify gate not rendered off by default"
echo "$OUT" | grep -q 'insecure: "true"' && fail "insecure fields rendered without any insecure flag"

# 2 · --registry-insecure: both repo secrets carry insecure
OUT=$(run --registry-insecure) || fail "install.sh --dry-run crashed with --registry-insecure"
COUNT=$(echo "$OUT" | grep -c 'insecure: "true"')
[ "$COUNT" -ge 2 ] || fail "expected insecure: \"true\" on both repo secrets, saw $COUNT"
echo "$OUT" | grep -q "VERIFY_INSECURE\|insecure: true" || true

# 3 · --verifier-image flips the gate on
OUT=$(run --verifier-image example/verifier:1) || fail "install.sh --dry-run crashed with --verifier-image"
echo "$OUT" | grep -q "enabled: true" || fail "verify gate not rendered on with --verifier-image"
echo "$OUT" | grep -q "example/verifier:1" || fail "verifier image not rendered into the subscription"

echo "PASS: install.sh dry-run checks (verifier default, registry-insecure secrets, verifier gate)"
