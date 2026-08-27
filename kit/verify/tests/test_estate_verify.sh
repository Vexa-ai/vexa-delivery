#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# vexa-verify.sh against a PLATFORM ESTATE entry — the regression that made the
# estate verifiable at all (2026-08-25).
#
# The defect this pins: an estate declares the four OSS release-train evidence
# kinds absent, with reasons, in `evidence_absent`. §4 read that as a missing
# file and refused with "candidate map absent from the bundle" — in-cluster, a
# failed PreSync hook that stops the sync and blames the wrong thing. The
# control was that the already-PUBLISHED seq-1 estate entry failed identically,
# so the verifier's model was wrong rather than the entry.
#
# What must hold, and both halves matter equally:
#   1. estate entry + ESTATE contract          -> ELIGIBLE
#   2. estate entry + OSS-SHAPED contract      -> NOT ELIGIBLE, because that
#      contract forbids the absence. Tolerating the absence must NOT have
#      become tolerating it unconditionally: the CONTRACT still adjudicates.
#   3. the refusal in (2) names the evidence kind, not a missing file.
#
# Runs offline. `oras` and `cosign` are stubbed — this test is about the
# verifier's evidence model, and a real signature would only prove cosign
# works. The signature path has its own coverage in publisher/tests.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$(dirname "$HERE")/vexa-verify.sh"
FIX="$HERE/fixtures"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# stub oras: `pull <ref> -o <dir>` copies the fixture entry into <dir>; the
# revocations pull (a different repo) must MISS, which is the "no revocation
# list published" path and is explicitly not an error.
cat > "$TMP/oras" <<EOF
#!/usr/bin/env bash
ref=""; out="."
while [ \$# -gt 0 ]; do
  case "\$1" in
    pull) shift;;
    -o) out=\$2; shift 2;;
    --insecure|--plain-http) shift;;
    *) ref=\$1; shift;;
  esac
done
case "\$ref" in
  *revocations*|*attestations*) echo "not found" >&2; exit 1;;
esac
mkdir -p "\$out"
cp -R "$FIX/estate-entry/." "\$out/"
exit 0
EOF
chmod +x "$TMP/oras"

# stub cosign: the entry fixture carries no real signature; verify-blob succeeds
# so the run reports on the EVIDENCE MODEL rather than on cryptography.
cat > "$TMP/cosign" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TMP/cosign"

# GNU-shaped sha256sum, which the verifier uses and macOS does not ship.
if ! command -v sha256sum >/dev/null; then
  cat > "$TMP/sha256sum" <<'EOF'
#!/usr/bin/env bash
shasum -a 256 "$@"
EOF
  chmod +x "$TMP/sha256sum"
fi

export PATH="$TMP:$PATH"
echo "-----BEGIN PUBLIC KEY-----fixture-----END PUBLIC KEY-----" > "$TMP/channel.pub"

# The fixture entry carries no signature bundle, so §2 would report "entry
# carries no signature" and fail for a reason unrelated to this test. Give it
# one; the stub cosign accepts it.
echo '{"fixture": true}' > "$FIX/estate-entry/entry.json.sigstore.json"
trap 'rm -rf "$TMP"; rm -f "$FIX/estate-entry/entry.json.sigstore.json"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

run_verify() {
  bash "$VERIFY" --entry-ref "registry.invalid/vexa/channel/fixture-estate:0.0.1-estate-20260825" \
    --pubkey "$TMP/channel.pub" --policy "$1" --workdir "$TMP/wd" 2>&1 || true
}

# 1 · estate entry + estate contract -> ELIGIBLE
OUT=$(run_verify "$FIX/contracts/estate-ok.json")
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "estate entry refused under its own estate contract"; }
echo "$OUT" | grep -q "OSS release-train evidence absent by design" \
  || fail "the log does not SAY the absence was declared — a silent tolerance is the wrong fix"
echo "$OUT" | grep -q "candidate map absent from the bundle" \
  && fail "the pre-fix refusal text is still emitted"
echo "  1 OK  estate entry verifies under an estate contract"

# 2 · estate entry + OSS-shaped contract -> NOT ELIGIBLE
OUT=$(run_verify "$FIX/contracts/oss-shaped.json")
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "an OSS-shaped contract accepted an estate — the contract stopped adjudicating"; }
echo "  2 OK  an OSS-shaped contract still refuses an estate"

# 3 · and it refuses for the RIGHT reason, naming the kind
echo "$OUT" | grep -q "declared ABSENT" \
  || { echo "$OUT"; fail "refusal does not name the declared-absent evidence"; }
echo "$OUT" | grep -q "'candidate_map' is declared ABSENT" \
  || fail "refusal does not name candidate_map specifically"
echo "  3 OK  the refusal names the evidence kind, not a missing file"

echo "test_estate_verify.sh: all checks passed"
