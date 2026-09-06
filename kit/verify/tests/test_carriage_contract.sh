#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# vexa-verify.sh against the 2026-09 CONTRACT SHAPE — `required_values[]` beside
# a `carriage{}` block (2026-08-29).
#
# WHAT THE SHAPE SPLIT DID. The live record for `vexa-internal` now separates
# what the release must be PROVEN to do (`required_values[]`) from what the
# entry carrying it must LOOK like (`carriage{}`). Every check in § 6 of the
# verifier is a carriage check and every one of them was written against the
# flat spelling, so against a nested contract they would each read a missing key
# and take a default.
#
# AND THAT IS THE DANGEROUS HALF: the defaults are not refusals. A missing
# `require_publication_mode` defaults to "published" and would refuse a
# candidate loudly — survivable. A missing `allow_break_glass` defaults to
# false, `min_entry_seq` to 0 and `forbid_absent_evidence` to empty, and those
# read as enforcement while enforcing nothing. A contract nobody could tell was
# being ignored is worse than no contract.
#
# What must hold:
#   1. a carriage-shaped contract adjudicates IDENTICALLY to its flat twin;
#   2. the verdict names the RECORD's id and sha256, not the flattened copy's —
#      an audit has to be able to open the file the hash refers to;
#   3. the carriage keys are actually READ, not merely tolerated: a carriage
#      block that demands a different publication mode still refuses;
#   4. `required_values[]` goes unadjudicated only where the contract does not
#      ask for it, and the run SAYS so rather than passing over it in silence.
#
# Offline. `oras` and `cosign` are stubbed, exactly as in test_estate_verify.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$(dirname "$HERE")/vexa-verify.sh"
FIX="$HERE/fixtures"
TMP=$(mktemp -d)

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

cat > "$TMP/cosign" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TMP/cosign"

if ! command -v sha256sum >/dev/null; then
  cat > "$TMP/sha256sum" <<'EOF'
#!/usr/bin/env bash
shasum -a 256 "$@"
EOF
  chmod +x "$TMP/sha256sum"
fi

export PATH="$TMP:$PATH"
echo "-----BEGIN PUBLIC KEY-----fixture-----END PUBLIC KEY-----" > "$TMP/channel.pub"

echo '{"fixture": true}' > "$FIX/estate-entry/entry.json.sigstore.json"
trap 'rm -rf "$TMP"; rm -f "$FIX/estate-entry/entry.json.sigstore.json"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

run_verify() {
  bash "$VERIFY" --entry-ref "registry.invalid/vexa/channel/fixture-estate:0.0.1-estate-20260825" \
    --pubkey "$TMP/channel.pub" --policy "$1" --workdir "$TMP/wd" 2>&1 || true
}

sha_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# 1 · a carriage-shaped contract adjudicates the same as its flat twin
FLAT=$(run_verify "$FIX/contracts/estate-ok.json")
CARR=$(run_verify "$FIX/contracts/estate-carriage.json")
echo "$CARR" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$CARR"; fail "the carriage shape was refused where its flat twin passes"; }
for check in "policy: evidence 'validation_contract' present" \
             "policy: no break-glass on this entry" \
             "policy: publication mode 'candidate'" \
             "policy: 'validation_contract' not declared absent"; do
  echo "$FLAT" | grep -qF "$check" || fail "the flat control lost '$check' — fixture drift"
  echo "$CARR" | grep -qF "$check" || fail "carriage: '$check' never ran"
done
echo "  1 OK  a carriage{} contract runs every check its flat twin runs"

# 2 · the verdict names the RECORD, not the flattened working copy
REC_SHA=$(sha_of "$FIX/contracts/estate-carriage.json")
echo "$CARR" | grep -q "contract fixture-estate-2026-09 @ sha256:$REC_SHA" \
  || { echo "$CARR" | tail -5; fail "the verdict does not name the record's own sha256 — an audit cannot open what it refers to"; }
echo "  2 OK  the verdict carries the record's id and sha256, not the copy's"

# 3 · the carriage keys are READ, not tolerated
WRONG=$(run_verify "$FIX/contracts/estate-carriage-wrong-mode.json")
echo "$WRONG" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$WRONG"; fail "a carriage block demanding 'published' accepted a candidate — the keys are being ignored"; }
echo "$WRONG" | grep -q "your policy requires 'published'" \
  || fail "the refusal does not name the carriage clause that caused it"
echo "  3 OK  a carriage clause still refuses — the keys adjudicate"

# 4 · required_values[] goes unadjudicated ONLY where the contract does not ask
#     for it, and the run says so. This fixture's carriage omits
#     `require_entry_values_proven`, so its proof half is genuinely out of scope
#     — but silence would be indistinguishable from a pass, which is the
#     property this check has always been about.
#
#     Until 2026-08-31 the verifier printed the unevaluated note UNCONDITIONALLY,
#     including against the live record, which sets the clause true and lists
#     seven required values. kit/verify/tests/test_values_proven.sh owns the
#     enforcing case; this one holds the line that the silence stays declared.
echo "$CARR" | grep -q "contract does not set require_entry_values_proven" \
  || fail "the run does not state that required_values[] went unadjudicated — a silent omission reads as a pass"
echo "$CARR" | grep -q "required_values\[\] is NOT adjudicated by this run" \
  || fail "the note does not name what went unadjudicated"
echo "  4 OK  the unadjudicated half is declared, not skipped in silence"

echo "test_carriage_contract.sh: all checks passed"
