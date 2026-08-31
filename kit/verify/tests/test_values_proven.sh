#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# `carriage.require_entry_values_proven` — the clause nothing read (2026-08-31).
#
# THE VOID. The live `vexa-internal` record has set this clause true since the
# 2026-09 shape landed, and listed seven `required_values[]` rows with
# `enforcement: "required"`. Nothing wrote a proof block; nothing read one. The
# verifier said so in its own transcript — "required_values[] is NOT evaluated
# by this verifier" — and every run printed a full roster of green carriage
# ticks beside a proof half that was not a check at all. A contract demanding
# proof of seven values admitted an entry proving none of them, and no operator
# reading the log could tell.
#
# This suite is the reversal, end to end and offline: a station's committed
# fills become a values_proven block, the block goes into a real entry built by
# `platform-entry`, and the verifier adjudicates it against a real contract.
#
# What must hold:
#   1. the whole chain works: fills -> block -> entry -> ELIGIBLE;
#   2. strip one required value's row and the verdict is NOT ELIGIBLE, naming
#      the id — the check counts, it does not merely print;
#   3. an entry with NO block at all is refused once per required id, which is
#      exactly what happens to every entry published through seq-11;
#   4. evidence citing an image digest this entry does not ship is refused —
#      proof about another release is not proof about this one;
#   5. a `waived` row passes ONLY when it names the human who granted it;
#   6. advisory values never gate, and the run says what it saw for them.
#
# Offline. `oras` and `cosign` are stubbed, exactly as in test_estate_verify.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VERIFY="$ROOT/kit/verify/vexa-verify.sh"
FIX="$HERE/fixtures/values-proven"
CONTRACT="$HERE/fixtures/contracts/estate-values-proven.json"
LEGACY_ENTRY="$HERE/fixtures/estate-entry"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

# The stub serves whatever currently sits in $TMP/entry, so a test can mutate
# the entry between runs and the "registry" follows.
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
cp -R "$TMP/entry/." "\$out/"
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

run_verify() {
  bash "$VERIFY" --entry-ref "registry.invalid/vexa/channel/fixture-estate:0.0.1-estate-20260831" \
    --pubkey "$TMP/channel.pub" --policy "$CONTRACT" --workdir "$TMP/wd" 2>&1 || true
}

# Mutate the served entry with a python snippet, from the pristine copy each time.
mutate() {
  cp "$TMP/entry.pristine.json" "$TMP/entry/entry.json"
  python3 - "$TMP/entry/entry.json" <<PY
import json, sys
p = sys.argv[1]
d = json.load(open(p))
$1
json.dump(d, open(p, "w"), indent=1)
PY
}

# ---------------------------------------------------------------- the chain
# 1 · a station's committed fills become the block, and the block is admitted.
python3 "$ROOT/publisher/vexa_values_proven.py" \
  --contract "$CONTRACT" --fills "$FIX/row-fills.log" --map "$FIX/rows.json" \
  --station fixture-station --out "$TMP/values-proven.json" > "$TMP/build.log" 2>&1 \
  || { cat "$TMP/build.log"; fail "the builder refused a fills log that PASSes every required value"; }

grep -q "V-fix-1: proven, 2 evidence row(s)" "$TMP/build.log" \
  || { cat "$TMP/build.log"; fail "two mapped PASS rows did not become two evidence rows"; }
grep -q "skipped (advisory, unproven): V-fix-2" "$TMP/build.log" \
  || { cat "$TMP/build.log"; fail "an advisory value with only a PART row should be skipped and SAID, not proven"; }
python3 - "$TMP/values-proven.json" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
assert [r["id"] for r in rows] == ["V-fix-1", "V-fix-3"], rows
ev = rows[0]["evidence"][0]
assert ev["what"].startswith("2026-08-31T08:0xZ E0 PASS"), ev
assert ev["tested_at"] == "2026-08-31T08:00:00Z", ev
PY
echo "  1a OK the fills log becomes evidence VERBATIM, with the coarse stamp rounded down"

python3 "$ROOT/publisher/vexa_channel.py" platform-entry \
  --spec "$FIX/estate-spec.yaml" --validation-contract "$FIX/validation-contract.yaml" \
  --values-proven "$TMP/values-proven.json" \
  --release 0.0.1-estate-20260831 --channel fixture-estate --entry-seq 12 \
  --identity fixture --signing-mode test_key --signing-note fixture \
  --publication-mode candidate --publisher fixture --out "$TMP/entry" >/dev/null \
  || fail "platform-entry refused an entry carrying a valid values_proven block"
echo '{"fixture": true}' > "$TMP/entry/entry.json.sigstore.json"
cp "$TMP/entry/entry.json" "$TMP/entry.pristine.json"

OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "a complete roster was refused"; }
echo "$OUT" | grep -qF "OK    values: V-fix-1 proven by station 'fixture-station' (2 evidence row(s))" \
  || { echo "$OUT"; fail "the roster does not name V-fix-1, its station and its evidence count"; }
echo "$OUT" | grep -qF "OK    values: V-fix-3 proven by station 'fixture-station'" \
  || { echo "$OUT"; fail "the roster does not name V-fix-3"; }
echo "  1 OK  fills -> block -> entry -> ELIGIBLE, one roster line per value id"

# 2 · strip one required row: the verdict must FLIP, not merely print a FAIL.
mutate "d['values_proven'] = [r for r in d['values_proven'] if r['id'] != 'V-fix-3']"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE — 1 check(s) failed" \
  || { echo "$OUT"; fail "removing a required value's proof did not flip the verdict, or was not counted"; }
echo "$OUT" | grep -qF "FAIL  values: V-fix-3 is REQUIRED by contract fixture-estate-values-2026-09" \
  || { echo "$OUT"; fail "the refusal does not name the missing value id"; }
echo "  2 OK  one missing required value = NOT ELIGIBLE, counted and named"

# 3 · no block at all — the seq-11-and-earlier case, refused once per value.
mutate "d.pop('values_proven')"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE — 2 check(s) failed" \
  || { echo "$OUT"; fail "an entry with no values_proven block was not refused once per required value"; }
echo "$OUT" | grep -q "this entry carries NO values_proven block" \
  || { echo "$OUT"; fail "the run does not distinguish 'predates the block' from 'proof is wrong'"; }
echo "  3 OK  an entry with no block is refused per required id, and told why"

# 4 · evidence about an image this entry does not ship.
mutate "d['values_proven'][0]['evidence'][0]['subject_digest'] = 'sha256:' + '9'*64"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "evidence citing a foreign image digest was admitted"; }
echo "$OUT" | grep -q "which this entry does not ship" \
  || { echo "$OUT"; fail "the refusal does not say the digest is not this entry's"; }
mutate "d['values_proven'][0]['evidence'][0]['subject_digest'] = d['images'][1]['index_digest']"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "evidence citing a digest this entry DOES ship was refused — the check is inverted"; }
echo "  4 OK  subject_digest must be one of this entry's images, and passes when it is"

# 5 · a waiver is a human act or it is nothing.
mutate "
d['values_proven'] = [r for r in d['values_proven'] if r['id'] != 'V-fix-3']
d['values_proven'].append({'id': 'V-fix-3', 'verdict': 'waived',
                           'station': 'fixture-station', 'waived_by': 'A Named Human'})"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "a named waiver was refused"; }
echo "$OUT" | grep -q "WAIVED by A Named Human" \
  || { echo "$OUT"; fail "the waiver passed without naming the human on the transcript"; }
mutate "
d['values_proven'] = [r for r in d['values_proven'] if r['id'] != 'V-fix-3']
d['values_proven'].append({'id': 'V-fix-3', 'verdict': 'waived', 'station': 'fixture-station'})"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "an anonymous waiver was admitted — that is an omission with a label"; }
echo "  5 OK  waived passes only when a human is named for it"

# 5b · a verdict the enum does not contain is a refusal, not a shrug.
mutate "d['values_proven'][0]['verdict'] = 'probably'"
OUT=$(run_verify)
echo "$OUT" | grep -q "only 'proven' or 'waived' answers a required value" \
  || { echo "$OUT"; fail "an unknown verdict did not refuse"; }
echo "  5b OK an unrecognised verdict refuses rather than defaulting"

# 6 · advisory rows are visible and never gate.
mutate "pass"
OUT=$(run_verify)
echo "$OUT" | grep -q "note  values: V-fix-2 is advisory in this contract" \
  || { echo "$OUT"; fail "an advisory value went unmentioned — a silent skip reads as a pass"; }
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "an unproven ADVISORY value gated the verdict"; }
echo "  6 OK  advisory values are reported and do not gate"

# 7 · the compat statement, tested rather than asserted in a PR body: the
#     already-published estate fixture (no block, like every entry through
#     seq-11) is refused by this contract, and the SAME entry passes a contract
#     that does not set the clause. Fail-closed, and scoped to the clause.
rm -rf "$TMP/entry"
cp -R "$LEGACY_ENTRY" "$TMP/entry"
echo '{"fixture": true}' > "$TMP/entry/entry.json.sigstore.json"
OUT=$(bash "$VERIFY" --entry-ref "registry.invalid/vexa/channel/fixture-estate:legacy" \
        --pubkey "$TMP/channel.pub" --policy "$CONTRACT" --workdir "$TMP/wd" 2>&1 || true)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "a pre-block entry passed a contract that requires the block"; }
OUT=$(bash "$VERIFY" --entry-ref "registry.invalid/vexa/channel/fixture-estate:legacy" \
        --pubkey "$TMP/channel.pub" --policy "$HERE/fixtures/contracts/estate-carriage.json" \
        --workdir "$TMP/wd" 2>&1 || true)
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "the new check gated a contract that never asked for it"; }
echo "$OUT" | grep -q "contract does not set require_entry_values_proven" \
  || { echo "$OUT"; fail "a contract that does not ask should SAY the half went unadjudicated"; }
echo "  7 OK  fail-closed on pre-block entries; inert where the contract is silent"

echo "test_values_proven.sh: all checks passed"
