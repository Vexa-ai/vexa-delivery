#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# `require_attestations` — the signed hand-off, enforced (2026-08-31, lane B).
#
# THE CLAUSE. `internal-prod.json` has carried
# `require_attestations: [{kind: station-verdict, station: vexa-staging}]`
# since the prod migration. Its refuser is meant to be plain: cargo that never
# departed staging must not sync to prod.
#
# WHAT WAS ALREADY THERE, and why it was not enough. The verifier could read an
# in-toto statement ACCUMULATED on the channel beside an already-published
# entry — pulled with oras, signature checked, subjects matched against the
# entry's images. That carrier binds by RELEASE VERSION and IMAGE DIGEST SET,
# and nothing else. It predates lane A, so it cannot bind to the thing lane A
# made the currency of this line: the entry's `values_proven` block. A station
# could sign ELIGIBLE and the entry could ship a different proof beside it, and
# every check would pass.
#
# WHAT THIS SUITE COVERS. The embedded carrier: a verdict rendered at DEPART,
# signed, and carried INSIDE the entry beside the proof it signs — bound to the
# candidate COMMIT and to the sha256 of the entry's own values_proven block.
#
# What must hold:
#   1. the whole chain works, offline: fills -> values_proven -> verdict ->
#      sign -> entry -> ELIGIBLE, with one roster line per bound fact;
#   2. NO attestation at all is refused (and the run says it looked in both
#      carriers before refusing);
#   3. a contract naming a station this entry never visited is refused —
#      an entry's verdict from station A does not answer a demand for B;
#   4. tampering with the proof AFTER departure is caught by the hash bind,
#      which is the check the accumulated carrier could never make;
#   5. a verdict earned on another candidate is refused;
#   6. verdict: REFUSED never admits, and the run prints what was unanswered;
#   7. a contract with no require_attestations is UNAFFECTED.
#
# Offline throughout. `oras` and `cosign` are stubbed as in the sibling suites,
# but the cosign stub here answers `version` and writes a bundle on `sign-blob`,
# so `vexa_station_verdict.py sign` runs its real code path — the pinned-
# toolchain check and the offline flags included — instead of being skipped.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
VERIFY="$ROOT/kit/verify/vexa-verify.sh"
FIX="$HERE/fixtures/values-proven"
CONTRACT="$HERE/fixtures/contracts/estate-station-verdict.json"
WRONG_STATION="$HERE/fixtures/contracts/estate-station-verdict-wrong.json"
NO_ATTESTATION="$HERE/fixtures/contracts/estate-values-proven.json"
STATION="vexa-staging-fixture"
CANDIDATE="0000000000000000000000000000000000000000"
MANIFEST="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

# The stub serves whatever currently sits in $TMP/entry, so a test can mutate
# the entry between runs and the "registry" follows. Attestations and
# revocations are NOT served: this suite is about the embedded carrier, and a
# channel with nothing accumulated on it is exactly the state that makes the
# fallback visible.
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

# Answers `version` in the shape require_pinned_cosign() parses (2.x, the
# pinned series), and writes the bundle file `sign-blob --bundle` names, so the
# signer's own code runs. verify-blob always succeeds: what the signature check
# is being tested for here is that it RUNS on the right file with the right
# key, which check 1c asserts from the transcript.
cat > "$TMP/cosign" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  version) echo "GitVersion:    v2.6.5"; exit 0;;
  # cosign_offline_flags() asks the binary which flags it accepts, so the stub
  # answers as a real 2.x does: --tlog-upload only. The 3.x-only flags are
  # deliberately absent — a stub that offered every flag would let a version
  # regression through unseen.
  sign) echo "      --tlog-upload   upload to the transparency log"; exit 0;;
  sign-blob)
    bundle=""
    while [ $# -gt 0 ]; do
      case "$1" in --bundle) bundle=$2; shift 2;; *) shift;; esac
    done
    [ -n "$bundle" ] && printf '{"fixture":"signed"}\n' > "$bundle"
    exit 0;;
esac
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
echo "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----fixture" > "$TMP/cosign.key"

run_verify() {
  bash "$VERIFY" --entry-ref "registry.invalid/vexa/channel/fixture-estate:0.0.1-estate-20260831" \
    --pubkey "$TMP/channel.pub" --policy "${1:-$CONTRACT}" --workdir "$TMP/wd" 2>&1 || true
}

# Every test starts from a pristine copy of the WHOLE entry directory, not just
# entry.json: check 6 rewrites an evidence file, and a restore that only put
# entry.json back left that file mutated underneath every later test — §3
# reported a digest mismatch and the suite blamed the check under test.
restore() {
  rm -rf "$TMP/entry"
  cp -R "$TMP/pristine" "$TMP/entry"
}

# Mutate the served entry from the pristine copy each time. Evidence digests
# are re-stamped afterwards where the mutation touched a file, so §3 does not
# fire and mask the check under test.
mutate() {
  restore
  python3 - "$TMP/entry/entry.json" <<PY
import json, sys
p = sys.argv[1]
d = json.load(open(p))
$1
json.dump(d, open(p, "w"), indent=1)
PY
}

# Rewrite one evidence FILE and re-stamp its digest in the entry, so the only
# thing that changed is the fact under test.
restamp() {
  python3 - "$TMP/entry" "$1" <<'PY'
import hashlib, json, pathlib, sys
root, name = pathlib.Path(sys.argv[1]), sys.argv[2]
entry = json.loads((root / "entry.json").read_text())
digest = hashlib.sha256((root / "evidence" / name).read_bytes()).hexdigest()
for row in entry["evidence"]:
    if row["name"] == name:
        row["sha256"] = digest
(root / "entry.json").write_text(json.dumps(entry, indent=1))
PY
}

# ------------------------------------------------------------------ the chain
# 1 · fills -> values_proven -> verdict -> sign -> entry -> ELIGIBLE.
python3 "$ROOT/publisher/vexa_values_proven.py" \
  --contract "$CONTRACT" --fills "$FIX/row-fills.log" --map "$FIX/rows.json" \
  --station "$STATION" --out "$TMP/values-proven.json" > "$TMP/build.log" 2>&1 \
  || { cat "$TMP/build.log"; fail "the builder refused a fills log that PASSes every required value"; }

python3 "$ROOT/publisher/vexa_station_verdict.py" render \
  --station "$STATION" --candidate-sha "$CANDIDATE" --manifest-sha256 "$MANIFEST" \
  --contract "$CONTRACT" --values-proven "$TMP/values-proven.json" \
  --out "$TMP/verdict" > "$TMP/render.log" 2>&1 \
  || { cat "$TMP/render.log"; fail "render refused a block that covers every required value"; }
grep -q "VERDICT: ELIGIBLE" "$TMP/render.log" \
  || { cat "$TMP/render.log"; fail "a covering block did not compute ELIGIBLE"; }

# The hash in the verdict is the CANONICAL form of the block, and the verifier
# recomputes it with jq. Assert the agreement here, on the real files, before
# anything downstream depends on it.
py_h=$(python3 -c "import json,sys; sys.path.insert(0,'$ROOT/publisher'); \
import vexa_channel as c; print(c.canonical_values_proven_sha256(json.load(open('$TMP/values-proven.json'))))")
jq_h=$(jq -Sc '.' "$TMP/values-proven.json" | tr -d '\n' | sha256sum | cut -d' ' -f1)
sv_h=$(jq -r '.values_proven_sha256' "$TMP/verdict/station-verdict.json")
[ "$py_h" = "$jq_h" ] || fail "python and jq disagree on the canonical block ($py_h vs $jq_h)"
[ "$sv_h" = "$jq_h" ] || fail "the verdict's values_proven_sha256 is not the canonical hash"
echo "  1a OK python and jq compute the same canonical values_proven hash"

python3 "$ROOT/publisher/vexa_station_verdict.py" sign \
  --verdict "$TMP/verdict" --key "$TMP/cosign.key" > "$TMP/sign.log" 2>&1 \
  || { cat "$TMP/sign.log"; fail "sign refused a rendered verdict"; }
[ -f "$TMP/verdict/station-verdict.json.sigstore.json" ] \
  || fail "sign produced no bundle beside the verdict"
grep -q -- "--tlog-upload=false" "$TMP/sign.log" \
  || { cat "$TMP/sign.log"; fail "the verdict was signed without the offline flags"; }
echo "  1b OK sign wraps cosign key-mode offline, and the bundle lands beside the file"

python3 "$ROOT/publisher/vexa_channel.py" platform-entry \
  --spec "$FIX/estate-spec.yaml" --validation-contract "$FIX/validation-contract.yaml" \
  --values-proven "$TMP/values-proven.json" --station-verdict "$TMP/verdict" \
  --release 0.0.1-estate-20260831 --channel fixture-estate --entry-seq 12 \
  --identity fixture --signing-mode test_key --signing-note fixture \
  --publication-mode candidate --publisher fixture --out "$TMP/entry" >/dev/null \
  || fail "platform-entry refused an entry carrying a matching signed verdict"
echo '{"fixture": true}' > "$TMP/entry/entry.json.sigstore.json"
cp -R "$TMP/entry" "$TMP/pristine"

OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "a correctly carried station verdict was refused"; }
echo "$OUT" | grep -qF "OK    station-verdict: '$STATION' rides inside this entry" \
  || { echo "$OUT"; fail "the run does not say which carrier adjudicated the clause"; }
echo "$OUT" | grep -qF "OK    station-verdict '$STATION': signature verifies" \
  || { echo "$OUT"; fail "no roster line for the verdict's signature"; }
echo "$OUT" | grep -qF "OK    station-verdict '$STATION': verdict ELIGIBLE" \
  || { echo "$OUT"; fail "no roster line for the verdict itself"; }
echo "$OUT" | grep -qF "is this entry's source commit" \
  || { echo "$OUT"; fail "no roster line binding the verdict to the candidate"; }
echo "$OUT" | grep -qF "signed over THIS entry's values_proven" \
  || { echo "$OUT"; fail "no roster line binding the verdict to the proof block"; }
echo "$OUT" | grep -q "recorded, NOT compared" \
  || { echo "$OUT"; fail "the manifest hash is carried but ungated, and the run must SAY so"; }
echo "  1 OK  fills -> verdict -> entry -> ELIGIBLE, one roster line per bound fact"

# 2 · no verdict anywhere: the clause refuses, having looked in both carriers.
mutate "d['evidence'] = [e for e in d['evidence'] if e['kind'] != 'station_verdict']"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "an entry with no station verdict passed a contract that requires one"; }
echo "$OUT" | grep -qF "no station_verdict evidence from '$STATION' rides inside this entry" \
  || { echo "$OUT"; fail "the run does not say the embedded carrier was empty before it fell back"; }
echo "$OUT" | grep -q "the upstream station has not signed this release" \
  || { echo "$OUT"; fail "the fallback did not refuse, or did not say why"; }
echo "  2 OK  no attestation in either carrier = NOT ELIGIBLE, and the log names both"

# 3 · a contract demanding a station this entry never visited.
OUT=$(run_verify "$WRONG_STATION")
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "a verdict from station A satisfied a contract demanding station B"; }
echo "$OUT" | grep -qF "no station_verdict evidence from 'vexa-staging-elsewhere'" \
  || { echo "$OUT"; fail "the refusal does not name the station the contract asked for"; }
echo "  3 OK  a verdict from another station does not answer this contract's demand"

# 4 · the proof swapped AFTER the station signed. This is the check the
#     accumulated carrier cannot make, and the reason the embedded one exists.
mutate "d['values_proven'][0]['station'] = 'somewhere-else'"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "a values_proven block swapped after departure was admitted"; }
echo "$OUT" | grep -q "the signature is over a different proof than the one shipped" \
  || { echo "$OUT"; fail "the refusal does not say the signature and the proof parted company"; }
mutate "d.pop('values_proven')"
OUT=$(run_verify)
echo "$OUT" | grep -q "carries no values_proven block at all" \
  || { echo "$OUT"; fail "a verdict binding to a block the entry does not carry was not named as such"; }
echo "  4 OK  tampering with the proof after departure breaks the hash bind"

# 5 · a verdict earned on a different candidate.
mutate "d['release']['source_sha'] = 'b' * 40"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "a verdict about another candidate was admitted"; }
echo "$OUT" | grep -q "a verdict earned on another candidate" \
  || { echo "$OUT"; fail "the refusal does not say the candidate is not this entry's"; }
echo "  5 OK  candidate_sha binds the verdict to the commit it was earned on"

# 6 · REFUSED never admits. platform-entry will not build one in (tested in
#     publisher/tests), so the file is swapped into a built entry directly —
#     which is also the tampering shape this check has to survive.
restore
SVNAME="station-verdict-$STATION.json"
python3 - "$TMP/entry/evidence/$SVNAME" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["verdict"] = "REFUSED"
d["unanswered_values"] = [{"id": "V-fix-3", "reason": "the station never ran the sweep"}]
json.dump(d, open(p, "w"), indent=1)
PY
restamp "$SVNAME"
cp -R "$TMP/entry" "$TMP/refused"
OUT=$(run_verify)
echo "$OUT" | grep -q "VERDICT: NOT ELIGIBLE" \
  || { echo "$OUT"; fail "a REFUSED station verdict admitted the entry"; }
echo "$OUT" | grep -q "the station that ran this candidate did not clear it" \
  || { echo "$OUT"; fail "the refusal does not say the station itself said no"; }
echo "$OUT" | grep -q "unanswered: V-fix-3" \
  || { echo "$OUT"; fail "a REFUSED verdict must print what it left unanswered"; }
echo "  6 OK  verdict REFUSED never admits, and the log carries the station's reasons"

# 7 · scope. A contract that does not ask for an attestation is untouched by
#     all of the above — asserted against the SAME entry, so the difference is
#     the contract and nothing else.
restore
OUT=$(run_verify "$NO_ATTESTATION")
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "the new check gated a contract that never asked for it"; }
# Roster lines only — the evidence FILE is still named station-verdict-*.json
# and still digest-checked by §3, which is correct and is not an adjudication.
# `grep -q ... && fail` would also have exited the suite on the happy path,
# because a failing grep at the end of an && list is a non-zero status under
# `set -e`.
if echo "$OUT" | grep -qE "^(OK|FAIL) +station-verdict"; then
  echo "$OUT"; fail "a contract with no require_attestations should adjudicate no station verdict"
fi
# ...and the same is true of an entry that carries a REFUSED verdict nobody
# asked about: the clause is the refuser, not the file's presence.
rm -rf "$TMP/entry"; cp -R "$TMP/refused" "$TMP/entry"
OUT=$(run_verify "$NO_ATTESTATION")
echo "$OUT" | grep -q "VERDICT: ELIGIBLE" \
  || { echo "$OUT"; fail "a verdict file gated a contract that did not require one"; }
echo "  7 OK  a contract without require_attestations is unaffected, either way"

echo "test_station_verdict.sh: all checks passed"
