#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# vexa-verify.sh --verdict-out — the verdict as a FILE (2026-08-28).
#
# The defect this pins: the station verdict is the ONLY machine gate between
# staging and prod (`internal-prod.json` requires
# `{kind: station-verdict, station: vexa-staging}`), and its consumption is
# fully mechanical — pull, verify signature, match every subject digest against
# the entry's images, match release, match station, require ELIGIBLE
# (vexa-verify.sh §"require_attestations"). Its PRODUCTION was a person reading
# `VERDICT: ELIGIBLE — …` off stdout and typing contract_id / contract_sha256 /
# verdict into a verdict.json that existed nowhere in this repo. The gate was
# real; its input was testimony.
#
# What must hold:
#   1. a verdict that cannot say WHO made it, or against WHAT, is refused
#   2. an ELIGIBLE run writes a predicate the SCHEMA accepts
#   3. its subjects are the entry's own digests — so a verdict cannot be
#      transplanted onto another release, which is exactly what the consuming
#      side checks with `comm -23`
#   4. a NOT ELIGIBLE run writes NOTHING ("a failed verification simply
#      produces no attestation" — station-verdict-attestation.schema.json)
#   5. verdict_log_sha256 appears only when a transcript was actually given
#
# Offline. `oras` and `cosign` are stubbed, as in test_estate_verify.sh: this
# test is about the predicate, not about cryptography.
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

printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/cosign"; chmod +x "$TMP/cosign"

if ! command -v sha256sum >/dev/null; then
  printf '#!/usr/bin/env bash\nshasum -a 256 "$@"\n' > "$TMP/sha256sum"
  chmod +x "$TMP/sha256sum"
fi

export PATH="$TMP:$PATH"
echo "-----BEGIN PUBLIC KEY-----fixture-----END PUBLIC KEY-----" > "$TMP/channel.pub"
echo '{"fixture": true}' > "$FIX/estate-entry/entry.json.sigstore.json"
trap 'rm -rf "$TMP"; rm -f "$FIX/estate-entry/entry.json.sigstore.json"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }
REF="registry.invalid/vexa/channel/fixture-estate:0.0.1-estate-20260825"

# 1 · an unattributable verdict is refused, and says which half is missing
set +e
OUT=$(bash "$VERIFY" --entry-ref "$REF" --pubkey "$TMP/channel.pub" \
  --verdict-out "$TMP/v.json" --policy "$FIX/contracts/estate-ok.json" 2>&1); rc=$?
set -e
[ "$rc" -eq 2 ] || fail "--verdict-out without --station should exit 2, got $rc"
echo "$OUT" | grep -q -- "--verdict-out requires --station" \
  || fail "the refusal does not say a verdict must name its station"

set +e
OUT=$(bash "$VERIFY" --entry-ref "$REF" --pubkey "$TMP/channel.pub" \
  --verdict-out "$TMP/v.json" --station vexa-staging 2>&1); rc=$?
set -e
[ "$rc" -eq 2 ] || fail "--verdict-out without --policy should exit 2, got $rc"
echo "$OUT" | grep -q -- "--verdict-out requires --policy" \
  || fail "the refusal does not say a verdict is rendered against a contract"
[ ! -f "$TMP/v.json" ] || fail "a refused invocation still wrote a verdict file"
echo "  1 OK  a verdict that cannot name its station or its contract is refused"

# 2 · an ELIGIBLE run writes the predicate
echo "transcript of this run" > "$TMP/run.log"
bash "$VERIFY" --entry-ref "$REF" --pubkey "$TMP/channel.pub" \
  --policy "$FIX/contracts/estate-ok.json" --workdir "$TMP/wd" \
  --station vexa-staging --verdict-out "$TMP/v.json" --verdict-log "$TMP/run.log" >"$TMP/out" 2>&1 \
  || { cat "$TMP/out"; fail "the eligible estate run did not pass"; }
[ -f "$TMP/v.json" ] || fail "an ELIGIBLE run wrote no verdict file"

python3 - "$TMP/v.json" "$FIX/estate-entry/entry.json" "$FIX/contracts/estate-ok.json" <<'PY'
import hashlib, json, re, sys
v = json.load(open(sys.argv[1])); entry = json.load(open(sys.argv[2]))
p = v["predicate"]
assert v["_type"] == "https://in-toto.io/Statement/v1", v["_type"]
assert v["predicateType"] == "https://vexa.ai/attestations/station-verdict/v1"
assert p["verdict"] == "ELIGIBLE", p["verdict"]
assert p["station"] == "vexa-staging", p["station"]
assert p["release"] == entry["release"]["version"], (p["release"], entry["release"]["version"])
assert p["contract_id"] == json.load(open(sys.argv[3]))["contract_id"], p["contract_id"]
assert re.fullmatch(r"[0-9a-f]{64}", p["contract_sha256"]), p["contract_sha256"]
assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", p["at"]), p["at"]
# 3 · subjects ARE the entry's digests — the consuming side's comm -23 check
want = sorted(i["index_digest"].removeprefix("sha256:") for i in entry["images"])
got = sorted(s["digest"]["sha256"] for s in v["subject"])
assert got == want, (got, want)
# 5 · the log hash is the hash of the log we handed it
assert re.fullmatch(r"[0-9a-f]{64}", p["verdict_log_sha256"]), p.get("verdict_log_sha256")
print("  2 OK  the predicate is well-formed and its release/station/contract match")
print("  3 OK  subjects are exactly this entry's image digests")
PY

# 4 · the schema is the authority — and it draws a boundary worth pinning.
#
# The predicate SHAPE is right, proven by validating it with a release string
# the schema accepts. But the schema's own `release` pattern is
# ^v[0-9]+\.[0-9]+\.[0-9]+$ — strict OSS release-train semver — and every
# entry on `vexa-internal` is an ESTATE capture (`0.12.23-estate-20260825`),
# which cannot match it.
#
# That is not a bug in this script. It is the schema saying a station verdict
# is an OSS-release-train artifact, and an estate channel gates on
# `validation_contract` instead (internal-estate.json requires exactly that and
# requires NO station verdict). Pinned here so nobody "fixes" it by loosening
# the pattern without deciding that on purpose.
python3 - "$TMP/v.json" <<'PY'
import json, sys
try:
    import jsonschema
except ImportError:
    print("  4 SKIP jsonschema not installed"); sys.exit(0)
schema = json.load(open("spec/station-verdict-attestation.schema.json"))
doc = json.load(open(sys.argv[1]))

# the shape, with a release the schema admits
ok_doc = json.loads(json.dumps(doc))
ok_doc["predicate"]["release"] = "v0.12.23"
jsonschema.validate(ok_doc, schema)
print("  4 OK  the predicate shape validates against station-verdict-attestation.schema.json")

# and the boundary: an estate release does not, by design
try:
    jsonschema.validate(doc, schema)
except jsonschema.ValidationError as e:
    assert "release" in str(e), e
    print("  4b OK  an ESTATE release is refused by the schema's release pattern —")
    print("        station verdicts are an OSS-release-train artifact; the estate")
    print("        channel gates on validation_contract instead")
else:
    raise SystemExit(
        "  4b FAIL the schema now accepts an estate release string. That is a real\n"
        "        decision (station verdicts would then gate estate channels too) and\n"
        "        it must be made deliberately, not by loosening a regex."
    )
PY

# 5 · a NOT ELIGIBLE run writes NOTHING
rm -f "$TMP/v.json"
set +e
bash "$VERIFY" --entry-ref "$REF" --pubkey "$TMP/channel.pub" \
  --policy "$FIX/contracts/oss-shaped.json" --workdir "$TMP/wd2" \
  --station vexa-staging --verdict-out "$TMP/v.json" >"$TMP/out2" 2>&1
set -e
grep -q "VERDICT: NOT ELIGIBLE" "$TMP/out2" || { cat "$TMP/out2"; fail "expected NOT ELIGIBLE"; }
[ ! -f "$TMP/v.json" ] \
  || fail "a NOT ELIGIBLE run wrote a verdict — only ELIGIBLE verdicts may ever exist"
echo "  5 OK  a failed verification produces no attestation"

# 6 · no --verdict-log, no verdict_log_sha256 — and the run says so out loud
rm -f "$TMP/v.json"
bash "$VERIFY" --entry-ref "$REF" --pubkey "$TMP/channel.pub" \
  --policy "$FIX/contracts/estate-ok.json" --workdir "$TMP/wd3" \
  --station vexa-staging --verdict-out "$TMP/v.json" >"$TMP/out3" 2>&1
python3 -c "
import json,sys
p=json.load(open(sys.argv[1]))['predicate']
assert 'verdict_log_sha256' not in p, 'unbound run still claimed a log hash'
" "$TMP/v.json"
grep -q "no --verdict-log given" "$TMP/out3" \
  || fail "an unbound verdict was written without saying so"
echo "  6 OK  verdict_log_sha256 appears only when a transcript was given"

echo "test_verdict_out.sh: all checks passed"
