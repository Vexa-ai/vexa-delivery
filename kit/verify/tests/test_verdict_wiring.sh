#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The verdict PRODUCER, end to end in the chart (2026-08-29).
#
# The defect this pins: on 2026-08-29 the PreSync verify Job in
# `vexa-production` ran, and SUCCEEDED, on every sync — and four consecutive
# nightly station reports read `verifier.verdict: ABSENT`, which
# spec/report.v1.schema.json defines as "the gate did not run, which is a
# finding rather than a pass". Both statements were true at once. The verdict
# existed as a line on the pod's stdout and then the pod was collected.
#
# `kit/verify/tests/test_verdict_out.sh` proved the CAPABILITY — the verifier
# can write its verdict to a file. This proves the WIRING: that the chart
# actually asks for it, that RBAC permits the write, and that the wrapper
# records a verdict on failure as well as on success without ever converting a
# failed verification into a passed sync.
#
# What must hold:
#   1. the rendered Job invokes the verifier with --station and --verdict-out
#   2. the Role carries exactly the verbs the write needs, and update/patch
#      are scoped by name to the one ConfigMap this gate may touch
#   3. an ELIGIBLE run records verdict=ELIGIBLE, failed_checks=0, the
#      contract's id and sha256, and the signed statement verbatim
#   4. a FAILED run records verdict=NOT_ELIGIBLE with the verifier's own count
#      — and still exits non-zero, so the PreSync gate fails closed
#   5. the keys are exactly the ones kit/validate/collectors.py reads, spelled
#      the way spec/report.v1.schema.json spells them
#   6. verify.recordVerdict false renders the pre-2026-08-29 Job unchanged
#   7. the same, run against the REAL verifier rather than a stub of it
#   8. a record it cannot write warns loudly and fails NOTHING — an RBAC gap on
#      bookkeeping must not become another "the gate failed for a reason that
#      has nothing to do with the evidence"
#
# Offline. helm renders; `vexa-verify` and `kubectl` are stubs, as in
# test_verdict_out.sh — this test is about the wiring, not about cryptography
# and not about the API server.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
TEMPLATE="$REPO/kit/verify/chart-template/channel-verify.yaml"

if ! command -v helm >/dev/null; then
  echo "test_verdict_wiring.sh: SKIP (helm not installed)"; exit 0
fi
if ! python3 -c "import yaml" >/dev/null 2>&1; then
  echo "test_verdict_wiring.sh: SKIP (PyYAML not installed)"; exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }

# ------------------------------------------------------------------- render
mkdir -p "$TMP/chart/templates"
cp "$TEMPLATE" "$TMP/chart/templates/channel-verify.yaml"
cat > "$TMP/chart/Chart.yaml" <<'EOF'
apiVersion: v2
name: fixture
version: 0.1.0-estate.20260825.rev139
appVersion: "0.12.23-estate"
EOF
# The publisher's own defaults, minus the two the wiring adds — so this render
# also proves the template survives values written before those keys existed.
cat > "$TMP/chart/values.yaml" <<'EOF'
verify:
  enabled: true
  registry: registry.invalid
  channel: fixture-estate
  image: registry.invalid/tools/verifier@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  contractConfigMap: vexa-contract-prod
  registrySecret: ""
  deadlineSeconds: 300
  requireApproval: ""
  approvalNamespace: argocd
  insecure: false
  entryTag: "0.12.23-estate-20260825"
  contractPolicy: ""
  channelPublicKey: ""
  tolerations: []
  nodeSelector: {}
  networkPolicy: true
  egressCIDR: 0.0.0.0/0
global:
  imagePullSecrets: []
EOF
helm template fixture "$TMP/chart" -n vexa-production > "$TMP/render.yaml" \
  || fail "the template does not render"
helm template fixture "$TMP/chart" -n vexa-production \
  --set verify.recordVerdict=false > "$TMP/render-off.yaml" \
  || fail "the template does not render with recordVerdict false"

# 1 · 2 · 6 — the manifest asks for the verdict, and RBAC permits writing it
python3 - "$TMP/render.yaml" "$TMP/render-off.yaml" "$TMP/script.sh" \
         "$TMP/args.txt" "$TMP/verdict.json" "$TMP/contract.json" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
off = [d for d in yaml.safe_load_all(open(sys.argv[2])) if d]

job = next(d for d in docs if d["kind"] == "Job")
c = job["spec"]["template"]["spec"]["containers"][0]

# 1 · the invocation
args = c["args"]
assert "--verdict-out" in args, args
assert "--station" in args, args
assert args[args.index("--station") + 1] == "vexa-prod", args
vfile = args[args.index("--verdict-out") + 1]
# --verdict-out refuses without --policy; the flag must still be there.
assert "--policy" in args, args
env = {e["name"]: e["value"] for e in c["env"]}
assert env["VEXA_VERDICT_FILE"] == vfile, (env, vfile)
assert env["VEXA_VERDICT_CM"] == "vexa-verify-verdict", env
assert env["VEXA_VERDICT_NS"] == "vexa-production", env
assert c["command"][:2] == ["/bin/sh", "-uc"], c["command"][:2]
# -uc and not -ec: `set -e` would exit at a failed verification and record
# nothing, which is the state this change exists to end.
print("  1 OK  the Job invokes the verifier with --station and --verdict-out")

# 2 · the Role, in the RELEASE namespace, minimal and name-scoped where it can be
role = next(d for d in docs
            if d["kind"] == "Role" and d["metadata"]["name"].startswith("vexa-verify-verdict"))
assert role["metadata"]["namespace"] == "vexa-production", role["metadata"]
rules = {tuple(sorted(r["verbs"])): r for r in role["rules"]}
unscoped = rules[("create", "get")]
assert "resourceNames" not in unscoped, unscoped
scoped = rules[("patch", "update")]
assert scoped["resourceNames"] == ["vexa-verify-verdict"], scoped
assert all(r["resources"] == ["configmaps"] for r in role["rules"]), role["rules"]
binding = next(d for d in docs
               if d["kind"] == "RoleBinding" and d["metadata"]["name"].startswith("vexa-verify-verdict"))
assert binding["subjects"][0]["name"] == "vexa-verify", binding["subjects"]
# The approvals Role, when it renders, still writes nothing anywhere.
print("  2 OK  the Role adds create/get plus update/patch scoped to the one ConfigMap")

# 6 · the escape hatch renders the pre-2026-08-29 Job, unchanged
job_off = next(d for d in off if d["kind"] == "Job")
c_off = job_off["spec"]["template"]["spec"]["containers"][0]
assert "command" not in c_off, c_off.get("command")
assert "--verdict-out" not in c_off["args"], c_off["args"]
assert "env" not in c_off, c_off.get("env")
assert not [d for d in off if d["metadata"]["name"].startswith("vexa-verify-verdict")]
print("  6 OK  recordVerdict false renders the Job exactly as it was")

open(sys.argv[3], "w").write(c["command"][2])
# The wrapper and the flags are both taken FROM THE MANIFEST, never retyped:
# a template that stopped passing --verdict-out could otherwise still pass the
# behavioural half of this test. Only the two paths are pointed at fixtures.
subst = {vfile: sys.argv[5], "/contract/contract.json": sys.argv[6]}
open(sys.argv[4], "w").write("".join(subst.get(a, a) + "\n" for a in args))
PY
# Not `mapfile`: macOS ships bash 3.2, where it does not exist, and this test
# has to run on a maintainer's laptop as well as in CI.
VERIFIER_ARGS=()
while IFS= read -r a; do VERIFIER_ARGS+=("$a"); done < "$TMP/args.txt"

# ------------------------------------------------------------------- stubs
#
# kubectl is EMULATED rather than delegated to a real binary: `create
# configmap --dry-run=client` needs no cluster, but CI is not promised a
# kubectl at all, and a test that silently skipped there would leave the wiring
# unproven on the only machine that runs it on every push. The emulation is
# strict about ConfigMap key names, which is the one thing --from-file=<dir>
# can get wrong.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/kubectl" <<PY
#!/usr/bin/env python3
import json, os, re, sys
a = sys.argv[1:]
if a[0] == "create":
    d = next(x.split("=", 1)[1] for x in a if x.startswith("--from-file="))
    data = {}
    for k in sorted(os.listdir(d)):
        if not re.fullmatch(r"[-._a-zA-Z0-9]+", k):
            sys.exit("invalid configmap key: " + k)
        data[k] = open(os.path.join(d, k)).read()
    name = a[a.index("configmap") + 1]
    print(json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
                      "metadata": {"name": name, "namespace": a[a.index("-n") + 1]},
                      "data": data}))
elif a[0] == "apply":
    open("$TMP/applied.json", "w").write(sys.stdin.read())
else:
    sys.exit("unexpected kubectl invocation: " + " ".join(a))
PY
chmod +x "$TMP/bin/kubectl"

if ! command -v sha256sum >/dev/null; then
  printf '#!/usr/bin/env bash\nshasum -a 256 "$@"\n' > "$TMP/bin/sha256sum"
  chmod +x "$TMP/bin/sha256sum"
fi

cat > "$TMP/contract.json" <<'EOF'
{"contract_id": "internal-prod", "min_evidence": []}
EOF
# `A && B || C` runs C when B fails, which is how the local lint and CI came to
# disagree once already (see the Makefile's `lint` target). Test, then branch.
if command -v sha256sum >/dev/null; then
  CSHA=$(sha256sum "$TMP/contract.json" | cut -d' ' -f1)
else
  CSHA=$(shasum -a 256 "$TMP/contract.json" | cut -d' ' -f1)
fi

# The eligible verifier: writes the statement --verdict-out asks for.
cat > "$TMP/bin/vexa-verify" <<'EOF'
#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do
  case "$1" in --verdict-out) out=$2; shift 2;; *) shift;; esac
done
echo "OK    entry pulled"
echo "VERDICT: ELIGIBLE — 0.12.23-estate-20260825 verified against contract internal-prod"
[ -n "$out" ] && cat > "$out" <<'JSON'
{"_type":"https://in-toto.io/Statement/v1",
 "predicateType":"https://vexa.ai/attestations/station-verdict/v1",
 "subject":[{"name":"vexa/api-gateway","digest":{"sha256":"aa"}}],
 "predicate":{"release":"0.12.23-estate-20260825","station":"vexa-prod",
              "verdict":"ELIGIBLE","contract_id":"internal-prod"}}
JSON
exit 0
EOF
chmod +x "$TMP/bin/vexa-verify"

export PATH="$TMP/bin:$PATH"
export VEXA_VERDICT_CM=vexa-verify-verdict VEXA_VERDICT_NS=vexa-production \
       VEXA_VERDICT_FILE="$TMP/verdict.json" VEXA_CONTRACT_FILE="$TMP/contract.json" \
       VEXA_STATION=vexa-prod VEXA_ENTRY_REF=registry.invalid/vexa/channel/x:1

# 3 · an ELIGIBLE run records the verdict
rm -f "$TMP/applied.json" "$TMP/verdict.json"
sh -uc "$(cat "$TMP/script.sh")" vexa-verify-gate "${VERIFIER_ARGS[@]}" >"$TMP/run1" 2>&1 \
  || { cat "$TMP/run1"; fail "the eligible run exited non-zero"; }
grep -q "verdict recorded in configmap/vexa-verify-verdict (ELIGIBLE)" "$TMP/run1" \
  || { cat "$TMP/run1"; fail "the run did not say it recorded a verdict"; }
grep -q "VERDICT: ELIGIBLE" "$TMP/run1" \
  || fail "the wrapper swallowed the verifier's own transcript"

python3 - "$TMP/applied.json" "$CSHA" <<'PY'
import json, sys
cm = json.load(open(sys.argv[1]))
d = cm["data"]
assert cm["metadata"]["name"] == "vexa-verify-verdict", cm["metadata"]
assert cm["metadata"]["namespace"] == "vexa-production", cm["metadata"]
assert d["verdict"] == "ELIGIBLE", d
assert d["failed_checks"] == "0", d
assert d["contract_id"] == "internal-prod", d
assert d["contract_sha256"] == sys.argv[2], (d["contract_sha256"], sys.argv[2])
assert d["station"] == "vexa-prod", d
# 5 · the keys are the ones the collector reads and the schema names, and the
# values are unpadded — collectors.py passes contract_sha256 straight into a
# ^[0-9a-f]{64}$ field, so a trailing newline off `jq -r` would fail validation
# two systems away from here.
import re
assert re.fullmatch(r"[0-9a-f]{64}", d["contract_sha256"])
assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", d["checked_at"]), d["checked_at"]
assert d["release"] == "0.12.23-estate-20260825", d
# and the signed statement rides along verbatim
st = json.loads(d["verdict.json"])
assert st["predicateType"] == "https://vexa.ai/attestations/station-verdict/v1"
print("  3 OK  an ELIGIBLE run records the verdict, the contract and the statement")
print("  5 OK  the keys and value shapes are the ones collectors.py reads")
PY

# 4 · a FAILED run records its verdict AND still fails the gate
cat > "$TMP/bin/vexa-verify" <<'EOF'
#!/usr/bin/env bash
echo "FAIL  entry signature does NOT verify against the pinned channel key" >&2
echo "---"
echo "VERDICT: NOT ELIGIBLE — 3 check(s) failed" >&2
exit 1
EOF
chmod +x "$TMP/bin/vexa-verify"
rm -f "$TMP/applied.json" "$TMP/verdict.json"
set +e
sh -uc "$(cat "$TMP/script.sh")" vexa-verify-gate "${VERIFIER_ARGS[@]}" >"$TMP/run2" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$TMP/run2"; fail "a failed verification must still fail the PreSync gate, got rc=$rc"; }
[ -f "$TMP/applied.json" ] || { cat "$TMP/run2"; fail "a failed verification recorded nothing"; }
python3 - "$TMP/applied.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["data"]
assert d["verdict"] == "NOT_ELIGIBLE", d
# NOT_ELIGIBLE with an underscore: report.v1.schema.json's enum is
# ["ELIGIBLE", "NOT_ELIGIBLE", "ABSENT", "UNKNOWN"] and a bundle carrying
# anything else is refused at the edge.
assert d["failed_checks"] == "3", d
assert d["contract_id"] == "internal-prod", d
assert "verdict.json" not in d, "a failed run must carry no attestation"
print("  4 OK  a failed run records NOT_ELIGIBLE with its own count, and still exits 1")
PY

# 8 · the wrapper against the REAL verifier, not a stub of it
#
# Checks 3 and 4 pin the wrapper's own behaviour with the verifier's output
# reproduced by hand — which is exactly the transcription this whole change
# exists to abolish, one level down. So the last check runs the real
# vexa-verify.sh over the estate fixture, with only `oras` and `cosign`
# stubbed, as test_estate_verify.sh does: the verdict line the wrapper parses
# and the verdict.json it copies are then the real ones.
FIX="$HERE/fixtures"
cat > "$TMP/bin/oras" <<EOF
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
chmod +x "$TMP/bin/oras"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/cosign"; chmod +x "$TMP/bin/cosign"
printf '#!/usr/bin/env bash\nexec bash "%s/kit/verify/vexa-verify.sh" "$@"\n' "$REPO" \
  > "$TMP/bin/vexa-verify"; chmod +x "$TMP/bin/vexa-verify"
echo "-----BEGIN PUBLIC KEY-----fixture-----END PUBLIC KEY-----" > "$TMP/channel.pub"
echo '{"fixture": true}' > "$FIX/estate-entry/entry.json.sigstore.json"
trap 'rm -rf "$TMP"; rm -f "$FIX/estate-entry/entry.json.sigstore.json"' EXIT

real_run() {   # $1 = contract, $2 = output prefix
  VEXA_CONTRACT_FILE="$1" \
  sh -uc "$(cat "$TMP/script.sh")" vexa-verify-gate \
    --entry-ref "registry.invalid/vexa/channel/fixture-estate:0.0.1-estate-20260825" \
    --pubkey "$TMP/channel.pub" --policy "$1" --workdir "$TMP/wd-$2" \
    --station vexa-prod --verdict-out "$VEXA_VERDICT_FILE" >"$TMP/$2" 2>&1
}

rm -f "$TMP/applied.json" "$TMP/verdict.json"
set +e; real_run "$FIX/contracts/estate-ok.json" run4; rc=$?; set -e
[ "$rc" -eq 0 ] || { cat "$TMP/run4"; fail "the real eligible run did not pass through the wrapper"; }
python3 - "$TMP/applied.json" "$FIX/estate-entry/entry.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["data"]
entry = json.load(open(sys.argv[2]))
assert d["verdict"] == "ELIGIBLE", d
assert d["failed_checks"] == "0", d
assert d["release"] == entry["release"]["version"], (d["release"], entry["release"]["version"])
st = json.loads(d["verdict.json"])
assert st["predicate"]["station"] == "vexa-prod", st["predicate"]
assert st["predicate"]["contract_sha256"] == d["contract_sha256"], (st["predicate"], d)
print("  8 OK  the real verifier's own verdict reaches the ConfigMap, contract sha and all")
PY

rm -f "$TMP/applied.json" "$TMP/verdict.json"
set +e; real_run "$FIX/contracts/oss-shaped.json" run5; rc=$?; set -e
[ "$rc" -eq 1 ] || { cat "$TMP/run5"; fail "the real failing run did not fail the gate, rc=$rc"; }
python3 - "$TMP/applied.json" "$TMP/run5" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))["data"]
assert d["verdict"] == "NOT_ELIGIBLE", d
# The count is the verifier's own, off its own verdict line — this is the
# assertion that would break if that line were ever reworded.
want = re.search(r"NOT ELIGIBLE\D+(\d+) check", open(sys.argv[2]).read()).group(1)
assert d["failed_checks"] == want, (d["failed_checks"], want)
assert int(want) > 0
assert "verdict.json" not in d, "a failed run must carry no attestation"
print("  8b OK a real NOT ELIGIBLE run records the count the verifier printed")
PY

# and a verdict that cannot be recorded does not turn a good sync into a bad one
cat > "$TMP/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
echo "Error from server (Forbidden): configmaps is forbidden" >&2
exit 1
EOF
chmod +x "$TMP/bin/kubectl"
cat > "$TMP/bin/vexa-verify" <<'EOF'
#!/usr/bin/env bash
echo "VERDICT: ELIGIBLE — everything passed"
exit 0
EOF
chmod +x "$TMP/bin/vexa-verify"
set +e
sh -uc "$(cat "$TMP/script.sh")" vexa-verify-gate "${VERIFIER_ARGS[@]}" >"$TMP/run3" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { cat "$TMP/run3"; fail "an RBAC gap on the record failed a passing sync"; }
grep -q "WARN  could not record the verdict" "$TMP/run3" \
  || { cat "$TMP/run3"; fail "a failed recording was silent"; }
echo "  9 OK  a recording it cannot make warns loudly and fails nothing"

echo "test_verdict_wiring.sh: all checks passed"
