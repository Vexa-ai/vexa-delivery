#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# kit/claim.sh and kit/install.sh --claim-code, against a FIXTURE EDGE and a
# STUB KUBECTL. Entirely offline: the edge is a local socket, the cluster is a
# log file, and no real credential exists anywhere in this run.
#
# The check that matters most is negative and easy to lose: THE CREDENTIAL MUST
# NEVER REACH STDOUT OR STDERR. Every assertion below that greps the captured
# output for the fixture password is checking the one property the whole design
# exists for, and it is the property a refactor breaks silently — an `echo` added
# while debugging leaves the value in the operator's scrollback and in whatever
# CI log captured it, and nothing fails.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
TMP=$(mktemp -d)
EDGE_PID=""
cleanup() {
  if [ -n "$EDGE_PID" ]; then
    kill "$EDGE_PID" 2>/dev/null || true
    # `wait` reaps it, so bash does not print its own "Terminated" notice after
    # the PASS line and make a clean run look like a crashed one.
    wait "$EDGE_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

# The value the fixture edge hands back. It is not a credential to anything; it
# is a needle, chosen to be greppable, so that a leak is a test failure rather
# than something a reviewer has to notice.
NEEDLE="PW-FIXTURE-NEVER-REAL"

fail() { echo "FAIL: $1" >&2; exit 1; }

# ---------------------------------------------------------------- fixture edge
# Answers exactly like edge/claim/claim_edge.py at the wire level: 200 with the
# credential for the one right code, and one indistinguishable 403 for anything
# else. It also COUNTS successful claims, which is how the dry-run check below
# proves a rehearsal does not spend a code.
cat > "$TMP/edge.py" <<PYEOF
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
CLAIMS = "$TMP/claims.count"

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n))
        except Exception:
            body = {}
        # The real edge normalises spaces and dashes away before it compares, so
        # the fixture does too: otherwise the kit could ship a code shape the
        # edge accepts and this test would not notice, or the reverse.
        typed = str(body.get("code", ""))
        ok = ("".join(ch for ch in typed if ch not in " -") == "123456"
              and body.get("station") == "pilot")
        if ok:
            with open(CLAIMS, "a") as fh:
                fh.write("1\n")
            payload = json.dumps({"station": "pilot", "username": "pilot",
                                  "password": "$NEEDLE"}).encode()
        else:
            payload = json.dumps({"error": "refused"}).encode()
        self.send_response(200 if ok else 403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass

s = HTTPServer(("127.0.0.1", 0), H)
print(s.server_address[1], flush=True)
s.serve_forever()
PYEOF

python3 "$TMP/edge.py" > "$TMP/port" &
EDGE_PID=$!
for _ in $(seq 1 100); do [ -s "$TMP/port" ] && break; sleep 0.05; done
PORT=$(cat "$TMP/port")
[ -n "$PORT" ] || fail "fixture edge did not start"
EDGE="http://127.0.0.1:$PORT/claim"

# ---------------------------------------------------------------- stub kubectl
# Logs every invocation and every manifest piped into it. It reads stdin ONLY
# for `apply -f -`: a stub that read stdin on every call blocks forever the
# first time the script runs a kubectl that pipes nothing.
#
# `get secret` answers from a marker file, so the "refuses unless --rotate"
# branch can be exercised in both directions without a cluster.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
echo "ARGV: $*" >> "$KUBECTL_LOG"
want_stdin=false
prev=""
for a in "$@"; do
  [ "$prev" = "-f" ] && [ "$a" = "-" ] && want_stdin=true
  prev="$a"
done
if $want_stdin; then { echo "--- manifest:"; cat; } >> "$KUBECTL_LOG"; fi
case "$*" in
  *"get secret"*) [ -f "$SECRET_EXISTS" ] && exit 0; exit 1;;
esac
for a in "$@"; do case "$a" in namespace) echo "kind: Namespace";; esac; done
exit 0
EOF
chmod +x "$TMP/bin/kubectl"
export PATH="$TMP/bin:$PATH"
export KUBECTL_LOG="$TMP/kubectl.log"
export SECRET_EXISTS="$TMP/secret-exists"

claim() { bash "$KIT/claim.sh" "$@" 2>&1; }
reset_log() { : > "$KUBECTL_LOG"; }

# 1 · the normal path: the Secret is written and the value never surfaces.
reset_log
OUT=$(claim --code 123456 --edge "$EDGE" --station pilot --namespace vexa-prod) \
  || fail "claim.sh refused a valid code"
echo "$OUT" | grep -q "$NEEDLE" && fail "THE CREDENTIAL REACHED STDOUT/STDERR"
echo "$OUT" | grep -q "claimed: station pilot" || fail "no receipt line"
echo "$OUT" | grep -q "vexa-station-credential" || fail "receipt does not name the Secret"
grep -q "kind: Secret" "$KUBECTL_LOG" || fail "no Secret manifest reached kubectl"
grep -q "name: vexa-station-credential" "$KUBECTL_LOG" || fail "wrong Secret name"
grep -q "$NEEDLE" "$KUBECTL_LOG" && fail "the manifest carried the value in PLAINTEXT"
# base64 of the needle: the value did land, and it landed encoded, from stdin.
NEEDLE_B64=$(printf '%s' "$NEEDLE" | base64 | tr -d '\n')
grep -q "password: $NEEDLE_B64" "$KUBECTL_LOG" \
  || fail "the Secret does not carry the claimed password"
# And it went in through STDIN, never argv — which is the whole point of not
# using `kubectl create secret --from-literal`.
grep "^ARGV:" "$KUBECTL_LOG" | grep -q "$NEEDLE_B64" \
  && fail "the credential appeared in kubectl's ARGUMENTS"

# 1b · the code is READ as `123 456`, so the space has to survive being typed.
#      Quoted, it is one argument and reaches the edge as `123 456`; the edge
#      normalises it away. Somebody will type it that way on the first call.
reset_log
OUT=$(claim --code "123 456" --edge "$EDGE" --station pilot --namespace vexa-prod) \
  || fail "claim.sh refused the code in the shape it is read aloud"
echo "$OUT" | grep -q "$NEEDLE" && fail "THE CREDENTIAL REACHED STDOUT/STDERR (spaced code)"
grep -q "password: $NEEDLE_B64" "$KUBECTL_LOG" \
  || fail "the spaced code wrote no credential"

# 2 · an existing Secret is a refusal, and --rotate is the way through.
touch "$SECRET_EXISTS"
reset_log
OUT=$(claim --code 123456 --edge "$EDGE" --station pilot --namespace vexa-prod) \
  && fail "claim.sh overwrote an existing Secret without --rotate"
echo "$OUT" | grep -q -- "--rotate" || fail "the refusal does not name the way through"
grep -q "kind: Secret" "$KUBECTL_LOG" && fail "it wrote a Secret while refusing"
# It must also refuse BEFORE spending the code: the check is knowable without
# claiming, and a spent-then-refused code costs a rotation for nothing.
BEFORE=$(wc -l < "$TMP/claims.count")
reset_log
claim --code 123456 --edge "$EDGE" --station pilot --namespace vexa-prod >/dev/null 2>&1 || true
[ "$(wc -l < "$TMP/claims.count")" -eq "$BEFORE" ] \
  || fail "the refused run spent the claim code anyway"

reset_log
OUT=$(claim --code 123456 --edge "$EDGE" --station pilot --namespace vexa-prod --rotate) \
  || fail "--rotate did not proceed over an existing Secret"
echo "$OUT" | grep -q "$NEEDLE" && fail "THE CREDENTIAL REACHED STDOUT/STDERR (--rotate)"
grep -q "password: $NEEDLE_B64" "$KUBECTL_LOG" || fail "--rotate wrote no credential"
rm -f "$SECRET_EXISTS"

# 3 · --print-once: the ONE path that prints, and it warns first.
reset_log
OUT=$(claim --code 123456 --edge "$EDGE" --station pilot --print-once) \
  || fail "--print-once failed"
echo "$OUT" | grep -q "pilot:$NEEDLE" || fail "--print-once printed no credential"
echo "$OUT" | grep -qi "WARNING" || fail "--print-once printed no warning line"
echo "$OUT" | grep -qi "spent" || fail "the warning does not say the code is spent"
grep -q "kind: Secret" "$KUBECTL_LOG" && fail "--print-once also wrote a Secret"

# 4 · --print-once and --namespace are one code, two deliveries: refuse.
OUT=$(claim --code 123456 --edge "$EDGE" --station pilot --print-once \
        --namespace vexa-prod) && fail "--print-once with --namespace was accepted"
echo "$OUT" | grep -qi "pick one" || fail "the refusal does not say to pick one"

# 5 · a wrong code: non-zero, generic, and it names no reason it cannot know.
reset_log
OUT=$(claim --code 222222 --edge "$EDGE" --station pilot --namespace vexa-prod) \
  && fail "a wrong code was accepted"
echo "$OUT" | grep -q "refused" || fail "no refusal message"
echo "$OUT" | grep -q "$NEEDLE" && fail "a refusal leaked the credential"
grep -q "kind: Secret" "$KUBECTL_LOG" && fail "a refused claim wrote a Secret"

# 6 · --dry-run contacts nothing, so a rehearsal cannot spend the code.
BEFORE=$(wc -l < "$TMP/claims.count")
reset_log
OUT=$(claim --code 123456 --edge "$EDGE" --station pilot --namespace vexa-prod --dry-run) \
  || fail "--dry-run failed"
echo "$OUT" | grep -q "dry run" || fail "--dry-run said nothing about being one"
[ "$(wc -l < "$TMP/claims.count")" -eq "$BEFORE" ] || fail "--dry-run SPENT the code"
[ -s "$KUBECTL_LOG" ] && fail "--dry-run talked to kubectl"

# 7 · install.sh --claim-code end to end: same credential everywhere it is
#     needed, the station Secret written, and nothing on the terminal.
reset_log
echo "test-key-placeholder" > "$TMP/channel.pub"
OUT=$(bash "$KIT/install.sh" --provider lke --registry reg.example:5000 \
        --channel pilot --channel-pubkey "$TMP/channel.pub" --skip-preflight \
        --claim-code 123456 --claim-edge "$EDGE" --station pilot 2>&1) \
  || fail "install.sh --claim-code failed"
echo "$OUT" | grep -q "$NEEDLE" && fail "install.sh PRINTED THE CREDENTIAL"
echo "$OUT" | grep -q "the code is now spent" || fail "install.sh did not report the claim"
grep -q "name: vexa-station-credential" "$KUBECTL_LOG" \
  || fail "install.sh wrote no station credential Secret"
grep -q "password: $NEEDLE_B64" "$KUBECTL_LOG" \
  || fail "the station Secret carries no claimed password"
# The claimed credential is also what the registry secrets get: without this the
# subscription 401s and the Application never leaves Unknown.
grep -q "username: pilot" "$KUBECTL_LOG" || fail "Argo repo secret got no username"
grep -q "password: $NEEDLE" "$KUBECTL_LOG" \
  || fail "Argo repo secret got no claimed password"

# 8 · install.sh --claim-code --dry-run: no exchange, no spent code.
BEFORE=$(wc -l < "$TMP/claims.count")
reset_log
OUT=$(bash "$KIT/install.sh" --provider lke --registry reg.example:5000 \
        --channel pilot --channel-pubkey "$TMP/channel.pub" --skip-preflight \
        --dry-run --claim-code 123456 --claim-edge "$EDGE" --station pilot 2>&1) \
  || fail "install.sh --claim-code --dry-run failed"
[ "$(wc -l < "$TMP/claims.count")" -eq "$BEFORE" ] \
  || fail "install.sh --dry-run SPENT the claim code"
echo "$OUT" | grep -q "NOT spent" || fail "the dry run did not say the code was kept"

# 9 · --registry-user and --claim-code are the same credential twice: refuse.
OUT=$(VEXA_CHANNEL_PASS=x bash "$KIT/install.sh" --provider lke \
        --registry reg.example:5000 --channel pilot --channel-pubkey "$TMP/channel.pub" \
        --skip-preflight --dry-run --registry-user pilot --claim-code 123456 2>&1) \
  && fail "install.sh accepted both credential routes at once"
echo "$OUT" | grep -q "Pass one" || fail "the refusal does not say to pass one"

echo "PASS: kit claim (secret written, value never on stdout, six digits spaced or not, rotate gate, print-once, refusal, dry-run, install.sh --claim-code)"
