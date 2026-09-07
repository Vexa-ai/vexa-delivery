#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# vexa-verify.sh — a path typo must not wear the attack message (2026-09-07).
#
# The script chdirs into --workdir and only THEN resolves --pubkey and --policy.
# A relative path therefore missed silently, and the miss surfaced as
#
#     FAIL  entry signature does NOT verify against the pinned channel key
#     FAIL  revocation list signature does NOT verify against the pinned channel key
#
# because cosign had been handed a key file that was not there. The identical
# entry returned `Verified OK` by hand one command later. The script's own
# comment says a signature failure "says someone may be attacking you", which
# makes it the worst available message a mistyped path can produce — the
# subscriber's next move is to call their security team.
#
# What must hold:
#   1. a --pubkey that does not exist is named as a MISSING FILE, exit 2,
#      before any verification runs and with no signature language anywhere
#   2. the same for --policy: a contract that cannot be read is not an empty
#      contract, and must never become "checks that did not run"
#   3. a RELATIVE --pubkey/--policy works — resolved against the directory the
#      operator ran from, never against --workdir
#
# Offline: `oras` and `cosign` are stubbed exactly as in the sibling tests.
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

# The stub REFUSES when --key names a file that is not there, which is what the
# real cosign does. Without that this test would pass on a script that still
# resolves the key inside the workdir.
cat > "$TMP/cosign" <<'EOF'
#!/usr/bin/env bash
key=""
prev=""
for a in "$@"; do [ "$prev" = "--key" ] && key=$a; prev=$a; done
if [ -n "$key" ] && [ ! -f "$key" ]; then
  echo "error: open $key: no such file or directory" >&2; exit 1
fi
exit 0
EOF
chmod +x "$TMP/cosign"

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

# 1 · a missing --pubkey is a missing file, not a forged entry
set +e
OUT=$(bash "$VERIFY" --entry-ref "$REF" --pubkey channel.pub \
  --workdir "$TMP/wd" 2>&1); rc=$?
set -e
[ "$rc" -eq 2 ] || fail "a --pubkey that is not there should exit 2, got $rc"
echo "$OUT" | grep -q "pubkey file not found: channel.pub" \
  || fail "the refusal does not name the missing file and its path"
echo "$OUT" | grep -qi "signature" \
  && fail "a path error still speaks the language of a signature failure"
echo "$OUT" | grep -qi "attack" \
  && fail "a path error still speaks the language of an attack"
echo "$OUT" | grep -q "entry pulled" \
  && fail "it started verifying before checking that the key exists"
echo "  1 OK  a missing --pubkey is named as a path, before anything is verified"

# 2 · a missing --policy is a refusal, not an empty contract
set +e
OUT=$(bash "$VERIFY" --entry-ref "$REF" --pubkey "$TMP/channel.pub" \
  --policy contracts/nope.json --workdir "$TMP/wd" 2>&1); rc=$?
set -e
[ "$rc" -eq 2 ] || fail "a --policy that is not there should exit 2, got $rc"
echo "$OUT" | grep -q "policy file not found: contracts/nope.json" \
  || fail "the refusal does not name the missing contract"
echo "  2 OK  a missing --policy refuses instead of checking nothing"

# 3 · a RELATIVE --pubkey and --policy resolve against the caller's directory
mkdir -p "$TMP/caller"
cp "$TMP/channel.pub" "$TMP/caller/channel.pub"
cp "$FIX/contracts/estate-ok.json" "$TMP/caller/contract.json"
set +e
OUT=$(cd "$TMP/caller" && bash "$VERIFY" --entry-ref "$REF" \
  --pubkey channel.pub --policy contract.json --workdir "$TMP/wd3" 2>&1); rc=$?
set -e
echo "$OUT" | grep -q "does NOT verify against the pinned channel key" \
  && fail "a relative --pubkey still reads as a forged entry (rc=$rc)"
echo "$OUT" | grep -q "^--- contract: " \
  || fail "a relative --policy was not read as a contract at all"
echo "  3 OK  relative paths resolve against the directory the operator ran from"

echo "test_path_resolution.sh: all checks passed"
