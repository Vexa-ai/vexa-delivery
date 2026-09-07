#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# install.sh: the two writes that reached a surface they do not own (2026-09-07).
#
# Both were found by the entry-5 station install and both are silent — the run
# succeeds, and what it destroyed is visible only from outside it.
#
#   1. THE NAMESPACE IT DID NOT CREATE. `ensure_namespace` applied a bare
#      Namespace unconditionally. Against a project pre-created by a platform
#      team — the documented pilot shape — the three-way merge PRUNED the PSA
#      labels and the SCC annotations down to `kubernetes.io/metadata.name`, and
#      preflight P4 then returned PASS because admission had become permissive.
#      Create-only is the fix: a namespace that already exists is not written to.
#
#   2. THE CONTRACT IT RE-SERIALIZED. The ConfigMap was written through
#      `json.dumps(yaml.safe_load(file))`, so the in-cluster gate hashed 617
#      bytes where the ledger record holds 757, and the recorded verdict named a
#      contract sha nothing else could match. A JSON contract now goes in
#      verbatim; a YAML one is converted AND both shas are recorded.
#
# Offline: a logging stub kubectl IS the cluster, and it captures the stdin of
# every `apply -f -`, so what is asserted is what the installer actually wrote.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/kubectl" <<'EOF'
#!/usr/bin/env bash
# Logs the invocation, and — for `apply -f -` — the object stream it was fed.
printf '%s\n' "$*" >> "$KUBECTL_LOG"
case "$*" in
  *"apply -f -"*) cat >> "$APPLIED"; exit 0;;
esac
case "$*" in
  *"get namespace"*)
      if [ -n "${STUB_NS_EXISTS:-}" ]; then exit 0; fi
      echo 'Error from server (NotFound): namespaces "x" not found' >&2; exit 1;;
  *"create namespace"*) echo "kind: Namespace"; exit 0;;
  *"create configmap"*)
      # Record the file the installer says is the contract, verbatim, so the
      # test can hash the bytes that would have gone into the ConfigMap.
      for a in "$@"; do
        case "$a" in
          --from-file=contract.json=*) cp "${a#*contract.json=}" "$CM_CAPTURE";;
          --from-literal=*) printf '%s\n' "${a#--from-literal=}" >> "$CM_LITERALS";;
        esac
      done
      echo "kind: ConfigMap"; exit 0;;
  *"create secret"*) echo "kind: Secret"; exit 0;;
  *"get deploy "*"-o jsonpath"*) exit 0;;
esac
exit 0
EOF
chmod +x "$TMP/kubectl"
export PATH="$TMP:$PATH"
echo "test-key-placeholder" > "$TMP/channel.pub"

fail() {
  echo "FAIL: $1" >&2
  [ -n "${OUT:-}" ] && printf '%s\n' "$OUT" | sed 's/^/    out| /' >&2
  [ -f "${KUBECTL_LOG:-}" ] && sed 's/^/    log| /' "$KUBECTL_LOG" >&2
  exit 1
}

run() {
  KUBECTL_LOG="$TMP/log.$RANDOM"; APPLIED="$TMP/applied.$RANDOM"
  CM_CAPTURE="$TMP/cm.$RANDOM"; CM_LITERALS="$TMP/lit.$RANDOM"
  export KUBECTL_LOG APPLIED CM_CAPTURE CM_LITERALS
  : > "$KUBECTL_LOG"; : > "$APPLIED"; : > "$CM_LITERALS"
  set +e
  OUT=$(bash "$KIT/install.sh" --provider lke --registry reg.example:5000 \
    --channel acme-stable --channel-pubkey "$TMP/channel.pub" \
    --skip-preflight --argocd skip --kyverno skip "$@" 2>&1)
  RC=$?
  set -e
}

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# 1 · A PRE-CREATED NAMESPACE IS NOT TOUCHED ----------------------------------
STUB_NS_EXISTS=1 run
[ "$RC" -eq 0 ] || fail "install.sh exited $RC against a pre-created namespace"
grep -q "create namespace" "$KUBECTL_LOG" \
  && fail "it rendered a Namespace for a namespace that already exists"
grep -q "^kind: Namespace" "$APPLIED" \
  && fail "it APPLIED a Namespace object over a namespace it did not create"
echo "$OUT" | grep -q "already exists — NOT touched" \
  || fail "the run did not say it was leaving the existing namespace alone"
# ...and it still did the rest of its job in that namespace.
grep -q "^kind: ConfigMap" "$APPLIED" || fail "the contract ConfigMap was not applied"
echo "  1 OK  a pre-created namespace is neither rendered nor applied over"

# 2 · A NAMESPACE THAT IS ABSENT IS STILL CREATED ------------------------------
run
[ "$RC" -eq 0 ] || fail "install.sh exited $RC on a greenfield namespace"
grep -q "create namespace" "$KUBECTL_LOG" \
  || fail "a namespace that does not exist was not created"
grep -q "^kind: Namespace" "$APPLIED" || fail "the created Namespace was not applied"
echo "  2 OK  an absent namespace is created, exactly as before"

# 3 · A JSON CONTRACT GOES IN BYTE-FOR-BYTE ------------------------------------
# The bytes the gate hashes must be the bytes the ledger holds. Trailing newline
# included: the 2026-08-29 station lost a verdict to one `0a` on the other write
# path, and this is that path.
printf '{\n  "contract_id": "byte-for-byte",\n  "carriage": {"require_publication_mode": "candidate"}\n}\n' \
  > "$TMP/contract.json"
WANT=$(sha_of "$TMP/contract.json")
STUB_NS_EXISTS=1 run --contract "$TMP/contract.json"
[ "$RC" -eq 0 ] || fail "install.sh exited $RC with a JSON contract"
GOT=$(sha_of "$CM_CAPTURE")
[ "$WANT" = "$GOT" ] \
  || fail "the contract was re-serialized: source sha256 $WANT, ConfigMap sha256 $GOT"
cmp -s "$TMP/contract.json" "$CM_CAPTURE" || fail "the mounted contract is not the source bytes"
echo "$OUT" | grep -q "contract.json sha256:$WANT" \
  || fail "the run did not print the sha the verdict will name ($WANT)"
echo "$OUT" | grep -q "verbatim" || fail "a JSON contract should be reported as mounted verbatim"
grep -q "^contract.sha256=$WANT$" "$CM_LITERALS" \
  || fail "the ConfigMap does not record its own contract sha"
echo "  3 OK  a JSON contract is mounted verbatim and its sha is printed"

# 4 · A YAML CONTRACT IS CONVERTED, AND BOTH SHAS ARE RECORDED -----------------
printf 'contract_id: yaml-shaped\ncarriage:\n  require_publication_mode: candidate\n' \
  > "$TMP/contract.yaml"
SRC=$(sha_of "$TMP/contract.yaml")
STUB_NS_EXISTS=1 run --contract "$TMP/contract.yaml"
[ "$RC" -eq 0 ] || fail "install.sh exited $RC with a YAML contract"
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$CM_CAPTURE" \
  || fail "the YAML contract was not converted to JSON for the gate"
CONV=$(sha_of "$CM_CAPTURE")
[ "$SRC" != "$CONV" ] || fail "impossible: the YAML and its JSON hash the same"
grep -q "^contract.source.sha256=$SRC$" "$CM_LITERALS" \
  || fail "the source YAML's sha is not recorded beside the converted document"
grep -q "^contract.sha256=$CONV$" "$CM_LITERALS" \
  || fail "the converted document's sha is not recorded"
echo "$OUT" | grep -q "both shas recorded" \
  || fail "the run did not say a conversion happened"
echo "  4 OK  a YAML contract is converted and BOTH shas are recorded"

echo "PASS: install.sh namespace (create-only) + contract (bytes the ledger holds)"
