#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The kit scripts that talk to the channel registry (bootstrap, self-update,
# release) wrote the registry login, base64 user:password when VEXA_CHANNEL_*
# is set, to ${TMPDIR:-/tmp}/vexa-channel-dockercfg/config.json with the
# default umask, and never removed it: their EXIT trap removed only $WORK.
#
# Each runs here with TMPDIR set to an empty dir, a fake ~/.docker login and
# stub oras/cosign. The dir must be empty once the script is gone: after it
# fails, after a dry run finishes, and after SIGTERM or SIGHUP mid-run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/kit-dockercfg-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }

mkdir -p "$T/home/.docker" "$T/bin" "$T/tree"
printf '{"auths":{"reg.invalid":{"auth":"Zml4dHVyZTpub3QtYS1zZWNyZXQ="}},"credsStore":"desktop"}\n' \
  > "$T/home/.docker/config.json"
cat > "$T/bin/oras" <<'STUB'
#!/bin/sh
# fails at once; with STUB_READY set, records its pid and hangs, so a signal lands mid-run
if [ -n "${STUB_READY:-}" ]; then echo $$ > "$STUB_READY"; exec sleep 30; fi
exit 1
STUB
cp "$T/bin/oras" "$T/bin/cosign"
chmod +x "$T/bin/oras" "$T/bin/cosign"
cp "$ROOT/kit/self-update.sh" "$T/tree/"
printf 'registry=reg.invalid\nchannel=fixture\ndigest=sha256:%064d\n' 0 > "$T/tree/.kit-source"
: > "$T/tree/.kit-source.pub"
: > "$T/key.pub"
: > "$T/cosign.key"
export HOME="$T/home" PATH="$T/bin:$PATH"
export VEXA_CHANNEL_REGISTRY=reg.invalid VEXA_CHANNEL_USER=fixture VEXA_CHANNEL_PASS=fixture-not-a-secret

assert_empty() {
  local left
  left="$(cd "$1" && find . -mindepth 1 -maxdepth 2 | head -5)"
  [ -z "$left" ] || fail "$2 left this in TMPDIR: $left"
}

BOOTSTRAP=(bash "$ROOT/kit/bootstrap.sh" --registry reg.invalid --channel fixture --pubkey "$T/key.pub" --dest "$T/dest")

run_case() {
  local name=$1; shift
  mkdir "$T/tmp-$name"
  TMPDIR="$T/tmp-$name" "$@" > "$T/$name.log" 2>&1 || true
  assert_empty "$T/tmp-$name" "$name"
}
run_case bootstrap "${BOOTSTRAP[@]}"
run_case self-update bash "$T/tree/self-update.sh"
run_case release bash "$ROOT/kit/release.sh" --registry reg.invalid --channel fixture --version v0.0.1 \
  --sign-key "$T/cosign.key" --dry-run
grep -q "dry-run: would push" "$T/release.log" || fail "release.sh did not reach its dry run: $(tail -3 "$T/release.log")"

signal_case() {
  local sig=$1 ready="$T/ready-$1" pid
  mkdir "$T/tmp-$sig"
  TMPDIR="$T/tmp-$sig" STUB_READY="$ready" "${BOOTSTRAP[@]}" > "$T/$sig.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 300); do [ -s "$ready" ] && break; sleep 0.1; done
  [ -s "$ready" ] || { kill "$pid" 2>/dev/null; fail "bootstrap.sh never reached oras (SIG$sig)"; }
  kill -"$sig" "$pid"
  wait "$pid" || true
  kill -9 "$(cat "$ready")" 2>/dev/null || true
  assert_empty "$T/tmp-$sig" "bootstrap.sh on SIG$sig"
}
signal_case TERM
signal_case HUP
echo "ok: bootstrap, self-update and release leave nothing in TMPDIR (failure, dry run, SIGTERM, SIGHUP)"
