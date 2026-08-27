#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# vexa-kit self-update — refresh an already-bootstrapped kit tree.
#
# Re-pulls the channel pointer, verifies the signature against the key this
# tree was bootstrapped with, and only then swaps the tree — atomically, so a
# failure anywhere leaves the working kit exactly as it was. Refuses on a
# signature failure, on a missing key, and on a tree it cannot identify.
#
# Same pull-verify-unpack order as kit/bootstrap.sh, and deliberately the same
# code shape rather than a shared library: bootstrap must stay curl-able with
# no kit on disk, so the two cannot share a file.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
usage: self-update.sh [options]     (run it from inside a bootstrapped kit tree)

options
  --version      version to move to, vX.Y.Z (default: the 'latest' tag)
  --pubkey       override the pinned key    (default: .kit-source.pub in this tree)
  --registry     override the recorded registry
  --channel      override the recorded channel
  --check        report what an update would do; change nothing
  --insecure     registry TLS is self-signed (test rigs)
  --plain-http   registry is plain HTTP     (test rigs)
EOF
  exit 2
}

SRC="$HERE/.kit-source"
[ -f "$SRC" ] || {
  echo "self-update.sh: no .kit-source in ${HERE} — this tree was not bootstrapped from a channel."
  echo "  Use kit/bootstrap.sh to install a verified tree first."
  exit 2
}
# shellcheck disable=SC1090
. "$SRC"

VERSION="latest" PUBKEY="$HERE/.kit-source.pub" CHECK=false
INSECURE=${insecure:-false} PLAIN_HTTP=${plain_http:-false}
REGISTRY=${registry:-} CHANNEL=${channel:-}
CURRENT_DIGEST=${digest:-unknown}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION=$2; shift 2;;
    --pubkey) PUBKEY=$2; shift 2;;
    --registry) REGISTRY=$2; shift 2;;
    --channel) CHANNEL=$2; shift 2;;
    --check) CHECK=true; shift;;
    --insecure) INSECURE=true; shift;;
    --plain-http) PLAIN_HTTP=true; shift;;
    *) usage;;
  esac
done
if [ -z "$REGISTRY" ] || [ -z "$CHANNEL" ]; then echo "self-update.sh: .kit-source names no registry/channel"; exit 2; fi
[ -f "$PUBKEY" ] || { echo "self-update.sh: pinned key missing: $PUBKEY — refusing to update unverified"; exit 2; }
command -v oras >/dev/null || { echo "self-update.sh: oras not on PATH"; exit 2; }
command -v cosign >/dev/null || { echo "self-update.sh: cosign not on PATH"; exit 2; }

PUBKEY="$(cd "$(dirname "$PUBKEY")" && pwd)/$(basename "$PUBKEY")"
PLAIN=()
[ "$PLAIN_HTTP" = true ] && PLAIN=(--plain-http)
[ ${#PLAIN[@]} -eq 0 ] && [ "$INSECURE" = true ] && PLAIN=(--insecure)
COSIGN_INSECURE=()
{ [ "$PLAIN_HTTP" = true ] || [ "$INSECURE" = true ]; } && COSIGN_INSECURE=(--allow-insecure-registry)

ISO_DOCKER_CONFIG="${TMPDIR:-/tmp}/vexa-channel-dockercfg"
mkdir -p "$ISO_DOCKER_CONFIG"
# Carry the credentials `oras login` already stored, minus the helper keys:
# blanking auths outright makes cosign UNAUTHORIZED against an authenticated
# channel registry, which is the common shape (rehearsal 2026-08-24).
python3 - "$HOME/.docker/config.json" > "$ISO_DOCKER_CONFIG/config.json" <<'PYCFG'
import base64, json, os, sys
try:
    auths = json.load(open(sys.argv[1])).get("auths") or {}
except Exception:
    auths = {}
auths = {k: v for k, v in auths.items() if isinstance(v, dict) and v.get("auth")}
host, user, pw = (os.environ.get(k) for k in
                  ("VEXA_CHANNEL_REGISTRY", "VEXA_CHANNEL_USER", "VEXA_CHANNEL_PASS"))
if host and user and pw:
    auths[host] = {"auth": base64.b64encode(f"{user}:{pw}".encode()).decode()}
json.dump({"auths": auths}, sys.stdout)
PYCFG
export DOCKER_CONFIG="$ISO_DOCKER_CONFIG"
export COSIGN_PASSWORD="${COSIGN_PASSWORD-}"

REF="${REGISTRY}/vexa/channel/${CHANNEL}/kit"
CURRENT_VERSION="$(sed -n 's/^version=//p' "$HERE/VERSION" 2>/dev/null || echo unknown)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== current: ${CURRENT_VERSION} (${CURRENT_DIGEST})"
echo "== resolving ${REF}:${VERSION}"
DIGEST="$(oras resolve ${PLAIN[@]+"${PLAIN[@]}"} "${REF}:${VERSION}" 2>/dev/null || true)"
DIGEST="$(printf '%s' "$DIGEST" | tr -d '[:space:]')"
case "$DIGEST" in
  sha256:*) :;;
  *) echo "self-update.sh: could not resolve ${REF}:${VERSION}"; exit 1;;
esac
echo "   digest ${DIGEST}"

if [ "$DIGEST" = "$CURRENT_DIGEST" ]; then
  echo "already at ${DIGEST} — nothing to do."
  exit 0
fi

# Verify before the new bytes are allowed anywhere near the live tree.
echo "== cosign verify ${REF}@${DIGEST} against $(basename "$PUBKEY")"
if ! cosign verify --key "$PUBKEY" \
      --insecure-ignore-tlog=true \
      ${COSIGN_INSECURE[@]+"${COSIGN_INSECURE[@]}"} \
      "${REF}@${DIGEST}" > "$WORK/verify.json" 2> "$WORK/verify.err"; then
  echo "SIGNATURE VERIFICATION FAILED — kit NOT updated; the existing tree is untouched."
  echo "  ref: ${REF}@${DIGEST}"
  echo "  key: ${PUBKEY}"
  sed -e 's/^/  cosign: /' "$WORK/verify.err" | tail -n 8
  exit 1
fi
echo "   signature OK"

if $CHECK; then
  echo "update available: ${CURRENT_VERSION} (${CURRENT_DIGEST}) -> ${DIGEST}  [--check: nothing written]"
  exit 0
fi

mkdir -p "$WORK/pull"
oras pull ${PLAIN[@]+"${PLAIN[@]}"} "${REF}@${DIGEST}" -o "$WORK/pull" >/dev/null
TARBALL="$(find "$WORK/pull" -maxdepth 1 -name 'kit-*.tgz' | head -n 1)"
[ -n "$TARBALL" ] || { echo "self-update.sh: artifact ${DIGEST} carries no kit-*.tgz; tree untouched"; exit 1; }

mkdir -p "$WORK/unpack"
tar -xzf "$TARBALL" -C "$WORK/unpack"
[ -f "$WORK/unpack/kit/install.sh" ] || { echo "self-update.sh: unpacked artifact is not a kit tree; tree untouched"; exit 1; }

NEW_VERSION="$(sed -n 's/^version=//p' "$WORK/unpack/kit/VERSION" 2>/dev/null || echo unknown)"
cp "$PUBKEY" "$WORK/unpack/kit/.kit-source.pub"
cat > "$WORK/unpack/kit/.kit-source" <<EOF
registry=${REGISTRY}
channel=${CHANNEL}
ref=${REF}
digest=${DIGEST}
version=${VERSION}
insecure=${INSECURE}
plain_http=${PLAIN_HTTP}
bootstrapped=${bootstrapped:-unknown}
updated=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
chmod +x "$WORK/unpack/kit/"*.sh 2>/dev/null || true

# Anything a customer put in the tree that we do not ship — their values file,
# their contract — survives the swap. We replace what we delivered, not what
# they wrote.
if [ -e "$HERE/.kit-local" ]; then
  cp -R "$HERE/.kit-local" "$WORK/unpack/kit/"
fi

# Atomic swap: stage the new tree next to the old one on the same filesystem,
# then two renames. A crash between them leaves .kit-previous to fall back to.
PARENT="$(dirname "$HERE")"
BASE="$(basename "$HERE")"
STAGED="$PARENT/.${BASE}.new.$$"
PREVIOUS="$PARENT/.${BASE}.previous"
rm -rf "$STAGED" "$PREVIOUS"
mv "$WORK/unpack/kit" "$STAGED"
mv "$HERE" "$PREVIOUS"
mv "$STAGED" "$HERE"
rm -rf "$PREVIOUS"

echo
echo "kit updated: ${CURRENT_VERSION} -> ${NEW_VERSION}"
echo "  digest  ${DIGEST}"
echo "  tree    ${HERE}"
