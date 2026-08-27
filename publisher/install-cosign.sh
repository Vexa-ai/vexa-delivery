#!/usr/bin/env bash
# Install the cosign the publisher is pinned to, verified against the release's
# published checksum file, into a directory of your choosing.
#
# WHY A PIN. The signature LAYOUT cosign writes into a signature repository is
# not stable across its major versions. cosign 2.x writes the legacy tag
# `sha256-<digest>.sig`; cosign 3.x defaults to an OCI referrers index. Kyverno
# 1.19 — the version kit/providers pins — reads only the first, and reports the
# second as "no signatures found": a correctly signed image denied at admission
# with a message saying it is unsigned. cosign 3.x can still be made to write
# the legacy layout with --new-bundle-format=false, but 3.x has already marked
# that flag deprecated ("this will be the only supported format in future
# versions"), so it is not something to build a product promise on.
#
#   ./publisher/install-cosign.sh [dest-dir]
#   export COSIGN_BIN=<dest-dir>/cosign-2.6.5
#
# vexa_channel.py refuses to sign with anything outside the pinned series (T1)
# and then proves the result is readable the way Kyverno reads it (T2).
set -euo pipefail

VERSION=2.6.5
DEST=${1:-$HOME/.local/bin}

case "$(uname -s)" in
  Darwin) OS=darwin ;;
  Linux)  OS=linux ;;
  *) echo "install-cosign.sh: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64|amd64)  ARCH=amd64 ;;
  *) echo "install-cosign.sh: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

ASSET="cosign-${OS}-${ARCH}"
BASE="https://github.com/sigstore/cosign/releases/download/v${VERSION}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== downloading ${ASSET} v${VERSION}"
curl -fsSL -o "$TMP/$ASSET"        "$BASE/$ASSET"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/cosign_checksums.txt"

echo "== verifying checksum"
want=$(awk -v a="$ASSET" '$2 == a {print $1}' "$TMP/checksums.txt")
if [ -z "$want" ]; then
  echo "no checksum line for $ASSET in the release's checksum file" >&2
  exit 1
fi
if command -v sha256sum >/dev/null; then
  got=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
else
  got=$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')
fi
if [ "$want" != "$got" ]; then
  echo "checksum mismatch for $ASSET: want $want, got $got" >&2
  exit 1
fi

mkdir -p "$DEST"
install -m 0755 "$TMP/$ASSET" "$DEST/cosign-${VERSION}"
echo "== installed $DEST/cosign-${VERSION}"
"$DEST/cosign-${VERSION}" version | grep GitVersion

cat <<EOF

Point the publisher at it:

  export COSIGN_BIN=$DEST/cosign-${VERSION}

EOF
