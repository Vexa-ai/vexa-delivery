#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# vexa-kit bootstrap — the customer end of the kit's own conveyor.
#
# One command, no repo checkout: pull the signed kit artifact from the channel
# registry, VERIFY ITS SIGNATURE AGAINST YOUR PINNED KEY BEFORE ANYTHING IS
# UNPACKED, then unpack it. If the signature does not verify, nothing lands on
# disk — that ordering is the whole security property, so keep it.
#
#   curl -fsSL <url>/bootstrap.sh | bash -s -- \
#     --registry <host[:port]> --channel acme-stable --pubkey channel.pub
#
# Deliberately self-contained: it sources nothing from the kit it is about to
# fetch, because at the time it runs there is no kit. kit/self-update.sh is the
# refresh path and repeats the same pull-verify-unpack for the same reason.
set -euo pipefail

ARTIFACT_TYPE="application/vnd.vexa.kit"

usage() {
  cat <<EOF
usage: bootstrap.sh --registry <host[:port]> --channel <name> --pubkey <channel.pub> [options]

required
  --registry     channel registry host[:port]
  --channel      channel name, e.g. acme-stable
  --pubkey       cosign public key of the channel; the kit signature is checked
                 against THIS key and nothing else

options
  --version      kit version to fetch, vX.Y.Z (default: the 'latest' tag)
  --dest         where to unpack           (default: ./vexa-kit)
  --insecure     registry TLS is self-signed (test rigs)
  --plain-http   registry is plain HTTP     (test rigs)
  --keep-tarball keep the downloaded tarball next to --dest
EOF
  exit 2
}

REGISTRY="" CHANNEL="" PUBKEY="" VERSION="latest" DEST="./vexa-kit"
INSECURE=false PLAIN_HTTP=false KEEP=false

while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY=$2; shift 2;;
    --channel) CHANNEL=$2; shift 2;;
    --pubkey) PUBKEY=$2; shift 2;;
    --version) VERSION=$2; shift 2;;
    --dest) DEST=$2; shift 2;;
    --insecure) INSECURE=true; shift;;
    --plain-http) PLAIN_HTTP=true; shift;;
    --keep-tarball) KEEP=true; shift;;
    *) usage;;
  esac
done
if [ -z "$REGISTRY" ] || [ -z "$CHANNEL" ] || [ -z "$PUBKEY" ]; then usage; fi
[ -f "$PUBKEY" ] || { echo "bootstrap.sh: no such public key: $PUBKEY"; exit 2; }
command -v oras >/dev/null || { echo "bootstrap.sh: oras not on PATH (https://oras.land)"; exit 2; }
command -v cosign >/dev/null || { echo "bootstrap.sh: cosign not on PATH (https://sigstore.dev)"; exit 2; }

PUBKEY="$(cd "$(dirname "$PUBKEY")" && pwd)/$(basename "$PUBKEY")"
PLAIN=()
$PLAIN_HTTP && PLAIN=(--plain-http)
[ ${#PLAIN[@]} -eq 0 ] && $INSECURE && PLAIN=(--insecure)
COSIGN_INSECURE=()
{ $PLAIN_HTTP || $INSECURE; } && COSIGN_INSECURE=(--allow-insecure-registry)

# Same credential-helper neutralization as the publisher: a configured
# credsStore with no Docker Desktop behind it hangs cosign's keychain lookup
# forever. Anonymous auth is what a public channel pull uses anyway.
ISO_DOCKER_CONFIG="${TMPDIR:-/tmp}/vexa-channel-dockercfg"
mkdir -p "$ISO_DOCKER_CONFIG"
# Carry the credentials `oras login` already stored, minus the helper keys:
# blanking auths outright makes cosign UNAUTHORIZED against an authenticated
# channel registry, which is the enterprise shape (rehearsal 2026-08-24).
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
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1 · resolve the tag to a digest ----------------------------------------------
# Everything after this point is digest-addressed: the tag is only ever used to
# discover a digest, never to fetch bytes. A tag can be moved; a digest cannot.
echo "== resolving ${REF}:${VERSION}"
DIGEST="$(oras resolve ${PLAIN[@]+"${PLAIN[@]}"} "${REF}:${VERSION}" 2>/dev/null || true)"
DIGEST="$(printf '%s' "$DIGEST" | tr -d '[:space:]')"
case "$DIGEST" in
  sha256:*) :;;
  *) echo "bootstrap.sh: could not resolve ${REF}:${VERSION} on ${REGISTRY}"; exit 1;;
esac
echo "   digest ${DIGEST}"

# 2 · verify BEFORE unpacking ---------------------------------------------------
echo "== cosign verify ${REF}@${DIGEST} against $(basename "$PUBKEY")"
if ! cosign verify --key "$PUBKEY" \
      --insecure-ignore-tlog=true \
      ${COSIGN_INSECURE[@]+"${COSIGN_INSECURE[@]}"} \
      "${REF}@${DIGEST}" > "$WORK/verify.json" 2> "$WORK/verify.err"; then
  echo "SIGNATURE VERIFICATION FAILED — refusing to unpack anything."
  echo "  ref:    ${REF}@${DIGEST}"
  echo "  key:    ${PUBKEY}"
  sed -e 's/^/  cosign: /' "$WORK/verify.err" | tail -n 8
  exit 1
fi
echo "   signature OK"

# 3 · pull by digest ------------------------------------------------------------
mkdir -p "$WORK/pull"
oras pull ${PLAIN[@]+"${PLAIN[@]}"} "${REF}@${DIGEST}" -o "$WORK/pull" >/dev/null
TARBALL="$(find "$WORK/pull" -maxdepth 1 -name 'kit-*.tgz' | head -n 1)"
[ -n "$TARBALL" ] || { echo "bootstrap.sh: artifact ${DIGEST} carries no kit-*.tgz (expected ${ARTIFACT_TYPE})"; exit 1; }

# 4 · unpack --------------------------------------------------------------------
mkdir -p "$WORK/unpack"
tar -xzf "$TARBALL" -C "$WORK/unpack"
[ -f "$WORK/unpack/kit/install.sh" ] || { echo "bootstrap.sh: unpacked artifact is not a kit tree"; exit 1; }

# Provenance for the refresh path: self-update.sh needs to know which channel
# this tree came from and which key it must keep verifying against, and the key
# is copied in so a moved/deleted --pubkey cannot silently weaken later pulls.
cp "$PUBKEY" "$WORK/unpack/kit/.kit-source.pub"
cat > "$WORK/unpack/kit/.kit-source" <<EOF
registry=${REGISTRY}
channel=${CHANNEL}
ref=${REF}
digest=${DIGEST}
version=${VERSION}
insecure=${INSECURE}
plain_http=${PLAIN_HTTP}
bootstrapped=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
chmod +x "$WORK/unpack/kit/"*.sh 2>/dev/null || true

DEST_ABS="$(mkdir -p "$(dirname "$DEST")" && cd "$(dirname "$DEST")" && pwd)/$(basename "$DEST")"
if [ -e "$DEST_ABS" ]; then
  echo "bootstrap.sh: ${DEST_ABS} already exists — move it aside, or use kit/self-update.sh to refresh it"
  exit 1
fi
mv "$WORK/unpack/kit" "$DEST_ABS"
$KEEP && cp "$TARBALL" "$(dirname "$DEST_ABS")/"

RESOLVED_VERSION="$(sed -n 's/^version=//p' "$DEST_ABS/VERSION" 2>/dev/null || true)"
cat <<EOF

vexa-kit ${RESOLVED_VERSION:-$VERSION} unpacked to ${DEST_ABS}
  verified ${DIGEST} against $(basename "$PUBKEY") before unpacking

next
  1. conformance preflight against your cluster:
       python3 ${DEST_ABS}/preflight/vexa_preflight.py --namespace vexa-staging
  2. install the subscription:
       ${DEST_ABS}/install.sh --provider <name> --registry ${REGISTRY} \\
         --channel ${CHANNEL} --channel-pubkey ${DEST_ABS}/.kit-source.pub
  3. later, refresh the kit itself (verified pull, refuses on bad signature):
       ${DEST_ABS}/self-update.sh
EOF
