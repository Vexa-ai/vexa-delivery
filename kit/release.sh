#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# vexa-kit release — publisher side of the kit's own delivery path.
#
# The kit is what a customer runs inside their perimeter, so it must arrive the
# same way everything else does: as a versioned, signed OCI artifact on the
# channel registry, pulled and verified before a single byte is unpacked. This
# script packages the kit tree and pushes it; kit/bootstrap.sh is the customer
# end, kit/self-update.sh is the refresh.
#
# Nothing here is Vexa-specific magic: oras push + cosign sign, the same flags
# publisher/vexa_channel.py uses for channel entries.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_TYPE="application/vnd.vexa.kit"

usage() {
  cat <<EOF
usage: release.sh --registry <host[:port]> --channel <name> --version vX.Y.Z \\
                  --sign-key <cosign.key> [options]

required
  --registry     channel registry host[:port]
  --channel      channel name, e.g. acme-stable
  --version      kit version to publish, vX.Y.Z (semver, 'v' prefix required)
  --sign-key     cosign private key; the pushed digest is signed with it

options
  --source       kit tree to package        (default: this script's directory)
  --out          where to write the tarball (default: a temp dir)
  --no-latest    do not move the 'latest' channel tag to this version
  --insecure     registry TLS is self-signed (test rigs)
  --plain-http   registry is plain HTTP     (test rigs)
  --dry-run      package and print the push, push nothing
EOF
  exit 2
}

REGISTRY="" CHANNEL="" VERSION="" SIGN_KEY="" SOURCE="$HERE" OUT=""
LATEST=true INSECURE=false PLAIN_HTTP=false DRY_RUN=false

while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY=$2; shift 2;;
    --channel) CHANNEL=$2; shift 2;;
    --version) VERSION=$2; shift 2;;
    --sign-key) SIGN_KEY=$2; shift 2;;
    --source) SOURCE=$2; shift 2;;
    --out) OUT=$2; shift 2;;
    --no-latest) LATEST=false; shift;;
    --insecure) INSECURE=true; shift;;
    --plain-http) PLAIN_HTTP=true; shift;;
    --dry-run) DRY_RUN=true; shift;;
    *) usage;;
  esac
done
if [ -z "$REGISTRY" ] || [ -z "$CHANNEL" ] || [ -z "$VERSION" ] || [ -z "$SIGN_KEY" ]; then usage; fi
case "$VERSION" in
  v[0-9]*.[0-9]*.[0-9]*) :;;
  *) echo "release.sh: --version must look like vX.Y.Z (got '$VERSION')"; exit 2;;
esac
[ -f "$SIGN_KEY" ] || { echo "release.sh: no such signing key: $SIGN_KEY"; exit 2; }
[ -f "$SOURCE/install.sh" ] || { echo "release.sh: '$SOURCE' is not a kit tree (no install.sh)"; exit 2; }
command -v oras >/dev/null || { echo "release.sh: oras not on PATH"; exit 2; }
command -v cosign >/dev/null || { echo "release.sh: cosign not on PATH"; exit 2; }

PLAIN=()
$PLAIN_HTTP && PLAIN=(--plain-http)
[ ${#PLAIN[@]} -eq 0 ] && $INSECURE && PLAIN=(--insecure)
COSIGN_INSECURE=()
{ $PLAIN_HTTP || $INSECURE; } && COSIGN_INSECURE=(--allow-insecure-registry)

# Neutralize docker credential helpers exactly as publisher/vexa_channel.py's
# cosign_env() does: with Docker Desktop absent the configured credsStore hangs
# forever inside cosign's keychain lookup. Anonymous auth is correct here.
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
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/kit"
mkdir -p "$STAGE"

# 1 · package ------------------------------------------------------------------
# Ship what a customer runs; leave out our test scaffolding and build residue.
echo "== packaging $SOURCE -> kit-${VERSION}.tgz"
tar -cf - -C "$SOURCE" \
    --exclude 'preflight/tests' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude '.git' \
    --exclude '.kit-source' \
    --exclude '.kit-source.pub' \
    . | tar -xf - -C "$STAGE"

# The version marker is what self-update compares and what a support ticket
# quotes. It is written into the package, never into the repo.
cat > "$STAGE/VERSION" <<EOF
version=${VERSION}
channel=${CHANNEL}
built=$(date -u +%Y-%m-%dT%H:%M:%SZ)
artifact_type=${ARTIFACT_TYPE}
EOF

TARBALL_DIR="${OUT:-$WORK/out}"
mkdir -p "$TARBALL_DIR"
TARBALL_DIR="$(cd "$TARBALL_DIR" && pwd)"
TARBALL="$TARBALL_DIR/kit-${VERSION}.tgz"
# Deterministic-ish: sorted names, no owner/group noise. Reproducibility is not
# a claim we make yet, so this is hygiene rather than a guarantee.
tar -czf "$TARBALL" -C "$WORK" kit
echo "   $TARBALL ($(wc -c < "$TARBALL" | tr -d ' ') bytes)"

if $DRY_RUN; then
  echo "== dry-run: would push ${REF}:${VERSION} (artifact-type ${ARTIFACT_TYPE}) and sign its digest"
  exit 0
fi

# 2 · push ---------------------------------------------------------------------
echo "== oras push ${REF}:${VERSION}"
PUSH_OUT="$(cd "$TARBALL_DIR" && oras push ${PLAIN[@]+"${PLAIN[@]}"} \
  --artifact-type "$ARTIFACT_TYPE" \
  "${REF}:${VERSION}" "kit-${VERSION}.tgz")"
echo "$PUSH_OUT"
DIGEST="$(printf '%s\n' "$PUSH_OUT" | awk '/^Digest:/ {print $NF}')"
[ -n "$DIGEST" ] || { echo "release.sh: could not read pushed digest from oras output"; exit 1; }
echo "   digest $DIGEST"

# 3 · sign the digest ----------------------------------------------------------
# Same flag set as publisher/vexa_channel.py cmd_push: no transparency log, no
# signing config, legacy bundle format — the channel verifies against a pinned
# key offline, which is the whole point of an air-gappable delivery.
echo "== cosign sign ${REF}@${DIGEST}"
cosign sign --yes --key "$SIGN_KEY" \
  --new-bundle-format=false --use-signing-config=false --tlog-upload=false \
  ${COSIGN_INSECURE[@]+"${COSIGN_INSECURE[@]}"} \
  "${REF}@${DIGEST}"

# 4 · move the channel pointer -------------------------------------------------
if $LATEST; then
  oras tag ${PLAIN[@]+"${PLAIN[@]}"} "${REF}@${DIGEST}" latest >/dev/null
  echo "== latest -> ${DIGEST} (same-byte descriptor, so the signature carries)"
fi

cat <<EOF

released kit ${VERSION}
  ref     ${REF}:${VERSION}
  digest  ${DIGEST}
  bootstrap it with:
    curl -fsSL <kit-bootstrap-url> | bash -s -- \\
      --registry ${REGISTRY} --channel ${CHANNEL} --pubkey channel.pub$( $INSECURE && printf ' --insecure')
EOF
