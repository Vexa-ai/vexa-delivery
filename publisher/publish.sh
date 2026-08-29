#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
#
# publish.sh — RUNBOOK § 1, as one command. Driven by `make publish`.
#
# WHAT IT IS: packaging. The manual crank was eight commands, and eight chances
# to mistype a flag on a step whose failure mode is a signature layout nobody
# notices for a month. This runs the same four verbs, in the same order, with
# the same flags:
#
#     fetch  ->  build  ->  sign-images  ->  push
#
# WHAT IT IS NOT: a weakening. Every check inside those verbs still runs and
# still refuses — C1..C9 in build, T1/T2 in sign-images and push, the ledger
# write that makes push the sole writer of channel.yaml. This script adds no
# flag that skips anything, and there is no --force.
#
# CREDENTIALS DO NOT MOVE (ADR-0001 § 6: no production credentials in this repo
# or its CI). The signing key stays wherever the human runner keeps it; this
# script reads the same environment the manual steps read, passes the PATH
# along, and never reads, copies, prints or caches the key. An unset variable is
# a refusal that names the variable — not a default, and not a silent skip.
#
# DRY_RUN=1 resolves everything, runs every environment check, prints the exact
# chain, and EXECUTES NOTHING. The build command it prints carries
# --publication-mode dry_run, so a chain copied out of a dry run cannot publish
# by accident. It is the preflight: does my environment have what a crank needs,
# and what exactly is about to run.
set -eu

PUB="$(cd "$(dirname "$0")" && pwd)"
CHANNEL_PY="$PUB/vexa_channel.py"

CHANNEL=${CHANNEL:-vexa-internal}
SUPERSEDES=${SUPERSEDES:-none}
PUBLICATION_MODE=${PUBLICATION_MODE:-candidate}
SIGNING_MODE=${SIGNING_MODE:-cosign_key}
VEXA_RELEASE_REPO=${VEXA_RELEASE_REPO:-Vexa-ai/vexa}
DRY_RUN=${DRY_RUN:-}
DELIVERY_RECEIPT=${DELIVERY_RECEIPT:-}
APPROVED_BY=${APPROVED_BY:-}
APPROVAL_RECEIPT=${APPROVAL_RECEIPT:-}
CHANNEL_TAG=${CHANNEL_TAG:-}
EXTRA_EVIDENCE=${EXTRA_EVIDENCE:-}
SIGNING_RECEIPT=${SIGNING_RECEIPT:-}
RELEASE=${RELEASE:-}
ENTRY_SEQ=${ENTRY_SEQ:-}

# DRY_RUN=0 must mean OFF. A make variable that is present-but-false is exactly
# how a "dry run" publishes for real.
case "$DRY_RUN" in 0|false|no|off) DRY_RUN="" ;; esac

die() { echo "publish: $1" >&2; exit 2; }

# One message shape for every missing input, and it always names the variable
# and says where the value lives. "KeyError: VEXA_CHANNEL_KEY" at step four of a
# crank is the failure this exists to prevent.
need_var() {
  eval "_v=\${$1:-}"
  [ -n "$_v" ] || die "\$$1 is not set — $2"
}

[ -n "$RELEASE" ] || die "RELEASE is not set: make publish RELEASE=vX.Y.Z ENTRY_SEQ=N"
[ -n "$ENTRY_SEQ" ] || die "ENTRY_SEQ is not set. The ledger is the authority for it: \`python3 publisher/vexa_stations.py --ledger \$VEXA_STATIONS_DIR show\` prints the channel's current entry_seq — pass the next one. It is not derived here, because a rollback floor a script guessed is a rollback floor nobody chose."

need_var VEXA_REPO "the Vexa-ai/vexa checkout the release tag is read from (C1)"
need_var VEXA_CHANNEL_REF "the channel's registry repository, e.g. channel.vexa.ai/vexa/channel/$CHANNEL"
need_var VEXA_SIGNATURE_REPOSITORY "where cosign writes sha256-<digest>.sig — the exact repository Kyverno asks for (T2)"
need_var VEXA_CHANNEL_KEY "path to the channel signing key. It stays with you: this script passes the path to cosign and never reads, copies or prints the key (ADR-0001 § 6)"
need_var VEXA_SIGNING_IDENTITY "the signing identity the entry DECLARES, e.g. the key fingerprint"
need_var VEXA_STATIONS_DIR "checkout of the vexa-stations ledger — push writes channels/$CHANNEL/channel.yaml there, and that file is the authority for entry_seq"

command -v python3 >/dev/null || die "python3 is not on PATH"

case "$PUBLICATION_MODE" in
  published)
    [ -n "$APPROVED_BY" ] || die "PUBLICATION_MODE=published requires APPROVED_BY — the publication half of the approval is a NAMED human (RUNBOOK § 2.3)"
    [ -n "$APPROVAL_RECEIPT" ] || die "PUBLICATION_MODE=published requires APPROVAL_RECEIPT — where that approval is recorded"
    [ -n "$DELIVERY_RECEIPT" ] || die "PUBLICATION_MODE=published requires DELIVERY_RECEIPT — build cross-checks the entry against our own prod run (C3..C5)"
    ;;
  candidate|dry_run) ;;
  *) die "PUBLICATION_MODE must be dry_run, candidate or published (got '$PUBLICATION_MODE')" ;;
esac

WORK=${WORK:-work/$RELEASE}
IN="$WORK/in"
ENTRY="$WORK/entry"
ARCHIVE="$IN/vexa-core-$RELEASE.tar.gz"

# In a dry run the entry is never built, so the mode the printed build command
# carries must be the one a dry run means — never the operator's real one.
BUILD_MODE=$PUBLICATION_MODE
if [ -n "$DRY_RUN" ]; then
  BUILD_MODE=dry_run
fi

# --- the chain -------------------------------------------------------------
# Each step goes through `step`, so the dry run prints exactly what the real run
# executes: one definition, two behaviours, and no second list to drift.
step() {
  echo "--- $1"
  shift
  if [ -n "$DRY_RUN" ]; then
    printf '   '
    for _a in "$@"; do printf ' %s' "$_a"; done
    printf '\n'
  else
    "$@"
  fi
}

echo "publish: $RELEASE -> channel $CHANNEL, entry_seq $ENTRY_SEQ, mode $BUILD_MODE${DRY_RUN:+ (DRY RUN — nothing executes)}"
echo "         work $WORK · ref $VEXA_CHANNEL_REF · ledger $VEXA_STATIONS_DIR"

step "1/4 fetch — the only step that reaches the network" \
  python3 "$CHANNEL_PY" fetch --release "$RELEASE" --repo "$VEXA_RELEASE_REPO" --out "$IN"

set -- python3 "$CHANNEL_PY" build \
  --release "$RELEASE" --channel "$CHANNEL" --entry-seq "$ENTRY_SEQ" \
  --supersedes "$SUPERSEDES" --vexa-repo "$VEXA_REPO" \
  --archive "$ARCHIVE" \
  --provenance-bundle "$IN/source-provenance.sigstore.json" \
  --trusted-root "$IN/trusted-root.jsonl" \
  --identity "$VEXA_SIGNING_IDENTITY" --signing-mode "$SIGNING_MODE" \
  --publication-mode "$BUILD_MODE" --out "$ENTRY"
if [ -n "$DELIVERY_RECEIPT" ]; then set -- "$@" --delivery-receipt "$DELIVERY_RECEIPT"; fi
if [ -n "$APPROVED_BY" ]; then set -- "$@" --approved-by "$APPROVED_BY"; fi
if [ -n "$APPROVAL_RECEIPT" ]; then set -- "$@" --approval-receipt "$APPROVAL_RECEIPT"; fi
# EXTRA_EVIDENCE is a space-separated list of kind=name=path. The station gate
# report goes in here, which is how a per-release guarantee document reaches the
# signed entry (RUNBOOK § 1.4).
# shellcheck disable=SC2086
for _e in $EXTRA_EVIDENCE; do set -- "$@" --extra-evidence "$_e"; done
step "2/4 build — C1..C9 refuse here, exit 3" "$@"

step "3/4 sign-images — T1 pins the cosign that signs, T2 proves the layout" \
  python3 "$CHANNEL_PY" sign-images \
  --candidate-map "$ENTRY/evidence/candidate-images.json" \
  --key "$VEXA_CHANNEL_KEY" --signature-repository "$VEXA_SIGNATURE_REPOSITORY"

set -- python3 "$CHANNEL_PY" push --entry "$ENTRY" --ref "$VEXA_CHANNEL_REF" \
  --sign-key "$VEXA_CHANNEL_KEY" --ledger "$VEXA_STATIONS_DIR"
if [ -n "$CHANNEL_TAG" ]; then set -- "$@" --channel-tag "$CHANNEL_TAG"; fi
if [ -n "$SIGNING_RECEIPT" ]; then set -- "$@" --signing-receipt "$SIGNING_RECEIPT"; fi
step "4/4 push — signs, proves T2, then writes the ledger LAST" "$@"

if [ -n "$DRY_RUN" ]; then
  echo "--- dry run complete: environment resolved, nothing fetched, built, signed or pushed"
else
  echo "--- published $RELEASE on $CHANNEL; the ledger commit in $VEXA_STATIONS_DIR is the audit trail — push it"
fi
