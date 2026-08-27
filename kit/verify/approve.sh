#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# vexa-approve — the human half of the gate.
#
# A named person approves one exact release for one environment. The approval
# is recorded IN YOUR CLUSTER (a ConfigMap, in your audit log), it quotes the
# verifier's verdict at the moment of approval, and production's PreSync check
# REFUSES to sync a release that has no approval record. So the human act is
# deliberate, attributed, auditable — and enforced, not merely expected.
#
# usage: approve.sh --release 0.12.24 --approved-by "Name <email>" \
#                   --entry-ref <registry/path:tag> --pubkey <file>
#                   [--policy <file>] [--namespace argocd] [--move-pin] [--insecure]
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
RELEASE=""; BY=""; ENTRY_REF=""; PUBKEY=""; POLICY=""; NS="argocd"; MOVE_PIN=""; INSECURE=""
REASON=""
while [ $# -gt 0 ]; do
  case "$1" in
    --release) RELEASE=$2; shift 2;;
    --approved-by) BY=$2; shift 2;;
    --entry-ref) ENTRY_REF=$2; shift 2;;
    --pubkey) PUBKEY=$2; shift 2;;
    --policy) POLICY=$2; shift 2;;
    --namespace) NS=$2; shift 2;;
    --reason) REASON=$2; shift 2;;
    --move-pin) MOVE_PIN=1; shift;;
    --insecure) INSECURE=1; shift;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
if [ -z "$RELEASE" ] || [ -z "$BY" ] || [ -z "$ENTRY_REF" ] || [ -z "$PUBKEY" ]; then
  echo "usage: approve.sh --release <ver> --approved-by <name> --entry-ref <ref> --pubkey <file>" >&2
  exit 2
fi

echo "== deterministic validation of $RELEASE"
VERDICT_LOG=$(mktemp)
set +e
sh "$HERE/vexa-verify.sh" --entry-ref "$ENTRY_REF" --pubkey "$PUBKEY" \
   ${POLICY:+--policy "$POLICY"} ${INSECURE:+--insecure} 2>&1 | tee "$VERDICT_LOG"
set -e
# No exit-status check here on purpose: the verdict line in the log is the
# authority, and it is grepped below. (PIPESTATUS is a bashism; this is sh.)
if ! grep -q "^VERDICT: ELIGIBLE" "$VERDICT_LOG"; then
  echo >&2
  echo "REFUSED: $RELEASE is not eligible. Nothing was approved and no pin moved." >&2
  echo "A release that fails validation cannot be approved into production by this path." >&2
  exit 1
fi

VERDICT_SHA=$(sha256sum "$VERDICT_LOG" | cut -d' ' -f1)
CONTRACT_ID=""; CONTRACT_SHA=""
if [ -n "$POLICY" ] && [ -f "$POLICY" ]; then
  CONTRACT_ID=$(jq -r '.contract_id // "unnamed"' "$POLICY")
  CONTRACT_SHA=$(sha256sum "$POLICY" | cut -d' ' -f1)
fi
AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Bind the approval to exact bytes: resolve the entry's manifest digest, so
# the record says which artifact was approved, not merely which tag.
ENTRY_DIGEST=$(oras resolve ${INSECURE:+--insecure} "$ENTRY_REF" 2>/dev/null || echo "")
[ -n "$ENTRY_DIGEST" ] || echo "warning: could not resolve the entry digest; approval records the tag only" >&2

echo
echo "== recording approval in your cluster"
kubectl -n "$NS" create configmap "vexa-approval-$RELEASE" \
  --from-literal=release="$RELEASE" \
  --from-literal=approved_by="$BY" \
  --from-literal=approved_at="$AT" \
  --from-literal=entry_ref="$ENTRY_REF" \
  --from-literal=entry_digest="$ENTRY_DIGEST" \
  --from-literal=verdict="ELIGIBLE" \
  --from-literal=verdict_sha256="$VERDICT_SHA" \
  --from-literal=contract_id="${CONTRACT_ID:-none}" \
  --from-literal=contract_sha256="${CONTRACT_SHA:-none}" \
  --from-literal=reason="${REASON:-routine promotion}" \
  --dry-run=client -o yaml \
  | kubectl label --local -f - -o yaml \
      vexa.ai/approval=true "vexa.ai/release=$RELEASE" \
  | kubectl apply -f -

kubectl -n "$NS" annotate configmap "vexa-approval-$RELEASE" \
  "vexa.ai/verdict-log=$(head -c 2000 "$VERDICT_LOG" | tr '\n' ';')" --overwrite >/dev/null
rm -f "$VERDICT_LOG"

echo "   approved: $RELEASE by $BY at $AT"

if [ -n "$MOVE_PIN" ]; then
  echo
  echo "== moving your production pin to $RELEASE"
  kubectl -n "$NS" patch applicationset vexa-channel-subscription --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/generators/0/list/elements/1/position\",\"value\":\"$RELEASE\"}]"
  echo "   production now follows $RELEASE. Its PreSync check will re-verify the"
  echo "   evidence AND require this approval record before anything is applied."
else
  echo
  echo "Approval recorded. Move the pin when you are ready:"
  echo "  kubectl -n $NS patch applicationset vexa-channel-subscription --type=json \\"
  echo "    -p '[{\"op\":\"replace\",\"path\":\"/spec/generators/0/list/elements/1/position\",\"value\":\"$RELEASE\"}]'"
fi
