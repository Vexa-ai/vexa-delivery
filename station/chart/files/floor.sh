#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# station floor — continuous substrate verification. The layer below GitOps:
# reconciliation cannot fix nodes, volumes, or storage classes, so the floor
# CHECKS them on a schedule and turns the station RED instead of letting the
# substrate drift silently. Namespace scope reports cluster facts as UNKNOWN
# rather than guessing.
set -u
FAILED=0; UNKNOWN=0; REPORT=""
line() { REPORT="${REPORT}${1}
"; }
ok()   { line "OK    $1"; }
red()  { line "RED   $1"; FAILED=$((FAILED+1)); }
unk()  { line "UNK   $1 (needs cluster scope)"; UNKNOWN=$((UNKNOWN+1)); }

SCOPE="${FLOOR_SCOPE:-cluster}"

# ---- cluster-scoped facts ---------------------------------------------------
if [ "$SCOPE" = "cluster" ]; then
  ready=$(kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready"' | wc -l | tr -d ' ')
  if [ "${ready:-0}" -ge "${MIN_NODES_READY:-1}" ]; then
    ok "nodes Ready: $ready >= ${MIN_NODES_READY:-1}"
  else
    red "nodes Ready: $ready < ${MIN_NODES_READY:-1}"
  fi

  released=$(kubectl get pv --no-headers 2>/dev/null | awk '$5=="Released"' | wc -l | tr -d ' ')
  if [ "${released:-0}" -le "${MAX_RELEASED_PVS:-0}" ]; then
    ok "Released PVs: $released (stranded-volume cost class)"
  else
    red "Released PVs: $released > ${MAX_RELEASED_PVS:-0} — reap or rebind"
  fi

  if kubectl get storageclass "${REQUIRED_STORAGE_CLASS:-}" >/dev/null 2>&1; then
    ok "storage class present: ${REQUIRED_STORAGE_CLASS:-}"
  else
    red "storage class MISSING: ${REQUIRED_STORAGE_CLASS:-}"
  fi

  # stuck detach (the 2026-08-21 CSI class): a VolumeAttachment that has been
  # deleting for longer than the ceiling means volumes cannot move
  now=$(date +%s)
  stuck=0
  while read -r ts; do
    [ -z "$ts" ] && continue
    t=$(date -d "$ts" +%s 2>/dev/null || echo "$now")
    age=$(( (now - t) / 60 ))
    [ "$age" -gt "${MAX_STUCK_ATTACH_MINUTES:-10}" ] && stuck=$((stuck+1))
  done <<EOF_TS
$(kubectl get volumeattachments -o jsonpath='{range .items[?(@.metadata.deletionTimestamp)]}{.metadata.deletionTimestamp}{"\n"}{end}' 2>/dev/null)
EOF_TS
  if [ "$stuck" -eq 0 ]; then
    ok "no VolumeAttachment stuck deleting > ${MAX_STUCK_ATTACH_MINUTES:-10}m"
  else
    red "$stuck VolumeAttachment(s) stuck deleting > ${MAX_STUCK_ATTACH_MINUTES:-10}m — CSI detach wedged"
  fi

  if [ "${ADMISSION_ENABLED:-true}" = "true" ]; then
    pols=$(kubectl get clusterpolicy --no-headers 2>/dev/null | grep -c "^vexa-")
    if [ "${pols:-0}" -ge 2 ]; then
      ok "admission: $pols vexa ClusterPolicies present"
    else
      red "admission: only ${pols:-0}/2 vexa ClusterPolicies present"
    fi
  else
    ok "admission: disabled by profile (verify gate is the enforcement point)"
  fi
else
  unk "nodes Ready"; unk "Released PVs"; unk "storage class"; unk "VolumeAttachments"
  if [ "${ADMISSION_ENABLED:-true}" = "true" ]; then
    pols=$(kubectl -n "$STAGING_NAMESPACE" get policy --no-headers 2>/dev/null | grep -c "^vexa-")
    if [ "${pols:-0}" -ge 2 ]; then
      ok "admission: $pols namespaced vexa Policies in $STAGING_NAMESPACE"
    else
      red "admission: only ${pols:-0}/2 namespaced vexa Policies in $STAGING_NAMESPACE"
    fi
  else
    ok "admission: disabled by profile (verify gate is the enforcement point)"
  fi
fi

# ---- namespace-visible facts ------------------------------------------------
for app in $(kubectl -n "$ARGOCD_NAMESPACE" get applications.argoproj.io --no-headers 2>/dev/null | awk '{print $1}'); do
  rev=$(kubectl -n "$ARGOCD_NAMESPACE" get application "$app" -o jsonpath='{.spec.source.targetRevision}' 2>/dev/null)
  if [ "$rev" = "UNPINNED" ]; then
    # a station waiting for its human approval is parked, not broken
    ok "app $app: parked (UNPINNED — awaiting approval)"
    continue
  fi
  s=$(kubectl -n "$ARGOCD_NAMESPACE" get application "$app" -o jsonpath='{.status.sync.status}/{.status.health.status}' 2>/dev/null)
  case "$s" in
    Synced/Healthy) ok "app $app: $s";;
    */Missing|Unknown/*) red "app $app: $s";;
    *) line "WARN  app $app: $s";;
  esac
done

if timeout 5 bash -c "exec 3<>/dev/tcp/${REGISTRY_HOST}/${REGISTRY_PORT}" 2>/dev/null; then
  ok "channel registry reachable: ${REGISTRY_HOST}:${REGISTRY_PORT}"
else
  red "channel registry UNREACHABLE: ${REGISTRY_HOST}:${REGISTRY_PORT}"
fi

# ---- verdict ----------------------------------------------------------------
if [ "$FAILED" -eq 0 ]; then STATUS=GREEN; else STATUS=RED; fi
printf '%s\n' "$REPORT"
echo "FLOOR: $STATUS ($FAILED red, $UNKNOWN unknown) at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

kubectl -n "$ARGOCD_NAMESPACE" create configmap station-floor \
  --from-literal=status="$STATUS" \
  --from-literal=failed="$FAILED" \
  --from-literal=unknown="$UNKNOWN" \
  --from-literal=at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --from-literal=report="$REPORT" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

[ "$STATUS" = "GREEN" ]
