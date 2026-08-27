# Receipt — prod adoption: vexa-production becomes subscriber #1

**Date** 2026-08-25 · **Cluster** LKE `590708` (production) · **Channel** `vexa-internal` · **Pin** `0.1.0-estate.20260825.rev139` (entry seq 2, `sha256:88acf796…`) · **Status: ADOPTED — soak window open until 2026-08-26 EOD**

This executes [the prod migration plan](/plans/2026-08-25-prod-migration). Founder authorization: commitments 1–5 + both deviations ("1-7 yes, snapshot-only"), then the pin act verbatim: **"pin approved, 1-4 yes"**.

## The headline numbers

- **36/36 pods kept their UID across the adoption sync** (the single delta was a CronJob's scheduled-run churn between captures).
- **111 ReplicaSets before, 111 after — zero new.** The newest RS in the namespace predates the sync by 5 hours (it is the 14:17Z rev-139 deploy). No pod template changed anywhere.
- App: `Synced / Healthy / Succeeded`. `vexa.ai/api/version` 200 throughout, serving `27b513d` / v0.12.23.
- PVs: 25, all Retain; 8 Released; same 3 Bound in vexa-production. None created, deleted, or rebound.

## What was done, in order

1. Freeze announced to the concurrent prod-writing session (6.1).
2. Before-state captured at helm rev 139 (pods, 13 generations, 18-ref digest map, manifest, values, PVs) (6.2).
3. **P6** fresh DB snapshot via the estate's own backup CronJob: `s3://<backup-bucket>/db/<estate>/<snapshot>.sql.gz` (172.3 MB). Snapshot-only per founder word; restore-test deferred.
4. **P2** Argo CD v3.5.1 → `argocd` ns, `resourceTrackingMethod: annotation` set **before any Application existed**; pool toleration mirrored from prod workloads. Inert: 13/13 generations unchanged.
5. **P3** Kyverno v1.19.0 → `kyverno` ns, zero policies → zero resource webhooks; dry-run admission probe untouched. Inert: generations unchanged.
6. Contract `vexa-contract-prod` = the estate contract (`vexa-internal-estate-2026-08`) + channel pubkey installed in vexa-production.
7. Candidate entry seq 2 published (separate publisher receipt: `publish-receipt-139.md`): 18/18 pins mirrored+signed, render-diff empty, `current` NOT moved.
8. **6.3–6.5** Application `vexa-prod` created sync-disabled; full `argocd app diff`: **fatal four all zero** (no selector / image / Secret diffs; LB Service + PVC label-only). Residual diff = `helm.sh/chart` labels + `tracking-id` + one CronJob jobTemplate label (future Jobs only). Caddy `checksum/caddyfile` neutralized via `ignoreDifferences` + `RespectIgnoreDifferences=true` — live value `0a795750…` verified preserved post-sync.
9. **6.6** Sync with ServerSideApply. Result: headline numbers above.
10. **6.7** `vexa-platform-drift-detector` suspended. Helm release secrets left in place (10 revisions of history). No `helm uninstall`, ever.

## Deviations, named

- **Generations ticked +1 on all 13 Deployments** while RS set and pod UIDs stayed identical: SSA's first apply took co-ownership and normalized spec serialization — a spec *write*, not a rollout. The plan's generation metric was a proxy; the RS/UID ground truth is the adoption invariant and it held.
- **Adoption values carry inline secrets** (the live estate's legacy shape) inside the Application spec — in-cluster only, same values the helm release secret already stores. Follow-up: move estate secrets to k8s Secrets via a planned, receipted rollout.
- **In-cluster PreSync verifier not active for this sync** (entry verified publisher-side: T1/T2 + offline checks). First post-adoption change: enable verifier + flip entries to `published` with named approver, per the estate contract's own inline note.
- **`vexa_channel.py verify` cannot verify platform-estate entries** (crashes on absent delivery-receipt) — pre-existing gap, also fails on seq 1; to file.
- Staging-verdict clause deferred until staging lives (platform#349, founder A/B pending).

## Rollback

Pin move back to seq 1 (`0.1.0-estate.20260825`), re-approve, sync — or full exit: delete Application cascade=false, `helm rollback vexa-platform 138`. DB snapshot above. Schema delta: none (billingLedgerMigration disabled; hook renders nothing — proven twice today).

## Soak

Per plan 6.8: one business day minimum, covering db-backup (02:00) and slo-check (05:30). Receipt finalizes after soak; until then this receipt is preliminary.
