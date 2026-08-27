# Receipt — adoption: taking custody of a live estate without recreating a pod

**Date** 2026-08-25 · **Cluster** throwaway LKE `647376`, namespace `vexa-prod-sim`, destroyed at the end of this run · **Channel** `vexa-internal` · **Chart** `vexa-platform` `0.1.20260825`

This is the **second** of two proofs. The first — [clean pull](/receipts/2026-08-25-throwaway-clean-pull) — asks whether the channel can produce production from nothing. This one asks whether a production that **already exists** can be handed over to the channel without going down.

**They are not the same claim and neither substitutes for the other.** Adoption proves zero-downtime custody transfer of a live estate; it proves nothing about deliverability, because the images are already on the nodes and the objects already exist. Deliverability is Proof 1's job, and Proof 1 is where the findings are.

**Production was never touched.** This ran against a Helm-installed simulation in a throwaway namespace.

---

## Setup — what was adopted

`helm install vexa-platform` from **the channel chart**, release name **`vexa-platform`** (the live production release name, not the kit's old hardcoded `vexa`), into `vexa-prod-sim`, with dummy secrets shaped per `docs/channel-secret-mapping.md` and the database pointed at an in-cluster double per the validation contract.

Settled state before adoption: **19 pods, 18 Running or Succeeded**, 3 total container restarts (all on one billing worker, from a real guard — see below).

## The headline number

**Zero pods were recreated. 18 of 18 kept the same pod UID across the adoption sync.**

A same-name pod with a same UID is the same running process: it was never deleted, never rescheduled, never restarted from scratch. This is the number that matters, because the failure mode adoption is guarding against — Argo's default `label` resource tracking trying to write `app.kubernetes.io/instance` into an **immutable** Deployment `spec.selector.matchLabels` — does not produce an error message. It produces a permanently OutOfSync Application whose only exits are recreating the workload or unwinding the install.

And the decisive corroboration, which does not depend on reading pod status at all:

```
14 Deployments  ->  14 ReplicaSets     (one each)
```

**Not one Deployment produced a second ReplicaSet.** A ReplicaSet is created whenever a pod template changes, so one-per-Deployment is proof that the adoption changed no pod spec anywhere in the estate. There is nothing to interpret in that number.

The kit change that makes this true is in `kit/install.sh`: `application.resourceTrackingMethod=annotation` is set on `argocd-cm` **before any Application exists**, so the tracking id lands in a mutable annotation rather than in the selector. Verified live:

```
$ kubectl -n argocd get cm argocd-cm -o jsonpath='{.data.application\.resourceTrackingMethod}'
annotation
```

## The diff before sync

Argo compared the published chart against the running estate **before being allowed to change anything**:

```
resources: 115    Synced: 110    OutOfSync: 5
```

**110 of 115 objects needed no change at all.** The 5 that differed:

```
ConfigMap      vexa-platform-billing-reconciliation-58ac982695f9
Deployment     vexa-platform-billing-provider-worker
CronJob        vexa-platform-billing-reconciliation
NetworkPolicy  vexa-platform-billing-provider-worker
NetworkPolicy  vexa-platform-billing-reconciliation
```

The delta, in full, for one of them — and it is representative:

```diff
--- live
+++ rendered
 metadata:
-  annotations:
-    meta.helm.sh/release-name: vexa-platform
-    meta.helm.sh/release-namespace: vexa-prod-sim
-  labels:
-    app.kubernetes.io/managed-by: Helm
   name: vexa-platform-billing-provider-worker
```

**Ownership metadata only.** Nothing in any spec. These five are the objects whose templates omit the chart's standard label block, which is why they show a difference where the other 110 do not — Helm's ownership annotations are present on the live object and absent from the render. Adoption's entire effect on this estate was to change who owns five objects.

## What the sync did

```
sync: Synced   operation phase: Succeeded   115/115 Synced
```

Restart counts moved on three pods inside the sync window (admin-api `0→2`, billing-auto-topup-worker `0→3`, billing-provider-worker `3→6`) and **then stopped**: re-measured 100 seconds later with no Argo activity, every count was stable except the billing-provider-worker, which is in an independent `CrashLoopBackOff`.

**I am not going to claim those three were unrelated to the adoption, because I cannot prove it.** What I can prove is that no pod was recreated and no pod template changed, so whatever those restarts were, they were containers restarting in place, not workloads being replaced. The billing-provider-worker was already restarting before adoption began, for a reason unrelated to it:

```
RuntimeError: billing provider worker in live mode requires a standard sk_live_ key
```

That is a real custody guard refusing a test-mode Stripe key, and it is doing exactly what it should.

## Pull upgrade and pin move — the prod ceremony, timed

The ceremony production will use is: **publish → staging proves → move the pin.** Rollback is **move the pin back.** Both directions were rehearsed against the adopted estate.

| Move | From → to | Result | Wall clock |
|---|---|---|---|
| **Forward** | `0.1.20260825` → `0.1.20260826` | `Succeeded`, `Synced` | **17 s** |
| **Rollback** | `0.1.20260826` → `0.1.20260825` | `Succeeded`, `Synced` | **10 s** |

**Across both moves, 17 of 17 pods kept the same UID.** One restart-count change, on the billing-auto-topup worker that was already unstable.

Rollback is not a special procedure, a script, or a runbook. It is the same one-field edit as the forward move, and it was measurably faster.

## The exact prod ceremony, now validated

Every step below was executed on the throwaway:

1. **Publish** the estate to the channel — chart, entry, signatures, mirrored images.
2. **Sign every image** into the channel's signature repo. *Do not skip this:* Kyverno was observed **denying 12 workloads** with `no signatures found` before signing and admitting all of them after. The gate was seen failing closed before it was seen passing.
3. **Install the kit** with `--chart-name vexa-platform --release-name vexa-platform`. The release name must match the existing release; the kit's old hardcoded `vexa` would have installed a second copy alongside production rather than adopting it.
4. **Confirm `resourceTrackingMethod=annotation`** on `argocd-cm` before any Application exists.
5. **Create the Application, do not sync.** Read the diff.
6. **Reconcile until the delta is ownership metadata only.** This is a gate, not a formality: a spec difference at this point means the channel does not hold what production runs, and syncing would change production.
7. **Sync.** Record pod UIDs and ReplicaSet counts before and after.
8. **Assert zero recreations** — same UIDs, one ReplicaSet per Deployment.
9. **Pin move forward**, then **back**, before trusting the mechanism with a real release.

## What still differs from real production

Stated plainly, because a rehearsal that does not name its gaps is a rehearsal that will be over-trusted.

| | Here | Real prod |
|---|---|---|
| **Data** | An empty in-cluster Postgres double | An Akamai managed instance with live customer transcripts. Migration timing and lock behaviour against populated tables is **not** tested by this run |
| **Secrets** | Dummies, plus a real transcription token, real OpenRouter key and a real Stripe **test-mode** key | Live credentials. Adopting prod means the real ones stay in place — this run does not exercise that |
| **Scale** | 3× g6-standard-4, prod replica counts | Larger pool, real traffic. **No load was applied during the adoption sync** — the zero-recreation result was measured on an idle estate |
| **GPU** | None | Transcription workers. No meeting was joined or transcribed |
| **Traffic** | None | Live users. A pod that is not recreated can still drop connections; that was not measured |
| **Monitoring stack** | Two CRDs applied by hand | Full kube-prometheus-stack. The `monitoring` namespace half of the estate was **not** adopted here at all |
| **Objects** | 115, `vexa-production` chart only | 115 plus `data-platform`, `twenty`, monitoring, and the additional manifests |

**The most important gap is the last two rows.** This proves adoption for the `vexa-platform` release. It does not prove adoption for the `monitoring` namespace's three releases, which carry their own ownership metadata and their own Helm history, and which include a `Prometheus` custom resource with an operator behind it.

## Custody

`vexa-production` and `monitoring` on LKE `590708` were read-only throughout, and `vexa-staging` was not touched. The throwaway cluster and its volumes were deleted at the end of this run.
