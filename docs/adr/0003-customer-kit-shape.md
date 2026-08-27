---
title: "ADR-0003 — Customer kit shape"
description: "Stock Argo CD + Kyverno + preflight: we ship configuration, not an agent."
---

**Status:** accepted · **Date:** 2026-08-21 · proven on a throwaway LKE cluster
([receipt](../receipts/2026-08-21-m2-throwaway-test.md))

## Context

PRD §0c: nothing proprietary of ours executes in the customer's perimeter — the customer runs
stock upstream GitOps; we ship signed artifacts plus policy configuration. The founder's chain
ruling (ADR-0002 §4) puts two customer environments behind the channel with the gate between them
held by the customer. Handoff §6 fixes the preflight's failure classes from observed incidents.

## Decisions

1. **Stock Argo CD, OCI source, ApplicationSet with a list generator** — one Application per
   customer environment, same channel, different positions: `enterprise-staging` tracks the
   `current` pointer (automated sync + selfHeal + prune); `enterprise-prod` tracks a pin the
   customer moves. `ServerSideApply=true` always (client-side apply is the mechanism under the
   0.12.23 ownership blocker and the 256KB annotation limit), `ignoreDifferences` on StatefulSet
   `volumeClaimTemplates` (Argo cannot normalise API-server defaults there — permanent OutOfSync
   with an empty diff otherwise; spike finding 3).
2. **Kyverno as the customer-owned admission layer**, two ClusterPolicies: digest-pinning for
   `vexaai/*` (NO_MUTABLE_TAGS at the customer's door) and cosign signature verification against
   the channel public key, with `repository` pointing at the channel registry so verification
   needs neither Docker Hub reachability nor any call to Vexa. The customer can tighten these;
   we cannot override them (P11).
3. **The preflight is the kit's front door** — `install.sh` refuses to install on a FAIL. Checks
   P1–P9 each carry the incident that earned them; the dynamic bot pod (absent from every render)
   is a first-class workload profile with production-measured sizes. Air-gapped mode via
   `--dump-snapshot`/`--snapshot`.
4. **One command per provider** — `install.sh --provider <name>`; provider deltas live in
   `providers/<name>/profile.env` and say honestly whether they were exercised (`PROFILE_TESTED`).
   lke: tested end-to-end. openshift: audit-grounded, not cluster-proven. aws-eks/gcp-gke/azure-aks:
   declared deltas only.
5. **Image signatures ride the channel registry** (cosign convention), so the admission layer
   verifies against infrastructure inside or near the customer's perimeter. Until Kyverno reads
   cosign's bundle-format referrers, channel signing uses the legacy `.sig` format
   (`--new-bundle-format=false`).

## Known gaps, stated

- **Argo does not verify the channel-entry signature at pull time** (no cosign verification of
  OCI sources in Argo CD today). Compensations: per-image signatures verified at admission
  independently; entry-level verification (`vexa-channel verify`, fully offline) runs at the
  operator/promotion step. Closure options when needed: a PreSync verification hook, or Kargo
  (M3) whose promotion step can verify before the pin moves.
- **PSA `restricted` namespaces refuse today's unhardened images** — the preflight says so
  honestly (P4 flags the bot). The hardening track (vexa#976/#1101/#1102, audit classes A–F) is
  product work in `Vexa-ai/vexa`, not kit work.
- **Node-level registry trust** (containerd CAs for a corporate registry) is provider
  documentation, not something the kit can reach from inside the cluster.

## Consequences

The kit is inspectable end-to-end by the subscriber (it is configuration plus one Python file),
which is what makes the "nothing of ours resident in your perimeter" claim auditable rather than
trusted. (The kit was Apache-2.0 from ADR-0005; since
[ADR-0008](/adr/0008-repository-apache-2) the whole repository is.)
