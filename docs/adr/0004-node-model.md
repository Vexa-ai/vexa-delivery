---
title: "ADR-0004 — The node model"
description: "Every station is consume → deploy → validate → sign."
---

**Status:** accepted (founder ruling 2026-08-21, in-session) · **Refines:** ADR-0002 §4
(stations-as-subscriptions) and ADR-0003 (the kit)

## The ruling, verbatim substance

The reproducible cluster the kit produces is **a node in a consume chain**: it listens to updates
and installs them deterministically. Nodes stack — staging → prod → enterprise staging →
enterprise prod. And a node is not only a consumer: **it publishes as well, gated on the checks it
collects for health approval, including human.** Every node is the same unit:

```
        ┌────────────────────────── one node ──────────────────────────┐
channel │ CONSUME          DEPLOY               VALIDATE       PUBLISH │ channel
  in ──▶│ pull entry,   ─▶ deterministic     ─▶ collect     ─▶ entry + │──▶ out
        │ verify sig +     install (Argo,       health,        its own │
        │ evidence         digest-pinned,       probes,        receipts│
        │                  admission-gated)     soak, human    appended│
        │                                       witness where          │
        │                                       configured             │
        └──────────────────────────────────────────────────────────────┘
```

- **Consume** — what M2 proved on the throwaway cluster: subscription, deterministic install,
  independent admission verification (ADR-0003).
- **Deploy** — Argo applying the digest-pinned set; `(entry digest, local values) → cluster
  state`, every reconcile.
- **Validate** — the node runs its configured check set against the *running* system: health
  probes, functional metrics (segment flow, join success — the PRD R4 judge), soak duration, and
  **the human witness where the node's policy requires one**. A check the node cannot run is
  declared absent, never assumed.
- **Publish** — when (and only when) the node's checks pass, it publishes the entry to its
  downstream channel **with its own receipts appended** to the evidence bundle. Publication is the
  promotion; there is no separate promotion mechanism. A failed or missing check blocks publish —
  the only override is the audited break-glass record inside the signed entry (ADR-0002 §5).

## Why the existing contracts already hold

The channel-entry schema anticipated the legs: per-image `validation_receipts`, `prod_soak`,
`witness`/`soak`/`readiness` evidence kinds, `evidence_absent`, and gated `publication`. What the
node model changes is **who runs the publisher**: not a central vendor tool only — *every node*
runs the publisher CLI as its publish leg, with inputs generalized from "release artifacts + the
internal delivery receipt" to "upstream entry + this node's own validation receipts". Evidence
accumulates hop by hop because each publication embeds the upstream bundle and appends.

Two consequences of "this node will be published as well":

1. **The node publishes onward** (primary meaning) — each station is a publisher whose authority
   is its collected evidence, human gate included where configured (enterprise prod's gate is the
   customer's; ours are ours).
2. **The node is made of published parts** — the kit, policies, preflight and check-set that
   constitute a node are themselves versioned, signed channel content, so a node's own definition
   updates through the same conveyor it serves (the PRD's operator-self-update requirement, now
   structural).

## Correction — same day, founder: the fourth leg SIGNS; it does not publish

Images are frozen at build — the same digests flow the whole chain or die on the way (a candidate
may never reach prod or enterprise prod; that is normal). So a node that validates successfully
has nothing new to publish: it **signs** — it attaches its stage attestation to the frozen digest
set. Promotion is signature accumulation, mechanically: downstream admission is a **predicate over
accumulated attestations** ("verified-in staging AND prod-soak ≥ N hours from the trusted prod
identity"), not receipt of a forwarded entry. One store, N signatures; no per-hop re-publication.
The channel entry remains the artifact's **birth record** (identity + build-time evidence);
everything after it is attestations attached to the digests over time.

**Industry form (this is a standard, not an invention):** the per-stage attestor model —
Binary Authorization–style attestors sign the digest at each stage and the deploy policy requires
the attestation set; the in-toto attestation framework is the statement format; SLSA's
**Verification Summary Attestation (VSA)** is the standardized "I verified this artifact against
my policy" statement a stage emits. Kyverno enforces it natively
(`verifyImages[].attestations` with conditions over predicate fields), so the customer policy
evolves from "signed by the channel key" to "**carries the required stage attestations from the
pinned identities**" — still fully offline-verifiable. Consequence for ADR-0002's open signing
decision: it is now **N stage identities, not one channel key**; each environment's policy pins
the set of upstream identities it trusts.

## Parallel branches — same ruling

Several candidates in flight at once (a hotfix racing a train, multiple RCs) cannot be excluded,
so the chain is a **partial order, not a line** — ugly, and irreducibly so. The attestation model
absorbs it by splitting three concerns that a linear channel conflated:

- **Eligibility** — per candidate, the stage predicate over its accumulated attestations. Needs
  no global ordering; parallel candidates race independently.
- **Selection** — when several candidates are eligible for one stage, an explicit per-stage
  policy chooses (newest-by-version among eligible is the default; Kargo's
  `NewestFreight`/`MatchUpstream` are exactly this policy, named).
- **Supersession/withdrawal — explicit and signed.** A candidate that died downstream, was
  overtaken, or must be pulled (vuln) gets a signed **withdrawal attestation**; every policy
  refuses withdrawn candidates, so a stale-but-eligible branch cannot be selected late.
- **No silent downgrade** — replacing a running newer version with an older eligible candidate is
  a signed, visible act. (This generalizes the schema's `entry_seq` monotonicity, which assumed a
  line; the linear sequence softens into this rule at M3.)

## What this does to the roadmap

- **M3 = the validate + publish legs of a node**, not a central controller: the health/check
  collection harness (R4 judge seed, witness capture) and the publisher running at the node,
  consuming its receipts. The **Kargo evaluation (§9 Q2) maps cleanly onto this** — Kargo's
  Freight/Stage/`VerifiedIn`/`ApprovedFor` is exactly consume-validate-publish between stages —
  so the adopt-vs-imitate call is now "does Kargo implement our node, or do we"; the
  dependency-posture decision stays the founder's.
- **The next cluster proof must run Vexa, including bots.** The M2 test proved the consume leg
  with a demo workload and is stated at that rung; a node that has never run the product cannot
  validate it. Acceptance for the next throwaway run: the chart deployed with isolated backing
  services, at least one bot spawned and admitted under the policy, and the node's validate leg
  producing real receipts from that run. (The spike's warnings apply: the isolation overlay is
  half a day of real work, and the chart's default values point at shared infrastructure — that
  hazard is part of what the node's values discipline must neutralize.)
- **Our own chain is nodes too**: staging and vexa cloud prod become the first two stacked nodes
  (customer #0 twice over), which is how the vexa-platform deploy targets actually retire
  (SUPERSEDES.md's CONTROLLER rows resolve to "the node's legs").
