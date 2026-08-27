---
title: "ADR-0001 — Repository charter"
description: "vexa-delivery, EE, supersedes the vexa-platform promotion tooling."
---

**Status:** accepted · **Date:** 2026-08-21 · **Deciders:** founder (name/org/license/creation),
session 2026-08-21 (structure)

## Context

The v0.12.23 production release (2026-08-17→19) took two days and was stopped six times by its own
guards; ~70% of the elapsed time was push-pipeline debt. The founder ruled (2026-08-19, PRD §0c)
that the delivery system is Enterprise Edition software in a new repository, superseding — not
paralleling — the promotion tooling in `vexa-platform`. The founding handoff
(`biz/drafts/2026-08-21-HANDOFF-enterprise-byoc-conveyor.md`) fixes the product: an Argo CD–based
pull conveyor in the customer's cloud, subscribed to a signed channel of digest sets plus evidence
bundles.

## Decisions

1. **Name and home:** `Vexa-ai/vexa-delivery`, private. (Founder answer 2026-08-21; alternatives
   `vexa-conveyor`, `vexa-ee` declined.)
2. **License:** proprietary short-form "Vexa Enterprise license", GitLab-EE style, holder Vexa
   Inc. (Founder answer 2026-08-21.) **Amended the same day by
   [ADR-0005](/adr/0005-kit-license-split): the license covers the vendor-side factory only; the
   customer-side `kit/` is Apache-2.0. Superseded 2026-08-24 by
   [ADR-0008](/adr/0008-repository-apache-2): the WHOLE repository is Apache-2.0; the repository
   stays private and access is granted per person. No EE license text remains.** The license
   deliberately did not encode a pricing unit —
   the pricing surface is an open founder question (handoff §9 Q3) and must not be smuggled in as
   license text. Apache-2.0 material copied from `Vexa-ai/vexa` stays Apache-2.0 with attribution;
   under ADR-0008 so does everything else here.
3. **Charter is carried, not restated:** README embeds handoff §1 and §3 verbatim as founder
   rulings. This ADR series (from 0001) owns delivery-system decisions; product-level decisions
   (chart, images, OSS behaviour) stay in `Vexa-ai/vexa`'s ADR series.
4. **Governance discipline is carried across explicitly** (PRD §0c): modularity with declared
   boundaries, single source of truth (one definition per contract, goldens are the spec,
   duplicate definitions are a red test — the `ContractSingleSourceTest` precedent), tests at
   every level with claims only at the rung the evidence supports (P19/D12: an over-claimed rung
   is a false green).
5. **Supersede map:** [SUPERSEDES.md](https://github.com/Vexa-ai/vexa-delivery/blob/main/SUPERSEDES.md) names every vexa-platform promotion
   file and its disposition. Retirement happens per-function as the conveyor takes each function
   over with evidence, never by this repo's existence alone.
6. **Hard boundaries** (handoff §8): no production credentials in this repo or its CI, ever; the
   publisher consumes released artifacts and receipts, not clusters. Never push into a customer
   cloud. Evidence verifiable offline in the customer's cloud. Founder gates: anything
   customer-visible, and the first channel publication.

## Open questions (recorded, not decided)

- **Kargo: adopt vs imitate** (handoff §9 Q2) — decided at M3 after a serious evaluation; the
  dependency-posture call is the founder's.
- **Pricing surface** (handoff §9 Q3) — needed before pilot, not before M2.
- **`hc-build.sh` / hosted-compat fork** — whether the fork disappears into OSS or the factory
  absorbs its build is unresolved; nothing in M0–M2 depends on it.
- **Public positioning:** the vexa.ai landing copy and founder-bio copy state "no open-core, no
  enterprise edition"; the EE factory is vendor-side operations tooling (commercial-and-safe under
  `Commercial-Boundary` — operations cannot be forked, and nothing already-Apache is being gated),
  but the public phrasing needs a founder decision before anything here becomes customer-visible.
