---
title: "ADR-0005 — Kit license split"
description: "The kit is Apache-2.0; the factory stays proprietary."
---

**Status:** superseded 2026-08-24 by [ADR-0008](/adr/0008-repository-apache-2) ·
**Amends:** ADR-0001 §2

> **Superseded.** There is no license split any more: the whole repository is Apache-2.0
> ([ADR-0008](/adr/0008-repository-apache-2)). This ADR's reasoning is what ADR-0008 extends — the
> argument that the product is the stream and the service, not the software, applied to the
> factory as well as to the kit. It is kept as record.

## Context

ADR-0001 put the whole repository under one proprietary EE license. Working through what a
customer actually receives showed that to be wrong at the edges, and the founder stated the
principle directly: **the product is not the software — it is the evidence-based artifacts,
support and co-design.**

Followed through: the product's images are Apache-2.0 and public (the MVP0 cluster pulled every
`vexaai/*` image anonymously, `imagePullSecrets: []`), and the chart lives in the Apache-2.0 OSS
repo. A customer needs no permission from us to run Vexa. What they subscribe to is the attested
release stream, the support lane and the co-design hours — none of which is software.

That left exactly one EE-licensed thing in a customer's hands: the **kit**. Which is
configuration around stock Argo CD and Kyverno, whose readability our own customer docs offer
as the proof that nothing proprietary of ours executes in their perimeter.
PRD §0c anticipated this ("the customer-side component ships open and auditable"); ADR-0001
under-applied it.

## Decision

1. **`kit/` is licensed Apache-2.0** (`kit/LICENSE`, `kit/NOTICE`, copyright Vexa Inc. 2026) —
   installer, preflight, admission policies, ApplicationSet, provider profiles.
2. **Everything else in this repository stays proprietary** under the root LICENSE, which now
   states its scope explicitly: the vendor-side factory — publisher, channel spec, release
   machinery — none of which is distributed to customers.
3. **The repository stays private.** Open license, private repo: the kit reaches customers with
   the kit, not through a public repository, and the factory it sits next to is not for
   publication.

## Consequences

- **No customer engagement needs a software license.** A pilot needs channel access (a
  credential) plus services (support, co-design) — a pilot letter, not a license grant. The
  credential is the whole access mechanism; expiry needs no legal act.
- **The public positioning stays true.** vexa.ai's "no open-core, no feature gating, no
  enterprise edition" survives unchanged: no feature is gated, no source is held back, and what
  is sold is a stream and a service. The flag raised earlier against that copy is withdrawn.
- **The auditability claim gets stronger**, because it now rests on a license rather than on our
  goodwill: a subscriber may read, modify and adapt the kit that runs in their cluster.
- Contributions back into `kit/` from customers become possible under an ordinary OSS inbound
  path if we ever want them; nothing here requires it.
