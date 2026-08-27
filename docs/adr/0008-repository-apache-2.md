---
title: "ADR-0008 — The whole repository is Apache-2.0"
description: "Open license, private repo, access per person; customer material moves out."
---

**Status:** accepted (founder ruling 2026-08-24) · **Amends:** [ADR-0001](/adr/0001-repo-charter) §2
and [ADR-0005](/adr/0005-kit-license-split)

## Context

[ADR-0005](/adr/0005-kit-license-split) drew the license boundary at the customer edge: `kit/`
Apache-2.0 because a customer runs it, everything else proprietary because we never distribute it.
That reasoning was sound and its conclusion has aged badly, for two reasons that only became
visible once a real subscriber's engineer was about to be given a clone.

**The boundary protects something we do not distribute.** ADR-0005 itself established that the
product is not the software — it is the attested release stream, the evidence, the support lane and
the co-design hours. Applied to the factory, the same argument runs the same way. The factory is
roughly two thousand lines of configuration and glue around stock Argo CD, Kyverno and cosign. A
competitor who copied all of it would still have no channel, no receipts, no reference customer and
no relationship, which is the entire thing being bought. An EE license over that is a fence around
a field we do not farm.

**The boundary costs us the contributor we want.** The kit was made Apache-2.0 precisely so
operators could shape it — ADR-0005's last consequence anticipates contributions back. But the
person who shapes the kit is the customer's platform engineer, and a repository whose root license
forbids copying is friction at exactly the moment we are asking that engineer to clone, read and
send a patch. The split had to be explained before the first commit could be made.

## The ruling

Founder, 2026-08-24, verbatim:

> let's go for apache 2 in private repo that we share access

## Decision

1. **The whole repository is licensed Apache-2.0**, copyright Vexa Inc. 2026. The root
   [`LICENSE`](https://github.com/Vexa-ai/vexa-delivery/blob/main/LICENSE) carries the Apache-2.0 text and the root [`NOTICE`](https://github.com/Vexa-ai/vexa-delivery/blob/main/NOTICE)
   states the scope. The Vexa Enterprise license text is removed.
2. **`kit/LICENSE` and `kit/NOTICE` stay** — not as a boundary marker but as a shipping
   requirement: `kit/release.sh` packages `kit/` into a standalone signed tarball, so the license
   has to travel with those bytes. Their text no longer describes a split.
3. **The repository stays private, and access is granted per person.** The first grant is the
   subscriber's platform engineer, so that they can clone and contribute. Public visibility is a
   separate decision and is not taken here.
4. **Customer-identifying material does not live in this repository.** Per-customer onboarding
   packs and station profiles move out and are gitignored, mirroring the rule `stations/` already
   enforces. What remains is a template.

Points 3 and 4 are the load-bearing pair. Point 3 is what makes 4 necessary.

## Consequences

- **This is irreversible for every version released under it.** Apache-2.0 is a perpetual,
  irrevocable grant. We may license *future* commits differently; we cannot claw back what any
  person with access has already received. There is no undo, and nobody should expect one.
- **A competitor may lift the factory.** Anyone we grant access to may copy, modify and
  redistribute all of it, including publicly, and owes us nothing but attribution and a NOTICE
  file. We are accepting this deliberately, on the judgment above about where the moat is. If that
  judgment is wrong, the cost lands here.
- **Confidentiality is not governed by a license, and this is the trap.** An open license plus a
  private repository reads as safe and is not: the moment we grant a person access, they lawfully
  hold everything in the tree, and Apache-2.0 places no confidentiality obligation on them at all.
  Whatever protects a customer's estate details must be a contract (an NDA, a pilot letter) or
  their absence from the repository. Decision 4 chooses absence, because it is the only one of the
  two that this repository can enforce.
- **Access grants are now the whole control surface.** Every grant is a decision with no technical
  undo — a revoked collaborator keeps their clone. Grants are founder-gated.
- **History is not rewritten.** The customer material removed by this change remains in the git
  history of this repository, and a collaborator with a clone can read it. The removal protects
  what is committed from here on; it does not retroactively unpublish. Rewriting history across a
  repo with open pull requests was judged out of scope, and stating the residual exposure plainly
  was judged better than a rewrite that would look like a guarantee.
- **Public vs private visibility remains open.** Nothing here argues for or against publishing the
  repository. That is a later founder decision, and it is a much larger one, because visibility —
  unlike a license — is what actually determines who reads the tree.
- **Contribution back becomes ordinary.** A subscriber's engineer clones, patches, and sends a pull
  request against a single well-known license with no boundary to explain first. The scoped first
  contribution offered to the pilot's engineer (the operator-side smoke) needs no special handling.
- **The public positioning stays true**, as it did under ADR-0005: no feature is gated, no source
  is held back, and what is sold is a stream and a service. The claim is now simply stronger.
