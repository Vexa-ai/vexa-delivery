---
title: "ADR-0009 — The repository goes public"
description: "The visibility decision ADR-0008 explicitly deferred: public, whole repository, on a fresh history."
---

**Status:** PROPOSED · **Decision owner:** founder · **Amends:**
[ADR-0008](/adr/0008-repository-apache-2) decisions 3 and consequence
"Public vs private visibility remains open"

## Context

[ADR-0008](/adr/0008-repository-apache-2) relicensed the whole repository
Apache-2.0 but kept it private with per-person access, and said in terms that
public visibility was a separate, larger decision not taken there. It also
recorded that history still carried removed customer material, and that access
grants were the whole control surface.

The reason to flip: **auditability of the attestation pipeline is the point.**
The product this factory sells is an attested release stream — signatures,
evidence bundles, gate reports, receipts. A delivery machine whose claims rest
on verifiable evidence argues for itself best when the machinery producing
that evidence is itself inspectable. A private attestation factory asks for
exactly the trust it exists to make unnecessary. Publishing also makes
contribution ordinary for the subscriber engineers ADR-0008 already invited
in, without a per-person grant ceremony.

A pre-publication scan (2026-08-27, full history, all branches, every blob)
found the tree and history were not publishable as-is: customer-identifying
references at HEAD, customer material in history, live operator infrastructure
coordinates at HEAD, and 120 of 160 commits without DCO sign-off.

## Decision

1. **The repository becomes public — the whole of it, publisher included.**
   No half-measures: the factory's value is the evidence chain, and the
   publisher is where the evidence chain is made.
2. **Publication happens on a fresh history**: a single signed-off initial
   commit of the scrubbed tree replaces the prior history. The repository was
   six days old with one contributor and had never been public; there was no
   provenance to preserve and substantial customer material in the old
   history. A content rewrite (`filter-repo`) was considered and rejected as a
   larger correctness surface for a worse result.
3. **Customer confidentiality is protected by exclusion, permanently.** No
   customer name, host, channel name, timeline, person, or evaluation state
   lives in the tree. Synthetic names (`pilot`, `rehearsal`) stand in where
   receipts and tests need a subscriber-shaped value. The `.gitignore` rules
   from ADR-0008 continue to keep real packs and stations out.
4. **Operator infrastructure is site configuration, not repository content.**
   Host addresses, filesystem roots, buckets, replica targets and vault
   locations live in `config/channel.env` (gitignored), documented by
   `config/channel.example.env`. The RUNBOOK refers to the variables.
5. **Contributions are DCO-signed Apache-2.0, inbound = outbound** —
   `CONTRIBUTING.md` states it, a CI workflow enforces it, `.mailmap`
   canonicalizes the author identity.
6. **The flip itself is the founder's act**, taken after reviewing the
   prepared tree, and is not delegated. Until the founder flips visibility,
   this ADR remains PROPOSED and the repository remains private.

## Consequences

- **The old history is discarded, not published.** Force-replacing `main` with
  the fresh root orphans every prior SHA; stale branches are deleted. Anyone
  holding a pre-flip clone still holds the old history — the rewrite protects
  what is published, it does not retroactively unpublish what access grants
  already distributed (the same residual ADR-0008 named).
- **GitHub metadata does not rewrite with git.** Issue and PR titles, bodies
  and comments survive and become public with the repository. They need their
  own review pass before the flip.
- **Open PRs and any external references to old SHAs break** at the
  force-replace. With one contributor this is coordination cost, not loss.
- **Branch protection on `main` becomes available and must be configured
  immediately after the flip** (free on public repositories; a 403 today).
- **Everything published is published forever.** Apache-2.0 was already
  irrevocable per recipient; public visibility makes the recipient set
  unbounded. The scrub must therefore be verified before the flip, not
  repaired after it.
- **The repository description drops "(EE)"** — stale since ADR-0008 made the
  whole tree Apache-2.0.
- **Links to private counterpart repositories** (`vexa-stations`,
  `vexa-platform`, the business workspace) are annotated "(private)" so a
  public reader knows the 404 is expected, not broken.
