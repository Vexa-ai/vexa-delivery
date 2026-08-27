---
title: "ADR-0002 — Channel format"
description: "Signed OCI entries, stations as subscriptions, the signing model left open."
---

**Status:** accepted (signing model explicitly OPEN) · **Date:** 2026-08-21

## Context

Handoff §5 fixes the evidence chain: Freight = digest set + provenance; the channel publishes a
signed manifest with evidence refs; the customer verifies at admission. The internal
prod-delivery-receipt.v1 schema (biz lifecycle state) is the proven receipt grammar to generalize.
v0.12.23 is the worked example: tag `e59874bc`, candidate map at the tag (rc.21, build `2dec3082`,
validation `ccd6da52`), compound delivery receipt, SLSA source-archive provenance.

## Decisions

1. **A channel entry is one OCI artifact** (`application/vnd.vexa.channel-entry.v1+json`):
   `entry.json` (the signed subject, schema `channel-entry.v1`) plus the digest-listed evidence
   bundle. Immutable per-release tags carry identity; one floating tag (`current`) carries
   position, moved by same-byte descriptor copy — the alias discipline already proven in
   `vexa:scripts/registry-manifest-alias.mjs`.
2. **The map is the identity carrier** (one carrier per fact): `images[]` in the entry is derived
   from the tag's `candidate-images.json`, whose sha256 must equal the delivery receipt's packet
   pin. The publisher refuses on any disagreement (checks C1–C9 in
   `publisher/vexa_channel.py`).
3. **Provenance claims at the rung that exists.** SLSA v1 covers the source archive (verified
   working offline with both cosign and gh against v0.12.23 on 2026-08-21); per-image attestations
   do not exist yet (verified: attestation store 404s on image digests), so every entry declares
   `image_provenance` in `evidence_absent` until vexa PRD §12 C1 lands. The schema makes stating
   absences mandatory (`evidence_absent` is required).
4. **Stations are channel subscriptions** — founder ruling 2026-08-21 (this session):
   *"we can and will chain this deliveries as [dev] → staging → vexa cloud prod → enterprise
   staging → [they manage the gate] → enterprise prod."*
   The same conveyor mechanics serve every hop:
   - **staging** and **vexa cloud prod** are our own subscriptions (customer #0) — prod pulls what
     staging's evidence permits;
   - **enterprise staging** subscribes to the channel pointer (`current`);
   - **enterprise prod** follows a **customer-held pin**, and moving that pin is *their* gate —
     their approval, their soak thresholds, their maintenance windows. We never move it and cannot.
   Nothing in the entry format is position-dependent, so one entry serves all stations; per-station
   policy is the subscriber's configuration (kit for the enterprise side, our own controller — M3 —
   for the internal side).
5. **Break-glass is data, not a bypass**: an entry with an incomplete chain requires an explicit
   `break_glass` record (named actor, reason, approver, receipt) and the publisher refuses
   otherwise. Audited-and-visible per the Attestation-Conveyor correction (no *unaudited* bypass).
6. **Publication is founder-gated in the schema**: `publication.mode: published` requires
   `approved_by` + `approval_receipt`; `test_key` signing is valid only for `dry_run`.

## The open decision: signing model

Keyless (Sigstore/Fulcio/Rekor, no long-lived secret, requires trust in the public
infrastructure) vs long-lived key (offline-friendly, but the key becomes the single fatal secret —
the condition TUF exists for). The choice needs a rotation and revocation story and belongs to the
founder with the first real publication (PRD §12 C1/C8). Until then: `test_key` mode, `dry_run`
only, enforced by schema. The worked example uses an ephemeral test key generated at build time
and never committed.

## Consequences

- The customer kit (M2) verifies: entry signature, bundle digests, map pin, source provenance —
  all offline; admission re-verifies image signatures and digest-pinning independently.
- The internal delivery receipt keeps its own schema and life; the channel entry embeds it as
  evidence rather than replacing it. When the receipt schema evolves (v2), the entry schema pins
  which version it understands.
