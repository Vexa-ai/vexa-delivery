# vexa-delivery

**Deliver self-hosted software into sovereign clusters — signed, attested, pull-only.**

vexa-delivery is the delivery machinery for [Vexa](https://github.com/Vexa-ai/vexa), the
open-source meeting-intelligence platform. It keeps a self-hosted deployment current without
the vendor ever touching the customer's environment: releases are published into a channel as
signed, digest-pinned entries; the customer's cluster pulls them, verifies them, and promotes
them under its own attestation.

## How it works

1. **Publish** — the publisher builds a channel entry: digest-pinned chart and images, cosign
   signatures, and an evidence bundle (gate reports, station verdicts) attached to the entry.
2. **Pull** — the subscribing cluster syncs the channel on its own schedule. Nothing is ever
   pushed; the vendor holds no access.
3. **Verify** — the kit's policy validates every entry against a contract: signatures, digest
   pinning, evidence completeness. Admission control independently re-verifies before a byte runs.
4. **Promote** — the update rolls automatically on staging. The operator runs their validation,
   attaches their own attestation, and the release promotes to production — one auditable
   artifact per promotion.

The environment stays deterministic end to end: what runs is exactly what was signed, and every
promotion carries the evidence that justified it.

## What's in the repository

| Path | What it is |
|---|---|
| `publisher/` | builds, signs and publishes channel entries; manages subscriber credentials |
| `kit/` | the customer-side kit: bootstrap, preflight, install, smoke — five steps, one command each |
| `station/` | station runners that validate entries in real environments and report verdicts |
| `contracts/` | the delivery contracts entries are validated against |
| `spec/` | the channel format and conformance specification |
| `docs/` | operator documentation and the ADR series |

## Design principles

- **Pull-only.** The vendor can never push into a customer environment and holds no credentials to it.
- **Verify before trust.** Signatures and digests are checked by the customer's own policy, with
  keys they pin — independently of the vendor.
- **Evidence over assertion.** Every entry carries its validation evidence; every promotion is
  attested. All of it is verifiable offline, inside the customer's perimeter.
- **No agent.** The customer-side footprint is configuration for standard components — Argo CD,
  Kyverno, cosign — readable in an afternoon. Nothing proprietary executes in the customer's
  perimeter.

## Status

The channel machinery runs Vexa's own cloud production — this repository's publisher and
stations deliver the releases we operate ourselves.

Built for Vexa; the pattern — signed pull-only channels, attestation-gated promotion, evidence
receipts — is general. Extracting a vendor-neutral core is on the roadmap.

## Getting started

Start at [docs/install](docs/install.mdx) — five steps from a kit you verify with your own key.

## Contributing

Contributions are welcome under Apache-2.0 (inbound = outbound). Commits require a
`Signed-off-by` line (DCO). See [CONTRIBUTING](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). © Vexa.ai Inc.
