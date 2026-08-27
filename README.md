# vexa-delivery

**Signed, pull-only delivery channels for self-hosted software.**

Your cluster stays yours. vexa-delivery keeps a self-hosted deployment current through a
channel your cluster pulls from — the open channel, free for everyone, or your enterprise channel: every entry is digest-pinned and cosign-signed, verified
inside your perimeter against keys you pin, rolled automatically on staging, and promoted
to production only under your own attestation. The publisher holds no access to your
environment — nothing is ever pushed, and the only thing that travels back is a report you
create and choose to send.

Everything in this repository is Apache-2.0: the publisher that builds and signs channel
entries, the kit a subscribing cluster installs, and the station runners that validate
entries in real environments. [Vexa](https://github.com/Vexa-ai/vexa), the open-source
meeting-intelligence platform, is the first workload — this machinery delivers Vexa's own
cloud production.

## Four moves

**Your running self-hosted Vexa service that stays up to date:**

1. **Bring your own cloud** — Kubernetes anywhere: GKE, AWS, OpenShift; a namespace in an
   existing cluster or an entire fresh one. Nothing Vexa-specific.
2. **Install Vexa Delivery.**
3. **Set it to consume the public images — or your enterprise channel.**
4. **Your cluster runs and self-updates as new images are published.**

## How it works

1. **Publish** — a channel entry: digest-pinned chart and images, cosign signatures, and an
   evidence bundle (gate reports, station verdicts) attached to the entry.
2. **Pull** — the subscribing cluster syncs the channel on its own schedule. Nothing is
   ever pushed; the publisher holds no credentials to the cluster.
3. **Verify** — the kit's policy validates every entry against a contract: signatures,
   digest pinning, evidence completeness. Admission control independently re-verifies
   before a byte runs.
4. **Promote** — the update rolls automatically on staging. The operator runs their
   validation, attaches their own attestation, and the release promotes to production —
   one auditable artifact per promotion.

The environment stays deterministic end to end: what runs is exactly what was signed, and
every promotion carries the evidence that justified it.

## Two ways to stay current

Everything Vexa runs on is open source and publicly published — images on Docker Hub,
charts and code in the open repositories. There is nothing to be locked into: you can
consume all of it without us, forever.

- **The open channel** delivers those public releases exactly as published — digest-pinned,
  signed, pulled from Docker Hub — so a self-hosted deployment stays current automatically.
  Community support.
- **Your enterprise channel** is operated with us for your company: releases arrive
  attestation-complete with the full evidence set (gate reports, station verdicts from real
  environments), gated against your own specification before anything reaches you, with a
  support lane behind it.

The channel is two-way, and the return path differs. On the open channel, the way back is
GitHub issues — plus any station report you choose to share. On your enterprise channel, the
return path is part of the contract: a ticket lane with response commitments, and the
[telemetry rung you set](docs/telemetry-ladder.mdx) — from silent to signed receipts to
health counters to diagnostics, never content. The more your side chooses to send back, the
faster your deployment improves — that bandwidth is what your enterprise channel is for.

Same machinery, same kit, same verification on both paths. The software is identical —
features never move behind a paywall — and switching paths is a subscription change, not a
migration.

## What's in the repository

| Path | What it is |
|---|---|
| `publisher/` | builds, signs and publishes channel entries |
| `kit/` | the subscriber-side kit: bootstrap, preflight, install, smoke — five steps, one command each |
| `station/` | station runners that validate entries in real environments and report verdicts |
| `contracts/` | the delivery contracts entries are validated against |
| `spec/` | the channel format and conformance specification |
| `docs/` | operator documentation and the ADR series |

## Design principles

- **Pull-only.** The publisher can never push into a subscribing environment and holds no
  credentials to it.
- **Verify before trust.** Signatures and digests are checked by the subscriber's own
  policy, with keys they pin — independently of the publisher.
- **Evidence over assertion.** Every entry carries its validation evidence; every promotion
  is attested. All of it is verifiable offline, inside the subscriber's perimeter.
- **No agent.** The subscriber-side footprint is configuration for standard components —
  Argo CD, Kyverno, cosign — readable in an afternoon. Nothing of the publisher's executes
  in the subscriber's perimeter.

## Status

This machinery runs Vexa's own cloud production and delivers Vexa releases today. Built for
Vexa; the pattern — signed pull-only channels, attestation-gated promotion, evidence
receipts — is general.

## Getting started

Start at [docs/install](docs/install.mdx) — five steps from a kit you verify with your own
key. Channels are credentialed today, both paths — [request access](mailto:dmitry@vexa.ai)
and your credential, channel key and bootstrap parameters arrive by mail.

## Contributing

Contributions are welcome under Apache-2.0 (inbound = outbound). Commits require a
`Signed-off-by` line (DCO). See [CONTRIBUTING](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). © Vexa.ai Inc.
