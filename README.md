# vexa-delivery

**Your running self-hosted [Vexa](https://github.com/Vexa-ai/vexa) service that stays up to
date.**

1. **Bring your own cloud** — k8s, GCloud, AWS, OpenShift. A namespace in a cluster, or an
   entire fresh one.
2. **Install Vexa Delivery.**
3. **Set it to consume the public images — or a private channel.**
4. **Cluster running, self-updating on new images published.**

Everything is open source, images public on Docker Hub. Nothing reaches in: your cluster
pulls, verifies with keys you pin, and promotes to production on your attestation.

> **Not built yet.** Every channel is credentialed today — the free one in step 3 is
> [issue #9](https://github.com/Vexa-ai/vexa-delivery/issues/9), not a running service.
> What else is and is not proven: [what's proven, and where](docs/tested.mdx).

Already running Vexa? Start at [docs/upgrade](docs/upgrade.mdx).

## How it works

Publish → gate → channel → pull → admission → smoke → station report → back to the gate.
The loop, with what each part checks and who holds it, is in
[docs/how-it-works](docs/how-it-works.mdx).

The environment stays deterministic end to end: what runs is exactly what was signed, and
every promotion carries the evidence that justified it.

## Channels — open or private

Everything Vexa runs on is open source and publicly published — images on Docker Hub,
charts and code in the open repositories.

- **The open channel** carries what upstream publishes: your deployment stays current with
  the latest open-source release, automatically. Community support. **It is not running
  yet** ([issue #9](https://github.com/Vexa-ai/vexa-delivery/issues/9)); every channel is
  credentialed today.
- **A private channel** is for what upstream does not have yet — a fix your environment
  needs now. We build it into your channel so you have it immediately, and the same change
  goes upstream as a pull request, so you converge back to the open release instead of
  carrying a fork. Releases arrive attestation-complete with the full evidence set, gated
  against your own specification, with a support lane behind it.

The channel is two-way. On the open channel the way back is GitHub issues, plus any station
report you choose to share. On a private channel it is part of the contract: a ticket lane
with response commitments and the [telemetry rung you set](docs/telemetry-ladder.mdx) —
never content.

The software is identical on both paths, and switching paths is a subscription change, not a
migration.

## What's in the repository

| Path | What it is |
|---|---|
| `publisher/` | builds, signs and publishes channel entries |
| `kit/` | the subscriber-side kit: bootstrap, preflight, install, smoke, validate — five steps, one command each |
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
- **Standard components, plus a named few of ours.** The subscriber-side footprint is Argo
  CD, Kyverno and cosign, plus three things of ours, each named with what switches it on:
  the PreSync verifier (a shell script on Alpine that reads the channel and writes nothing —
  **off** unless installed with `--verifier-image`); on the station-bundle path, the floor
  check (**on** by default, every 10 minutes; it writes one ConfigMap holding its verdict)
  and the receipt sender (**off** by default; the only component that reaches outward, and
  only to the channel host the cluster already pulls from). Configuration and code you can
  read in an afternoon, running in the subscriber's own perimeter under their own control.
  Full table: [docs/security](docs/security.mdx).

## Status

This machinery runs Vexa's own cloud production and delivers Vexa releases today. Built for
Vexa; the pattern — signed pull-only channels, attestation-gated promotion, evidence
receipts — is general.

## Getting started

Two doors. **Already running Vexa?** Start at [docs/upgrade](docs/upgrade.mdx) — one read-only
script writes the report your bundle gets built to fit; that is the whole first step.
**Nothing running yet?** Start at [docs/install](docs/install.mdx) — five steps from a kit you
verify with your own key. Channels are credentialed today, both paths —
[request access](mailto:dmitry@vexa.ai) and your credential, channel key and bootstrap
parameters arrive by mail.

## Contributing

Contributions are welcome under Apache-2.0 (inbound = outbound). Commits require a
`Signed-off-by` line (DCO). See [CONTRIBUTING](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). © Vexa.ai Inc.
