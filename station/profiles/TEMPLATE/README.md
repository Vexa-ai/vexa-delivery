# `<customer>` station profile — template

**Template. Copy this directory, fill it in, and keep your copy out of git.**
`station/profiles/*/` is gitignored except this template — same rule and same
reason as [`onboarding/`](../../../onboarding/TEMPLATE/README.md) and
`stations/`: a filled profile carries their registry hostnames, their namespace
and project names, and the shape of their cluster. See
[ADR-0008](../../../docs/adr/0008-repository-apache-2.md).

A profile is the values file that instantiates the station chart
([`station/chart/`](../../chart/)) for one customer, plus the contract their
publish gate must satisfy, plus a note on how the bundle reaches their cluster
in *their* motion (a merge into their config repo, a CLI run, an Argo
Application they already own).

## The three files

| File | What it carries |
|---|---|
| `values-<name>.yaml` | The station chart's values for their environment: `scope` (`cluster` or `namespace`), channel name, chart/signature repositories, registry host and port, the pinned channel public key, their namespaces, whether cluster admission is available, and the floor CronJob's thresholds. See [`station/chart/values.yaml`](../../chart/values.yaml) for every key and its default. |
| `contract-<name>.json` | The station half of the publish gate: publication mode, required evidence kinds, whether vendor approval is required. Shape: `vexa-internal-prod-2026`, in the stations ledger (a private repository) at `channels/vexa-internal/contracts/internal-prod.json` — contract instances are records and live there, not here (see [`contracts/README.md`](../../../contracts/README.md)). **We ingest this; we do not author it** — see [`stations/README.md`](../../../stations/README.md). |
| `README.md` | How the bundle reaches them, their one-time ops asks, who moves the production pin. |

## Two things to get right

- **`scope: namespace` is not a degraded `cluster`.** A tenant cannot read
  nodes or storage classes, so the floor reports cluster facts as UNKNOWN by
  design, and the PreSync verify gate — not cluster admission — becomes the
  enforcement point.
- **The channel public key is pinned, not fetched.** It arrives with the
  onboarding pack and is written into the values; a key that arrives over the
  same channel it is meant to verify proves nothing.
