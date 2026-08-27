# stations — their contract gates our publish

> **The durable record is in
> the stations ledger (a private repository)**, at
> `channels/<channel>/stations/<station>/`. A real customer's directory here is
> gitignored by design (below), so what lives here is a working copy that
> exists only on whichever laptop last ran an ingest — which is precisely why
> the record moved. `pilot`'s `contract.yaml` was landed there on 2026-08-25 and
> is the authority; the copy under `stations/pilot/` is derived from it.
>
> A contract instance moves **only by pull request on that repository**: its
> sha256 is the contract's identity and appears in every gate report rendered
> under it.

A **station** is one customer's environment as we hold it on the publisher
side: enough of their cluster's shape to *render what we are about to ship
into it*, plus the contract that says what a release must prove before it may
run there. One directory per customer.

The channel publisher ([`publisher/vexa_channel.py`](../publisher/vexa_channel.py))
answers *may this release exist?* — nine named cross-checks, C1–C9. This lane
answers the other half: **may this release be published at THIS station?**
Checks S1–S9, same refusal shape, exit 3.

The direction matters. A gate we own that we can also relax is a preference.
The station's contract is **the customer's file** — we ingest it, we do not
author it, and the gate report names the contract by `sha256`. That report is
the per-release guarantees document, generated rather than written.

## What a station is made of

**One file** — `station-report.yaml` — with named sections. The customer
produces it; `kit validate` writes it.

| Section | What it carries | Who writes it |
|---|---|---|
| the head | Station name, kit revision, Kubernetes server version, provider, namespaces, contract id + `sha256`, phase verdicts, redaction verdict. | kit |
| `profile` | Substrate facts: provider, k8s version, scope (`cluster`/`namespace`), namespace, storage class, PSA mode, whether a LimitRange/ResourceQuota is present, mirror host. Never credentials. | kit, from the cluster |
| `values` | The customer-local values ([`kit/profiles/vexa/customer-values.example.yaml`](../kit/profiles/vexa/customer-values.example.yaml)) with every credential replaced by a placeholder. Only the SHAPE travels. | customer, redacted by kit |
| `contract_document` | The station half of [`kit/verify/policy.example.yaml`](../kit/verify/policy.example.yaml) plus a `require:` list — the per-release guarantees this station demands. | the customer |
| `preflight_receipt` | The P1–P9 conformance run from [`kit/preflight/vexa_preflight.py`](../kit/preflight/vexa_preflight.py). | kit, on their cluster |
| `smoke_receipt` | The last end-to-end run at the station: dispatch → admit → transcript → teardown. | kit, on their cluster |
| `smoke_console`, `install_log` | The consoles, tail-trimmed with the count recorded. Present only when a run produced one. | kit, on their cluster |
| `sections[]` | The `sha256` and length of every section above. | kit |

`sections[]` is what makes it a report rather than a note: it names the
station, and its digests are checked against the section text on ingest, so a
section edited in transit is a refusal, not a surprise later.

**One file, and that is the design.** The person who approves this before it
leaves their perimeter has to read all of it, and six files in a tarball is a
review task where one commented document is a read. It goes back on every
release, so a document nobody finishes costs more each time.

## Producing one — `kit validate`

On the customer side, inside their perimeter:

```
python3 kit/validate/vexa_validate.py --namespace <ns> \
    --customer-values my-values.yaml --flows --out .
```

It runs preflight, runs the smoke, redacts the values, carries the contract
they maintain, and writes one commented `station-report.yaml`. Nothing leaves
their cluster except that file, and it carries no credential.

> **Rung, honestly:** the report format, the publisher side, and
> `kit/validate/vexa_validate.py` as one command are all merged on `main`. What
> is still synthetic is the **worked example**: the rehearsal report below was
> hand-assembled from this repo's own example files with **fabricated**
> preflight and smoke receipts, both labelled SYNTHETIC, and rendered by the
> packager's own writer. The first real report is a subscriber's, and it will
> not be committed here (see the `stations/` rule in `.gitignore`).

## Consuming one — `publisher/vexa_station.py`

### `ingest`

```
python3 publisher/vexa_station.py ingest --bundle station-report.yaml --station rehearsal
```

- **S1 report shape** — exactly one YAML document, a mapping, `schema_version:
  1`, and under a size a person could have read. (No archive, so nothing to
  traverse out of — the traversal, link and single-root checks lost their
  subject rather than being dropped.)
- **S2 completeness** — every section role this report *kind* requires is
  present and non-empty.
- **S3 manifest identity** — the report names *this* station, every declared
  section hashes to the text that is there to read, nothing undeclared rides
  along, and a top-level key that is neither a manifest field nor a declared
  section is a refusal.
- **S4 no plaintext secrets** — **defense in depth.** The customer redacts;
  we refuse to *hold* what they missed. Each section is parsed back into its
  own format — values as YAML, profile as an env file — and scanned for
  secret-shaped keys carrying real values (a key ending in `Name`/`Ref`/`Path`
  is a reference, not a credential), plus credential-shaped patterns anywhere
  in the bytes (PEM private keys, `sk-`/`sk-ant-`, `ghp_`, `AKIA…`, `AIza…`,
  `xox…`, JWTs, `client-key-data`). **A refusal never prints the value** —
  section, line and rule only, so the refusal text is safe to paste into an
  issue.

On pass it copies the report verbatim into `stations/<name>/` and writes
`ingest-receipt.json` beside it with the ingested-at stamp, the report's own
digest, and the section digests. The sections are **not** written back out as
files: a directory of derived copies is a second version of what the customer
sent, and it can disagree with the first.

### `gate`

```
python3 publisher/vexa_station.py gate --station rehearsal \
    --chart work/chart/vexa-0.12.26.tgz \
    --evidence work/evidence/v0.12.26.json
```

- **S5 render** — `helm template` with the station's `values` section over the
  chart defaults (written to a temporary file for the length of the render and
  no longer). Redacted placeholders are fine: the gate reads shapes, not
  credentials. A render failure is a refusal — better here than in their Argo.
- **S6 resources** — every container (including `initContainers`) declares
  cpu **and** memory, requests **and** limits. Anchored to
  [`Vexa-ai/vexa#1005`](https://github.com/Vexa-ai/vexa/issues/1005): a
  LimitRange does not refuse an undeclared container, it silently squeezes it
  to 64Mi. Survival in the customer's LimitRange is a property of what we
  ship, not of their cluster.
- **S7 no hostPath** — a host mount reaches out of the tenancy the station
  promised.
- **S8 digest-pinned** — every image reference ends in `@sha256:<64 hex>`.
  A mutable tag means the bytes that passed the gate are not the bytes that
  run.
- **S9 contract** — every `require:` item is either matched by a guarantee in
  `--evidence` or explicitly waived.

Exit 0 on pass, **exit 3 on refusal**, and a report at
`stations/<name>/gate-report-<date>.md` either way — the refusal is evidence
too. A second run on the same day rotates the earlier report aside rather than
overwriting it: a refusal that vanishes when someone re-runs with a waiver is
exactly what an audit wants to see.

### Evidence and waivers

`--evidence` is a JSON file listing what this release actually proved:

```json
{"release": "v0.12.26", "guarantees": ["german-teams-meeting-validated", "images-digest-pinned", "no-hostpath"]}
```

A `require:` item with no matching guarantee refuses the publish — unless a
human waives it, and a waiver must say why:

```
--waive german-teams-meeting-validated \
--reason "de-AT Teams run slips to the 2026-08-26 window; staging tier only"
```

Waivers are never silent: printed loudly on stderr, written into the gate
report under their own heading, and carried as *"a waiver is a promise nobody
checked"* so the next release can be asked whether it is still needed. An
unpaired `--waive` (or a reason that says nothing) is itself a refusal.

## The contract's `require:` list

The station half of the contract, added below the channel-entry half:

```yaml
contract_id: rehearsal-2026-01

# channel-entry half — read by kit/verify
require_vendor_approval: true
require_publication_mode: published
allow_break_glass: false

# station half — read by publisher/vexa_station.py gate
require:
  - german-teams-meeting-validated
  - images-digest-pinned
  - no-hostpath
```

Item names are the customer's vocabulary, not ours — the gate matches strings
and refuses what it cannot match, which is the point: a guarantee we cannot
name we cannot claim. Agree the list with the customer, then treat edits like
contract changes, because they are.

## What is committed here

[`rehearsal/`](rehearsal/) — the SYNTHETIC worked example: one
`station-report.yaml`, with a gate report against the packaged 0.12.26 chart.
It exists so the shape is readable in one sitting.

**Real customer stations are not committed.** The `values` section is a
customer's environment even after redaction, and receipts name their clusters.
Keep them under `stations/<name>/` locally; the ingest receipt and the gate
report are the artefacts that travel, attached to the release.
