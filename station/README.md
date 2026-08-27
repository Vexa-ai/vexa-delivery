# The standing station — declaration of record

The internal station (LKE `vexa-channel-station`) as declared: the
ApplicationSet that subscribes `vexa-staging` (follows `*`) and `vexa-prod`
(UNPINNED until approval) to the `vexa-internal` channel, plus the contracts
in `../contracts/`. Workloads on the station come ONLY from Argo reconciling
this declaration against the channel — never from hand applies. Changing the
station = editing here, then `kubectl apply -f station/applicationset.yaml`.
Renaming an element `env` is app identity: it tears down and recreates that
station's workloads (observed 2026-08-21; the station rebuilt itself from the
channel alone).

## What the operator provides, and what the chart provides

The bundle is machinery. Three objects it deliberately does **not** author:

| Object | Namespace | Why the chart does not own it |
|---|---|---|
| **the station credential** `Secret` (default `vexa-station-credential`, keys `username`/`password`) | `prodNamespace` | it is a credential |
| **the report contract** `ConfigMap` (`receiptSender.contractConfigMap`, key **`contract.yaml`**) | `prodNamespace` | it is the customer's own declaration of what may leave their perimeter |
| the pinned channel public key, mirror location, tool image digests | inline in `root-app.yaml` | site facts |

**The report contract is not the entry contract, and 1.0.5 conflated them.**
Two different documents wear the word *contract*:

- **the report contract** — `contract.yaml`, carrying `report_scope`
  (tier · trigger · destination · allowed_sections). The **receipt sender** mounts
  it at `/contract/contract.yaml` and refuses to collect above the tier it
  declares. The chart **references** it by name and never renders it: a
  `report_scope` we authored would make Vexa the author of the document that
  bounds Vexa.
- **the entry contract** — `policy.json`, carrying publication mode, required
  evidence kinds and required attestations. The chart **does** render these
  (`vexa-contract-staging` / `vexa-contract-prod`, in the **argocd** namespace)
  for the PreSync verify gate that the subscription's Applications carry.

Through chart 1.0.5 `receiptSender.contractConfigMap` defaulted to
`vexa-contract-prod` — an entry contract, in another namespace, under another
key. The mount could not have worked. 1.0.6 removes the default, names the key
in the volume so the kubelet refuses rather than the tool failing three layers
later, and refuses the render outright if the value is empty.

A minimal report contract:

```yaml
contract_id: vexa-prod-report-2026
report_scope:
  schema: report.v1
  tier: 1                       # 0 silent · 1 release · 2 health · 3 usage
  trigger: explicit-command-only   # `scheduled` is what authorises a CronJob
  destination: channel.vexa.ai
```

```bash
kubectl -n vexa-production create configmap vexa-station-contract \
  --from-file=contract.yaml=./my-report-contract.yaml
```

## Installing the machinery without the subscription

`subscription.enabled` (default **true**) gates the ApplicationSet *and* the
entry-contract ConfigMaps its PreSync gate reads — one concept, one switch.
An estate already running Vexa by another path sets it `false` and gets the
receipt sender, admission and the floor without a second Vexa stack appearing
in namespaces its contract may not permit.

## The sender's image

`receiptSender.image` points at the **kit runtime image**
(`../kit/runtime/Dockerfile`) — python3 · PyYAML · jsonschema · kubectl · oras,
plus the kit tree at `/kit`. Digest-pinned and cosign-signed into the station's
`signatureRepository`, because its reference contains `vexaai/` and the
station's own Kyverno policies check exactly that. The channel's `kit` artifact
is a **tarball** for a workstation; a Job cannot exec a tarball.
