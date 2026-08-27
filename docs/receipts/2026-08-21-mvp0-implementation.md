---
title: "MVP0 implementation state"
description: "What is built, what was proven live on the Akamai cluster, and what is not done."
---

The milestone is [#7](https://github.com/Vexa-ai/vexa-delivery/issues/7). This file records what
is built, what was proven live, and what is not done — stated at the rung the evidence supports.

**Proof cluster:** a throwaway LKE cluster, us-sea, k8s 1.36.3, 2× g6-standard-4 (8 GB),
tagged `throwaway` (cluster id and name in the session log, not here). Registry: in-cluster `registry:3` with a self-signed cert. Signing: an
ephemeral test key (the real key ceremony is a founder gate). No production credential was used
at any point.

---

## 1 · What is implemented

### Publisher (`publisher/vexa_channel.py`)

| Verb | What it does |
|---|---|
| `fetch` | Pulls the release archive, its SLSA provenance bundle and the Sigstore trusted root via `gh`. |
| `build` | Assembles a channel entry from the tag's candidate map + the internal delivery receipt; nine named cross-checks (C1–C9), any of which refuses the entry. |
| `verify` | Re-runs every offline check against a built entry. |
| `push` | Pushes the entry artifact via `oras`, cosign-signs it, moves the channel tag. |
| **`chart`** *(new)* | Extracts the OSS chart at the tag, **bakes a digest pin into every image** from the candidate map — including the three the runtime spawns on demand (`browserImage`, `agentImage`, `agentWorkerImage`) — merges the node baseline, stamps an Argo-native sync hook onto the migrations Job, `helm package`s and pushes it to the channel as an OCI chart. |
| **`sign-images`** *(new)* | cosign-signs every digest in the candidate map into the channel's signature repository, in the legacy signature format Kyverno 1.19 reads. |

Verified in the packaged chart: `vexa-0.12.23.tgz` carries
`gateway.image.tag: v0.12.23@sha256:514ba270…` (and the same shape for admin-api, meeting-api,
runtime, agent-api, terminal) plus `runtime.browserImage:
vexaai/vexa-bot:v0.12.23@sha256:2bd879c6…`. Every digest equals the delivery receipt's.

### Kit (`kit/`, Apache-2.0 as of [ADR-0005](../adr/0005-kit-license-split.md); whole repo as of [ADR-0008](../adr/0008-repository-apache-2.md))

- **`profiles/vexa/node-baseline.yaml`** — the *delivered toggles* (never image identity; digests
  are baked per release by the publisher): `imagePullPolicy: IfNotPresent` (digest-pinned refs
  make `Always` pointless and Hub-quota-expensive), `gateway.replicaCount: 1`,
  `migrations.enabled: false` (see the finding in §4).
- **`profiles/vexa/customer-values.example.yaml`** — the only file the customer edits; injected
  into the subscription as `valuesObject`, applied over every release, never leaves their cluster.
- **`argocd/applicationset.yaml`** — now consumes the channel **chart** over helm-OCI:
  staging tracks `*` (newest published version = the pointer), production tracks the customer's
  pin. `ServerSideApply=true`; `ignoreDifferences` on StatefulSet `volumeClaimTemplates`.
- **`install.sh`** — gained `--customer-values` (rendered into the ApplicationSet) and
  registration of the helm-OCI chart repository alongside the entry-artifact repository.

### Operations

- **`RUNBOOK.md`** — the per-release manual crank, founder gates marked ⛔.
- **`onboarding/README.md`** — the subscriber pack template (credential · `channel.pub` · docs ·
  customer-values template · support address).

---

## 2 · What was proven live

1. **One-command install** on a bare cluster: preflight PASS → Argo CD v3.5.1 → Kyverno v1.19.0 →
   both admission policies → chart repo registration → subscription. Both Applications generated.
2. **The channel delivered a real release.** `vexa-enterprise-staging`: **Synced / Healthy,
   revision `0.12.23`**, 12 pods Running — gateway, admin-api ×2, meeting-api ×2, agent-api,
   runtime, terminal ×2, postgres, redis, minio (+ the minio-init Job Completed).
3. **Every workload runs a digest, not a tag.** Live readback:
   `vexaai/v012-gateway:v0.12.23@sha256:514ba2702ab03da4f90a6df58893cfec634ee61b913a1500ee6b56714dca89f2`.
4. **Admission is genuinely fail-closed — demonstrated, not asserted.** The control plane sat in
   `ContainerCreating` and would not start while the image signatures were missing; Kyverno
   refused them. When `sign-images` completed, **all twelve pods came up on their own**, with no
   manifest touched and no sync command issued. That is the fail-closed policy and the
   self-healing pull in one observation.
5. **The customer gate holds by construction.** `vexa-enterprise-prod` exists, tracks `UNPINNED`,
   and syncs nothing. Only a pin move — the customer's act — changes that.
6. **Sync waves work.** First sync brought up postgres/redis/minio, then the control plane; no
   ordering failure, no deadlock.

---

## 3 · Defects found and fixed during the build

| Defect | Fix |
|---|---|
| The Argo hook stamp landed at the wrong indent → `YAML parse error on job-migrations.yaml` at render time. | Corrected the stamp's leading indentation; the packaged chart is re-verified structurally after every `chart` run. |
| **cosign hung indefinitely** (observed blocked in `wait4` on a Docker credential helper that does not exist on this machine) — the first signing run produced zero signatures in 15 minutes with no error. | `cosign_env()` now points `DOCKER_CONFIG` at an isolated empty config. All ten digests then signed in seconds. |
| Argo CD refused the self-signed test registry over TLS for both the entry repo and the chart repo. | Repo secrets marked `insecure` for the test rig; production uses a real CA (`--registry-ca` covers the corporate-CA case for Kyverno). |

---

## 4 · Finding worth filing on the product

**The OSS chart's migrations Job cannot succeed on 0.12.x.** It fails with
`ModuleNotFoundError: No module named 'meeting_api.database'` and retries to `backoffLimit`. The
stack is unaffected because the services create their schema on boot — verified live: six tables
(`api_tokens`, `meeting_sessions`, `meetings`, `platform_settings`, `transcriptions`, `users`)
exist with the Job disabled. The node baseline therefore ships `migrations.enabled: false`, and
the publisher's Argo hook stamp stays in place for the first release that ships real migrations.

Anyone installing the OSS chart with defaults meets this. It is a product defect our own delivery
testing caught before a customer did — the conveyor doing its job — and belongs on
`Vexa-ai/vexa`.

---

## 5 · Not done (against the #7 acceptance)

- **Bot spawn not yet driven.** The stack is up; no meeting bot has been launched and admitted.
  This is the remaining piece of acceptance item 1.
- **No real channel entry published.** The chart and signatures are live, but `entry.json` for
  0.12.23 is still the dry-run golden signed with a test key. The first real publication needs
  the key ceremony — a founder gate.
- **Test infrastructure, not production.** In-cluster registry rather than GHCR; ephemeral test
  key rather than the channel key.
- **Acceptance items 2 and 3 pending 0.12.24**: staging self-promotion across a real release
  boundary, and one rollback by pin.
- **Teardown:** the proof cluster is still standing for the 0.12.24 leg; it is tagged
  `throwaway` and is destroyed when the acceptance completes or the work pauses.
