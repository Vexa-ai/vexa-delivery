# Receipt — clean-pull of the production estate onto an empty cluster

**Date** 2026-08-25 · **Cluster** throwaway LKE `647376` (`us-sea`, 3× g6-standard-4, tag `throwaway`), destroyed at the end of this run · **Channel** `channel.vexa.ai/vexa/channel/vexa-internal` · **Entry** `0.12.22-estate-20260825`, seq 1, digest `sha256:42fcfa3a488afb29fb8724451d7edef90613e39f37777e8d59228d58e7e51f40`

**Production was never touched.** Every read against `vexa-production` and `monitoring` was `get`/`describe`/`helm get`. No object was created, patched or deleted in either namespace. `vexa-staging` was not touched at all.

---

## What this proves, in one sentence

The production estate — all 115 objects — **resolved and applied onto an empty cluster from the channel's signed artifacts alone**, with images pulled from `channel.vexa.ai` and Kyverno verifying every signature, after exactly two operator acts: `kit/install.sh`, and seeding the cluster's Secrets.

**And what it does not prove: that the estate then WORKS.** 16 of 24 workloads reached `Running`. The rest failed, and every failure is written up below. This receipt is the finding list, not a green tick — the clean pull was worth running precisely because it produced them.

## The validation contract

Everything below was validated at a **declared fidelity**, not against a vague "test environment". The contract is `station/validation-contract-internal.yaml`, id `vexa-internal-estate-2026-08-25`, `sha256 f66b2a938661d95c8558979b06efc7bf52dc32457be4d70b1dbbe0c4cde90f1f`, and that hash is **inside the signed entry** (`estate.validation_contract`), so it cannot drift from the release it describes.

The rule it states, and which the publisher now enforces by refusing an entry that breaks it: **real by default; each double carries a justification; an unjustifiable double is a contract violation.**

| Dependency | Fidelity | Why |
|---|---|---|
| Managed Postgres | **double** — in-cluster `postgres:16-alpine`, schema from the chart's own migration, data empty | Real is *harmful*: a migration hook from a pulled chart would run DDL against live customer transcripts |
| Stripe | **real** (test mode, sandbox account) | *Deviation from the brief, deliberate.* The brief said stripe-mock. A test-mode sandbox is the real API, real signing, real error semantics, and moves no money — higher fidelity than a mock, and it satisfies "real is harmful" without being harmful |
| Transcription tier | **real** | The dev tier, real URL and token. No reason to fake a service whose realness is free |
| Model gateway | **real** | OpenRouter, real credential from the vault |
| Object storage | **double** — separate throwaway bucket | Real is harmful: the backup CronJob would write into the production backup path |
| DNS / load balancer | **real** by construction | The cluster provisions its own NodeBalancer from the estate's own LoadBalancer Service |
| Mail | **absent** | Real means sending mail to real recipients from a validation run. A dummy sink was rejected: it would make "mail works" look proven |
| Docker Hub / upstream registries | **absent — and this absence IS the proof** | If the run can reach Docker Hub, a missing mirror is invisible: the pull succeeds upstream and looks green |
| GPU transcription workers | **absent** | No GPU pool on the throwaway |

Four real, two doubles, three absent, **zero dummy endpoints**. Claims the absences make unavailable are enumerated in the contract's `unproven_claims` and are not asserted anywhere in this receipt.

---

## The findings — in the order the cluster produced them

Each of these was invisible until an estate was pulled onto a cluster that had nothing. That is the argument for running this proof at all.

### 1. The mirror was decoration. Nothing pulled from it.

**Neither the `vexa-platform` chart nor the vendored `vexa` subchart has any registry-prefix mechanism** — no `global.imageRegistry`, no `image.registry` key, nothing. Every image is pinned as a bare Docker Hub reference (`vexaai/v012-gateway@sha256:…`, `caddy@sha256:…`).

So the channel can mirror every image the estate needs — 13.01 GB of it — and the estate still pulls from `docker.io`.

**For us that is invisible**: Docker Hub is reachable, the pods come up, everything looks correct. **For a customer whose firewall allows exactly one host — the entire premise of mirroring — the install simply fails, at their site, on their maintenance window.**

Fixed by `chart/vexa-platform/values-channel-images.yaml` (Vexa-ai/vexa-platform#353): 33 references rewritten. Verified by rendering the packaged channel chart:

```
objects: 115
non-channel images:  0
```

### 2. Nothing could pull anyway: the kit never provisioned a kubelet pull secret

Argo's repo-server fetches charts with a **repository Secret in the `argocd` namespace**. That is what the kit created. But images are pulled by the **kubelet, in the workload namespace, from `spec.imagePullSecrets`** — and no such Secret existed.

Every pod:

```
FailedToRetrieveImagePullSecret: Unable to retrieve some image pull secrets (vexa-channel-registry)
Failed to pull image "channel.vexa.ai/…/images/redis@sha256:7aec734b…":
  authorization failed: no basic auth credentials
```

**after a sync Argo reported as `Succeeded`, `115/115 Synced`, `phase: Succeeded`.** From Argo's side it *was* successful — it applied every object correctly. The failure is one layer below the layer that reports success.

The kit created a namespace registry credential only when `--verifier-image` was passed, and named it for the PreSync verifier. Nothing existed for the kubelet, because until the channel carried images nothing needed one.

Fixed in `kit/install.sh`: the credential is now created unconditionally with `--registry-user`.

### 3. Four workloads have no `imagePullSecrets` at all, and no values key to give them one

`caddy`, `capacity-resize`, `collector-watchdog`, `system-host-labeler` render with none. Correct while their images were public; fatal against an authenticated channel, and **unreachable by any values overlay** because the chart has no key.

Fixed in the kit by attaching the pull secret to the namespace's ServiceAccounts — the kubelet applies it to every pod using that account, so it covers workloads whose chart forgot one **without the chart having to change first**. The chart should still be fixed.

### 4. `templates/cronjob-transcription-check.yaml` hardcodes `dockerhub-secret`

Two sites, no values path. The two `txcheck` CronJobs carry a credential name the channel does not provision. Filed as [`Vexa-ai/vexa-platform#359`](https://github.com/Vexa-ai/vexa-platform/issues/359) (private), and shipped as a **declared hole inside the signed entry** (`estate.known_holes[0]`) so a subscriber reads it before hitting it.

### 5. The published estate carries OUR PRODUCTION DATABASE HOSTNAME

This is the one that matters most.

`vexa.database.host` is a chart value, baked into the published chart, reading:

```
DB_HOST = a460746-akamai-prod-6818120-default.g2a.akamaidb.net
```

A subscriber who installs this estate and does not know to override it **points their cluster at our production Postgres.** On this run the admin-api did exactly that:

```
asyncpg.exceptions.InvalidAuthorizationSpecificationError:
  no pg_hba.conf entry for host "<throwaway-host>", user "vexa_app", database "vexa"
```

It was rejected because the managed instance's `pg_hba` does not list the throwaway cluster's egress IP. **That is a firewall saving us, not a design.** The estate had no per-cluster default and no required-value gate.

`database.host` must become a **required customer value** that the chart refuses to render without — the subchart already has the `required` helper for exactly this when `postgres.enabled=false`; the parent supplies a default that silently satisfies it.

### 6. The channel does not deliver the CRDs its own content depends on

The first sync failed:

```
failed to discover server resources for group version monitoring.coreos.com/v1
```

The estate renders a `ServiceMonitor`, and the CRD that defines it comes from kube-prometheus-stack — which the channel **does not carry** (declared hole `kube-prometheus-stack-not-mirrored`). An undeclared ordering dependency: the estate cannot install until a chart from a *different* source is installed first, which also breaks the one-host claim for monitoring.

### 7. `targetRevision: "*"` silently matches nothing when the chart version is a prerelease

The chart was first published as `0.1.0-estate.20260825`. Argo:

```
invalid revision: version matching constraint not found in 1 tags
Sync Status: Unknown    Health Status: Healthy
```

**`Healthy` while resolving nothing.** Semver `*` does not match prereleases. Republished as `0.1.20260825` and it resolved immediately. A channel whose publisher happens to use a prerelease version string produces a subscription that reports healthy and delivers nothing.

### 8. Subscriber overrides applied to the Application are reverted

Patching `spec.source.helm.valuesObject` directly is undone by the ApplicationSet controller on the next reconcile. Correct behaviour, and worth stating: **the only supported place for per-cluster values is the kit's `--customer-values` at install time.**

### 9. The billing worker refuses a test-mode Stripe key

```
RuntimeError: billing provider worker in live mode requires a standard sk_live_ key
```

`stripe_test_custody.py` is a real guard doing its job. It also means the estate **as published is hardwired to live billing mode**, so the highest-fidelity Stripe validation available (a real test-mode sandbox) cannot be exercised without a values change the published estate does not offer.

### 10. Kyverno verifies only `*vexaai/*`

The admission policy's `imageReferences` is `["*vexaai/*"]`. The mirrored third-party images — `caddy`, `redis`, `postgres`, `bitnami/kubectl` — pass admission **unverified**, even though we mirrored them and could attest that they are what we copied. Not wrong (we cannot attest to upstream builds) but it is a narrower guarantee than "the channel verifies what it serves".

---

## What did work, stated precisely

| | |
|---|---|
| Kit preflight | **PASS** on the shaped cluster — and it caught a real defect first: `DynamicPod/vexa-bot` could not schedule on a fully-tainted node pool |
| Argo CD | installed, `resourceTrackingMethod=annotation` set **before any Application existed** (the kit fix) |
| Kyverno | installed; both policies enforcing |
| Entry resolution | `115` resources resolved from the channel chart |
| Signature verification | Kyverno **denied 12 workloads** with `no signatures found` before the images were signed, and **admitted all of them** after. The gate is real, and it was observed failing closed before it was observed passing |
| Sync | `115/115 Synced`, `phase: Succeeded` |
| Image pulls | from `channel.vexa.ai`, `0` from Docker Hub |
| Workloads running | **16 Running, 3 Completed** of 24, with every non-running one explained above |
| Entry signature | verifies against the vaulted public key alone; anonymous entry read still `401` |

## Images mirrored

**43 images, 43 succeeded, 0 failed. 16.24 GB** (17,433,428,939 bytes across all platforms of every index). Every destination digest was verified equal to its source digest with `crane digest`, twice — inline during the run and again in an independent pass reading the result file back against the live registry.

40 landed on the first pass; **3 failed on Docker Hub's rate limit** and succeeded on retry:

```
TOOMANYREQUESTS: You have reached your unauthenticated pull rate limit.
```

The cause was burst volume rather than a missing credential, but it is worth knowing that a mirror run of this estate can exhaust an anonymous quota partway through and leave a channel that looks populated and is not.

**Blob serving confirmed non-redirecting**, which is the `redirect: disable: true` property from Vexa-ai/vexa-platform#352 doing its job — a 307 to `linodeobjects.com` would silently reintroduce a second egress host:

```
small layer   num_redirects=0 http_code=200 size=317616
265 MB layer  num_redirects=0 http_code=200  (HEAD)
              num_redirects=0 http_code=206  (ranged GET)
```

All 43 signed into `channel.vexa.ai/vexa/channel/vexa-internal/signatures`; the repo lists 43 signature tags.

**One measurement worth recording:** `registry.k8s.io/pause` measures **551 MB**. That is not an error — the index carries seven children, two of them `windows/amd64`, each with a ~265 MB *uncompressed* Windows base layer. They were checked for being foreign/non-distributable (URL-referenced, never transferred) and they are not: plain `application/vnd.docker.image.rootfs.diff.tar`, no `urls` field, and the channel genuinely stores and serves the 265 MB blob. So the 16.24 GB is real transferred data, and **mirroring multi-arch indexes wholesale is most of the cost** — the estate needs `linux/amd64`.

Both the production estate's image set and the `pilot-stable` OSS set are mirrored, the latter against the standing promise.

## Disaster recovery, as far as this goes

`production = channel + secret store + database backup` is **partly** demonstrated. The channel half is real: the object graph and the images came from it. The secret half is a list of names, not a restore. The data half was not attempted. A DR claim needs a run that restores a real backup into a real managed instance, which this was not.

