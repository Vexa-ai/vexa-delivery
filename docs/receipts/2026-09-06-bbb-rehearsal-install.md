---
title: "Rehearsing the kit against a namespace-scoped tenant behind a pull-through registry"
description: "The transport and both gates exercised end to end; seven kit defects found, three of them on the paths a struggling subscriber hits first. Rung 4 of 4 — a PSA-restricted tenant with Kyverno emulating restricted-v2, NOT OpenShift."
---

**Date:** 2026-09-06. **Channel:** a private subscriber channel, referred to
here as `<subscriber>-stable`. **Registry:** a **Harbor v2.15.2 proxy-cache**
at `<harbor-host>`, upstream `channel.vexa.ai`. **Cluster:** a dedicated
single-node `kind` cluster, Kubernetes **v1.30.0**, on its own kubeconfig.
**Container work** ran on an internal build host, never on a laptop.

## The rung, stated first because everything below is conditioned on it

**Rung 4 of 4, and it is NOT OpenShift.**

| Rung | What it is | Reachable |
|---|---|---|
| 1 | `crc` with the OKD preset | no — needs `/dev/kvm` |
| 2 | OKD single node, agent-based installer | no — needs `/dev/kvm` |
| 3 | MicroShift 4.18 in a VM | no — needs `/dev/kvm` |
| **4** | **`kind` + PSA `restricted` + Kyverno emulating `restricted-v2`** | **this run** |

The host's AMD-V is **disabled and latched in firmware** (`MSR_VM_CR = 0x18` →
`SVMDIS=1` under `SVM_LOCK=1`), on bare metal, MSR write-locked until reset. One
firmware bit gates three of the four rungs.

So: **no `oc`, no SCC objects, no OLM, no Routes, no internal registry, no
GitOps operator.** This run proves **the transport, the kit and the gate
behaviour**. It proves nothing about SCC, and it does not supersede the
2026-08-21 MicroShift 4.18 rehearsal, which remains the strongest SCC evidence
held. `PROFILE_TESTED` on the `openshift` profile stays `no`.

The tenant is namespace-scoped by ServiceAccount kubeconfig — every application
act below was performed as that tenant, and every claim about what it may not do
is from **attempting the verb**, never from `kubectl auth can-i`.

---

## What was proven

### The transport works, end to end

The subscription resolved chart `0.12.35` through the proxy-cache and rendered
**31 resources**. `${REGISTRY}/vexa/channel/${CHANNEL}` composed onto the Harbor
project path exactly as the proxy-cache expects, so no kit change was needed to
put a pull-through in front of the channel.

`--registry-insecure` was **required**: Argo CD has no per-repository CA-bundle
knob for OCI repositories, so a corporate-CA registry needs the repo secret to
opt out of verification while Kyverno gets the CA as a trust bundle. That
asymmetry is already documented in `install.sh`; this run confirms it is not
optional.

### Gate 1 — the PreSync verify gate: **ELIGIBLE**

```
OK    entry pulled: <harbor-host>/vexa/channel/<subscriber>-stable:v0.12.23
OK    entry signature verifies against the pinned channel key
OK    digest evidence/candidate-images.json … delivery-receipt … source-provenance … trusted-root
OK    candidate map matches the delivery receipt's packet pin
OK    policy: entry_seq 4 >= your floor 1
OK    policy: publication mode 'published'
OK    vendor approval: published by the founder
VERDICT: ELIGIBLE — v0.12.23 verified against contract example-2026-01 @ sha256:ec035d34d526…
```

A private channel entry, pulled through a customer-shaped pull-through
registry, signature-verified offline against a key delivered by a separate
route. That is the whole thesis, and it holds.

### Gate 2 — Kyverno signature admission: **DENY**, because the installer was never told where the signatures are

All six Vexa Deployments were denied:

```
resource Deployment/<ns>/vexa-vexa-gateway was blocked due to the following policies
vexa-verify-channel-signature:
  autogen-vexa-images-signed-by-channel: 'failed to verify image
  docker.io/vexaai/v012-gateway@sha256:514ba2702ab0…: .attestors[0].entries[0].keys: no signatures found'
```

`install.sh` warns in its own comments that this message is **byte-identical**
whether the image is unsigned, unfetchable, or merely looked for in the wrong
place. This run's first reading of it — *unsigned* — was wrong, and the
correction is the finding.

**The images are signed.** Every image digest of entry 4 answers **200** at the
channel's own signature repository,
`channel.vexa.ai/vexa/channel/<subscriber>-stable/signatures`, at the
conventional `sha256-<digest>.sig` path, carrying a genuine cosign object: a
`vnd.dev.cosign.simplesigning.v1+json` layer, a
`vnd.dev.sigstore.bundle.v0.3+json` layer, and the
`dev.cosignproject.cosign/signature` annotation — the exact layout
[the signature-layout receipt](/receipts/2026-08-25-signature-layout) proved
this Kyverno **ADMITS**. Signature reads on the channel are credential-free by
design (RUNBOOK § 5.2), so anyone holding the entry can re-run this check.

| Probe | Result |
|---|---|
| the six `.sig` objects at the **channel** signature repository | **200 · 200 · 200 · 200 · 200 · 200** |
| the same digests' `.sig` tags on **Docker Hub** | **404**; 0 `.sig` tags across all six `vexaai/v012-*` repos |

This run probed only the second row and concluded from it. The second row is
the layout working as designed — the signatures live at the channel, which is
where the entry says they live — not evidence of an unsigned image.

**What failed is the install, not the packet.** This run did not pass
`--signature-repository`, so `install.sh:262-267` **deleted the repository line
out of the admission policy** and Kyverno looked for signatures beside each
image on Docker Hub, where by design there are none. That is the failure
[`tested` § *The from-docs run, 2026-08-27*](/tested#the-from-docs-run-2026-08-27)
already documents, reproduced here — and it is **defect 7** below.

Withdrawn, in full: *"the images are genuinely unsigned"*, *"there is nowhere a
signature exists to point it at"*, and *"on this entry the kit's own default
admission policy is unsatisfiable"*. The policy is satisfiable and this entry
satisfies it. Nothing follows from this run about the publish crank, and no
advice to run with admission off follows from it either.

---

## Seven defects in the kit

### 1 · `install.sh` has no adoption path, and running it against an existing Argo is destructive

There is no `--skip-argo`, no `--adopt`, no `--argocd-existing`; steps 2 and 3
are unconditional except under `--dry-run`. The `openshift` profile's own
comment says *"When the operator (or a house Argo) is present, run install.sh
against it rather than letting step 2 install a second Argo"* — **but the script
offers no mechanism to do that.**

Measured with `kubectl apply --server-side --dry-run=server` as the tenant
against upstream `argo-cd/v3.5.1/manifests/install.yaml`:

- **49 objects would be written**, including `deployment.apps/argocd-dex-server`
  and `statefulset.apps/argocd-application-controller` — re-adding the
  hard-coded `runAsUser: 1001` (dex) and `runAsUser: 999` (redis) that a
  restricted-range policy then rejects;
- **9 objects Forbidden** — 3 CRDs, 3 ClusterRoles, 3 ClusterRoleBindings.

So a real run **half-lands**: it breaks the working Argo, is refused on the
cluster-scoped nine, and `set -e` stops the script — leaving no subscription and
an Argo that no longer admits. Step 2 was therefore never executed here; steps
4/5/6 were rendered by `install.sh --dry-run` and applied by hand, tenant-first.

**Suggested shape:** `--argocd-existing` / `--kyverno-existing` that assert the
version and namespace and skip the install, rather than a flag that silences
the failure.

### 2 · The preflight crashes as a tenant instead of failing

`take_snapshot` performs an unwrapped `kubectl get nodes`:

```python
snap["nodes"] = kubectl_json(["get", "nodes"], kubeconfig=kubeconfig, context=context)["items"]
```

**Every other read in that same function is inside `try/except RuntimeError`** —
`namespace`, `limitranges`, `resourcequotas`, `networkpolicies`, and notably
`storageclasses`, which is also cluster-scoped. So someone anticipated
cluster-scoped refusals and missed this one. A namespace-scoped tenant gets a
Python traceback, and `install.sh` then prints `preflight FAILED`, which is a
lie: nothing was checked.

This lands squarely on the OpenShift path, whose whole premise is *project, not
cluster*. `--namespace-scoped` on `vexa_validate.py` does **not** cover it. The
workaround — the one a platform team would be forced into — is `--dump-snapshot`
as an admin, then `--snapshot` air-gapped. Real verdict once run that way: **FAIL
on P4**, everything else PASS.

P4's failure is the dynamic bot pod carrying no `securityContext` — correct for
SCC, refused by PSA `restricted`. Worth being precise: it is a **static-analysis
result and the live cluster contradicts it**, because a mutating webhook runs
before PSA validation. (`kit/report`'s own README already handles namespace
scope correctly, reporting cluster facts as UNKNOWN rather than guessing. The
preflight should borrow that posture.)

### 3 · `install.sh` never passes the manifests to the preflight — so its best checks run on nothing

```
python3 "$HERE/preflight/vexa_preflight.py" \
    --namespace "$STAGING_NS" ${KUBECONFIG_ARG[@]+"${KUBECONFIG_ARG[@]}"} \
```

No `--manifests`. So `objects = []`, and **P2 (resources fit the LimitRange) and
P3 (quota headroom) evaluate only the synthetic bot profile** — never the
delivered chart.

The cost was immediate. The tenant's LimitRange had a container memory max of
**2560Mi**, the recorded value, sized for the bot's 2Gi `/dev/shm`. The chart's
own postgres asks a **4Gi** limit:

```
create Pod vexa-vexa-postgres-0 in StatefulSet vexa-vexa-postgres failed error:
pods "vexa-vexa-postgres-0" is forbidden: maximum memory usage per Container is 2560Mi, but limit is 4Gi
```

P2's own anchor is *"a customer LimitRange squeezed undeclared bots to 64Mi"* —
and the same class of failure happened anyway, at sync time, because the check
ran against nothing. **This is the finding to carry forward first:** the
preflight is the right tool, invoked so that its two most valuable checks are
inert.

### 4 · `WaitForFirstConsumer` deadlocks the sync

The chart's standalone `agent-workspaces` PVC plus a `WaitForFirstConsumer`
StorageClass produce a circular wait: Argo counts a `Pending` PVC as un-Healthy
and will not start the wave containing the Deployments that would consume it, so
the PVC waits for a consumer that waits for the PVC. The sync sits at
*"waiting for healthy state of /PersistentVolumeClaim/…"* indefinitely.

The one provider with `PROFILE_TESTED=yes` binds `Immediate`, which is why this
has never been seen — **and many OpenShift default CSI classes are
`WaitForFirstConsumer`.** Cleared here by pre-binding a PV.

### 5 · Two objects share one name, and only a single-namespace tenant notices

`install.sh` names both of these `vexa-channel-registry`:

- the **Argo repository** Secret in `$ARGOCD_NS` (`Opaque`);
- the **kubelet pull** Secret in each workload namespace (`dockerconfigjson`).

They never collide only because `ARGOCD_NAMESPACE` defaults to `argocd` while
the workloads live elsewhere. On **one project** — the shape the `openshift`
profile exists for — they are the same object. The second create fails with
`type: Invalid value: "kubernetes.io/dockerconfigjson": field is immutable`, and
every ServiceAccount is left with its `imagePullSecrets` pointing at an `Opaque`
Argo secret the kubelet cannot use.

That is exactly the `ImagePullBackOff` the thirty-line comment at
`install.sh:348` was written to prevent, reintroduced by a namespace choice.

### 6 · `kit/smoke` raises where it should report — and that blocks the receipt

Against a half-converged estate, smoke produced **no verdict and no receipt**:

```
RuntimeError: port-forward to svc/vexa-vexa-admin-api did not come up in 15s
  at kit/smoke/vexa_smoke.py:83
```

`kit/smoke/README.md` promises that `--non-interactive` *"skips or bounds the
human phase but never fakes it: no admitted bot → honest FAIL"* — but that guard
covers **S3 only**. S1 and S2 have none.

**The consequence is the sharpest thing this run found.** `vexa_validate.py`
therefore wrote a `station-report.yaml` with no `smoke_receipt` section, and the
ingest gate correctly refused it:

```
REFUSED S2: report is incomplete; missing smoke_receipt (section 'smoke_receipt')
```

RUNBOOK § 3 says **failure reports matter more than success ones**, and § 3.2
says an un-ingested report is an **un-represented customer**. So today: **the
path that breaks is the failure-reporting path.** A subscriber whose install
goes wrong cannot file the receipt that would represent them — precisely when we
most need it.

### 7 · `install.sh` demands a flag for something it already knows, and degrades silently without it

`--signature-repository` defaults to *"alongside each image"* (`install.sh:39`)
— the one layout this channel does not use. When the flag is absent, lines
262-267 neither warn nor refuse; they **delete** the `${SIGNATURE_REPOSITORY}`
line from the rendered policy, and the admission rule that results denies every
Vexa workload with a message that reads exactly like an unsigned image. That is
Gate 2 above, and it cost this run its whole second half.

The script holds both halves of the correct value already. It composes
`--registry` and `--channel` into `${REGISTRY}/vexa/channel/${CHANNEL}` for the
Argo repository (`install.sh:298,315`); the signature repository is that same
reference plus `/signatures` — which is precisely what the onboarding mail and
[the install page](/install#step-3-install) ask the subscriber to retype by
hand.

**Suggested shape:** derive `SIG_REPO` from `--registry` + `--channel` by
default, keep the flag as the override for a subscriber who mirrors the channel
elsewhere, and make *no signature repository* an explicit opt-out rather than a
silent deletion.

This is the third time this defect has been paid for: once on 2026-08-27
(recorded on [`tested`](/tested#the-from-docs-run-2026-08-27)), once here, and
once again in the reading of this run's own DENY. The 2026-08-27 fix put the
flag in the documented command — which repairs the copy-paste path and leaves
every other path open.

Defects 2 and 6 are one class: *the kit raises where it should report*, on the
two paths a struggling subscriber hits first. Defect 7 is the mirror of it —
*the kit silently proceeds where it should refuse* — and it is the one that
produced a false finding rather than a slow one.

---

## What did not happen, said plainly

- **The `HOME` / minio-init `mkdir /.mc` blocker was not reached.** Admission
  stopped every application Deployment before a pod existed, and the rendered
  set contains **no minio-init hook at all** at chart `0.12.35`. Not reproduced,
  not refuted — unreachable in this run.
- **Postgres initialised and served under an injected arbitrary UID**
  (`uid=1000920000 gid=0(root)`; *"database system is ready to accept
  connections"*), contradicting the audit row that says the official image
  cannot. **Marked unconfirmed** — this was Kyverno emulating SCC, not SCC — and
  offered as a candidate correction to re-check, not a fact to carry forward.

The emulated SCC did hold on real product pods rather than only on probes: all
three workloads that reached Running were mutated to `runAsUser 1000920000`,
`fsGroup 1000920000`, `runAsNonRoot true`, `seccompProfile RuntimeDefault`,
`seLinux s0:c26,c5`.

## Final state

| | |
|---|---|
| Subscription | `sync=OutOfSync`, `health=Healthy`, revision `0.12.35` |
| Running | minio, postgres, redis |
| Denied at admission | gateway, admin-api, agent-api, meeting-api, runtime, terminal — all six for defect 7, not for anything about the entry |
| `kit/report` | **PASS**, 664 lines |
| `kit/smoke` | **FAIL**, no receipt |
| Ingest | **REFUSED at S2** |

## One-time platform-team asks, as measured

Each row is a verb the tenant **attempted and was refused**; see
[`openshift-parity.mdx` § How the station lands there](../engineering/openshift-parity.mdx).

| # | Act | Why the tenant cannot |
|---|---|---|
| 1 | Install the three Argo CRDs | CRDs are cluster-scoped |
| 2 | Install Kyverno and the two `ClusterPolicy` objects the admission policy is made of | cluster-scoped |
| 3 | Bind a cluster-scoped **read** ClusterRole to the Argo application-controller | RBAC is cluster-scoped, and without it a namespace-scoped Argo never syncs |
| 4 | Create each project with its SCC annotations and PSA labels | namespaces are cluster-scoped |
| 5 | Set the project LimitRange ceiling **≥ the largest container limit in the chart**, not merely ≥2560Mi | project admin is read-only on quota and limits |
