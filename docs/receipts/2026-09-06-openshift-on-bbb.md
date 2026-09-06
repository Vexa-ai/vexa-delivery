---
title: "OpenShift-shaped rig on a bare-metal host — Harbor transport proven, SCC emulated"
description: "The transport rig reproduced end to end against the live private channel; the cluster rung fell to the last one on the ladder because the host's firmware has AMD-V switched off."
---

**What this is.** An attempt to stand up a *genuine* OpenShift on an in-house
bare-metal host, shaped like the pilot subscriber's environment, with a Harbor
transport rig in front of the private channel. **The transport half succeeded
and is the durable result. The cluster half reached rung 4 of a 4-rung ladder
and is therefore not OpenShift** — stated here as the headline rather than
buried, because a reader skimming for "OpenShift proven" must not find it.

`PROFILE_TESTED` is **not** flipped by this receipt, and nothing here justifies
flipping it.

<Note>
The subscriber is not named. Their registry hostnames, project names and estate
details are not in this document. The rig host is written as `<rig-host>` and
the private channel exercised as `<channel>`.
</Note>

## The rung, honestly

| Rung | What it would have proven | Reached |
|---|---|---|
| 1 — OpenShift Local (`crc`), OKD preset | genuine OpenShift: SCC, Routes, OLM, internal registry, GitOps operator | **no** — needs `/dev/kvm` |
| 2 — OKD single-node, agent-based installer in libvirt | genuine OpenShift | **no** — needs `/dev/kvm` |
| 3 — MicroShift 4.18 in a CentOS Stream 9 VM | genuine SCC admission (the rung the 2026-08-21 rehearsal stood on) | **no** — needs `/dev/kvm` |
| 4 — Kubernetes + PSA `restricted` + Kyverno reproducing `restricted-v2` | the *shape* of the constraint, not the constraint | **yes — and it is not OpenShift** |

### Why rungs 1–3 were unreachable

The host has no `/dev/kvm`, and it cannot be given one from the operating
system:

```
$ sudo modprobe kvm_amd
modprobe: ERROR: could not insert 'kvm_amd': Operation not supported
$ dmesg | grep kvm
kvm_amd: SVM not supported by CPU 36
```

| Measurement | Value |
|---|---|
| `grep -o '\bsvm\b' /proc/cpuinfo \| wc -l` | `0` — the base SVM feature bit is absent |
| `grep -o '\bsvm_lock\b' /proc/cpuinfo \| wc -l` | `128` — the CPUID `0x8000000A` sub-feature bits are published, so the silicon has SVM |
| `rdmsr 0xC0010114` (`MSR_VM_CR`) | **`0x18`** → `SVM_LOCK=1`, **`SVMDIS=1`** |
| `systemd-detect-virt` | `none` — bare metal, so this is not an outer hypervisor withholding nested virt |

`SVMDIS=1` under `SVM_LOCK=1` is AMD-V disabled in firmware and latched until
reset. The kernel clears `X86_FEATURE_SVM` on that basis. **The MSR is
write-locked; there is no OS-side path.** The remedy is a firmware setting and a
reboot — an owner's act, not a worker's, and not attempted.

QEMU/TCG software emulation was considered and rejected: an OKD single-node
bootstrap under pure emulation is a multi-hour proposition on a host that is
carrying other people's live work.

**Consequence for the ladder as written:** three of its four rungs are gated on
one firmware bit. Worth knowing before planning around it again — the ladder's
top three are a single point of failure, and the failure is invisible until
`modprobe` runs.

## The transport rig — reproduced, and it works

Harbor **v2.15.2** as a docker compose, ports **18443/18081** (chosen after
checking the host's running containers and listening sockets), private CA, data
and logs under the rig directory rather than `/data` or `/var/log`.

The four API calls the parity document refers to, exactly:

| # | Call | Body, in short | Result |
|---|---|---|---|
| 1 | `POST /api/v2.0/registries` | `type: docker-hub`, **no credential** | id 1, `healthy` |
| 2 | `POST /api/v2.0/projects` | `dockerhub-proxy`, public, `registry_id: 1` | created |
| 3 | `POST /api/v2.0/registries` | `type: docker-registry`, `https://channel.vexa.ai`, subscriber machine account | id 2, `healthy` |
| 4 | `POST /api/v2.0/projects` | `vexa-channel`, private, `registry_id: 2` | created |

### The nine checks, through the proxy

| # | Check | Result |
|---|---|---|
| 1 | entry `<channel>:current` | `sha256:ce96f4c1…` — **byte-identical to a direct upstream fetch of the same tag** |
| 2 | immutable tag `v0.12.23` | same digest — the same-byte pointer holds through the proxy |
| 3 | entry manifest shape | `artifactType: application/vnd.vexa.channel-entry.v1+json`, 8 layers |
| 4 | entry **content** | `entry.json`, `VERIFY.md`, `entry.json.sigstore.json` and all five `evidence/*` pulled; release `v0.12.23`, `channel.entry_seq 4` |
| 5 | signature tags | all three `sha256-….sig` resolved |
| 6 | chart `charts/vexa:0.12.35` | resolved |
| 7 | referrers / attestations | **empty — and this is correct.** This channel uses the `.sig` tag layout, not the referrers API; the attestations ride *inside* the entry as `evidence/` layers, which check 4 retrieved |
| 8 | `verifier` and `kit` repos | resolved |
| 9 | anonymous Docker Hub lane | `dockerhub-proxy/library/alpine:3.21` pulled **with no login at all** |

### The cluster pulls through it

containerd on the rig node trusts the rig CA through
`/etc/containerd/certs.d/<rig-host>:18443/hosts.toml`, and both `crictl pull`
and real workload pulls succeed over TLS. **The host's docker daemon was not
reconfigured** — the trust is on the cluster side, which is also the shape the
kit documents (`--registry-ca`, never `REGISTRY_INSECURE`).

The cluster authenticates to Harbor with a **Harbor robot account**, not with
the channel credential. The subscriber credential exists only in the Harbor
endpoint and in a `600` env file on the rig host; it is never handed to the
cluster.

## Revocation — the one row this rig did NOT verify

The parity matrix records *"Revocation behavior — upstream credential rotated —
**MATCHED, fails closed**"*. **This rig could not reproduce that, and does not
claim it in either direction.**

What was established:

- Harbor **refuses to create** a registry endpoint whose credential is wrong:
  `400 BAD_REQUEST — "the registry is unhealthy"`. That is a genuine
  fail-closed, at configuration time.
- The channel itself refuses a wrong secret: `401` on `/v2/`, on the entry, on
  `revocations`, and on the chart path. The `signatures/manifests/…` path
  returns `200` anonymously, **by design** — RUNBOOK § 5.2 makes signature
  reads credential-free so a stock zero-credential verifier can work.

What could not be established:

- Mutating the credential on the **live** endpoint via `PUT
  /api/v2.0/registries/{id}` — partial body, then full body, each with and
  without restarting `harbor-core` and `registry` — never produced a refusal.
  Artifacts in never-before-proxied repositories kept flowing, and the endpoint
  reported `healthy` throughout.

A `healthy` status against a knowingly wrong credential is not self-consistent,
so **the likeliest reading is that the `PUT` never applied the secret** rather
than that Harbor serves without authenticating. But the rig cannot distinguish
the two, and the honest test is a real rotation at the channel, which is not a
rehearsal act. **Recorded as an open question.**

One adjacent finding, cheap and worth carrying: **`POST
/api/v2.0/registries/ping` returned `200` for a payload carrying a knowingly
wrong secret, while `POST /api/v2.0/registries` returned `400` for the same
payload.** Ping is not an authentication test for this upstream — do not use it
as a credential check.

## The tenant shape

An isolated Kubernetes v1.30.0 cluster on its own API port and its own
kubeconfig. A pre-existing cluster on the same host, carrying unrelated live
work, was deliberately not used.

Project `vexa-dev` carries the tenant grant a platform team would issue:

| Piece | Value | Source |
|---|---|---|
| `openshift.io/sa.scc.uid-range` | `1000920000/10000` | the base is the UID **measured on an admitted pod in the pilot subscriber's own project** |
| `openshift.io/sa.scc.supplemental-groups` | `1000920000/10000` | same |
| `openshift.io/sa.scc.mcs` | `s0:c26,c5` | representative |
| PSA | `enforce/audit/warn: restricted` | SCC-clean is not PSA-clean; where both are enforced the delivered set must satisfy the union |
| ResourceQuota | 16 CPU / 32Gi requests, 32 CPU / 64Gi limits, 60 pods | the station contract's `resource_ceiling`, sized for **app plus Argo** |
| LimitRange | default request 64Mi, **max 2560Mi** | 64Mi is the recorded default that produces the silent-squeeze class; 2560Mi is the documented floor, because the bot's memory-backed `/dev/shm` (2Gi) counts against its 2560Mi limit. The recorded rig max of 1Gi refuses the bot at admission — that is the boundary, so the rig sits exactly on it |

`restricted-v2` is reproduced as **two staged policies — mutate, then reject**
— under Kyverno **v1.19.0**, the pin `kit/providers/openshift/profile.env`
carries.

### SCC proof, both directions

**A pod delivering no `securityContext` at all** — what the chart ships — was
admitted and mutated to:

```json
{ "runAsUser": 1000920000, "fsGroup": 1000920000, "runAsNonRoot": true,
  "seLinuxOptions": {"level": "s0:c26,c5"},
  "seccompProfile": {"type": "RuntimeDefault"} }
```

per container: `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
`seccompProfile: RuntimeDefault`. Inside the container: `uid=1000920000
gid=0(root)`.

**A pod that hardened itself out of range** was refused:

```
unable to validate against any security context constraint: provider "restricted-v2":
.spec.securityContext.runAsUser: Invalid value: 1001: must be in the ranges: [1000920000, 1000929999]
```

An in-range explicit `runAsUser: 1000920007` was admitted. The operational rule
the kit states — *deliver no `securityContext` at all* — is the behaviour the
rig reproduces.

**Incidental confirmation:** the first admitted pod reports `HOME=/`. The
`HOME`-under-a-random-UID defect shows up on the very first workload, before
Vexa is involved at all.

### Argo CD, and what the run added

`ARGOCD_VERSION=v3.5.1` namespace-install, into the tenant project.

- **The upstream manifests were refused, exactly as documented.** They carry
  precisely two hard-coded UIDs — `runAsUser: 1001` (dex) and `runAsUser: 999`
  (redis) — and the `argocd-redis` Deployment was rejected at admission:
  `Invalid value: 999: must be in the ranges: [1000920000, 1000929999]`. The
  rejection arrived on the **Deployment**, not on the Pod, because Kyverno's
  autogen rules cover pod controllers. Stripping the two `runAsUser` lines (a
  two-line diff over 2 968) admits the whole set, and every Argo pod then runs
  under the injected project UID.
- **`namespace-install.yaml` ships no CRDs, and CRDs are cluster-scoped.** Argo
  came up half-dead until they were applied — `argocd-server` exiting on
  `the server could not find the requested resource (post appprojects.argoproj.io)`.
  The tenant kubeconfig is **Forbidden** on `customresourcedefinitions`, so this
  is a **platform-team act that the parity document does not currently list**
  among the one-time asks. It belongs on that list.
- **The ~7-pods-of-quota claim is confirmed**: 7 pods, 448Mi requested, 8
  Services, 8 ConfigMaps, 6 Secrets against the project quota.
- **The OperatorHub / OpenShift GitOps operator route was not available** at
  this rung — it needs OLM, which only a genuine OpenShift or OKD provides. The
  operator remains recommended on evidence about upstream Argo's images, still
  not on a run of it. Unchanged by this receipt.

### Tenant scoping — two fidelity gaps found and closed

Both are worth carrying beyond this rig.

1. **`kubectl auth can-i` reported permissions the API server then refused.** It
   answered `yes` to `get nodes`, `create namespaces` and `get clusterpolicies`
   for a ServiceAccount that is in fact `Forbidden` on all three. Every scope
   claim in this receipt is from **attempting the verb**, never from `can-i`.
   A rig that had trusted `can-i` would have reported a broken tenant boundary
   that was in fact intact — or, worse, the reverse.
2. **Upstream Kubernetes' `admin` ClusterRole is not OpenShift's project
   `admin`.** It lets the holder `patch` its own ResourceQuota and `delete` its
   own LimitRange; OpenShift's does not. Left as-is, the rig would have let the
   tenant widen the very constraint under test. Replaced with a purpose-built
   role that grants everything `edit` does plus local RBAC, with quota and
   limits **read-only**. A second leak in the same area: the namespaced
   `*/*/*` Role the parity document says a namespace-scoped Argo needs had been
   bound to the *tenant*; it is Argo ServiceAccount material and is now bound
   only to Argo's own ServiceAccounts.

After both fixes the tenant can create Deployments, Secrets and RoleBindings in
its project, and is refused on `nodes`, on other namespaces, on cluster-scoped
resources, on its own quota and on its own LimitRange.

## What this receipt does NOT claim

Stated as gaps, in the register the OpenShift provider README already uses:

- **No OpenShift or OKD was involved.** No `oc`, no SCC objects, no OLM, no
  Routes, no internal registry, no GitOps operator. `restricted-v2` here is a
  policy engine reproducing a documented behaviour, not the admission
  controller itself. The 2026-08-21 MicroShift 4.18 rehearsal remains the
  strongest SCC evidence the project holds; **this run does not supersede it and
  is a weaker rung.**
- **`kit/install.sh --provider openshift` was not run.** This receipt covers
  the environment, not the install. That is the next track.
- **Vexa was not deployed and has not been observed converging.** The `HOME`
  defect is untouched by anything here.
- **Revocation fail-closed is unverified**, per the section above.
- **`Route` versus `LoadBalancer`, test/prod policy deltas, general egress
  beyond the registry, and the cross-project firewall** remain exactly as open
  as they were.

## Teardown

The rig is left **running**, deliberately: it is the environment the install
rehearsal runs against next. Nothing on the host outside the rig was modified —
the container daemon was not restarted or reconfigured, no images or volumes
were pruned, no network configuration was changed, no reboot occurred, and the
unrelated workloads sharing the host were untouched throughout.

Teardown, when it comes, is: delete the rig cluster, `docker compose down` in
the rig directory, remove the rig directory, and remove the two `600` env files.
No state outside those survives.
