---
title: "The install that the chart unblocked: entry 5 running, at its own digests"
description: "A digest-pinned chart published for the release, an install that resolved it by default, and V-est-8 answered — six delivered images, six identical digests. Plus the namespace grant the installer silently removed."
---

**Date:** 2026-09-07, the same day and the same rig as
[the run that stopped](/receipts/2026-09-07-bbb-station-entry5). **Channel:**
the pilot channel on the **live** registry. **Station:** our own rehearsal
station, not a customer's. **Cluster:** the rung-4 rig from
[2026-09-06](/receipts/2026-09-06-openshift-on-bbb). **Container work** ran on
an internal build host, never on a laptop.

**Two sentences.** The morning's run verified a candidate entry and then
stopped, because the channel carried no chart for that release; a digest-pinned
chart was published, and the same procedure resumed and completed — the
subscription resolved the new chart by default, the in-cluster gate recorded
**ELIGIBLE**, and **every delivered image is running at the digest the entry
names**. It also surfaced that the installer silently strips the PSA and SCC
grant off a namespace it did not create, which had turned the first green
reading into a green obtained from enforcement being absent.

<Note>
The subscriber is not named. Their registry hostnames, project names and estate
details are not in this document. The channel is written as `<pilot-channel>`.
</Note>

## The rung, unchanged

**Rung 4 of 4, and it is NOT OpenShift** — a `kind` cluster with PSA
`restricted` and Kyverno emulating `restricted-v2`. No `oc`, no SCC objects, no
OLM, no Routes, no internal registry, no GitOps operator. `PROFILE_TESTED` on
the `openshift` profile stays `no`.

## The chart, and why its version is not the release's

```
oci://<registry>/vexa/channel/<pilot-channel>/charts/vexa
  version 0.12.36   appVersion 0.13.1
  sha256:b8a1529c530a398eb6786cdb6547e16b9ba47eb08bf8e79582661130cf788a34
```

Packaged by the publisher from a `git archive` of the release tag, with the
pins read out of that tag's own candidate map, the node baseline merged after
them, the PreSync gate template injected, and the Argo hook stamp on the
migration job. Signed with the channel key, cosign 2.6.5, in the legacy
`sha256-<hex>.sig` layout the subscriber's Kyverno reads.

`Chart.yaml` keeps two version lines and they are two facts. **`appVersion` is
the release** — the PreSync gate derives its entry ref from exactly this field,
so it has no freedom. **`version` is the chart revision**, and it is what a
subscriber's `targetRevision: "*"` ranks. The product tree declares
`version: 0.12.1` at *every* tag and has never bumped it, so taking the tree's
number would have published a chart ranking **below** the one already on the
channel; taking the release's number would re-collapse the two spaces that
`--chart-version` exists to separate. `0.12.36` is the next revision in this
channel's own monotonic counter, which stood at `0.12.35`.

**Nine of the release's eleven images are pinned into it, byte-identical to the
packet.** The two that are not are not chart images: one is built by the
release workflow but referenced by no template, the other is the
single-container lane the chart does not deploy. No reference in the render
carries no digest.

## Proof 1 — the default resolution moved

```
helm show chart oci://…/charts/vexa            # no --version
   name: vexa   version: 0.12.36   appVersion: 0.13.1
```

This is the line that mattered. `install.sh` renders the delivered set with
`helm template … oci://…/charts/<chart>` and **no `--version`**, and the
staging Application follows position `*`; what that resolves to *is* what a
subscriber installs. Before the publish it was the previous entry's chart, at
the previous release's `appVersion`. The Application synced **Synced ·
Healthy · Succeeded** on the new one without being told the version.

## Proof 2 — the in-cluster gate, ELIGIBLE, recorded

```
OK    entry pulled: <registry>/vexa/channel/<pilot-channel>:v0.13.1
OK    entry signature verifies against the pinned channel key
OK    freshness: entry expires 2026-10-07T11:12:17Z (29 day(s) left)
OK    candidate entry: map present; delivery receipt deferred by definition
OK    revocation list signature verifies against the pinned channel key
OK    policy: entry_seq 5 >= your floor 5
OK    policy: publication mode 'candidate'
VERDICT: ELIGIBLE — v0.13.1 verified against contract <candidate lane>
OK    verdict recorded in configmap/vexa-verify-verdict (ELIGIBLE)
```

The station report's `release.verifier` block reads `verdict: ELIGIBLE`,
`failed_checks: 0`. **Every previous report from this station read `ABSENT`** —
the schema's word for *the gate did not run*. This is the first one that
carries a verdict the cluster actually produced.

Kyverno's signature admission **admitted every workload**, closing the last
run's defect 7: `--signature-repository` was supplied this time, so the policy
looked for signatures where the channel keeps them rather than beside each
image on a public hub, where by design there are none.

## Proof 3 — V-est-8, answered

*"The cluster runs exactly the entry's bytes."* Measured off `imageID` on every
non-Argo container.

| Entry image | Running | Verdict |
|---|---|---|
| `v012-admin-api` | `sha256:ce50d52d5223…` | **identical** |
| `v012-agent-api` | `sha256:62a82d365cc2…` | **identical** |
| `v012-gateway` | `sha256:005622cbda65…` | **identical** |
| `v012-meeting-api` | `sha256:7c7615549feb…` | **identical** |
| `v012-runtime` | `sha256:9819e361f965…` | **identical** |
| `v012-terminal` | `sha256:fe13eb1e798b…` | **identical** |
| the minutes/flows tier | — | not running: the tier is off by default; the pin is in the chart |
| the bot and the agent worker | — | not running: spawned per dispatch, pinned as the runtime's spawn references |
| two more in the map | — | not chart images |

**Six equal, zero different, and nothing running that the entry does not
name** — apart from three digest-pinned infrastructure images from the node
baseline, which the entry correctly does not describe, and the station's own
verifier build (below).

## What went wrong, and it is the most useful thing here

### The installer removed the namespace's security grant

`install.sh`'s `ensure_namespace` does
`kubectl create namespace <ns> --dry-run=client -o yaml | kubectl apply -f -`
on a namespace it did not create. The three-way merge prunes what an earlier
declarative apply had put there, so the grant went from

```
pod-security.kubernetes.io/{enforce,enforce-version,audit,warn}: restricted
openshift.io/sa.scc.uid-range · .supplemental-groups · .mcs
```

to the single `kubernetes.io/metadata.name` label. **PSA enforcement and the
annotations the mutation policy reads were gone, silently, from a namespace the
installer does not own.**

It was caught by the check that should have caught it, saying the opposite of
what it usually says: **P4 returned PASS** — *"no SCC and no PSA enforce label
on the namespace — admission here is permissive; nothing to trip, nothing
verified about hardened namespaces."* A pass obtained from the enforcement
being absent. Had the run stopped there, it would have reported a hardened
estate that was not one.

The grant was re-applied from its own manifest and every delivered pod was
deleted so it would be re-admitted under the restored posture. **They all came
back except the database**, and the ones that came back carry, injected by the
mutating webhook before PSA validated them:

```yaml
fsGroup: 1000920000
runAsUser: 1000920000
runAsNonRoot: true
seLinuxOptions: {level: "s0:c26,c5"}
seccompProfile: {type: RuntimeDefault}
```

That is the standing P4 caveat, measured rather than assumed: the chart ships
none of those fields — deliberately, it is the delivery rule — the webhook
supplies them, and `restricted` then admits the pod.

### The delivered database does not fit the project's ceiling

```
create Pod …-postgres-0 in StatefulSet …-postgres failed error:
pods "…-postgres-0" is forbidden: maximum memory usage per Container is
2560Mi, but limit is 4Gi
```

The chart asks `postgres.resources.limits.memory: 4Gi`; this project's
LimitRange caps a container at `2560Mi` — the floor the OpenShift provider
notes name, because the bot's 2Gi memory-backed `/dev/shm` counts against its
own limit. This is not new in this release: the previous chart asks for the
same 4Gi.

**Nothing was widened to get past it.** The estate is therefore partly down —
the admin tier crash-loops behind the missing database, and the post-restore
smoke records exactly that, with a receipt.

**And `P2` passed while it was true.** *"Declared resources on every container,
and they fit the LimitRange"* is the check whose whole purpose is to predict
this refusal before the first sync; it had the rendered manifests and the
LimitRange in hand, and it returned PASS in both runs of this session. It
appears to verify that limits are **declared**, not that they are under the
LimitRange's `max`.

### The published verifier image cannot parse the gate the chart injects

The chart-injected PreSync gate passes `--station` and `--verdict-out` whenever
`verify.recordVerdict` is on, which is its default. The newest verifier image
the channel serves is dated 2026-08-24, predates both flags, and answers

```
unknown argument: --station
OK    verdict recorded in configmap/vexa-verify-verdict (NOT_ELIGIBLE)
```

— a sync blocked **on an argument, not on evidence**, and recorded as if the
entry had failed. It fired for real: publishing the chart made the subscription
sync, and that Job failed this way before this run had touched the cluster.

The kit ships the verifier's entire source, Apache-2.0, on the stated principle
that every line running in a subscriber's cluster is readable there — so the
station built it and passed it with `--verifier-image`. Neither admission
policy matches it; both scope to the product's own image namespace. **The fix
is a publisher act: republish the verifier from the current kit.** Until then a
subscriber taking a freshly published chart, at the default, gets a gate that
fails on its own arguments.

### Two smaller ones

**A relative `--pubkey` reads as a forged entry.** `vexa-verify.sh` chdirs into
its workdir and then resolves `--pubkey`/`--policy`; a relative path silently
misses, and the failure surfaces as *"entry signature does NOT verify against
the pinned channel key"*, plus the same line for the revocation list. The
identical entry verified `Verified OK` by hand one command later. The script's
own comment says a signature failure *"says someone may be attacking you"* —
which makes it the worst available message for a path typo.

**The in-cluster verdict names a contract hash nothing else can match.**
`install.sh` writes the contract ConfigMap through
`json.dumps(yaml.safe_load(file))`, re-serializing the record — 757 bytes of
document into 617 bytes of compact JSON. The gate hashes the mounted copy, so
it recorded one hash while the record, and the report's own `contract_document`
section, hash to another. Same defect class the chart template fixed with a
double-quoted scalar; the other write path still has it.

## Phase verdicts, for the record

**Host verify ELIGIBLE** exit 0 · **preflight FAIL** exit 1 (P4 alone; 7 of 8
PASS, and **P2 now passes** where the previous chart failed it, closing a
refusal the node baseline named) · **install ran**, exit 0, `--skip-preflight`
after the P4 refusal was recorded verbatim · **Argo Synced/Healthy/Succeeded**
· **in-cluster gate ELIGIBLE**, 0 failed checks · **smoke PASS** before the
grant was restored, **FAIL with a receipt** after · **validate** exit 1, a
428-line report, redaction verified, 0 leaks · **ingest ACCEPTED**, verdict
`REFUSED`, flag `contract-breach`.

## What this receipt does NOT claim

- **No OpenShift or OKD was involved.** Unchanged.
- **The estate is not fully up.** The database is refused by the project's own
  LimitRange. V-est-8 is a question about identity and it is answered; *"the
  delivered set runs in this project shape"* is answered **no**.
- **No meeting was captured.** The smoke ran non-interactive; the capture and
  minutes checks were skipped, so nothing here says anything about the
  release's quality.
- **No station verdict was signed and nothing was submitted.**
- **Revocation fail-closed remains unverified**, exactly as it was.

## Final state

| | |
|---|---|
| Channel | one chart added and signed; `:current` not moved, no entry touched, no pin moved, no credential minted or rotated |
| Rig | running the release, under its restored PSA and SCC grant, minus the database |
| Ledger | station `state.yaml` and receipt written by the ingest reducer, its sole writer; the narrative committed beside them |
| Findings | five, recorded, none fixed |
