---
title: "Week-exit rehearsal — playing the customer against the live channel"
description: "One agent, no hands: mint the real entry, publish the kit, bootstrap a fresh cluster from nothing but a subscriber credential, install, verify, gate, self-upgrade. Fourteen defects, eleven fixed, three open."
---

**Date:** 2026-08-24. **Authorised by:** the founder, for this rehearsal, on the
day. **Channel:** `channel.vexa.ai/vexa/channel/pilot-stable` — the **live**
registry, not a test rig. **Cluster:** LKE `vexa-rehearsal` (id **646952**),
us-sea, k8s **v1.36.3**, 2× g6-standard-4, tag `throwaway`, created and
**destroyed** the same day. **Container work** ran on `bbb`, never on the
laptop.

The question this rehearsal was built to answer is not "does the machinery
work". It is **"if we send the kit to the pilot subscriber on Monday, what happens?"** So it was
run the way they will run it: from an empty directory, with a pull-only
credential, against the real channel, with nothing borrowed from this
repository.

The short answer is that **the customer would have got stuck four separate
times before a single Vexa pod started**, and none of the four would have
looked like our fault to them. Every one is now fixed and proven. Three things
remain open and are named at the bottom.

---

## What was proven, in order

### 1 · The entry on the customer channel was not one we could send

Before anything else, the entry `pilot-stable:current` was pulled and read. It
carried:

| Field | Value it carried | Why that is not sendable |
|---|---|---|
| `publication.mode` | `dry_run` | The kit's own example contract says `require_publication_mode: published`. **The customer's contract would have refused it.** |
| `signing.identity` | `sha256:c494cbb0…` — the **ephemeral test key** of the M1 worked example | The entry is actually signed by the live channel key `sha256:f6aac70e…`. A customer pinning what the entry named would have pinned the wrong key. |
| `chart` | `null` | while a hand-packaged chart `0.12.30` sat beside it on the channel, corresponding to **no release** — `Vexa-ai/vexa` has no `v0.12.30` tag. |

**Decision taken, and why.** The brief allowed for minting an entry at the
chart's lineage. There is no honest way to do that: `v0.12.23` is the newest
tag that exists, and it is the only one with a real candidate map and a real
delivery receipt. So the entry was **rebuilt at v0.12.23** from genuine inputs
— nothing fabricated, no `--break-glass` — and the chart was **repackaged by
the publisher** from that tag and republished, so the entry names a chart that
exists and was built from the release it claims.

```
python3 publisher/vexa_channel.py build \
  --release v0.12.23 --channel pilot-stable --entry-seq 2 --supersedes v0.12.23 \
  --vexa-repo ~/dev/vexa --delivery-receipt <receipt> --archive <archive> \
  --provenance-bundle <bundle> --trusted-root <root> \
  --chart-ref channel.vexa.ai/vexa/channel/pilot-stable/charts/vexa \
  --chart-digest sha256:2a378b88… --chart-version 0.12.31 \
  --identity sha256:f6aac70ec20248f977403f256594ef50a5ea14b2b42e4d4ca1e456742db8fab9 \
  --signing-mode cosign_key --publication-mode published \
  --approved-by "…" --approval-receipt "…" --out <dir>
#   C1 tag v0.12.23 -> e59874bc2dfff3a75475696ac33cc0c62e71e75a
#   C3 map pin OK; C5 10 images consistent; C6 cosign verify-blob-attestation: Verified OK
```

`vexa_channel.py verify` then passed **all ten** offline checks including the
entry signature and the SLSA provenance against the archive bytes.

**The `0.12.30`-vs-`0.12.23` "lineage mismatch" turned out to be a symptom of a
design defect, not a mistake by whoever published it.** `cmd_chart` wrote the
release version into *both* of Chart.yaml's version lines. Helm keeps two
because they are two facts — `version` is the chart revision a subscriber's
`targetRevision: "*"` ranks, `appVersion` is the release it deploys. Collapsed,
a release could never ship a second chart revision, and chart revisions shared
a number space with releases. `--chart-version` separates them.

### 2 · VERIFY.md documented a command that has never worked

The published `VERIFY.md` told the customer to run:

```
cosign verify-blob --key <channel.pub> --bundle entry.json.sigstore.json \
  --new-bundle-format entry.json
```

which returns, on every entry this publisher has ever produced:

```
Error: signature not found in transparency log
```

The channel signs **offline against a pinned key** and uploads nothing to
Rekor, deliberately — that is what makes it air-gappable. So the flag that
works is `--insecure-ignore-tlog=true`, and `--new-bundle-format` must be
absent because the bundles are legacy. Both `write_verify_md` and the
publisher's own `cmd_verify` carried the wrong flags, so **the publisher's
verify refused genuine entries**.

Recorded working commands, verbatim, against the live channel:

```
# the entry blob
cosign verify-blob --key channel.pub --bundle entry.json.sigstore.json \
  --insecure-ignore-tlog=true entry.json
# → WARNING: Skipping tlog verification …
#   Verified OK

# the OCI artifact carrying it
cosign verify --key channel.pub --insecure-ignore-tlog=true \
  channel.vexa.ai/vexa/channel/pilot-stable@sha256:4b9baf51…
# → The signatures were verified against the specified public key
```

`cosign` here is **v3.1.3**, not 2.4.3. It has `--use-signing-config`, and in
3.x it *requires* it: `--tlog-upload=false` is refused on its own with
`"--tlog-upload=false is not supported with --signing-config"`. Signing needs
**both** `--tlog-upload=false --use-signing-config=false`. Both flags are
already deprecation-warned; a cosign bump will need this revisited.

VERIFY.md now also tells the reader to check the key they pin against the
identity the entry names — the defect in §1 existed precisely because nothing
did.

### 3 · The kit had never been published to a real registry

`kit/release.sh` aborted at the first push:

```
./kit/release.sh --registry channel.vexa.ai --channel pilot-stable --version v0.1.0 …
== oras push channel.vexa.ai/vexa/channel/pilot-stable/kit:v0.1.0
./kit/release.sh: line 127: PLAIN[@]: unbound variable
```

`${PLAIN[@]}` and `${COSIGN_INSECURE[@]}` are **empty unless `--insecure` or
`--plain-http` is passed**, and an empty array under `set -u` is "unbound
variable" on bash 3.2. So the scripts worked only on the plain-HTTP test rig
and broke on exactly the path a real TLS registry takes. `install.sh` had
already learned this and carries the `${arr[@]+"${arr[@]}"}` idiom in a
comment; `release.sh`, `bootstrap.sh` and `self-update.sh` had not.

Underneath it sat a second one: all four scripts and `cosign_env()` wrote
`{"auths": {}}` to defeat a hanging Docker credential helper. That is correct
against a public registry and **fatal against an authenticated one** — the
entry pushed and its signature failed `UNAUTHORIZED`. The hazard is the
*helper*, not the credentials. They now carry the on-disk auths across, drop
`credsStore`, and accept an explicit credential from
`VEXA_CHANNEL_{REGISTRY,USER,PASS}` — environment, never argv.

After the fix, published to the live channel: kit **v0.1.0 … v0.1.5**, each
signed, each moving `latest`.

### 4 · A customer with nothing but a credential gets a verified kit

A clean directory holding **only** `bootstrap.sh` and `channel.pub`, run with
`HOME` and `TMPDIR` isolated and only the **pull-only** subscriber credential:

```
== resolving channel.vexa.ai/vexa/channel/pilot-stable/kit:latest
   digest sha256:fad45fe7…
== cosign verify … against channel.pub
   signature OK
vexa-kit v0.1.0 unpacked to /private/tmp/reh/customer/vexa-kit
  verified sha256:fad45fe7… against channel.pub before unpacking
```

The negative, same run, wrong pinned key:

```
SIGNATURE VERIFICATION FAILED — refusing to unpack anything.
  cosign: Error: no matching signatures: invalid signature …
$ ls ./should-not-exist
ls: ./should-not-exist: No such file or directory
```

Verify-before-unpack holds in both directions, and **nothing came from this
repository**.

**Write-scoping proven at the registry.** With the subscriber credential:

```
oras push … kit:evil        → 401 Unauthorized on POST /blobs/uploads/
oras resolve … kit:latest   → sha256:fad45fe7…
```

### 5 · Install: authenticated channel, and a Kyverno flag that lies quietly

`install.sh` had **no way to give Argo CD or Kyverno a registry credential**.
The Argo repository Secrets carried url/name/type and nothing else, so against
`channel.vexa.ai` the repo-server 401s and the subscription never syncs. Added
`--registry-user` (password from `VEXA_CHANNEL_PASS`).

Kyverno needed the same, and cost the most time for the smallest reason. The
controller flag takes a **bare secret name resolved in Kyverno's own
namespace**. Passing `kyverno/channel-registry-creds` is accepted silently and
the fetch stays anonymous, which surfaces as:

```
failed to verify image docker.io/vexaai/v012-gateway@sha256:514ba270…:
  .attestors[0].entries[0].keys: no signatures found
```

— **indistinguishable from an unsigned image**, while the signature was in fact
present and readable by that very credential (verified independently: HTTP 200
for the publisher, 200 for the subscriber, 401 anonymous).

Preflight on the clean cluster: **PASS**, P1–P9.

### 6 · The channel flows, digest-pinned, into a fresh cluster

`vexa-enterprise-staging` resolved `*` to chart **0.12.31**, pulled it from the
authenticated OCI registry, and reached **Synced / Healthy** with 13 pods:
admin-api ×2, agent-api, gateway, meeting-api ×2, runtime, terminal ×2, plus
postgres, redis, minio and its init Job. `vexa-enterprise-prod` tracked
`UNPINNED` and synced nothing — the customer-held gate, working.

### 7 · The station loop was broken at the join

`kit/validate` produced `station.tar.gz`, redaction verified — **4 values
removed, 0 found anywhere in the archive that was written**. The publisher then
refused it:

```
REFUSED S2: bundle is incomplete; missing smoke_receipt
            (one of: smoke-receipt.json, smoke-receipt.txt, smoke-receipt.md)
```

`validate` names its receipt `smoke-receipt-20260824-165142.md`, because an
operator runs smoke more than once. And `station.json` carried neither the
station **name** the ingest checks `--station` against, nor the `files[]`
digest list its S3 check reads — it wrote a `contents` list of bare names
instead. **Every genuine bundle was refused, and had always been.** The ingest
had never seen one.

Fixed on both sides, keeping the load-bearing half intact: `validate` emits
`station` (new `--station` flag) and `files[]` with digests; `ingest` accepts
the dated receipt name while still refusing an ambiguous match. Then:

```
python3 publisher/vexa_station.py ingest --bundle station.tar.gz --station rehearsal-pilot
ingested station 'rehearsal-pilot' -> stations/rehearsal-pilot at 2026-08-24T16:51:48Z
  caaddb8bfc9c  contract.yaml
  144505ea16b1  preflight-receipt.txt
  e4f884940853  profile.env
  7bbe252e4f8a  smoke-console.txt
  4a1ea9855851  smoke-receipt-20260824-165142.md
  dc5ccc2163da  values.redacted.yaml
```

### 8 · The station gate refused the chart, and was right to

```
python3 publisher/vexa_station.py gate --station rehearsal-pilot --chart vexa-0.12.32.tgz …
REFUSED S6: station 'rehearsal-pilot' refuses this publish — 8 finding(s)
  - S6: Job/…-minio-init containers/minio-init does not declare resources.requests.cpu   (×4)
  - S8: Deployment/…-redis    image 'valkey/valkey:8-alpine' is not digest-pinned
  - S8: StatefulSet/…-minio   image 'minio/minio:latest'     is not digest-pinned
  - S8: StatefulSet/…-postgres image 'postgres:17-alpine'    is not digest-pinned
  - S8: Job/…-minio-init      image 'minio/mc:latest'        is not digest-pinned
```

**This is the most important product finding of the day.** The delivery
system's entire claim to an enterprise buyer is *an exact, attested image-digest
set*. That claim covered only Vexa's own images. The four data-plane
dependencies floated, **two of them on `:latest`** — and the Kyverno
digest-pinning policy never caught them because it matches `*vexaai/*`.

Three were pinnable from `kit/profiles/vexa/node-baseline.yaml` and now are, at
digests resolved on the day. The fourth, `minio/mc:latest`, was **hardcoded in
the chart template** with no value to override, and the same Job declared no
resources at all — the exact LimitRange-squeeze class the preflight's P2 exists
to catch. That needed a change in the OSS chart:
[`Vexa-ai/vexa#1321`](https://github.com/Vexa-ai/vexa/pull/1321).

Proven that the fix closes the finding: a chart packaged from the v0.12.23 tree
**with #1321 applied** (in a throwaway clone, local tag, never pushed) gates
clean —

```
PASS — station 'rehearsal-pilot' admits vexa-0.12.32.tgz
```

**Gate-report stamping** works and did not need new machinery: `--extra-evidence
other=<name>=<path>` carries it into the signed entry. One fix was required —
every attached file was stamped `application/json`, so a markdown gate report
would have made the entry lie about its own evidence. Media type now follows
the extension, and entry seq 3 carries the real report:

```
{"name":"station-gate-rehearsal-pilot-2026-08-24.md","kind":"other",
 "sha256":"cccc1776…","media_type":"text/markdown"}
```

The report stamped into the published entry is the **refusal**, because that is
what the real chart earns today. That is the honest state, not a tidy one.

### 9 · Pull-only self-upgrade: 26 seconds, zero kubectl

```
BEFORE:    chart 0.12.31 at 16:56:07Z
PUBLISHED: entry seq 3 + chart 0.12.32 at 16:56:14Z
UPGRADED:  chart 0.12.32 at 16:56:40Z — 26s after publish, zero kubectl writes
```

The newly pinned dependency arrived with it:
`postgres:17-alpine@sha256:18cfe3ef…` live in the StatefulSet. Nothing on the
vendor side touched the cluster; the cluster pulled.

### 10 · Kit self-update

Run five times over the day, each time as the customer, each time verifying the
signature against `.kit-source.pub` before unpacking:

```
kit updated: v0.1.0 -> v0.1.1 … v0.1.4 -> v0.1.5
```

It is worth saying plainly that this loop is why the rehearsal finished: every
fix found in the customer's hands was published to the channel and pulled back
down through the same path a customer uses. **The delivery mechanism was used
to deliver its own repairs.**

### 11 · The PreSync verify gate, switched on for the first time

It had been off in every install to date. Turning it on found **four** defects
in a row, each of which fails the sync for a reason that has nothing to do with
the evidence:

| # | What happened | Fix |
|---|---|---|
| 1 | The Job's pod could not pull the verifier image at all — `ImagePullBackOff`; the kubelet had no channel credential | `imagePullSecrets` on the Job |
| 2 | `backoffLimit: 0` + a pod that never starts = a Job that **never fails**, so Argo sat on `waiting for completion of hook batch/Job/vexa-verify` **indefinitely, with no timeout and no self-recovery** | `activeDeadlineSeconds: 300` |
| 3 | The hook asked for the entry at `v{{ .Chart.Version }}` — the **chart revision** — when entries are tagged by **release** | `.Chart.AppVersion` |
| 4 | `vexa-verify.sh` verified the entry signature with `--new-bundle-format` — the §2 bug again — and reported **`entry signature does NOT verify against the pinned channel key`** on a correctly signed entry, **blocking the sync** | `--insecure-ignore-tlog=true` in all three channel-key checks; the SLSA check keeps the flag, being genuinely keyless v0.3 |

Defect 4 is the one worth losing sleep over. It is the gate's loudest possible
alarm — *this release may be forged* — fired on a good release, by our own
wrong flag.

With verifier **v0.1.1** (built on `bbb`, `linux/amd64`, pushed and signed):

```
OK    entry pulled: channel.vexa.ai/vexa/channel/pilot-stable:v0.12.23
OK    entry signature verifies against the pinned channel key
OK    digest evidence/candidate-images.json … delivery-receipt … source-provenance … trusted-root
OK    digest evidence/station-gate-rehearsal-pilot-2026-08-24.md
OK    candidate map matches the delivery receipt's packet pin
OK    policy: evidence 'candidate_map' … 'delivery_receipt' … 'source_provenance' … 'trusted_root' present
OK    policy: no break-glass on this entry
OK    policy: entry_seq 3 >= your floor 1
OK    policy: publication mode 'published'
OK    vendor approval: published by Dmitry Grankin (founder)
VERDICT: ELIGIBLE — v0.12.23 verified against contract example-2026-01 @ sha256:ec035d34…
```

And the negative, with one line added to the station's contract in its own
cluster (`require_evidence_kinds += soak`):

```
FAIL  policy: required evidence 'soak' absent
VERDICT: NOT ELIGIBLE — 1 check(s) failed
```

Pod phase `Failed`. That a failed verifier stops the sync was observed
separately and involuntarily, during defect 4: the Application stayed
`OutOfSync` and did not advance until the verifier passed.

### 12 · `mail_cursor` — the question does not arise

A fresh install creates **six** tables and none of them is `mail_cursor`:

```
api_tokens · meeting_sessions · meetings · platform_settings · transcriptions · users
\d mail_cursor → Did not find any relation named "mail_cursor".
```

So `ALTER TABLE mail_cursor ADD COLUMN token TEXT` (per `Vexa-ai/vexa#1318`) is
**not needed on a fresh install of this chart, and cannot be applied**: the
flows schema is not provisioned at all, because the flows tier is not part of
the delivered set. Confirmed independently by smoke S4 (below). The ALTER is a
question for an existing flows deployment, not for the pilot subscriber's first install.

---

## What FAILED or was partial

### S3 — the bot joined nothing, and the cause is our own tenant

The M365 rig produced a real Teams meeting via Graph with
`lobbyBypassSettings: {scope: everyone}` accepted by the API. The bot pod
spawned from the correct digest-pinned image
(`vexaai/vexa-bot:v0.12.23@sha256:2bd879c6…`, 1.6 GB, pulled in 33s) and failed:

```
TeamsJoinRedirectError: teams_auth_redirect: the anonymous Teams join was
redirected to the Microsoft sign-in page; this meeting link offered no
anonymous pre-join, so the bot never reached the meeting and no host was ever
asked to admit it (url=https://login.microsoftonline.com/common/oauth2/v2.0/authorize)
```

`completion_reason: join_failure`, `bot_outcome: never_admitted`,
`segments_captured: 0`.

**This is a rig-tenant policy, not a per-meeting setting and not a product
defect.** `lobbyBypassSettings` governs the lobby; it does not grant *anonymous
join*, which is a Teams **meeting policy** on the organiser
(`AllowAnonymousUsersToJoinMeeting`). Changing it is a tenant setting change and
was not made. **S3 is therefore PARTIAL: dispatch, image, pod and error
reporting all proven; capture not proven, and no audio question was ever
reached.** Making S3 genuinely hands-free needs that policy flipped on the rig
by a human, once.

Worth noting for its own sake: the product recorded a full, correct
`ExitReason` and provenance block. This is precisely the per-reason detail that
an internal taxonomy note (private)
says the aggregate snapshot throws away.

### S3, first attempt — a default install cannot run a meeting at all

Before the join was even attempted:

```
[FAIL] S3 · bot dispatch refused (HTTP 503):
       {'detail': 'no transcription backend configured — set it in Settings or
        environment variables TRANSCRIPTION_SERVICE_URL + TRANSCRIPTION_SERVICE_TOKEN'}
```

`customer-values.example.yaml` mentions `transcriptionServiceToken` only as a
commented-out line reading "from your subscription pack", and **never mentions
`transcriptionServiceUrl` at all**. Nothing in preflight, install, or the docs
tells an operator this is mandatory before anything can work. A customer
following the documented path installs successfully, reaches Synced/Healthy,
and then cannot run a single meeting. Supplied by hand here from the dev
backend to get past it. **This is a customer-facing gap and it is still open —
see below.**

### S4 — the flows tier is not delivered, and used to crash the run

```
[FAIL] S4 · no reachable vexa-vexa-flows-api Service in vexa-staging —
       the flows tier is not part of this delivered set
```

Before the fix, `--flows` ended the entire run in a Python traceback: no
receipt, no verdict, and an operator with no way to tell "not delivered" from
"broken". The station bundle produced by that run was missing its smoke
receipt entirely.

### The agent/model tier

Not exercised. The flows tier is not in the delivered set, so the question of
whether a model credential exists for it never arose. **Recorded as a known
gap, not tested.**

### Kyverno signature admission — BLOCKED, and this is the headline

The customer-side admission gate — the thing that is supposed to verify our
attestations *independently of us* — **cannot read the signatures we publish.**

The mechanism, isolated:

| | Signature location | What cosign 3.1.3 writes | Kyverno 1.19 |
|---|---|---|---|
| **No `COSIGN_REPOSITORY`** | beside the artifact | tag `sha256-<digest>**.sig**`, media type `application/vnd.oci.image.manifest.v1+json` | reads it |
| **With `COSIGN_REPOSITORY`** (a flat signature repo — what the channel uses) | `…/signatures` | tag `sha256-<digest>` (**no `.sig`**), an **image index** whose child is a **sigstore bundle v0.3** | **"no signatures found"** |

Confirmed both ways on the live channel. `--registry-referrers-mode=legacy`
does not change it; `--new-bundle-format=false` does not change it. The
signature is present and correct — `COSIGN_REPOSITORY=… cosign verify` passes —
and Kyverno cannot see it.

The consequence for a customer is the worst available shape: **a correctly
signed release is denied at admission with a message that says it is
unsigned.** For the rehearsal to continue past this point, the
`vexa-verify-channel-signature` ClusterPolicy was **deleted**, and everything
after §6 was proven with **image-signature admission OFF**. That is recorded
here rather than smoothed, and nothing downstream should be read as
"admission-verified".

The fix was not attempted because the obvious route — signing the images in
place on `docker.io/vexaai/*` — writes to a public namespace and is a
publishing act that needs its own decision.

---

## Fixes this rehearsal forced

In this repository, on branch `rehearsal-receipt`:

| Commit | What |
|---|---|
| `52aa170` | publisher: VERIFY.md and `cmd_verify` documented/ran a cosign command that fails on every genuine entry; `cosign_env` could not authenticate; chart version ≠ appVersion |
| `7574bf2` | kit: `release`/`bootstrap`/`self-update` could not work against a real, authenticated, TLS channel (bash 3.2 empty arrays; blanked auths) |
| `9dd620b` | `install.sh` registry credentials for Argo and Kyverno; smoke S4 reports instead of crashing; `--extra-evidence` media type |
| `270e32a` | the PreSync gate's four defects; the station loop's filename/manifest mismatch; dependency image pins |

In `Vexa-ai/vexa`: [**#1321**](https://github.com/Vexa-ai/vexa/pull/1321) — the
minio-init Job was unpinnable (`minio/mc:latest` hardcoded in the template) and
declared no resources.

`make test` and `make lint` green.

---

## What the customer must do differently

1. **Set the transcription backend before installing.** `transcriptionServiceUrl`
   *and* `transcriptionServiceToken`. Without both, the install succeeds and no
   meeting can ever run. This belongs in `install.mdx` and in
   `customer-values.example.yaml` as a required field, not a comment.
2. **Pass `--registry-user`** and export `VEXA_CHANNEL_PASS`. Every enterprise
   channel is authenticated; without it Argo never syncs.
3. **Expect `enterprise-prod` to sit at `Unknown`** with
   `improper constraint: UNPINNED` until they move their own pin. That is the
   gate, not a fault, but the error text reads like one.
4. **Do not enable image-signature admission yet.** It will deny correctly
   signed images. Digest-pinning admission is fine and should stay on.

---

## What this does NOT prove

- **Nothing about transcription quality, or about capture at all.** No audio
  ever reached the pipeline. S3 proved dispatch, image identity, pod lifecycle
  and error reporting — and stopped there.
- **Nothing about image-signature admission.** It was deleted to proceed. Every
  result from §6 onward was obtained with it off.
- **Nothing about the flows/agent tier**, which is not in the delivered set.
- **Nothing about OpenShift.** One provider profile (`lke`) was exercised.
- **Nothing about the chart the customer would actually receive passing its own
  gate.** The gate passes only against a chart carrying the unreleased #1321.
  On the real `v0.12.23` tree it refuses, correctly, and the entry now on the
  channel carries that refusal as evidence.
- **Nothing about scale, upgrade-under-load, rollback, or break-glass.** One
  install, one upgrade, one cluster, no failure injection.
- **Nothing about the dependency images' provenance.** They are pinned now;
  pinned is reproducible, not attested.
- **The 26-second upgrade is one measurement** on a two-node cluster with a warm
  image cache — a demonstration that the transport works unattended, not a
  latency guarantee.
- **Nothing about the LKE volume lifecycle beyond one teardown.**
- **`publication.approved_by` names the founder for an approval given to run
  this rehearsal**, recorded in `approval_receipt` pointing at this file. It is
  not an approval of v0.12.23 for the pilot subscriber's production.

---

## 13 · The state the channel was left in

Publishing five chart revisions over the day left `targetRevision: "*"`
resolving to `0.12.35` while the entry's `chart.digest` named `0.12.32` — the
subscriber would have run a chart its own entry does not describe. A rehearsal
that leaves that behind has broken the thing it was checking, so the channel
was made coherent before the session ended:

| Repository | Left holding |
|---|---|
| `pilot-stable` | one entry — `current` = seq **4**, release **v0.12.23**, chart **0.12.35**, `publication.mode: published`, identity `sha256:f6aac70e…`, gate report in evidence |
| `pilot-stable/charts/vexa` | **`0.12.35` only** |
| `pilot-stable/kit` | `v0.1.0`–`v0.1.5`, `latest` → `v0.1.5` |

The hand-packaged **`0.12.30`** — the chart matching no release that started
this whole investigation — was **deleted**, along with the four superseded
rehearsal revisions. Final check with the commands `VERIFY.md` now prints:

```
cosign verify-blob … --insecure-ignore-tlog=true entry.json   → Verified OK
cosign verify   … --insecure-ignore-tlog=true …@sha256:ce96f4c1…
                                                → verified against the specified public key
```

## Cluster

**Destroyed.** LKE 646952 deleted at the end of the session. No failure required
keeping it.

**And its volumes, which the cluster deletion does not take with it.** LKE's
default StorageClass is `linode-block-storage-**retain**`; the four PVCs this
install created survived the cluster and had to be detached and deleted by
hand, and the API reported them still attached to an already-deleted node for
**about four minutes** — a detach/delete retry loop is required, not a single
call. The `lke` provider profile already warns about this class (measured: 69
stranded PVs, $888/yr) and it is right to. **32 stranded volumes remain on the
account from earlier sessions** — not from this one, and not cleaned here
because deleting other people's data is not this agent's call.

A customer running the kit on LKE inherits the same behaviour and should be
told: **deleting the cluster does not delete the data, or stop the bill.**

## The single biggest thing between here and sending the kit

**The signature-admission incompatibility.** Everything else found today is
fixed and proven. That one is not, and it is the only defect that breaks the
central promise: *your admission layer independently verifies our attestations
before a byte runs*. Today it cannot — and it fails in the direction that makes
our own good releases look forged. A bank's security review will ask to see
that gate work. Until it does, the kit ships with its most quotable control
switched off.

{/* vexa-agent */}
