# RUNBOOK — the operator's day

**The loop, in the founder's words (2026-08-25): we publish · the cluster
deploys · we get a receipt · they do not touch.** Every mechanism in this
repository serves one of those four beats — publisher and gate serve *publish*;
Argo and the pin serve *deploys*; the station bundle and submit serve
*receipt*; signatures, admission and `selfHeal` serve *nobody touches*. This
runbook is organised by them. The same loop runs for a customer's estate and
for our own: since the subscriber-#1 pivot, `vexa-platform` is a subscriber
like any other.

**The invariant (founder, 2026-08-25): the channel is the ONLY writer of
cluster state.** One publisher per channel, so what the channel holds *is* what
staging and then prod run; the signed entry at the pin is the single answer to
"what is running"; `selfHeal` reverts anything out of band. **A hotfix is
publish → staging → pin.** *One loop, one write surface, applied to
deployment.* Everything in § 4 exists because an exception to that invariant
must be a designed, audited path rather than a habit.

Two rules hold across every beat:

- **The publisher consumes released artifacts and receipts, never clusters, and
  holds no production credentials.** Nothing here reaches into a subscriber's
  cluster, because there is no path.
- **There is no silent path.** Every check that can refuse, refuses loudly and
  writes what it refused into a signed artifact. A gap needs a `--break-glass`
  record or a named waiver; neither is quiet.

⛔ marks a founder gate. **Rungs are stated:** a step that exists only on an
open PR says so with its number, because a command printed in a runbook reads
as a command you can run. Where something is designed but unbuilt, this file
says *unbuilt* rather than describing it in the present tense.

**Per-verb flag reference:** [`docs/reference/`](docs/reference/index.mdx),
generated from each tool's own `--help`. This runbook says *when* and *why*;
the reference says *what the flags are*, and it cannot go stale — a verb
without a hand-written line fails `make test`.

---

## 0 · Preconditions

- **Channel registry live** on `channel.vexa.ai`, on its own host, with one
  machine account per subscriber (§ 5).
- **The signing toolchain pinned** — see § 1.5. Ambient `cosign` is not it.
- ⛔ **Key ceremony done** — channel keypair generated, private key
  founder-held, `channel.pub` in every onboarding pack.
  <br>*Rung: customers pin a **raw key** today. The decided model (2026-08-25)
  is a pinned **root CA** with short-lived leaves and an RFC-3161 timestamp
  chain, verified by Kyverno's `certChain` attestor — not TUF, not keyless.
  It is **design, not implementation**, and the manifest is explicit that
  where a root CA private key would live is unanswered. Rotating a pinned raw
  key means touching every customer cluster, which is exactly what that design
  exists to avoid.*
- **A delivery receipt** from our own production run of the release. `build`
  cross-checks against it; without one there is nothing to cross-check.
- **A validation contract**, referenced by the entry by **id and hash**. Real
  by default: a double is allowed only where real is impossible or harmful and
  carries its own justification; a dependency with no usable real is declared
  `absent` and every dependent claim marked **not-proven**, never faked. *No
  bare greens, no undeclared substitution* — and the same mechanism tells a
  subscriber what THEIR release was validated against.

---

## 1 · Beat one — WE PUBLISH

One release, one operator. Everything after `fetch` is offline.

### 1.0 The crank is one command

```bash
make publish RELEASE=vX.Y.Z ENTRY_SEQ=N
make publish RELEASE=vX.Y.Z ENTRY_SEQ=N DRY_RUN=1     # prints the chain, runs nothing
```

`fetch → build → sign-images → push`, in that order, with the flags § 1.1, § 1.2,
§ 1.5 and § 1.6 spell out one at a time.

**Packaging, not weakening.** Every check inside those verbs still runs and still
refuses — C1..C9 in `build`, T1/T2 in `sign-images` and `push`, and the ledger
write that makes `push` the sole writer of `channel.yaml`. There is no flag here
that skips one, and no `--force`.

**No credential moves** (ADR-0001 § 6). The signing key stays wherever you keep
it: the target reads the same environment the manual steps read, passes the
key's **path** to cosign, and never reads, copies or prints the material. An
unset variable is a refusal that names the variable — never a default.

| Variable | Is |
|---|---|
| `RELEASE` | the release tag, e.g. `v0.12.24` |
| `ENTRY_SEQ` | the next entry sequence. **Not derived** — `vexa_stations.py … show` prints the current one; a rollback floor a script guessed is a floor nobody chose |
| `VEXA_REPO` | the `Vexa-ai/vexa` checkout the tag is read from (C1) |
| `VEXA_CHANNEL_REF` | the channel's registry repository |
| `VEXA_SIGNATURE_REPOSITORY` | where `sha256-<digest>.sig` must land — the exact repository Kyverno asks for (T2) |
| `VEXA_CHANNEL_KEY` | **path** to the channel signing key |
| `VEXA_SIGNING_IDENTITY` | the identity the entry declares |
| `VEXA_STATIONS_DIR` | the stations-ledger checkout `push` records into |

Optional, all defaulted: `CHANNEL` (`vexa-internal`), `PUBLICATION_MODE`
(`candidate`; `published` additionally requires `APPROVED_BY`,
`APPROVAL_RECEIPT` and `DELIVERY_RECEIPT`), `SUPERSEDES`, `CHANNEL_TAG`,
`EXTRA_EVIDENCE` (space-separated `kind=name=path`), `SIGNING_RECEIPT`, `WORK`
(default `work/<release>`).

**What it does NOT do:** the chart (§ 1.3), the station gate (§ 1.4) and
customer-#0 verification (§ 1.7) are separate acts with their own inputs and
their own refusals, and collapsing them into the same line would hide a gate
report behind a release number.

> **The rest of § 1 is the appendix: what `publish` does.** It is the same
> commands, in the same order, and it is where the flags are explained. Run them
> by hand when a crank stops and you need one step in isolation.

### 1.1 Gather the inputs

```bash
python3 publisher/vexa_channel.py fetch --release vX.Y.Z --out work/in
```

The only network step, and it reaches GitHub, not a cluster.

### 1.2 Build the entry

```bash
python3 publisher/vexa_channel.py build --release vX.Y.Z \
  --channel acme-stable --entry-seq N --supersedes vX.Y.(Z-1) \
  --vexa-repo ~/dev/vexa --delivery-receipt <receipt> \
  --archive work/in/vexa-core-vX.Y.Z.tar.gz \
  --provenance-bundle work/in/source-provenance.sigstore.json \
  --trusted-root work/in/trusted-root.jsonl \
  --identity <key fp> --signing-mode cosign_key \
  --publication-mode published --out work/entry
```

Cross-checks **C1..C9** run here — tag identity, map identity, map↔receipt pin,
receipt identity, image consistency, provenance verification, bundle digesting,
completeness-or-break-glass, schema. Any failure refuses with **exit 3**.

⛔ `--publication-mode published` **requires `--approved-by` and
`--approval-receipt`.** That is the publication half of the approval (§ 2.3).
`candidate` and `dry_run` need neither, which is what makes the internal
channel's candidate lane possible (§ 6).

### 1.3 Package the chart

```bash
# the open-source vexa chart, digests baked in, pushed to the channel
python3 publisher/vexa_channel.py chart --release vX.Y.Z --vexa-repo ~/dev/vexa \
  --baseline kit/profiles/vexa/node-baseline.yaml --out-dir work/chart \
  --push oci://<REG>/vexa/channel/acme-stable/charts
```

The chart's semver **is** the channel position a station follows.

For the internal channel the chart is the proprietary `vexa-platform` umbrella
instead:

```bash
# RUNG: PR-OPEN — Vexa-ai/vexa-delivery-internal#40. Never pushed, never signed.
python3 publisher/vexa_channel.py platform-chart --release X.Y.Z \
  --chart-dir ~/dev/vexa-platform/chart/vexa-platform \
  --pin-set <pins.txt> --out-dir work/platform-chart \
  [--unpinnable '<repo>=<reason>']
```

**The pin set is an explicit input, never inferred.** `vexa-delivery-internal#40` established that the
platform's digest set exists *only in the live cluster*: the repo references
every image by tag, and `release/registry.yaml` — the file originally named as
the pin source — is a 126-entry evidence-**check** registry holding no digest
pins at all. Capturing the pin set from a cluster and publishing it into a
signed entry is what turns cluster-only state into an artifact anything can be
verified against. Checks **P1..P4** refuse rather than guess, and a hole must be
**declared** with `--unpinnable`; silent partial pinning is the failure mode the
command exists to prevent.

### 1.4 Gate the release against every station

This is the half of the question the channel publisher does not answer. `build`
asks *may this release exist*; the station gate asks *may it be published AT
this customer's station, given that station's contract*.

```bash
python3 publisher/vexa_station.py gate --station <name> \
  --chart work/chart/vexa-X.Y.Z.tgz --evidence work/evidence/vX.Y.Z.json \
  [--waive <require-item> --reason "<why, loudly recorded>"]
```

**S5..S9** render the chart with the station's own values and match every
`require:` item against evidence this release produced. Exit `3` is a refusal,
and a refusal is the system working (§ 4.1). Either way it writes
`stations/<name>/gate-report-<date>.md`, naming the station, the chart and its
`sha256`, the values' `sha256`, the contract id **and hash**, and a verdict per
check and per contract item. **Generated, not written** — it is the per-release
guarantees document, and it is stamped into the signed entry with
`build --extra-evidence other=<name>=<path>`.

**A guarantee list is a claim; the gate is the check.** The sharpest instance:
a release *claimed* `no-hostpath` in its evidence, S9 accepted the claim — and
the object-level check refused the publish anyway.

*Rung: PR-open [vexa-delivery-internal#38](https://github.com/Vexa-ai/vexa-delivery-internal/pull/38) adds
**S10..S14**, the outbound half of the two-directional contract —
`delivery_scope`: namespaces, cluster-scoped yes/no, PSS level, image-source
allowlist, sum-of-requests ceiling. Standard vocabularies throughout, so a
reviewer who recognises PSS/SCC stops evaluating and starts checking.*

### 1.5 Sign the images, with the pinned toolchain

```bash
./publisher/install-cosign.sh                        # verified against the release checksum
export COSIGN_BIN=$HOME/.local/bin/cosign-2.6.5

python3 publisher/vexa_channel.py sign-images \
  --candidate-map work/entry/evidence/candidate-images.json \
  --key <channel.key> --signature-repository <REG>/vexa/channel/acme-stable/sigs
```

**The publisher signs with cosign 2.6.5, not with ambient `cosign`.**
`push`, `sign-images` and `attest` refuse to sign with a binary outside the
pinned series. `VEXA_COSIGN_ALLOW_UNPINNED=1` overrides — loudly, and the
signing-run record then states what actually signed.

**The signature LAYOUT is what breaks, not the signature:**

| Signer | Writes | Kyverno 1.19 |
|---|---|---|
| cosign 2.x default | tag `sha256-<hex>.sig`, cosign signature manifest | **reads it** |
| cosign 3.x default | `sha256-<hex>`, OCI referrers index, bundle v0.3 | **`no signatures found`** |
| cosign 3.x `--new-bundle-format=false` | the 2.x layout again | reads it |

The corrected diagnosis was **not** the cosign major version: the layout rested
on a deprecated flag of an unpinned binary, and **nothing checked the output**.
Drift was already live — 14 referrers tags against one `.sig`. Worse, an
unsigned image and a referrers-signed image are **indistinguishable** at
admission: both deny as unsigned.

### 1.6 Push, and prove it the way Kyverno reads it

```bash
python3 publisher/vexa_channel.py push --entry work/entry \
  --ref <REG>/vexa/channel/acme-stable --sign-key <channel.key> \
  --ledger <stations-ledger>
```

Immutable tag only; the chart's semver is the pointer. Two toolchain checks run
**inside** this path so they cannot be skipped:

| | |
|---|---|
| **T1** | the cosign that signs is inside the pinned series |
| **T2** | after signing, `sha256-<digest>.sig` exists in the signature repository, holds a `application/vnd.dev.cosign.simplesigning.v1+json` layer, and verifies against the channel key |

**A pin is a promise; T2 is the proof.** Kyverno's entire wire conversation is
one request — `GET https://<registry>/v2/<signature-repository>/manifests/sha256-<hex>.sig`
— and T2 asserts exactly that. Its refusal names the consequence:

```text
REFUSED: T2: the tag Kyverno 1.19 will ask for does not exist:
  channel.vexa.ai/vexa/channel/pilot-stable/signatures:sha256-e98025e2….sig.
  This is the cosign 3.x referrers layout; admission would report the image as
  UNSIGNED. Sign with cosign 2.6.5
```

`push` also **generates `VERIFY.md` from the signing run**. It is never
hand-maintained: a hand-written verification command was documented for months
and had never worked once.

`--ledger` (or `$VEXA_STATIONS_DIR`) makes `push` the **sole writer** of
`channels/<channel>/channel.yaml` in
the stations ledger (a private repository),
and that file — not the registry — is the **authority for `entry_seq`**. The
copy inside the published entry is derived from it. The write is last in the
path, after the push it records, and it is one commit by pathspec.

```bash
python3 publisher/vexa_stations.py --ledger <stations-ledger> show
```

reads the whole ledger: every channel's sequence and current entry, every
station's pin, observed position, last verdict and flags. Push the ledger after
a crank — its git history is the audit trail, and there is no second log to
keep in step with it.

### 1.7 Customer-#0 verification, before announcing

A throwaway node consumes the new release through the kit (staging follows
`*`), the bot pod is admitted and Running, then the node is destroyed. This is
the per-release proof the chain claims. Receipts to
[`docs/receipts/`](docs/receipts/).

**Destroying an LKE cluster does not delete its volumes or stop the bill.** The
default storage class is `-retain`, and the API reports PVCs attached to an
already-deleted node for minutes afterwards — **a detach/delete retry loop, not
a single call.**

---

## 2 · Beat two — THE CLUSTER DEPLOYS

We publish; nothing pushes. What moves is a subscriber's own Argo, on its own
poll, against a position the subscriber chose.

### 2.1 Environments are POSITIONS, not channels

One channel per product-and-contract; a new channel only when the content or
the gating differs.

| Channel | Carries | Subscribers |
|---|---|---|
| `vexa-internal` | the platform — our own stack | our staging (`current`) + our prod (pin) |
| `pilot-stable` | OSS + Minutes, that customer's contract and key | their dev (`current`) + later their prod (pin) |
| `<shape>-stable` | the standard bundle for a shape | future sprint customers |

Inside a subscriber's cluster the two environments are two elements of one
`ApplicationSet` ([`kit/argocd/applicationset.yaml`](kit/argocd/applicationset.yaml)):

| Position | Follows | Sync |
|---|---|---|
| staging (element `env: enterprise-staging`) | `*` — the newest published chart version | automated, `prune: true`, `selfHeal: true` |
| production (element `env: enterprise-prod`) | a pin string, and only the subscriber moves it | **no automated sync at all** |

The release train's stage→prod ceremony collapses into **publish → staging
proves → pin move = prod deploy**, and rollback is the pin move back.

**The element's `env` is app IDENTITY.** Renaming one is a declared teardown of
that station's workloads. Observed live — and the station then rebuilt itself
from the channel alone, 12 pods, zero hand commands, which is the loop proving
itself.

### 2.2 The pin move

```bash
kubectl -n argocd patch applicationset vexa-channel-subscription --type=json \
  -p '[{"op":"replace","path":"/spec/generators/0/list/elements/1/position","value":"0.12.24"}]'
```

The pin is the release's **chart version** — `0.12.24`, no `v` prefix. That is
the whole promotion ceremony: one change, in their cluster, in their window.
Admission verification runs again in production regardless.

An unpinned prod reports `improper constraint: UNPINNED` at `Unknown`. **That
is the gate, not a fault** — though the error text reads like one.

### 2.3 Two approvals, by two parties

They are not interchangeable, and conflating them is the error this section
exists to prevent. **Vexa's approval never stands in for theirs.**

| | Publication approval | Promotion approval |
|---|---|---|
| Whose | ⛔ **ours** — a named human at Vexa | **theirs** — a named human at the subscriber |
| Recorded in | the signed entry, as `publication.approved_by` | a ConfigMap in *their* cluster, written by `kit/verify/approve.sh` |
| Enforced by | `require_vendor_approval: true` in their contract | the PreSync hook's `--require-approval` |
| Says | this release may exist on this channel | this release may run here |

`approve.sh --move-pin` approves and moves the pin in one act. The ConfigMap it
writes carries the release, approver, timestamp, entry ref and digest, the
verdict and its `sha256`, the contract id and `sha256`, and the reason — so
"we accepted 0.12.24 on the 19th" is a record, not a memory.

For the internal channel there is a machine gate under the human one: the prod
contract requires `vexa-staging`'s signed `station-verdict` for that exact
candidate. Since 2026-08-31 there are two carriers for it and the verifier
reads both (§6c) — the verdict carried INSIDE the entry, which binds to the
candidate commit and to the sha256 of the entry's own `values_proven` block;
or, where none rides inside, the attestation accumulated on the channel beside
the entry, which binds by release version and image digest set. The run says
which one adjudicated.

### 2.4 Pin-back

Rollback is the same field, the previous version — measured at **26 seconds,
no hands**. Argo rolls the workloads in reverse; admission verifies the older
digests against the same key; entries never disappear and digests are
immutable, so what you go back to is byte-identical to what ran.

**It rolls back code, not data.** Schema convergence
(`admin_api/schema/sync.py`) reconciles the DB to the models — it creates
missing tables, columns and indexes and does not care which version a cluster
jumped from — but it is **additive and forward-only**. One step back is safe
because each release reads the previous release's schema. Two steps back is a
restore. Check the migration notes in the release's evidence bundle first.

Before a sync has ever run there is also a free exit: `argocd app delete
--cascade=false`.

### 2.5 Adopting an existing estate — three findings first

From the prod migration plan (rung: PR-open
[vexa-delivery-internal#39](https://github.com/Vexa-ai/vexa-delivery-internal/pull/39), **not executed** —
nothing migrated, adopted, patched, scaled or restarted):

1. **13 of 13 prod Deployments carry `app.kubernetes.io/instance` inside their
   immutable `.spec.selector`.** Argo's *default* tracking method rewrites that
   label to the Application name — rejected by the API server on the selector,
   and orphaning pods where it lands. Set
   `application.resourceTrackingMethod: annotation` **before** the Application
   exists.
2. **`kit/argocd/applicationset.yaml` hardcodes `helm.releaseName: vexa`;
   prod's release is `vexa-platform`.** Applied as written, Argo adopts nothing
   and instead creates a second parallel set of workloads beside the live ones,
   in the live namespace, on the live database.
3. **The `vexa-platform-drift-detector` CronJob** runs `helm get manifest` +
   `kubectl diff` every 30 minutes and reports permanent drift the moment Helm
   stops being the source of truth. It already fails intermittently.

---

## 3 · Beat three — WE GET A RECEIPT

For a pilot, two passes are what "the delivery path works" means, and each
one's deliverable is a receipt rather than an assertion:

| | What happens | The receipt |
|---|---|---|
| **Pass 1** | they bootstrap and install on their own cluster | the **station bundle** — proves the environment *and* becomes the spec we gate against |
| **Pass 2** | we publish an update; their cluster takes it unattended | a **second receipt** naming the new revision |

**Installing IS contributing.** And **failure reports matter more than success
ones**: the deliverable of a pilot is what it is actually like to keep a bank
current from outside.

### 3.1 What a station report is

**One file** — `station-report.yaml`, produced by the subscriber's own
`kit/validate/vexa_validate.py`, with named sections instead of archive
members: `profile` (substrate facts — provider, k8s version, scope, namespace,
storage class, PSA mode, LimitRange and quota presence, mirror host; **never
credentials**) · `values` (only the *shape* travels) · `contract_document`
(**their file**) · `preflight_receipt` · `smoke_receipt` · `smoke_console` and
`install_log` when a run produced them. The head carries the manifest facts —
station, kit revision, Kubernetes version, provider, namespaces, contract id
and sha256, phase verdicts — and `sections[]` carries the `sha256` of every
section's text. That manifest is what makes it a report rather than a note.

One file because **the operator has to approve it before it leaves their
perimeter**, and six files in a tarball is a review task where one commented
document is a read. It goes back on every release, so the cost of a document
nobody finishes compounds.

Redaction is verified from the finished document, not from intent: any value
under a key matching `password|token|secret|key|apikey` is replaced, then the
rendered file — the exact bytes that would be sent — is scanned, exiting **3**
if a removed value still appears, **naming a count, never a value**.

### 3.2 Ingest

```bash
python3 publisher/vexa_station.py ingest --bundle <station-report.yaml> --station <name> \
  --channel <chan> --ledger <stations-ledger> [--force]
```

**S1..S4** run before anything is kept: report shape (one YAML document, a
mapping, report.v1, bounded size), completeness of the section roles this
report *kind* requires, manifest identity (every declared section hashes to
the text that is there, nothing undeclared rides along), and a plaintext-secret
scan that is defence in depth over the customer's own redaction — each section
parsed back into its own format so a credential inside a block scalar is caught
exactly as one inside a file was. S4 prints section, line and rule and **never
the value**, so a refusal is safe to paste into a ticket. It writes
`stations/<name>/ingest-receipt.json` with the ingest stamp, the report's own
digest and every section digest, beside the report itself, verbatim.

Until a station is ingested we cannot gate a release against it, so an
un-ingested report is an **un-represented customer** — their contract is not
consulted on any publish.

`stations/<name>/` here is a **scratch directory** — gitignored, one laptop,
gone with the laptop. `--ledger` is what makes the receipt durable: the report
verbatim, its reduced manifest and its ingest receipt land in
`channels/<chan>/stations/<name>/receipts/<timestamp>/`, and `state.yaml` is
recomputed with the station's observed position, last verdict, and flags
(`stale`, `contract-breach`, `revoked`). `ingest` is the sole writer of that
directory, exactly as `push` is the sole writer of `channel.yaml`.

A pin move is the one write a human makes, and it refuses to run without a
reason:

```bash
python3 publisher/vexa_stations.py --ledger <stations-ledger> pin \
  --channel <chan> --station <name> --position 0.12.35 \
  --justification "dev station receipt <path>: PASS on <date>"
```

### 3.3 The return leg

```bash
# RUNG: PR-OPEN — vexa-delivery-internal#38.
python3 publisher/vexa_station.py ingest --from-registry channel.vexa.ai --station <name>
```

The subscriber's `vexa_validate.py --submit` validates the report against
`report.v1`, prints the payload path so they can open it first, and pushes to
`<host>/vexa/stations/<station>/bundles:<date>` with their own path-scoped
credential, printing the digest as their receipt. This pulls it back. It rides
`channel.vexa.ai` deliberately — the host their firewall already permits, so
adopting the return leg needs no change request.

### 3.4 The drift signal, at two layers

**App layer:** an out-of-band change is **reverted** on the next sync, not
merely reported. A permanent local difference belongs in the subscriber's
values file — and a station that keeps diverging is telling us its values file
is wrong, which is a bundle to re-ingest rather than a cluster to argue with.

**Substrate layer — the floor.** A CronJob from the station bundle re-checks
the substrate every 10 minutes and writes its verdict to the `station-floor`
ConfigMap: nodes Ready, Released PVs, the required storage class,
VolumeAttachments stuck deleting, admission policies present, every Argo app
Synced and Healthy — with **`UNPINNED` recognised as parked-awaiting-approval,
not broken** — and channel reachability.

```bash
kubectl -n argocd get cm station-floor -o jsonpath='{.data.report}'
```

Under `scope: namespace` the floor reports cluster facts as **UNKNOWN rather
than guessing**, and nothing in the install path needs cluster-admin.

---

## 4 · Beat four — THEY DO NOT TOUCH, and the exceptions

**Delivery down is not product down.** Pull has no runtime dependency: if the
channel, the registry or we ourselves are unreachable, running pods keep
serving. That is why almost every incident is answered by a pin move rather
than by hands in a cluster — *the kubectl reflex is a hand-crank habit.*

### 4.1 A gate refusal

Exit `3`, a dated report, and a named check or contract item. Not an outage.
Three exits, and only three: **make the release satisfy the item**, **amend the
contract with the customer** (their vocabulary — treat an edit like a contract
change), or **waive it**. Waivers print on stderr, get their own heading in the
report, and are carried forward so the next release can be asked whether the
waiver is still needed. An empty reason is itself a refusal.

### 4.2 Expiry and refresh

*Rung: PR-open [vexa-delivery-internal#38](https://github.com/Vexa-ai/vexa-delivery-internal/pull/38).*

Entries carry a required `expires` (`build --expires-days`, default 30),
refused by `verify` and by the PreSync gate. **The refusal is deliberately not
the signature refusal:**

```text
OK    entry signature verifies against the pinned channel key
FAIL  STALE CHANNEL — this entry expired at …, 1 day(s) ago. The signature is not
      in question and nothing has been tampered with: nobody has published to this
      channel since. Do not work around this by widening the contract. Contact Vexa.
```

The `OK` directly above the `FAIL` is the whole feature — the rehearsal's worst
defect was a good release reported as forged. Re-stamp the horizon without a
version bump:

```bash
python3 publisher/vexa_channel.py refresh --entry <dir> --out <dir> --expires-days 30
#   entry_seq 2 -> 3   ·   same release, re-signed
```

Customers tighten below our horizon with `max_entry_age_days`. Nothing widens
it. **The live `pilot-stable` entry predates the field and cannot pass the
hardened verifier**; republishing it is ⛔ founder-gated, because that entry
carries a founder approval for a specific act.

### 4.3 Withdrawal and revocation

**Today, withdrawal is manual:** notify subscribers on the email lane, they pin
back, and a `push` of a fixed release supersedes. **Never delete an immutable
tag.** A withdrawn release stops being promotable; a pinned customer keeps
running, and withdrawal never touches their cluster.

*Rung: PR-open [vexa-delivery-internal#38](https://github.com/Vexa-ai/vexa-delivery-internal/pull/38)* adds a
signed list:

```bash
python3 publisher/vexa_channel.py revoke --ref <channel base ref> --channel <name> \
  [--version vX.Y.Z | --digest sha256:…] --reason "<text>" \
  --severity low|medium|high|critical [--supersedes vX.Y.Z] [--advisory URL] --key <channel.key>
```

Appends to a cosign-signed `revocations.v1` at `<channel>/revocations:latest`.
Three properties, all load-bearing:

- **An absent list is an EMPTY list, not an error.** The fail-closed reading
  would refuse every install made before the capability existed. That decision
  lives in one commented place so nobody later "fixes" it.
- **Kyverno cannot read the list.** Revocation is enforced by the verify gate,
  not at admission — stated in the publisher's output, in `spec/channel.md`,
  and at the top of the policy the customer installs.
- We can publish and cannot un-publish. Revocation stops promotion; it does not
  un-deliver.

An empty list is already live on `pilot-stable`, signed with the real channel
key, so the capability exists before it is needed.

### 4.4 Break-glass — two different things

**Entry-level break-glass — built, and in use.** An incomplete evidence chain
needs `build --break-glass "actor=..,reason=..,approved_by=..,receipt=.."`, and
the record becomes **visible data inside the signed entry**, which a
subscriber's verifier reads before deciding. Contracts carry
`allow_break_glass: false`; refusing all break-glass entries is a supported
policy. It is also the fast lane by design: a hand-built image cannot be set on
a station, because admission refuses unsigned images — so the escape hatch is a
signed, recorded bypass that the next entry must supersede, **instead of a
silent fork.**

**Incident break-glass — the ceremony is SPECIFIED, NOT BUILT.** The intended
shape is:

1. **Declare** — a named human, recorded. A break-glass nobody wrote down is
   indistinguishable from an intrusion.
2. **Pause `selfHeal`** — otherwise Argo fights the fix. Staging self-heals;
   prod has no automated sync, so there is nothing to pause there.
3. **Act.**
4. **Reconverge THROUGH the gate** — the manual change becomes a published
   release, the pin moves, `selfHeal` goes back on, and the station report
   proves reconvergence. A residue that violates the contract is **refused**,
   and it is resolved by re-doing it as a release, amending the values, or
   recording a waiver. There is no fourth path where the cluster keeps running
   something nothing verified. *Exception named, bounded, reconciled.*

**Nothing in this repository implements any of it.** There is no declare
artifact, no pause procedure, no reconvergence check, and no code path named
for it — the only `selfHeal` occurrences are static Argo configuration.
Even step 2 is unspecified: whether "pause `selfHeal`" means editing the
ApplicationSet (which `selfHeal` would itself contest) or `argocd app set
--sync-policy none` is not written down anywhere. The founder's sequencing
ruling is that **break-glass moves into the prod-migration plan — prod does not
migrate onto a mechanism whose failure mode is undefined.** Until it is built,
step 4 is the only part this runbook can hold you to.

**Cluster dead:** disaster recovery is a clean pull plus the secret store plus
a database backup. That is the same statement as proof one in § 6.

---

## 5 · Channel infrastructure

### 5.1 The registry lives off the product cluster

*Rung: moved 2026-08-25; receipt on PR-open
[vexa-delivery-internal#41](https://github.com/Vexa-ai/vexa-delivery-internal/pull/41), infrastructure in
[`Vexa-ai/vexa-platform#352`](https://github.com/Vexa-ai/vexa-platform/pull/352) (private).*

`channel.vexa.ai` runs on a **dedicated Linode**, host label
`channel-registry-host`, tag `channel-infra`, with a valid Let's Encrypt
certificate — outside the production cluster. The in-cluster `channel-registry`
is scaled to 0 with its PVC retained and its manifests kept as a rollback path.

The reason is circular dependency, in the founder's words: **a cluster outage
must not kill the mechanism that restores the cluster.**

Storage is **S3-compatible object storage** (bucket `$CHANNEL_BUCKET` in
`$CHANNEL_BUCKET_REGION` — site values in [`config/channel.example.env`](config/channel.example.env)), moved as a
byte-verified **copy, not a re-push** — both drivers use the same
`docker/registry/v2` key tree, so all 590 objects moved verbatim and every
digest still resolved. That is what made the host move nearly free: no content
moved at all.

**That bucket is a distribution copy, and it is protected as one.** Versioning
is enabled, so an overwrite or a delete leaves the previous bytes retrievable
by version id — the ordinary accident (a wrong `oras push`, a mistyped
`s3 rm`) is recoverable without anyone rebuilding anything. A nightly job on
the replica host mirrors the whole bucket to `$CHANNEL_REPLICA_PATH`:

```bash
ssh $CHANNEL_REPLICA_HOST cat $CHANNEL_REPLICA_PATH/last-run.json   # objects + bytes, last run
```

It uses `rclone sync --backup-dir`, so an object that vanishes upstream is
moved aside into `deleted/<date>/` instead of being dropped — a mass-delete
upstream cannot replicate itself into a loss. The script decrypts its
credentials from the operator's secrets vault at run time; nothing
credential-shaped sits on that host.

**What a total bucket loss costs is hours of republish and zero customer
action** — every artifact was built from a tagged release, and what could not
be rebuilt (what was published, at which sequence, to whom) lives in the
ledger. The full model, including keys, is
[docs/engineering/durability.mdx](docs/engineering/durability.mdx).

**`storage.redirect.disable: true` is load-bearing configuration, not tuning.**
The S3 driver's default answer to a blob GET is a **307 to a presigned
`…linodeobjects.com` URL**. Correct S3 practice, wrong for this product:
mirroring images into the channel exists so a customer allows **one** host
through their firewall. *Our own clients follow redirects without complaint, so
it would have looked green in every test we run and failed at the customer.*

Rollback: point the DNS A record back at the in-cluster address and scale the
two Deployments to 1. For storage, restore the `filesystem` stanza and remount
the retained PVC — it holds the complete pre-migration tree as a point-in-time
image.

### 5.2 The edge, and what is anonymous

The registry cannot express "read this path without credentials" — htpasswd is
all-or-nothing — so the split is enforced at the Caddy edge:

| Path | Access |
|---|---|
| Signature reads: `GET\|HEAD ^/v2/.+/signatures/(manifests\|blobs\|referrers)/[^/]+$` | **anonymous** — a stock zero-credential Kyverno must verify without a secret |
| `/v2/`, `tags/list`, `_catalog`, everything else | subscriber credential — **enumeration stays behind credentials** |
| Mutating verbs | publisher credential only |

`referrers` is included so the modern cosign layout works the day we move to
it. Those paths were found by **measuring the verifier's three requests in the
access log**, not by guessing; two earlier hypotheses were tested and
withdrawn. Two 404s look like policy failures and are not: an anonymous
manifest GET with no `Accept` header returns `MANIFEST_UNKNOWN` (content
negotiation), and an anonymous GET of a signature that does not exist is a 404
— which is how "unsigned" reaches Kyverno.

**When images later mirror INTO the channel, the pull path must NOT become
anonymous.** It needs kubelet `imagePullSecrets` on every pod that pulls a
mirrored image — a per-namespace chart concern the chart does not do today —
plus Kyverno read access for digest resolution. Read the receipt as *the
signature half is solved, on the real channel, with no credential*, not as *the
channel is solved for admission*.

Egress is now honestly labelled: since storage became S3, the registry's
NetworkPolicy allows **TCP/443 to arbitrary external hosts** (every in-cluster
range excepted), because NetworkPolicy selects on IP and Linode publishes no
address to pin.

### 5.3 Rotating the edge credential

The edge presents a dedicated pull-only account, `edge-signature-reader`,
upstream on the anonymous paths, reading its Basic credential from the
`EDGE_READER_BASIC` key of `$CHANNEL_ROOT/env` on the standalone host.

`vexa_subscriber.py add edge-signature-reader` now rotates **both halves in
one step** — the bcrypt line in `$CHANNEL_ROOT/htpasswd` AND the base64
`EDGE_READER_BASIC` in `$CHANNEL_ROOT/env` — then recreates the stack, so the
manual step that [vexa-delivery-internal#35](https://github.com/Vexa-ai/vexa-delivery-internal/issues/35)
tracked no longer exists on the live path. (The old in-cluster procedure in
`vexa-platform/cluster/channel-registry-ns/README.md` § Apply now applies only
to the scaled-to-0 rollback deployment.)

Blast radius is bounded and loud: a stale `EDGE_READER_BASIC` makes anonymous
signature reads return `401`, Kyverno denies visibly at admission, immediately.
**It does not fail open.**

One scar from the same area, worth carrying: **Docker Compose v5 interpolates
`$` in `env_file`**, and ate three characters of a bcrypt hash — 57 instead of
60. The publisher's hash happened to survive, so exactly one subscriber's
writes failed while the publisher's worked, and a smoke test that exercised
only the publisher would have passed. It was caught by running the same request
against the old edge as a control. **A credential that half-works deserves more
suspicion than one that does not work at all.**

### 5.4 Subscriber lifecycle

```bash
python3 publisher/vexa_subscriber.py list             # who exists, and their scope
python3 publisher/vexa_subscriber.py add <account>    # mint — also rotates
python3 publisher/vexa_subscriber.py revoke <account> # remove, stack recreated
```

The tool operates the **standalone host** (`$CHANNEL_REGISTRY_SSH`,
`$CHANNEL_ROOT/` — site values in
[`config/channel.example.env`](config/channel.example.env)) over SSH — since
the 2026-08-25 move off the cluster there is
no Secret and no Deployment on this path. A rotation touches **two files**:
`htpasswd` (raw bcrypt, the registry's read path) and `env` (Caddy's
`{env.*}` gates — `PUBLISHER_BCRYPT`, `SUB_<NAME>_BCRYPT`,
`EDGE_READER_BASIC`), then runs `docker compose up -d --force-recreate` —
a plain `docker restart` does **not** re-read `env_file`. After the recreate
the tool proves the new credential against the live `/v2/` before printing it.

Pull-only per subscriber; no GitHub accounts, no per-customer ceremony. **The
password is never written anywhere** — not to a file, not to a log, not to the
process title, not to a remote argv: `add` prints it once to stdout and
forgets it. Vault it immediately in the operator's secrets vault
(`$CHANNEL_CREDENTIAL_VAULT`), then deliver it
**age-encrypted** to a key the subscriber already controls (usually an SSH
public key from their GitHub account, fingerprint cited in the mail), or hand
it to their own vendor-credential intake. `channel.pub` travels by a different
route, because a trust anchor and a secret must not share a channel.

Special cases: `add publisher` also rewrites the edge's `PUBLISHER_BCRYPT`;
`add edge-signature-reader` also rewrites `EDGE_READER_BASIC` (§ 5.3);
`revoke` of either requires `--force`. Granting a NEW subscriber
station-write is deliberately manual — one `basic_auth` line in the Caddyfile
plus one `SUB_<NAME>_BCRYPT` env entry — after which `add <name>` maintains
it. **The publisher credential never leaves us.**

Pull-only is proxy enforcement, and the security model does not rest on it:
every artifact is signed and digest-pinned, and the subscriber verifies with a
key only they hold.

A subscriber whose registry needs credentials passes
`install.sh --registry-user <user>` with the password in `VEXA_CHANNEL_PASS` —
**never in argv**.

---

## 6 · The internal channel — we are subscriber #1

**`vexa-platform` is just another subscriber with a private channel.** The
chain consumes itself: candidates first, verdicts accumulate, and the
published entry is built from what the internal stations already signed.

**The migration is done when two proofs hold**, and the first pin-move delivery
flows:

| | Proof | What it establishes |
|---|---|---|
| **1** | **Deliverability** — an empty cluster plus the kit plus the secrets materialises the entire prod estate from signed artifacts alone | this is also the disaster-recovery statement: production = channel + secret store + database backup. **Adoption can never prove this.** |
| **2** | **Continuity** — live prod adopts with **zero restarts** | the estate can move onto the channel without an outage |

```bash
# 0 contract INSTANCES are records and live in vexa-stations, not here; every
#   script below takes the contract as a --policy path, so point it at a checkout
STATIONS=${VEXA_STATIONS_DIR:?set to your stations-ledger checkout}

# 1 candidate entry — BEFORE prod runs it: no receipt, no soak, by definition
python3 publisher/vexa_channel.py build --release vX.Y.Z --channel vexa-internal \
  --publication-mode candidate ... --out work/candidate
python3 publisher/vexa_channel.py push --entry work/candidate \
  --ref <REG>/vexa/channel/vexa-internal --sign-key <channel.key>

# 2 staging station verifies against ITS contract; if ELIGIBLE, signs the verdict.
#   --verdict-out WRITES verdict.json from the run that proved it. Until
#   2026-08-28 this file was transcribed by a person from the VERDICT line
#   below, and nothing bound the signed claim to the run that produced it.
#   --verdict-log binds the two: its sha256 rides in the predicate as
#   verdict_log_sha256. Omit it and the run says so out loud.
sh kit/verify/vexa-verify.sh --entry-ref <REG>/vexa/channel/vexa-internal:vX.Y.Z \
  --pubkey channel.pub --policy contracts/internal-staging.json \
  --station vexa-staging --verdict-out verdict.json --verdict-log verify.log \
  2>&1 | tee verify.log
python3 publisher/vexa_channel.py attest --kind station-verdict --release vX.Y.Z \
  --metrics verdict.json --key <channel.key> --out work/att \
  --push <REG>/vexa/channel/vexa-internal

#   ⛔ this ACCUMULATED form is an OSS-RELEASE-TRAIN artifact. The predicate's
#   `release` must match ^v[0-9]+\.[0-9]+\.[0-9]+$, so an ESTATE release
#   (0.12.23-estate-20260825) cannot carry one. Pinned by
#   kit/verify/tests/test_verdict_out.sh check 4b.
#
#   THE ESTATE USES THE OTHER CARRIER (2026-08-31). Because vexa-internal
#   publishes estate entries, `internal-prod.json`'s require_attestations
#   clause could only ever REFUSE them — unsatisfiable, not dormant. An estate
#   station renders its verdict instead, and it rides INSIDE the next entry:
#
#     python3 publisher/vexa_values_proven.py --contract <estate contract> \
#       --fills <ledger>/stations/<station>/row-fills.log --map <rows>.json \
#       --station <station> --out values-proven.json
#     python3 publisher/vexa_station_verdict.py render --station <station> \
#       --candidate-sha <commit> --manifest-sha256 <consist manifest> \
#       --contract <estate contract> --values-proven values-proven.json \
#       --out work/verdict
#     python3 publisher/vexa_station_verdict.py sign \
#       --verdict work/verdict --key <channel.key>
#     python3 publisher/vexa_channel.py platform-entry ... \
#       --values-proven values-proven.json --station-verdict work/verdict
#
#   The verdict is COMPUTED from the contract and the block, never typed; it
#   binds to the candidate commit and to the sha256 of the block the entry
#   ships. Enforced by vexa-verify.sh §6c, tested end to end in
#   kit/verify/tests/test_station_verdict.sh.

# 3 prod station: its contract REQUIRES staging's signature
#   (require_attestations: [{kind: station-verdict, station: vexa-staging}])
sh kit/verify/vexa-verify.sh ... --policy "$STATIONS"/channels/vexa-internal/contracts/internal-prod.json
sh kit/verify/approve.sh --release X.Y.Z ... --policy "$STATIONS"/channels/vexa-internal/contracts/internal-prod.json

# 4 published entry, built FROM the accumulated evidence
python3 publisher/vexa_channel.py build --release vX.Y.Z --channel acme-stable \
  --delivery-receipt ... --extra-evidence other=station-verdict...=... --out work/entry
```

Standing station: LKE `vexa-channel-station` — `vexa-staging` (auto `*`) and
`vexa-prod` (UNPINNED until approval).

**What the channel must carry is the exact prod estate**, inventoried from the
live namespace rather than idealised from the chart — monitoring, analytics,
billing workers and the edge included, with any gap either covered or excluded
for a stated reason. **Secrets never ship.**

**Staging subscribes before prod. *Rung: not done.*** `vexa-staging` currently
has zero workloads and a `failed` Helm release at revision 203, so adopting it
would be a fresh install that rehearses none of the real risk and produces a
green receipt for something never tested — leaving prod as the first real
adoption. It was left exactly as found, deliberately.

The one-time, ceremony-gated prod transition is a **dated plan, not a crank**:
[docs/plans/2026-08-25-prod-migration.mdx](docs/plans/2026-08-25-prod-migration.mdx)
(merged as [vexa-delivery-internal#39](https://github.com/Vexa-ai/vexa-delivery-internal/pull/39); not executed
as of 2026-08-25). It composes by reference — § 1 publishes the entry it pins,
§ 7 installs the station it subscribes.

---

## 7 · The station crank — station-as-code

The station's own machinery is a signed chart on the channel. One bootstrap
object installs the app that installs Vexa; after that, station changes are
releases, not kubectl sessions.

```bash
# bootstrap (once): channel credentials + the root Application
kubectl apply -f station/root-app.yaml     # carries the site values inline

# change the station: edit, bump, publish, move the pin
python3 publisher/vexa_channel.py station-chart \
  --contract staging=$VEXA_STATIONS_DIR/channels/<chan>/contracts/<staging-record>.json \
  --contract prod=$VEXA_STATIONS_DIR/channels/<chan>/contracts/<prod-record>.json \
  --out-dir work/station-chart \
  --push oci://<REG>/vexa/channel/<chan>/station
cosign sign --key <channel.key> <REG>/.../vexa-station@<digest>
#   then edit targetRevision in station/root-app.yaml and kubectl apply —
#   the pin move IS the approval act; the station reconciles itself
```

**The entry contract is a PUBLISH INPUT, not a file in this repository.**
`station-chart` copies the bytes of the named ledger record into the chart's
`files/contracts/` and pins each by `sha256` in `station-chart-receipt.json`; the
`vexa-contract-staging` / `vexa-contract-prod` ConfigMaps the PreSync gate reads
are that record verbatim. **A chart with a contract missing refuses to render** —
there is no fallback, because an empty `policy.json` makes a verifier print OK
for every check it never ran.

Through chart 1.0.7 an `internal-prod.json` was committed here and the chart
bound *it*. Both ledger records say that copy must not bind an estate and
`contracts/README.md` said the record wins; nothing enforced it, and a drifted
copy produces verdicts naming a contract id whose bytes are in no ledger.
`make test` now refuses any `files/contracts/*.json` that is not a byte-copy of
a named record.

**Contract shapes.** The 2026-09 records split `required_values[]` (what the
release must be proven to do) from `carriage{}` (what the entry must look like).
The verifier reads the carriage keys — it flattens the block into a working copy
and still hashes the *record* for the verdict — and since **2026-08-31 it also
adjudicates `required_values[]`** whenever the carriage sets
`require_entry_values_proven`. For every value row with `enforcement: required`
the entry must carry a `values_proven` row that is `proven` with evidence, or
`waived` by a named human; a missing id, a missing block or a bad verdict is a
counted FAIL and the verdict is NOT ELIGIBLE. Evidence naming a
`subject_digest` must name one of this entry's own images.

Before that date the clause was **void in both directions** — the publisher
wrote no block and the verifier printed "required_values[] is NOT evaluated" —
so the live record could demand proof of seven values and admit an entry that
proved none of them, with a full roster of green carriage ticks in the log.
**Every entry through seq-11 predates the block and is refused by the live
contract.** That is the correct fail-closed reading: publish an entry that
carries the proof, do not widen the contract. Build the block with
`publisher/vexa_values_proven.py` from the station's committed `row-fills.log`,
then seal it in with `platform-entry --values-proven`.

`station/root-app.yaml` is the **one object ever applied by hand**. Its
`targetRevision` is the station pin; its inline values carry the only
site-specific facts — mirror location, pinned public key, tool image digest.
`prune: false` so the machinery is never auto-deleted; `selfHeal: true` so a
hand patch to any bundle-managed object reverts, **which is the point**.

Scope modes: `scope: cluster` (you own the cluster — admission as a Kyverno
ClusterPolicy) versus `scope: namespace` (shared cluster, no cluster-admin —
the OpenShift-tenant shape; admission becomes a namespaced Policy and the floor
marks cluster facts UNKNOWN). The second is the first pilot subscriber's exact
shape.

### Publishing the kit RUNTIME IMAGE

The channel's `kit` artifact is a **tarball** — right for an operator unpacking
it on a workstation, useless to a Job, which cannot exec one. The station
chart's receipt sender needs a container, and until 1.0.6
`receiptSender.image` had nothing on the channel to point at.

```bash
# ON BBB — every container workload does (founder ruling 2026-08-08)
docker build -f kit/runtime/Dockerfile \
  --build-arg KIT_COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg KIT_DESCRIBE="$(git describe --tags --always --dirty)" \
  -t <REG>/vexa/channel/<chan>/images/vexaai/kit-runtime:<tag> .
docker push …                          # then take the pushed DIGEST
COSIGN_REPOSITORY=<SIGNATURE_REPOSITORY> $COSIGN_BIN sign --yes --key <channel.key> \
  --tlog-upload=false --new-bundle-format=false <ref>@<digest>
```

**Sign it into the station's `signatureRepository`, not the station-chart
signature repository.** The published reference contains `vexaai/`, which is
precisely what the station's two Kyverno ClusterPolicies match: the sender pod
is admission-checked like any app image, so it must be **digest-pinned** and
its `sha256-<digest>.sig` must sit where `${SIGNATURE_REPOSITORY}` points. An
image signed in the wrong repository and an unsigned image are
indistinguishable at admission — both deny. Prove it the way § 1.6's T2 does,
against the same tag Kyverno asks for.

### Publishing the kit itself

```bash
kit/release.sh --registry <REG> --channel <name> --version vX.Y.Z --sign-key <cosign.key>
```

The kit rides its own conveyor: packaged, pushed as `application/vnd.vexa.kit`,
cosign-signed, `latest` moved. Shipping a kit fix is a release — never an email
with a tarball — and subscribers take it with `self-update.sh --check` then
`self-update.sh`. During the rehearsal the delivery mechanism was used to
deliver its own repairs five times.
