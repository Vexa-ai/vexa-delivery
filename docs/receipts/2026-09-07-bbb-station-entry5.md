---
title: "A candidate lane, verified and then stopped: the station run on entry 5"
description: "A contract that admits a candidate entry, ELIGIBLE against it, and an install that did not happen because the channel carries no chart for that release. Four kit defects closed, two new ones found."
---

**Date:** 2026-09-07. **Channel:** the pilot channel on `channel.vexa.ai` — the
**live** registry, not a test rig. **Station:** our own rehearsal station, not a
customer's. **Cluster:** the rung-4 rig from
[2026-09-06](/receipts/2026-09-06-openshift-on-bbb), unchanged. **Container
work** ran on an internal build host, never on a laptop.

**Two sentences, so a reader skimming does not take the wrong one away.** A
contract that admits a **candidate** entry was written, recorded in the state
ledger by pull request, and rendered **ELIGIBLE** against entry seq 5 by kit
**v0.1.6** — that half works and is durable. **The install did not run**,
because the channel carries no chart for that release, so **nothing here proves
that the cluster runs the entry's bytes** and this receipt does not claim it.

<Note>
The subscriber is not named. Their registry hostnames, project names and estate
details are not in this document. The channel is written as `<pilot-channel>`
and the rig's pull-through registry as `<harbor-host>`.
</Note>

## The rung, unchanged

**Rung 4 of 4, and it is NOT OpenShift** — a `kind` cluster with PSA
`restricted` and Kyverno emulating `restricted-v2`. No `oc`, no SCC objects, no
OLM, no Routes, no internal registry, no GitOps operator. `PROFILE_TESTED` on
the `openshift` profile stays `no`, and nothing below changes that.

## Why a candidate lane exists at all

Entry seq 5 is published `candidate`. Three things follow from that, and every
existing contract on the channel refuses it for at least one of them:

| The entry | The kit's default contract |
|---|---|
| `publication.mode: candidate` | `require_publication_mode` defaults to `published` |
| no `publication.approved_by` — the publisher was not given `--approved-by` | `require_vendor_approval` refuses an unapproved publication |
| `delivery_receipt` is exempt in candidate mode by C8; `soak`, `image_provenance` and `chart` are declared absent with reasons | `require_evidence_kinds` names `delivery_receipt` |

Those refusals are **correct**. A candidate lane is the shape that consumes such
an entry **without weakening the published lane**, which is untouched — a second
contract for a second station, not an edit to the first.

## The contract

`contract_id: bbb-rehearsal-candidate-2026-09-07`, sha256
`da5d15d4a2e63c062741a2a7fcf33727ecde7269cfadffa27f56ccd9571ce533`. JSON in the
2026-09 `carriage{}` shape, in the state ledger, moved there **by pull request**
as contracts must be.

```json
{
  "contract_id": "bbb-rehearsal-candidate-2026-09-07",
  "carriage": {
    "require_publication_mode": "candidate",
    "require_vendor_approval": false,
    "require_evidence_kinds": ["candidate_map", "source_provenance", "trusted_root"],
    "allow_break_glass": false,
    "min_entry_seq": 5,
    "max_entry_age_days": 30
  },
  "report_scope": { "schema": "report.v1", "tier": 1, "cadence": "per-release",
                    "trigger": "explicit-command-only", "destination": "channel.vexa.ai",
                    "allowed_sections": [ … seven names … ],
                    "require_redaction_verified": true }
}
```

**What it deliberately omits, and why each omission is a reading of the entry
rather than a convenience.**

| Omitted | What including it would have done |
|---|---|
| `delivery_scope` | `vexa-verify.sh` refuses outright — *"your contract states a delivery_scope and this entry carries no station_gate evidence"*. The publisher-side scope gate runs at publish time; a candidate carries no `station_gate` evidence, so the clause is unsatisfiable by construction, not by this estate's choice. The object-level bound here is PSA `restricted` + Kyverno, which is where it binds anyway and which was not touched. |
| `forbid_absent_evidence` | refuses the entry on any of the four absences it states honestly in its own body |
| `require_entry_values_proven` + `required_values[]` | the entry carries no `values_proven` block; every required id would refuse |
| `require_attestations` | no station verdict has been signed for this release |
| `soak`, `security_hardening` | pin attestations that are declared absent |

**`report_scope.allowed_sections` is the current spelling, and this matters
beyond our own file.** `kit/validate` **refuses** a contract carrying the older
`allowed_files` rather than ignoring it — *"a bound we cannot read is not a bound
we will guess at"*. The pilot's own contract in the ledger still carries
`allowed_files`, so **its next submit will be refused locally until that clause
is renamed.** That is a one-line edit, and it is a pull request against their
contract, not something we can do on their behalf.

## Proof 1 — the kit came from the channel, verified before it was unpacked

```
== resolving channel.vexa.ai/vexa/channel/<pilot-channel>/kit:latest
   digest sha256:f885bbae2efeae28ea778e8e47ae0ba0a2ddc7bc28404b08de9139909ed824fb
== cosign verify …/kit@sha256:f885bbae… against channel.pub
   signature OK
vexa-kit v0.1.6 unpacked to …
```

The public key was the ledger's own `channel.pub`,
`sha256:f6aac70ec20248f977403f256594ef50a5ea14b2b42e4d4ca1e456742db8fab9` —
byte-identical to the copy on the build host and to the one the rig's admission
policy pins. The pull used a **pull-only station credential**, supplied through
the environment as `bootstrap.sh` reads it, never on a command line.

## Proof 2 — ELIGIBLE

```
OK    entry pulled: channel.vexa.ai/vexa/channel/<pilot-channel>:v0.13.1
OK    entry signature verifies against the pinned channel key
OK    freshness: entry expires 2026-10-07T11:12:17Z (29 day(s) left)
OK    digest evidence/candidate-images.json
OK    digest evidence/source-provenance.sigstore.json
OK    digest evidence/trusted-root.jsonl
OK    candidate entry: map present; delivery receipt deferred by definition
OK    source archive sha256 recorded: 9d805615dc…
OK    revocation list signature verifies against the pinned channel key
OK    release v0.13.1 is not revoked
OK    no image digest in this entry is revoked
--- contract: bbb-rehearsal-candidate-2026-09-07 @ sha256:da5d15d4a2e6…
note  contract carries a carriage{} block; its keys are read as the entry checks below
OK    policy: evidence 'candidate_map' present
OK    policy: evidence 'source_provenance' present
OK    policy: evidence 'trusted_root' present
OK    policy: no break-glass on this entry
OK    policy: entry_seq 5 >= your floor 5
OK    policy: publication mode 'candidate'
OK    policy: entry is 0d old, within your max_entry_age_days of 30
---
VERDICT: ELIGIBLE — v0.13.1 verified against contract bbb-rehearsal-candidate-2026-09-07 @ sha256:da5d15d4a2e63c062741a2a7fcf33727ecde7269cfadffa27f56ccd9571ce533
```

A candidate entry on a private channel, signature-verified offline against a key
delivered by a separate route, admitted by a contract that names the candidate
mode explicitly. **The gate works and the lane is real.**

## Where it stopped, at the exact line

**The channel carries no chart for this release.** The entry says so itself, in
its own `evidence_absent` block:

```
chart: OCI chart publishing pending (vexa PRD §12 C1);
       the OSS chart ships in the Vexa-ai/vexa tree
```

and the channel's chart repository has exactly one tag:

```
oras repo tags channel.vexa.ai/vexa/channel/<pilot-channel>/charts/vexa
→ 0.12.35            # Chart.yaml: version 0.12.35, appVersion 0.12.23
```

Three consequences, each measured:

1. **The installer would render the wrong release.** `install.sh` renders the
   delivered set with `helm template … oci://…/charts/<chart>` and **no
   `--version`**, so it resolves the newest chart — `0.12.35`, the previous
   entry's. Installing under an entry-5 lane would put the previous entry's
   bytes on the cluster.
2. **The digest sets are disjoint.** Of the entry's **11** candidate-map image
   digests, **0** appear in chart `0.12.35`, which pins six application images
   at the previous release's digests. The intersection is empty — not narrow,
   empty.
3. **The in-cluster gate would ask for the wrong entry.** The PreSync verify
   hook derives its `--entry-ref` from `Chart.AppVersion`, so chart `0.12.35`
   asks the verifier for the `published` entry — which this candidate contract
   correctly refuses. The lane and the chart disagree by construction.

The OSS chart in the product tree at the matching tag is not a substitute
either: it pins **no digests at all**, referencing images by a floating tag, so
the rig's own digest-pinning admission policy would refuse it. Producing a
digest-pinned chart is the publisher's `chart` step, and publishing it is a
signing act on the channel key — neither is a station's act, and neither was
attempted.

**Nothing was relaxed to get past this.** The contract was not widened, the
admission policies were not touched, `--skip-preflight` was not used, and
`install.sh` was run only with `--dry-run`. The rig is byte-for-byte as the
previous run left it.

### The one-line fix, named

Publish a digest-pinned chart for this release to the channel, with
`appVersion` equal to the release version, and the same run becomes an install.
Until then **the channel's installable state is still the previous entry**, and
a candidate lane can verify but not deliver.

## The claim this run was for, answered honestly

*"The cluster runs exactly the entry's bytes."* It cannot be answered here,
because none of the entry's bytes were delivered. The station report's own
`release` block is the evidence:

| Entry seq 5 candidate map | Running on the rig |
|---|---|
| 11 application images | **none of them** |
| — | three infrastructure pods at the **previous** chart's pinned digests (object store, database, cache) |
| — | seven GitOps pods |
| — | `release.verifier.verdict: ABSENT` — the in-cluster gate never ran, because no sync happened |

An empty answer, said out loud, rather than a green one assembled from a
different release's pods.

## What the kit did right — four defects closed

Measured against the seven recorded on
[2026-09-06](/receipts/2026-09-06-bbb-rehearsal-install), with v0.1.6 pulled
from the channel:

| # | 2026-09-06 | 2026-09-07 |
|---|---|---|
| 1 | no adoption path; running against an existing Argo is destructive | `--argocd adopt --kyverno adopt` exist. The dry run reported *"argocd: ADOPTING the existing argocd-server — it is already v3.5.1. Nothing is applied."* |
| 2 | the preflight **crashes** as a namespace-scoped tenant | cluster-scoped refusals now render `[????] UNEVALUATED` with the remedy and the exact RBAC error. No traceback. |
| 3 | `install.sh` never passes the manifests, so P2/P3 check nothing | `install.sh` renders the chart itself and passes `--manifests`; P2 and P3 evaluated the whole delivered set |
| 6 | `kit/smoke` **raises** where it should report, so no receipt exists and the ingest refuses | the same port-forward failure now reads *"reported, not raised; the run continues so this receipt exists"* |

**Defect 6's closure is the one worth stating twice.** The previous receipt
called it the sharpest thing that run found: *the path that breaks is the
failure-reporting path*, so a subscriber whose install goes wrong cannot file
the receipt that would represent them. This run drove a **failing** estate all
the way through:

```
[PASS] S1 · 7 Deployments fully available
[FAIL] S2 · RuntimeError: port-forward … did not come up in 15s — reported, not raised;
            the run continues so this receipt exists
[SKIP] S3 · no --meeting-url in non-interactive mode
[SKIP] S4 · flows tier not requested
VERDICT: FAIL  →  receipt: smoke-receipt-…md
```

`vexa_validate.py` then wrote a 402-line `station-report.yaml` **carrying a
`smoke_receipt` section** — exit 1, redaction verified, three values removed,
zero leaks — and the ingest gate that refused at S2 on 2026-09-06 **accepted
it**, wrote the station's first `state.yaml`, and derived the
`contract-breach` flag from the non-PASS verdict. A failure is now
representable end to end.

Phase verdicts, for the record: **preflight FAIL** (exit 1 — P4 alone, on the
dynamic bot pod that carries no `securityContext`; seven of eight PASS with an
admin snapshot, and the live cluster contradicts P4 because a mutating webhook
runs before PSA validation) · **install skipped** · **smoke FAIL** (exit 1) ·
**validate exit 1** · **ingest accepted**, verdict `REFUSED`.

## Three new findings

**1 · A kit bootstrapped from the channel reports no version.**
`vexa_validate.py` fills its `kit:` block from `git describe` / `git rev-parse`,
and a bootstrapped tree is not a git checkout — so `kit.commit`,
`kit.describe` and the state ledger's `kit_version` are all `null`, while the
tree itself knows: `VERSION` beside `install.sh` reads `version=v0.1.6`. The
ledger row for a station that used a **git clone** carries a revision; the row
for a station that followed the **documented onboarding path** does not. That
is backwards, and it means we cannot currently say which kit produced any real
subscriber's report. *Suggested shape: read `VERSION` first and fall back to
git, rather than the reverse.*

**2 · `--entry-seq` and `--entry-digest` are cross-checked against nothing.** A
first pass of this run passed both flags, and the report recorded the entry
sequence and digest as fact while listing six running image digests, **none of
which belong to that entry**. The report was discarded and regenerated without
the flags, so the one filed asserts no position — but a mistyped number would
have been ingested as an observation. The tool already has both sides in hand:
the asserted digest and the observed image list. *Suggested shape: refuse, or
mark the position `asserted` rather than `observed`, when the entry's images are
not the ones running.*

**3 · A station's write path is its account name, and a station whose ledger
name differs cannot submit.** The channel edge confines a station credential to
`/v2/vexa/stations/<account>/**` and compares the authenticated user against the
path segment, while `--submit` pushes to `…/vexa/stations/<station-name>/…`. A
station whose directory name in the ledger is not its account name gets a 403 at
the moment it tries to file its report — which is, again, the failure-reporting
path. Not exercised in this run (no write was attempted); recorded from the
edge's own scope matrix and the submit path composition.

## The pull path, since it is a standing question

The rig's pull-through registry proxies the public image host **anonymously** —
its upstream endpoint carries no credential — and the cluster node has a mirror
entry only for the rig registry, so the delivered workloads' own image pulls go
**directly** to the public host from the build host's address. Neither path
spends the publishing account's budget. Measured at the time of this run:
anonymous, from the build host, `limit 100/h · remaining 100`; the publishing
account, `limit 200/h · remaining 11`. **Budget was not a constraint on this
run and did not cause the stop.**

## What this receipt does NOT claim

- **No OpenShift or OKD was involved.** Unchanged from 2026-09-06.
- **The cluster does not run the entry.** Nothing was installed, nothing was
  synced, no application pod of this release exists.
- **Nothing is said about the release's quality.** This is a delivery-path run.
- **Defects 4, 5 and 7 from 2026-09-06 were not re-tested** — they live past the
  install, and the install did not run. They are neither closed nor reopened.
- **Revocation fail-closed remains unverified**, exactly as it was.

## Final state

| | |
|---|---|
| Contract | in the state ledger, merged by PR, copied byte-identically onto the station |
| Station record | `state.yaml` + `receipts/<ts>/` written by the ingest reducer, its sole writer; narrative merged by PR |
| Rig | untouched — same Argo, same Kyverno policies, same three infrastructure pods, same namespaces |
| Channel | untouched — no publish, no tag moved, no pin moved, no credential minted or rotated |

The rig is left running, deliberately: it is the environment the install runs
against on the day a chart for this release exists.
