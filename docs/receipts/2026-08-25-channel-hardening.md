---
title: "Channel hardening — expiry, revocation, the two-directional contract, the submit path"
description: "Four features that live in signed artifacts or customer-pinned config, proven against the live channel, the live edge and a live cluster. Three defects found by running it."
---

**Date:** 2026-08-25. **Channel:** `channel.vexa.ai` — the **live** registry.
**Cluster:** LKE `vexa-byoc-demo` (646792), us-sea, k8s **v1.36.3**, a real
Vexa install (13 workloads, flows tier up). **Edge:** the live
`channel-registry` Caddy in LKE 590708, changed and rolled out. Container work
ran on `bbb`.

Why these four now: each lives in a **signed artifact** or in **customer-pinned
config**. Adding a required field to a signed entry after a bank has pinned the
format is a format break; adding a contract section after their change board
approved the file is a contract change. Cheap this week, expensive in six.

---

## 1 · Entry expiry

`expires` is now required in `channel-entry.schema.json`, set at build time
(`--expires-days`, default 30), and refused by the publisher's `verify` and by
the PreSync verifier — **with a message that is not the signature message.**

Live, against a scratch channel carrying an entry that expired yesterday:

```
OK    entry pulled: channel.vexa.ai/vexa/scratch/hardening:current
OK    entry signature verifies against the pinned channel key
FAIL  STALE CHANNEL — this entry expired at 2026-08-24T12:19:45Z, 1 day(s) ago. The signature is
      not in question and nothing has been tampered with: nobody has published to this channel
      since. Do not work around this by widening the contract. Contact Vexa.
...
VERDICT: NOT ELIGIBLE — 1 check(s) failed
```

The signature line above it is the point. The rehearsal's worst defect was a
good release reported as forged; an expired entry and a forged one are
different events with different remedies and they never share a message.

**Republishing without a version bump**, same channel, same release:

```
$ vexa_channel.py refresh --entry <dir> --out <dir> --expires-days 30
  entry_seq 2 -> 3
  expires   2026-08-24T12:19:45Z -> 2026-09-24T12:20:59Z
$ vexa_channel.py push --entry <dir> --ref … --sign-key … --channel-tag current
  permanent tag …:v0.12.23-seq3 -> sha256:dc758fe3…
  channel tag  …:current        -> sha256:dc758fe3… (same-byte descriptor)
$ vexa-verify.sh …
OK    freshness: entry expires 2026-09-24T12:20:59Z (29 day(s) left)
VERDICT: ELIGIBLE — v0.12.23 satisfies every check
```

The release tag now names the *current* entry for that release and every entry
also gets a permanent `<version>-seq<N>` tag. Rollback protection is
`entry_seq` monotonicity, which is inside the signature; tag immutability never
carried it. The alternative — a new tag per refresh — would have left the
PreSync hook (which asks for the entry at the release tag) pulling the stale
entry forever.

Customers can tighten from their side with `max_entry_age_days`.

## 2 · Revocation

A cosign-signed `revocations.v1` list at `<channel>/revocations:latest`.

```
$ vexa_channel.py revoke --ref …/vexa/scratch/hardening --channel scratch-hardening --key …
no --version/--digest given: publishing the list as it stands (this is how an EMPTY list goes live before it is needed)
published …/revocations:latest digest sha256:6b0250c2… — 0 entries
```

Verifier, empty list:

```
OK    revocation list signature verifies against the pinned channel key
OK    revocation list is current (expires 2026-09-24T12:21:17Z)
OK    release v0.12.23 is not revoked
OK    no image digest in this entry is revoked
VERDICT: ELIGIBLE
```

Then one `revoke --version v0.12.23 --severity critical --supersedes v0.12.24`,
and the **same entry** thirty seconds later:

```
OK    entry signature verifies against the pinned channel key
OK    freshness: entry expires 2026-09-24T12:20:59Z (29 day(s) left)
OK    revocation list signature verifies against the pinned channel key
  CRITICAL: hardening validation 2026-08-25: synthetic revocation, this channel is a scratch fixture  -> move to v0.12.24
FAIL  release v0.12.23 is REVOKED by the channel (1 notice(s), printed above)
VERDICT: NOT ELIGIBLE — 1 check(s) failed
```

And with no list published at all:

```
note  no revocation list published on this channel — treated as EMPTY, which is correct for a channel that predates the capability, NOT an error
```

**An empty list is live on `pilot-stable`**, signed with the real channel key
(`sha256:f6aac70e…`, the identity the live entry names):

```
published channel.vexa.ai/vexa/channel/pilot-stable/revocations:latest
  digest sha256:c27243bc1c63d0620687728b9bbb2324845f880a593f6705031b8f0630160133 — 0 entries
```

**Kyverno cannot read this list.** Stated in the publisher's own output, in
`spec/channel.md`, and in a block at the top of
`kit/policy/kyverno-vexa-admission.yaml`. Admission verifies signatures on
images; it does not fetch a vendor document. The PreSync gate is the
enforcement point, and the two gates are not supersets of one another.

## 3 · The two-directional contract

`delivery_scope` (what a release may DO) and `report_scope` (what may leave),
in one customer-held file, in PSS/SCC and OLM-shaped vocabulary.

**Enforced twice, and the two are not equivalent — which is said out loud
rather than implied.** The station gate renders the chart and checks the
objects (S10–S14). The PreSync verifier has no chart and cannot render one, so
it checks that the gate ran against *this* contract at *this* revision and
enforced *these* clauses, and prints:

```
note  delivery_scope is enforced PUBLISHER-SIDE on the rendered chart (S10-S14).
note  this verifier re-checks the CLAIM, not the objects: it has no chart to render.
note  the object-level check that binds is your own Pod Security admission + Kyverno.
```

Live, against the real product chart packaged from `v0.12.23` with
[`Vexa-ai/vexa#1321`](https://github.com/Vexa-ai/vexa/pull/1321) applied:

```
PASS — station 'rehearsal' admits vexa-0.12.40.tgz
```

Same chart with a `hostPath: /` and `privileged: true` planted on the gateway
Deployment:

```
REFUSED S7: station 'rehearsal' refuses this publish — 3 finding(s)
  - S7:  Deployment/station-vexa-gateway mounts hostPath volume 'node-root' (/)
  - S12: Deployment/station-vexa-gateway mounts a hostPath volume (PSS baseline forbids it)
  - S12: Deployment/station-vexa-gateway containers/gateway is privileged (PSS baseline forbids it)
  MET  no-hostpath — matched by --evidence guarantees
```

The last line is worth keeping: the release *claimed* `no-hostpath` in its
evidence and the claim was accepted at S9 — the object check refused it anyway.
A guarantee list is a claim; the gate is the check.

`report.v1` (`spec/report.v1.schema.json`) sets `additionalProperties: false`
on every object, so there is nowhere to put a transcript, a title, a
participant, a mail body or a log line. Unit tests assert the refusal for each.
The kit ships its own byte-identical copy of the schema (the tarball carries
`kit/` and nothing else) and a test fails on drift.

## 4 · The submit path, end to end on live infrastructure

**The edge.** One new `handle` block above the publisher-only write gate:
subscribers may write to `/v2/vexa/stations/<their own name>/**` and nothing
else. Validated with `caddy validate` in a container on `bbb`, then exercised
against a throwaway Caddy + dummy-upstream rig on `bbb` before prod was
touched, then applied to the live edge (server-side dry run first, ConfigMap
and Deployment backed up).

Against **`https://channel.vexa.ai`**, with the real `pilot` subscriber
credential:

| Request | |
|---|---|
| `GET /healthz` | **200** |
| `GET …/signatures/manifests/…` anonymous | **404 from the registry** — the anonymous read path still reaches it |
| `GET …/channel/pilot-stable/manifests/current` as pilot | **404 from the registry** — pull unchanged |
| `POST …/v2/vexa/stations/pilot/bundles/blobs/uploads/` | **202** |
| `POST …/v2/vexa/stations/acme/bundles/blobs/uploads/` | **403 — this credential may only write to /v2/vexa/stations/pilot/** |
| `POST …/v2/vexa/channel/pilot-stable/blobs/uploads/` | **401** |
| `DELETE …/channel/pilot-stable/manifests/current` | **401** |
| `POST …/stations/pilot/…` anonymous | **401** |

The bcrypt hash was taken **out of the registry's own htpasswd**, so granting
submit handled no password at any point.

**The round trip.** `vexa_validate.py` run against the live BYOC demo cluster —
preflight, smoke, bundle, redaction, report.v1, `report_scope`, push:

```
VERDICT: PASS                                   (preflight P1-P9)
VERDICT: PASS  →  smoke-receipt-20260825-122741.md
redaction: 7 value(s) removed, 0 found in the archive
== submit — validating what would leave this perimeter
   report.v1 OK — every field below is in the schema, and the schema has no field that could hold your content
   payload:     …/report-pilot-2026-08-25.json
   open it. that is what it is for.
   destination: channel.vexa.ai/vexa/stations/pilot/bundles:2026-08-25
submitted: channel.vexa.ai/vexa/stations/pilot/bundles:2026-08-25
digest:    sha256:35b16775b8121b891ae222cfbd8bef5bd5f96815a3c189a5028035c9aac03a49
this is your receipt — it names the exact bytes that left, and we can be held to it
```

The values file this ran against **did** carry live credentials (a flows API
key and a mailbox app password). Seven were removed and the post-write scan of
the extracted archive found zero — the redaction was exercised on real
material, not a fixture.

Return leg, as the publisher:

```
$ vexa_station.py ingest --from-registry channel.vexa.ai --station pilot
pulled channel.vexa.ai/vexa/stations/pilot/bundles:2026-08-25 -> station.tar.gz (sha256 ceef2ffc1525…)
ingested station 'pilot' -> stations/pilot at 2026-08-25T12:27:58Z
  f203751bc593  contract.yaml
  144505ea16b1  preflight-receipt.txt
  e4f884940853  profile.env
  501ab8ad8038  smoke-console.txt
  94beacc1c1af  smoke-receipt-20260825-122741.md
  4639ed643978  values.redacted.yaml
```

---

## Defects this batch found by running it

**1 · A registry allowlist that refuses every Docker Hub image.** `vexaai/x`
*is* `docker.io/vexaai/x` and `postgres` *is* `docker.io/library/postgres` — the
registry is implicit and a chart writes the short form. Matching the raw string
produced **eight refusals on the real v0.12.23 render, all spurious**. References
are now normalised the way a runtime does, and both forms are matched so a
customer who wrote the short prefix gets what they meant.

**2 · A contract clause of the wrong shape crashed instead of refusing.** A
YAML list item ending in `:` loses its quotes and parses as a mapping;
`str.startswith` raised `TypeError`. The near-miss is worse than the crash — a
list that parses as a mapping silently matches nothing. Every `delivery_scope`
clause is now type-checked, and an **unrecognised** clause refuses the contract
outright: a clause nobody enforces is a clause the customer believes is being
checked.

**3 · A finding that was not one.** `oras tag` appeared to mangle a full
reference into `…/hardeningurrent`. It was **zsh's `:c` parameter modifier** on
`"$VAR:current"`, not the publisher. The comment claiming a publisher bug was
written and then removed before commit. Recorded because the near-miss is the
lesson: an anomaly is a finding, and a finding is a hypothesis until it is
isolated.

## What this does NOT prove

- **The live `pilot-stable` entry predates `expires` and the hardened verifier
  refuses it** — verified, exactly as designed:
  `FAIL entry declares no expiry — it predates channel freshness; ask Vexa to
  republish it`. **Republishing that entry with an expiry is founder-gated and
  is a hard prerequisite for shipping a verifier that enforces this.** It was
  not done here: the live entry carries a founder approval for a specific act,
  and refreshing it is a publish nobody approved. No customer is affected today
  — the deployed verifier is v0.1.1, which does not check freshness.
- **`report_scope` and `delivery_scope` were exercised against a contract copied
  from the rehearsal fixture**, whose Harbor mirror prefix is invented. The
  clause mechanics are proven; the *values* the subscriber will actually put in their file
  are theirs to write.
- **PSS `restricted` refuses the v0.12.23 chart — 20 findings** (no
  `runAsNonRoot`, no dropped capabilities, no `allowPrivilegeEscalation: false`,
  no seccomp profile, on essentially every workload). The fixture therefore
  states `baseline`. A bank asking for `restricted` is a chart change, and it is
  a real one; this is the first time it has been measured.
- **Nothing about admission.** Image-signature admission is
  [vexa-delivery-internal#36](https://github.com/Vexa-ai/vexa-delivery-internal/pull/36)'s business and was not
  re-exercised here.
- **The submit path was proven with `--submit` against a real cluster and the
  real edge, once.** No concurrency, no large bundle, no failure injection, no
  second subscriber.
- **The scratch channel `vexa/scratch/hardening` and the `pilot` station bundle
  are left on the live registry.** The registry has no delete enabled for these
  paths in the current configuration; they are named here so a later cleanup
  knows what is fixture.

{/* vexa-agent */}
