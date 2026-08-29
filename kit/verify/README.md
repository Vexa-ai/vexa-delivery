# verify — the gate: deterministic validation + human approval

> **[`policy.example.yaml`](policy.example.yaml) is the only policy file here,
> and it binds nobody.** It is an annotated example: copy it, edit it, pin it.
> `policy.internal-estate.yaml` moved out on 2026-08-25 — it was an *instance*
> (`vexa-internal-estate-2026-08`, our own estate channel), and instances are
> records. It now lives in
> the stations ledger (a private repository) at
> `channels/vexa-internal/contracts/policy.internal-estate.yaml`. Every script
> here takes `--policy <path>`, so pass the path into your checkout; nothing
> resolves a policy by name.

Two things must be true before a release runs, and neither is assumed:

1. **Deterministic validation** — [`vexa-verify.sh`](vexa-verify.sh). Same bundle in, same verdict
   out; no judgment anywhere in it. It checks the entry's signature against the channel key you
   pinned, every evidence file's hash against the signed entry, the candidate map against the
   delivery receipt's pin, the source provenance offline against the bundled trusted root, and
   then **your policy** ([`policy.example.yaml`](policy.example.yaml)) — required evidence kinds,
   whether break-glass is acceptable at all, a sequence floor that blocks silent downgrades.
2. **Human approval** — [`approve.sh`](approve.sh). A named person approves one exact release; the
   record lands in *your* cluster with who, when, which entry digest, and the verdict at that
   moment. Production's PreSync check **refuses to sync a release nobody approved**.

## Two humans, by different parties

| Approval | Whose | Where it lives | Enforced by |
|---|---|---|---|
| Publication | **Vexa's** — a named person approved putting this release on the channel | inside the signed entry (`publication.approved_by`) | `require_vendor_approval: true` in your policy |
| Promotion | **Yours** — a named person approved it for your production | a ConfigMap in your cluster, in your audit log | `--require-approval` on the production PreSync hook |

Vexa's approval never stands in for yours. Your staging can require ours (nothing we did not
approve reaches you); your production additionally requires your own.

## Running it

```bash
# validate anywhere — workstation, your CI, or the PreSync hook
./vexa-verify.sh --entry-ref <registry>/vexa/channel/<name>:<ver> \
                 --pubkey channel.pub --policy policy.json

# approve, and optionally move the pin in one act
./approve.sh --release 0.12.24 --approved-by "Jane Doe <jane@bank.example>" \
             --entry-ref <registry>/vexa/channel/<name>:0.12.24 \
             --pubkey channel.pub --policy policy.json --move-pin
```

[`presync-job.yaml`](presync-job.yaml) wires the same script as an Argo CD PreSync hook, so a
failed verdict fails the sync and nothing is applied. [`Dockerfile`](Dockerfile) builds the
image it runs: Alpine plus cosign, oras and jq — the logic is the shell script beside it, and
every line of it is Apache-2.0 and readable.

## The verdict is written down

A verdict that lives only on a pod's stdout does not survive the pod. On 2026-08-29 the gate had
been running and passing in production for four nights while every station report read
`verifier.verdict: ABSENT` — the report schema's phrase for *the gate did not run* — because
nothing recorded that it had.

So the PreSync Job records its own outcome, pass or fail, as a ConfigMap in the release namespace
(`verify.verdictConfigMap`, default `vexa-verify-verdict`): the verdict, the contract's id and
sha256, when it was checked, how many checks failed, and — when the run was ELIGIBLE — the signed
station-verdict statement verbatim. That is the object [`kit/validate`](../validate) reads when it
builds a station report.

Three things it does not do. It does not turn a failed verification into a passed sync: the Job
still exits with the verifier's own status. It does not fail a sync when the record itself cannot
be written — that warns in the pod log and the report reads ABSENT, which is a finding. And the
record is not an attestation; it is unsigned bookkeeping. The signed artifact is the statement
`--verdict-out` writes, and a failed run produces none, by design.

`verify.recordVerdict: false` turns all of it off, for a subscriber whose Argo may not create a
Role in the workload namespace.

## The honest note

This is the one component of ours that runs inside your cluster. It exists because "validated"
should mean a machine checked it, not that someone remembered to. It is open source, it reads
only the channel and its own policy, and it writes exactly one object — the verdict ConfigMap
above, in your namespace, under a Role you can read in the chart. The alternative — Kyverno enforcing
evidence directly at admission, with no component of ours at all — is the direction recorded in
ADR-0004 and needs per-image attestations upstream first.
