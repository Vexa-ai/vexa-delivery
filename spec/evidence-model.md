# The evidence model — values, rank, three subjects, contracts as channel gates

This is the model the factory is being built to. It is not a description of what runs today.
**Every table carries a `State` column, and [State of implementation](#state-of-implementation)
is the same picture in one place, as of 2026-08-29.** A spec written as though it were all
shipped is a lie with a schema attached, and the honest state is part of what makes the rest
credible.

| Marker | Meaning |
|---|---|
| **BUILT** | code exists, runs, and has produced the artifact in question |
| **IN REVIEW** | written and under review — the PR is named |
| **RULED** | decided, not built |
| **NOT STARTED** | no execution, no code |

## The objective

A merge reaches production the same day, through machine gates, and every claim made about it is
provable: traceable from **value → evidence → environment**, and verifiable offline by a subscriber
whose cluster the vendor never touches.

Two concerns, deliberately separate:

- **Delivery speed** — how long a merge takes to become a running image.
- **Provability** — whether what shipped can be shown to have earned it.

**Evidence never blocks the loop. It rides it.** A gate that halts delivery to collect evidence
turns provability into a tax, and a taxed loop stops turning. Evidence is emitted by steps that
were going to run anyway, signed where it is produced, and carried forward by digest.

## Value and evidence are different nouns

The single most load-bearing distinction in this model, and the one that collapses first if left
implicit.

| | **A value** | **Evidence** |
|---|---|---|
| What it is | a claim | an observation |
| Shape | one sentence a human can witness | a signed envelope |
| Declared | on the work item, before the work | by the step that produced it |
| Identity | a `value_id` that travels with the change | subject digest + predicate type |
| Always carries | its rank (below) | the environment it was observed in |
| Answers | *what did we say this does* | *what was seen, where* |

**The relation is many-to-many.** One evidence run covers many values — a single set-level
validation exercises dozens of claims at once. One value needs fresh evidence per environment: the
same claim proven in staging is not proven in production, because the configuration differs and the
configuration is what makes an observation mean anything. See
ADR-0010 (in review, [#10](https://github.com/Vexa-ai/vexa-delivery/pull/10))
§ *What must ride with the per-image claim, or it means nothing*: the per-image claim carries the
configuration it was exercised under, or it is not a claim.

**Environment is stamped, never inferred.** An envelope without the environment it ran on is a
sentence with the subject removed.

**Nondeterministic modules get statistical evidence, not a green tick.** Where a module is flaky by
nature — a browser joining a live meeting, a transcription pass over real audio — a single passing
run is evidence that it passed once, which is not the claim anyone cares about. The evidence is a
**rate over a declared window**: numerator, denominator, window bounds, and the environment. A
threshold is then a contract predicate over that rate, not a boolean the producer decides.

| Element | State |
|---|---|
| `value_id` declared on the work item and carried to the candidate map | **RULED, NOT BUILT** — minimal form planned: `value_ids[]` on the candidate map |
| Environment stamped on every evidence row | **BUILT** for entry-level evidence; **RULED, NOT BUILT** per-image |
| Statistical evidence as a rate over a declared window | **IN REVIEW** — spec draft v2 in [#10](https://github.com/Vexa-ai/vexa-delivery/pull/10); no producer |

## Rank — who can prove a claim

Every value declares its **rank**. Every evidence envelope records **how it was produced**. The
contract is where the two meet.

| Rank | What can produce it | Example | State |
|---|---|---|---|
| `autonomous` | a machine gate that ran and exited | a named CI gate result; a schema conformance check | **RULED, NOT BUILT** |
| `statistical` | a metric window over real operation | a production soak: rate over a declared window | **RULED, NOT BUILT** |
| `human` | only a person, attesting | perceived transcription quality; a value sign-off | **RULED, NOT BUILT** |

**Enforcement is by signature, not by convention.** Rank maps to the class of functionary permitted
to sign the evidence that satisfies it. A contract row for a `human`-rank value requires an
attestation signed by a **human identity**; a green CI run cannot satisfy it, however many gates it
contains, because no human key signed anything. Conversely an `autonomous` row is not satisfied by a
person asserting the gate passed — the gate's own signed result is the only thing that counts.

This is what makes rank more than a label: it is a constraint on the permitted signer set, checked
by the same machinery that checks anything else in the contract.

The witness flow — a human observing a run and recording what they saw — exists today and is
**unsigned**, so nothing it produces can satisfy a `human`-rank row yet. That gap is the work, not
an oversight.

## The three subjects

A claim binds to the thing it is actually about, and to nothing larger. Full reasoning in
ADR-0010 (in review,
[#10](https://github.com/Vexa-ai/vexa-delivery/pull/10) — not on `main`, so it is referenced by PR,
not by path); the shape:

```
  PULL REQUEST            compliance · security · value · rights · licence
  (repo#number,           claims about a CHANGE AND ITS ARGUMENT
   pinned to its
   merge commit SHA)
      │
      │  merge commit → release archive → SLSA source provenance
      ▼
  IMAGE DIGEST            build provenance · SBOM · CVE scan · prod soak
  (sha256:…)              claims about an ARTIFACT
      │
      │  collected by the candidate map (image → source, per image)
      ▼
  DIGEST SET              station verdict · delivery receipt
  (the entry's images)    claims about an ASSEMBLY
```

**The pull request, not the commit.** A commit is a diff; a PR is a diff **with an argument
attached**, and compliance and value are judgments about the argument. The merge commit rides along
as the *binding* — the path by which a PR's claims reach an image — not as the subject.

**Set-level validation exists because some claims are assembly claims.** *"The documented API
surface works as documented"* is not provable on a PR: no single change owns it, and it is false or
true only of a running assembly.

**Set evidence binds to the set and decomposes onto members.** The vocabulary already exists in
[`validation-contract.schema.json`](validation-contract.schema.json), and it is the point of that
document:

| Field | What it carries |
|---|---|
| `dependencies[].fidelity` | `real` · `double(…)` · `dummy-endpoint` · `absent`; anything but `real` REQUIRES a justification |
| `proves` | one line: what this configuration genuinely establishes |
| `does_not_prove` | one line: what a reader must NOT conclude |
| `unproven_claims[]` | claims an absent or substituted dependency makes unavailable, written out so a receipt cannot accidentally assert them |

An image reused in a different assembly therefore inherits exactly what the configuration rows
justify — not the set's verdict, and not nothing. A consumer running outside the exercised
configuration does not get a weaker claim; they get the claim plus the explicit statement of what it
does not prove for them, and their contract decides whether that is enough.

**Through `value_id`s on the candidate map, one set run validates many PRs.** The map is already the
carrier that binds each image to its source and its runs; carrying the value ids there is what lets a
single set-level observation discharge the claims of every change inside it, without re-running
anything per PR.

| Element | State |
|---|---|
| PR as an attestation subject | **RULED, NOT BUILT** |
| Image-digest subject: candidate map binds image → source → runs | **BUILT** |
| Per-image SLSA provenance | **NOT STARTED** — every entry declares `image_provenance` in `evidence_absent[]` |
| Digest-set subject: station verdict + delivery receipt | verdict producer and chart wiring **IN REVIEW** ([#10](https://github.com/Vexa-ai/vexa-delivery/pull/10)); delivery receipt **BUILT** |
| Decomposition vocabulary (`proves` / `does_not_prove` / `unproven_claims`) | **BUILT** as schema; **no producer** |
| `value_ids[]` on the candidate map | **RULED, NOT BUILT** |

## Contracts are the gates to channels

A **channel** is an ordered stream of entries ([`channel.md`](channel.md)). A **contract** is what
decides whether an entry may enter it, and whether an entry may run once pulled.

A contract is a machine-readable list of:

- **required evidence** — kind, and (ruled, not built) the rank or signer identity that must have
  produced it, and its freshness bound;
- **refusals** — including the refusal of a *declared absence*: `evidence_absent[]` states what an
  entry does not carry, and `forbid_absent_evidence` is how a subscriber refuses an entry for
  declaring away something they require. The gap becomes checkable data rather than silence.

Contracts are checked **at publish and at admission** — and, stated plainly rather than papered
over, **these are two gates, not one gate run twice**:

| Gate | Where | What it evaluates | State |
|---|---|---|---|
| Publish | publisher, gate `C8` and its siblings | the publisher's own invariants: evidence completeness unless `--break-glass`, digest-pinning well-formedness, `delivery_scope` on the rendered chart | **BUILT** — has gated the five entries published to date |
| Admission | the subscriber's cluster | the subscriber's contract predicates — `require_evidence_kinds`, `require_attestations`, `forbid_absent_evidence`, `max_entry_age_days` — plus stock signature and digest-pinning checks | **BUILT**, runs; `admission.enabled` is false in the estate today, pending the signature-repository ruling ([ADR-0002](../docs/adr/0002-channel-format.md)) |

The publisher does not hold the subscriber's contract and cannot evaluate it. That is a correct
consequence of the two-party design, and it means "both sides run the same contract" is not a claim
this repository can make.

**`evidence_absent[]` + `forbid_absent_evidence` is built and barely exercised.** The only contract
that forbids an absence today is the vendor's own internal one. No subscriber contract forbids
anything yet, which means the sharpest property of the design is currently unproven by use.

## Where everything lives

Three stores, three jobs, and no store does two of them.

| Store | Role | Holds | Never |
|---|---|---|---|
| **OCI registry** | the truth store | signed envelopes, content-addressed, offline-mirrorable | is not a read surface — deliberately dumb, no query, no index of its own |
| **Git ledger** | the history | records naming digests, positions, receipts | never holds envelopes |
| **Projection** | the legibility layer | read-models rebuilt from artifacts at ingest: which values are proven, at what rank, in which environment, expiring when | never authoritative; disposable and rebuildable; one writer per surface |

Two consequences worth stating:

- **Entries move pointers, not bytes.** The channel pointer moves by descriptor copy; an immutable
  tag carries identity and a floating tag carries position. Nothing is re-wrapped and nothing is
  rewritten.
- **Mirroring a registry is how evidence reaches an air-gapped estate.** Because the truth store is
  content-addressed and the verification path needs no network, a copied registry is a complete
  copy of the proof.

| Element | State |
|---|---|
| Registry as truth store; entries as signed OCI artifacts | **BUILT** |
| Attestation addressing | **RULED, NOT BUILT** — attestations are currently addressed by mutable release tag (`attestations:<kind>.<release>`), not by subject digest. This is a defect, named here rather than deferred |
| Git ledger of positions and receipts | **BUILT** |
| Ledger head-hash anchored into an external log | **RULED, NOT BUILT** ([#12](https://github.com/Vexa-ai/vexa-delivery/issues/12)) |
| Projection read-model | **RULED, NOT BUILT** |

## The standard stack

Founder ruling, 2026-08-29 ([#12](https://github.com/Vexa-ai/vexa-delivery/issues/12)): **wherever a
widely-adopted standard covers a layer, adopt it; keep bespoke machinery only where the void is
verified.** Borrowed vocabulary lets a reviewer who recognises the standard stop evaluating and
start checking.

| Layer | Standard | State |
|---|---|---|
| Evidence envelope | [in-toto Statement](https://github.com/in-toto/attestation) + [DSSE](https://github.com/secure-systems-lab/dsse) | **RULED, NOT BUILT** |
| Build claim, per image | [SLSA provenance v1](https://slsa.dev/spec/v1.1/provenance) | **NOT STARTED** — declared absent on every entry |
| Verdict | [SLSA VSA v1](https://slsa.dev/spec/v1.1/verification_summary), `policy.digest` = the contract's sha256 | **RULED, NOT BUILT** — the bespoke verdict producer is **IN REVIEW** ([#10](https://github.com/Vexa-ai/vexa-delivery/pull/10)) |
| Signing | [cosign](https://docs.sigstore.dev/cosign/system_config/registry_support/) key-mode, one identity per station, `threshold` in the contract | **RULED, NOT BUILT** — one key signs everything today; station identity is string-compared |
| Admission | [Kyverno](https://kyverno.io/docs/policy-types/cluster-policy/verify-images/sigstore/), Audit-first on a first install | policy **BUILT**; Audit-first **RULED, NOT BUILT** |
| Addressing | subject digest, with [OCI referrers](https://github.com/opencontainers/distribution-spec/blob/main/spec.md) where the consumer's registry supports it | **RULED, NOT BUILT** |
| Statistical production evidence | [AnalysisRun](https://argo-rollouts.readthedocs.io/en/stable/features/analysis/)-pattern metric windows, wrapped as an in-toto predicate and signed onto image digests | **IN REVIEW** ([#10](https://github.com/Vexa-ai/vexa-delivery/pull/10)); no producer |
| Ledger | git, with the head hash periodically anchored into a log we cannot rewrite ([Rekor](https://github.com/sigstore/rekor) or equivalent) | **RULED, NOT BUILT** |

## What is deliberately not standard, and why

Each of the following was searched for across in-toto, SLSA, VSA, Witness, Kargo, Binary
Authorization, Flux, Ratify and GUAC, and not found. *Not found* is a bounded search, not a proof of
novelty, and is written that way.

| Ours | Why no standard covers it | State |
|---|---|---|
| **PR as attestation subject** | in-toto subjects are matched purely by digest. A change **plus its argument** is not a digest, and compliance and value are judgments about the argument | **RULED, NOT BUILT** |
| **Soak signed onto image digests** | verification systems mark an *assembly* verified in a stage; none decompose a runtime claim to per-image digests, so none let a recombined bundle inherit production history | **IN REVIEW** ([#10](https://github.com/Vexa-ai/vexa-delivery/pull/10)); no producer |
| **`evidence_absent[]` + `forbid_absent_evidence`** | declaring a gap has prior art; a machine-checkable consumer policy that **refuses a specific declared gap** does not. A verdict object reports pass or fail and has no vocabulary for *"I did not check X, and you may refuse me for it"* | **BUILT**, exercised only by the vendor's own contract |
| **`unproven` as a first-class verdict** | pass/fail leaves a leg with no producer to be silently omitted. A leg that nothing produces must say so out loud | **RULED, NOT BUILT** |

## The development flow this enables

1. **State the value** — one sentence a human can witness — **its rank**, and **which contracts will
   consume it**.
2. **Validation is derived from those contracts, not designed per change.** Nobody invents a test
   plan per pull request; the contracts that will have to accept the result already say what
   evidence must exist and who must have signed it.
3. **Agents implement, and collect evidence en route.** The evidence is a by-product of the steps
   that were going to run, signed where produced.
4. **Two human moments remain**, and only two: **value sign-off** — a person attesting the claim is
   the claim — and **promotion approval** — a person releasing it into an environment.

Everything between those two moments is machine-gated. That is the whole point of ranking values: it
makes explicit which moments genuinely require a person, so the rest can stop requiring one.

## State of implementation

As of **2026-08-29**. Nothing below is aspiration stated as fact.

| Piece of the model | State |
|---|---|
| Publish gate (`C8` and siblings) | **BUILT** — has gated the five entries published to date |
| Channel entry: signed digest set + evidence bundle, offline-verifiable | **BUILT** |
| Candidate map binding image → source → runs | **BUILT** |
| `evidence_absent[]` + `forbid_absent_evidence` | **BUILT** — exercised only by the vendor's own internal contract; no subscriber contract forbids anything yet |
| Admission gate (Kyverno policy, signature + digest-pinning) | **BUILT**, runs — `admission.enabled` false in the estate today, pending the signature-repository ruling ([ADR-0002](../docs/adr/0002-channel-format.md)) |
| Set-level decomposition vocabulary (`proves` / `does_not_prove` / `unproven_claims`) | **BUILT** as schema — **no producer** |
| Station-verdict producer + chart wiring | **IN REVIEW** — [#10](https://github.com/Vexa-ai/vexa-delivery/pull/10) |
| ADR-0010, three subjects | **IN REVIEW** — [#10](https://github.com/Vexa-ai/vexa-delivery/pull/10) |
| Statistical soak evidence (rate over a declared window) | **IN REVIEW** — spec draft v2 in [#10](https://github.com/Vexa-ai/vexa-delivery/pull/10); **no producer** |
| Verdict emitted as a SLSA VSA | **RULED, NOT BUILT** — [#12](https://github.com/Vexa-ai/vexa-delivery/issues/12) |
| Value ids (`value_ids[]` on the candidate map) | **RULED, NOT BUILT** |
| Rank (`autonomous` / `statistical` / `human`), enforced by signer class | **RULED, NOT BUILT** — the witness flow exists and is unsigned, so no `human`-rank row can be satisfied today |
| Per-station signing identities + `threshold` in the contract | **RULED, NOT BUILT** — one key signs everything; station identity is string-compared |
| Digest addressing for attestations | **RULED, NOT BUILT** — attestations are tag-addressed today, which is a defect |
| Projection read-model | **RULED, NOT BUILT** |
| Ledger head-hash anchoring | **RULED, NOT BUILT** |
| Kyverno Audit-first on first install | **RULED, NOT BUILT** — the kit installs at Enforce |
| Per-image SLSA provenance | **NOT STARTED** — every entry declares `image_provenance` absent |

**Two honest readings of that table.** The evidence *carriage* is built — entries, bundles, digests,
offline verification, the publish gate. The evidence *semantics* — values, rank, subjects, standard
predicates — are ruled and mostly unbuilt. And the property the design leans on hardest, a
subscriber refusing a declared absence, has never been exercised by a subscriber.
