# ADR-0010 — Evidence binds to three subjects, and recombination is the test

**Status: PROPOSED** (2026-08-28). Supersedes nothing. Decides where a claim lives.

## The question

We want per-PR validation — compliance, security, value, each a **pass plus the
reasoning for the pass** — collected and promoted up to the train. But a train is
not the last assembly: its images are recombined into different bundles, per
service, per channel. So: does an **image** carry this evidence, or does it carry
only the train evidence it was part of?

## The decision

**Three subject types. A claim binds to the thing it is actually about, and to
nothing larger.**

```
  PULL REQUEST            compliance · security · value · rights · licence
  (repo#number,           claims about a CHANGE AND ITS ARGUMENT
   pinned to its
   merge commit SHA)
      │
      │  merge commit → release archive → SLSA source provenance
      ▼
  image digest            build provenance · SBOM · CVE scan
  (sha256:…)              claims about an ARTIFACT
      │
      │  collected by the candidate map (image → source, per image)
      ▼
  digest SET              station verdict · prod soak · delivery receipt
  (the entry's images)    claims about an ASSEMBLY
```

**Recombination is the test that decides the boundary**, and it is not a
thought experiment — it is what this channel does. Disassemble a set and
reassemble it differently:

- **PR-level and image-level attestations follow each image.** They are bound to
  identifiers that did not change. An image that moves into a new bundle brings its
  provenance, its SBOM, its scan, and — through the merge commit and the source
  chain — the compliance, security and value reasoning of the PRs that produced it.
- **set-level attestations do not transfer.** A soak over ten images says those
  ten ran together in prod for a window. It says nothing about a new set of three,
  and a verifier must not read it as if it did.

So the answer to the question is **both, and never each other's**: the image holds
what is true of the image; the assembly holds what is true of the assembly.

## Why this is not a compromise

The mechanism for the recombined bundle to be honest about what it inherited
already exists: **`evidence_absent[]`**. A bundle assembled from images that each
carry provenance, an SBOM and a commit's compliance reasoning, but which has never
itself soaked, declares the soak absent — and the consumer's contract decides
whether that is acceptable (`forbid_absent_evidence`). The gap becomes visible
data rather than silence.

That is the same property that lets an edge entry ship with fewer attestations
than a promoted one, using one contract language and two acceptance policies.

## What a PR-level attestation asserts

Subject: the **pull request** — `repo#number` — **pinned to its merge commit SHA**.
Predicate: one leg per named check, each carrying a verdict and its basis.

**Why the PR and not the commit** (founder correction, 2026-08-28: *"PR has
narrative — not commit"*). A commit is a diff. A PR is a diff **with an argument
attached**, and compliance and value are judgments about the argument, not about
the bytes. Binding them to a commit would apply this ADR's own test — *a claim
binds to the thing it is actually about* — inconsistently, which the first draft
of this ADR did.

The durability objection that produced that first draft was simply wrong: a PR
number is permanent and addressable forever. What is transient is the PR's
*branch*, not the PR.

**And `Vexa-ai/vexa` already decided this.** `merge-card` is choke point 1 of the
delivery constitution (ADR-0029 there): main accepts a PR only when **both its
value and its diff are accepted** — `pr-value` green plus the `state:
value-signed` human sign-off, and a fresh non-author review. It is a required
status check. The unit at which value is judged is already the PR; this ADR now
matches it instead of contradicting it.

The merge commit is carried alongside as the **binding**, not the subject: it is
how a PR's claims reach an image, via the release archive and its SLSA provenance.

### Two consequences of choosing the PR

1. **A commit that reaches main without a PR carries none of this.** Direct pushes
   exist. Such a commit must show as `unproven` in the roll-up rather than being
   silently absent — a change that landed with no narrative, no value sign-off and
   no non-author review is precisely the thing a reviewer should be able to see.
2. **A release contains many PRs**, so an entry's evidence carries one attestation
   per PR in the range. That is a real growth in the evidence set and probably
   wants a roll-up object — a per-release summary that names each PR and its
   verdicts, with the individual attestations addressable beneath it.

Most of the machinery exists in `Vexa-ai/vexa` and is not yet attested —
`gates.yml` (34 named gates including `licenses`, `image-licenses`,
`contract-version`, `contract-conformance`, `arch-report`, `isolation`),
`pr-value.yml` (a real compose stack driven through the full FSM by a
contract-faithful bot), `contribution-rights.yml`, `docs-current.yml`. The work is
not to build the checks. It is to **bind their results to a commit, sign them, and
carry them.**

Legs, with what already produces them:

| Leg | Produced today by |
|---|---|
| `rights` | `contribution-rights.yml` (DCO + corporate authorization) |
| `licence` | gates `licenses`, `image-licenses` |
| `architecture` | gates `isolation`, `graph`, `exports`, `arch-report` |
| `contract-compatibility` | gates `contract-version`, `contract-conformance` |
| `docs-truth` | `docs-current.yml` |
| `value` | `pr-value.yml` + `merge-card` (`state: value-signed`, a named human) |
| `security` | ⛔ nothing today |
| `compliance` | ⛔ nothing today |
| `reversibility` | ⛔ nothing today — a bank asks; we cannot answer |
| `data-protection` | ⛔ nothing today — does this change what personal data is processed, or where it goes? A GDPR/DORA buyer asks this per change |

## ⛔ The hazard, and the structural guard

The founder's requirement is *a pass **and the reasoning for the pass***. Reasoning
is what makes this useful to a reviewer — "CI green" is not an argument.

It is also how this becomes dangerous. **A signed, plausible-sounding
justification that nothing verified is worse than no attestation at all**, because
a regulated buyer will trust it. An LLM can produce an excellent paragraph
explaining why a change is compliant without that paragraph being true.

Therefore, structurally, not as a warning:

1. **The verdict is machine-derived. The reasoning is evidence, not prose.** Each
   leg's `pass` comes from a check that ran and exited. It is never inferred from
   the reasoning.
2. **Every reasoning field cites its basis** — a run URL, a gate name and its
   output digest, a file and line, or a named human. A leg whose reasoning cites
   nothing is `unproven`, never `pass`.
3. **`unproven` is a first-class verdict** and must be expressible alongside `pass`
   and `fail`, so a leg with no producer says so instead of being omitted. The four
   legs marked ⛔ above are `unproven` on every PR today, and the attestation must
   say that out loud.
4. **A human-authored leg names the human.** Compliance and value judgments that
   rest on a person carry that person, the way `published` mode already requires
   `--approved-by`.

## Consequences

- Four legs have no producer. They are `unproven` until they do, and the
  attestation is honest about it rather than silent.
- Commits that land without a PR have no PR-level evidence, by construction. The
  roll-up must show that rather than omit it.
- The train's evidence set becomes the union of what its images carry plus what the
  assembly earned — not a flat list, and consumers must be able to ask at which
  level a claim was made.
- `spec/channel-entry.schema.json` needs a level for each evidence row. Today the
  rows are flat, which is exactly why this question was ambiguous.
- A recombined bundle inherits automatically at two levels and must re-earn the
  third. That is a feature and should be documented as the reason the split exists.
