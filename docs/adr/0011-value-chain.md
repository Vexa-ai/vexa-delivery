---
title: "ADR-0011 — The value chain: contract → PRD → fills → values_proven → station-verdict"
description: "Every station is the same four-step cell. Five objects carry the chain between them, and every clause names its refuser."
---

**Status:** accepted (founder canonicalization 2026-08-31, in-session) · **Refines:**
ADR-0004 (the node model) and ADR-0010 (evidence binds to three subjects) · **Supersedes:**
nothing

## The enforcement law

> **A rule that cannot refuse is prose; every clause here names its refuser.**

That sentence is the acceptance criterion for this ADR and for every contract written under
it. A clause with no refuser is documentation of an intention, and this line has already
shipped one: `carriage.require_entry_values_proven` sat in a live contract while nothing
wrote `values_proven` and nothing read it, so a contract could demand proof of seven values
and admit an entry that proved none. It was not wrong. It was **void**, silently, for as
long as it existed.

## The question

The delivery line has seven stations. Station 5 (prod) is fully mechanical: a contract with
named values, a cosign entry, an in-cluster PreSync verifier, a subscriber-held contract
ConfigMap. **Stations 1 through 3 have no contracts at all** — they run on prose, a fills
log with hand-invented row labels, and a human who remembers what was supposed to happen.

Two failures came out of that gap in a single week, and neither announced itself:

- The founder V-signed a candidate against **lane-framing prose** while believing join code
  was aboard, and the station's row 0 read `compose ps` — which cannot see a spawn image —
  so the station exercised a **stale bot** while every fill read cargo-green. Two readers,
  two different views of the same candidate, no object either could point at.
- Row ids were per-train (`A1`, `F3`). The same claim carried a different name on every
  train, so nothing downstream could verify that a value proved at staging was the value
  prod required. The evidence existed and was unusable.

So: what is the smallest set of objects that makes a station's work **verifiable by the next
station instead of re-performed**, and what refuses when one is missing?

## The decision — THE STATION CELL

**Every station is the same four-step machine, parameterized only by `(contract,
exercisable substrate)`.** There is no station-shaped special case anywhere in the line;
what looks like one is a parameter.

```
        ┌───────────────────────── one station cell ─────────────────────────┐
cargo   │ ADMIT            MINT              PROVE            DEPART         │  cargo
  in ──▶│ verify against  ─▶ derive the PRD ─▶ exercise rows ─▶ compile       │──▶ out
        │ THIS station's    ex-ante:          fills append-     values_proven │
        │ contract:         contract ×        only, with        · sign the    │
        │ upstream          candidate         tested@digest;    station-      │
        │ values_proven +   substrate         a failure DROPS   verdict       │
        │ station-verdict   = what must be    the car, with                   │
        │ (signature, id    proven HERE to    a comment on                    │
        │ roster, subject   earn departure    the record                      │
        │ digests)                                                            │
        └─────────────────────────────────────────────────────────────────────┘
                    ▲                                              │
                    └────── the previous cell's DEPART ────────────┘
```

1. **ADMIT** — verify the incoming cargo against **this** station's contract: the upstream
   `values_proven` rows and the upstream `station-verdict` — its signature, its value-id
   roster against what this contract requires inherited, and its subject digests against
   what actually arrived. **Refusal is the feature.** A station that cannot refuse its input
   is a conveyor, not a gate.
2. **MINT** — derive the **PRD** *ex ante*, before anything is exercised: the contract's
   required values crossed with this candidate's substrate. It says what must be proven
   **here** to earn departure. A PRD assembled after the fills is a transcript, and a
   transcript cannot refuse anything.
3. **PROVE** — exercise the rows. Fills are **append-only**, each carrying `tested@<digest>`
   wherever the finding is about an artifact. A failure **drops the car**, with the comment
   on the record — not a note in a chat.
4. **DEPART** — when the PRD is complete: compile `values_proven`, render and sign the
   **station-verdict**. That verdict is the next station's ADMIT input.

### The nouns

| Noun | What it is | Who may change it |
|---|---|---|
| **CONTRACT** | **the law.** One per station. Names the values that station requires and the carriage rules that bind it. | a human, **by pull request only**. Its sha256 is its identity and rides in every verdict rendered under it. |
| **VALUES** | **the currency.** Minted at a station when evidence backs a contract's named claim; verified downstream, never re-minted. | nobody, directly — a value exists because a fill backs it. **New value rows enter a contract by PR, never by per-train improvisation.** |
| **EVIDENCE** | **the backing.** Fills, bound to digests, in the words the station recorded them in. | append-only. |

**Evidence backs values; values satisfy contracts.** The three are not synonyms and the
substitutions are exactly where the line has failed: evidence presented as a value (a green
log with no contract id), or a value asserted with no backing (a `proven` row with no
`evidence[]`).

### Two properties this buys, stated because they are load-bearing

**(a) ADMIT verifies the previous DEPART, so the chain has no gaps by construction.** The
question *"is there a hop where evidence stopped being checked?"* has a mechanical answer:
if every cell's ADMIT names the upstream station and its verdict hash, a gap is a missing
`admitted` block, and it is visible in one field rather than reconstructible from three
repositories. The chain is closed because each link *is* the check on the one before it.

**(b) Stations differ only in parameters.** Substitute `(contract, substrate)` and every
station in the line falls out of the same cell:

| # | Station | ADMIT verifies | PROVE consists of | DEPART signs |
|---|---|---|---|---|
| **1** | **triage → candidate** | the branch exists and the PRs it names are real; nothing upstream to inherit | **the founder V-sign on the consist manifest**, per car, on the manifest's sha256 | the candidate is a signed consist manifest with a mandatory not-aboard section |
| **2** | **candidate-checks** | station 1's manifest + V-sign rows; refuses a candidate with no conforming signed manifest | the **check roster** — architecture, security, licence, collision, dedupe — and the drop-offs, each with the comment and who decided | a complete roster with every drop-off commented |
| **3** | **bbb staging** | station 2's roster complete and its drops commented | probes, row 0 over the manifest's **image closure**, the live join, the witness rows | `values_proven` compiled + a station-verdict rendered |
| **4** | **cluster staging** *(optional)* | station 3's verdict | the estate shape: chart render, sync, post-sync row 0 | a verdict over the estate contract |
| **5** | **prod** | `require_attestations` — station 3's (or 4's) signed verdict, in-cluster, at PreSync | rollout, live traffic, the prod soak, the full-estate digest sweep | the delivery receipt and the prod-soak attestation |
| **6** | **enterprise** *(skipped today)* | our prod verdict | the customer's own check set, their witness where their policy requires one | their verdict, to their own downstream |
| **7** | **OSS release** | prod's receipt | the candidate packet: tag, notes, image digests, reconciled issues | the published release, digest-pinned |

**Human gates are not exceptions to the cell.** A founder V-sign, a witness session, a
customer's acceptance — each is a **row whose refuser is a named human signature**. It has a
value id, it lands in `values_proven` as `waived` with `waived_by` or as `proven` with the
human named in its evidence, and its absence refuses departure exactly like a failed probe.
That is why station 1, which is entirely a human act, is the same machine as station 5,
which is entirely a mechanical one.

## The five objects

Each is shipped as a schema file so code validates against it rather than against a reading
of this page. **The files are normative**; the shapes below are the readable form, and the
golden instances under `spec/goldens/value-chain/` are the worked example.

| Object | Schema file | Cell step | Its sha256 is cited by |
|---|---|---|---|
| **consist-manifest** | [`spec/consist-manifest.schema.json`](https://github.com/Vexa-ai/vexa-delivery/blob/main/spec/consist-manifest.schema.json) | output of station 1's DEPART; input to every MINT | the PRD, the station-verdict |
| **station-prd** | [`spec/station-prd.schema.json`](https://github.com/Vexa-ai/vexa-delivery/blob/main/spec/station-prd.schema.json) | MINT | the station-verdict |
| **fill-line** | [`spec/fill-line.schema.json`](https://github.com/Vexa-ai/vexa-delivery/blob/main/spec/fill-line.schema.json) + parser [`spec/fill_line.py`](https://github.com/Vexa-ai/vexa-delivery/blob/main/spec/fill_line.py) | PROVE | `values_proven[].evidence[].ref` |
| **values_proven** | [`spec/values-proven.schema.json`](https://github.com/Vexa-ai/vexa-delivery/blob/main/spec/values-proven.schema.json) | DEPART | the station-verdict |
| **station-verdict** | [`spec/station-verdict.schema.json`](https://github.com/Vexa-ai/vexa-delivery/blob/main/spec/station-verdict.schema.json) | DEPART | the next station's ADMIT |

These five are **draft-07**. The `channel-entry` family is 2020-12 and stays so; the split is
deliberate and narrow — these objects are consumed by shell and by the stdlib-only manifest
generator in another repository, where draft-07 is the dialect a hand-rolled validator can
honestly claim to implement.

### 1. consist-manifest — the candidate's identity

**Its sha256 IS the candidate's identity.** The founder V-signs against it; the station's
row 0 enumerates FROM it. One generated object, both readers.

```json
{
  "schema_version": 1,
  "train_id": "t26-01226",
  "base_sha": "<40 hex>",
  "candidate_sha": "<40 hex>",
  "cars": [{"pr": "owner/repo#N", "author": "…", "commits": ["<40 hex>"], "surfaces": ["core/meetings"]}],
  "not_aboard": [{"pr": "owner/repo#N", "reason": "held for #1075 by founder"}],
  "image_closure": [{"image": "vexaai/vexa-bot", "dockerfile": "core/meetings/services/bot/Dockerfile",
                     "built_by": "runtime-spawn", "row0_required": true}],
  "generated_at": "2026-08-31T11:55:00Z",
  "generator": "render-manifest.py/1.0"
}
```

Three clauses and their refusers:

- **`not_aboard` is mandatory and may not be silently empty.** An empty section is legal only
  as the single sentinel row `none-considered-excluded`. *Refuser:* the generator refuses to
  run without an explicit not-aboard input file — a machine can enumerate what IS aboard, but
  only a human knows what a reader will wrongly assume is aboard.
- **`image_closure` includes spawn images.** They never appear in `compose ps`; that is the
  hole row 0 fell through. *Refuser:* station 3's row-0 row enumerates from this array, so an
  image missing here is a row nobody filled, and the PRD is incomplete.
- **`cars[].pr` is repo-qualified, and unreferenced commits group as `unattributed` rather
  than being dropped.** A commit that reached the candidate with no PR carries no narrative,
  no value sign-off and no non-author review. *Refuser:* the reviewer, who can now see it.

Generated by `render-manifest.py` in the biz workspace
(`skills/lifecycle/deliver/bin/render-manifest.py`), which vendors this schema inline. The
vendoring is deliberate: a cross-repo import makes the generator unrunnable whenever this
checkout is absent, and a generator that cannot run is a manifest nobody writes. The two
copies are held identical by `publisher/tests/test_value_chain.py`.

### 2. station-prd — the ex-ante work order

```json
{
  "schema_version": 1,
  "station": "station-3-staging",
  "contract_id": "vexa-internal-staging-2026-09",
  "contract_sha256": "<64 hex>",
  "manifest_sha256": "<64 hex>",
  "candidate_sha": "<40 hex>",
  "rows": [{"value_id": "V-stg-3", "claim": "…", "spec": "the minimal exercise", "slot": "fills"}],
  "proposed_values": [{"value_id": "V-stg-9", "claim": "…", "rationale": "why the contract should carry this standing"}],
  "derived_at": "2026-08-31T09:00:00Z"
}
```

- **Rows key on contract value ids and on nothing else.** `V-est-1`, never `A1`. *Refuser:*
  the compiler — a fill whose value id is not in the contract compiles to no row, and the
  contract's required value stays unproven, and DEPART refuses.
- **`proposed_values` is mandatory as an array (write `[]`).** A claim this candidate makes
  that no contract covers goes here, and its only path into `rows` is **a pull request against
  the contract**. *Refuser:* the contract's reviewer. This is the clause that kills per-train
  improvisation at the root: an invented row can be exercised, but it cannot depart as a value.
- **`derived_at` precedes every fill's `ts`.** *Refuser:* mechanical — the ordering is
  checkable, and it is the only thing separating a work order from a transcript.
- **`slot: inherited`** is how the line gets cheaper than N full validations: the station
  verifies the upstream signed claim rather than re-proving it. *Refuser:* ADMIT, which checks
  the signature and the id roster before any row is marked inherited.

### 3. fill-line — the append-only log grammar

One exercised row is one line. The log is append-only, which is the whole mechanism: a fill
records something done at a moment, so an edited fill is a claim about the past that nothing
can check.

```
<ts> <V-id> <VERDICT> [tested@<digest>] <evidence…>

2026-08-31T12:35:00Z V-stg-2 PASS tested@sha256:<64 hex> compose PROBE FULL PASS (aaa-prb1388) …
```

Normative regex, carried identically in the schema's `line_grammar` and in the parser so the
two cannot drift into separate files:

```
^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)[ \t]+
 (?P<value_id>V-[A-Za-z0-9][A-Za-z0-9._-]*)[ \t]+
 (?P<verdict>PASS|FAIL|PART|WAIVED)
 (?:[ \t]+tested@(?P<digest>sha256:[0-9a-f]{64}))?[ \t]+
 (?P<evidence>\S.*)$
```

Blank lines and `#` comments are skipped. **Anything else is MALFORMED and is reported, never
dropped** — a line the parser silently ignored is a fill that exists in the log and not in
the compiled values, which is the exact gap the log exists to close. *Refuser:*
`fill_line.py --check`, exit 1.

- `PASS` compiles to `proven`. `WAIVED` compiles to `waived` **and requires a named human**;
  the compiler raises rather than emitting an anonymous waiver.
- **`FAIL` and `PART` compile to nothing.** A partial exercise is not a proof. There is no
  verdict for *we did not get to it*: an unexercised row simply has no line, **and the missing
  line is what refuses departure.**
- Truncated timestamps (`13:0xZ`, as several real logs carry) are refused: a fill that cannot
  be ordered against `derived_at` cannot be shown to be ex-post.

### 4. values_proven — the compiled currency

Aligned **exactly** with the block embedded in `channel-entry.schema.json`, which is the copy
the in-cluster verifier enforces against a signed entry. The standalone file is the
addressable definition; `publisher/tests/test_value_chain.py::EmbeddedValuesProven` resolves
the embedded `$ref`s and compares the two structurally. **A drift between them is a finding,
not a variant.**

```json
[{"id": "V-est-1", "verdict": "proven", "station": "vexa-staging",
  "evidence": [{"what": "verbatim from the fill line", "ref": "<path>#L12",
                "tested_at": "2026-08-31T12:35:00Z", "subject_digest": "sha256:<64 hex>"}]},
 {"id": "V-est-6", "verdict": "waived", "station": "vexa-staging", "waived_by": "Dmitriy Grankin"}]
```

- **`proven` requires non-empty `evidence`.** A proven verdict with no evidence is the exact
  shape of the void this block exists to close. *Refuser:* the schema, `if/then`.
- **`waived` requires `waived_by`.** An anonymous waiver is indistinguishable from an
  omission. *Refuser:* the schema, and the compiler before it.
- **Rows are station CLAIMS, not the verifier's findings.** The verifier checks that the claim
  exists, names a station, carries evidence, and that any `subject_digest` is genuinely one of
  this entry's images. **It cannot re-run a station**, and pretending otherwise is how a signed
  plausible paragraph becomes worse than no attestation at all (ADR-0010's hazard).

### 5. station-verdict — the signable body

```json
{
  "schema_version": 1,
  "station": "station-3-staging",
  "candidate_sha": "<40 hex>",
  "manifest_sha256": "<64 hex>",
  "contract_id": "vexa-internal-staging-2026-09",
  "contract_sha256": "<64 hex>",
  "values_proven_sha256": "<64 hex>",
  "verdict": "ELIGIBLE",
  "rendered_at": "2026-08-31T13:00:00Z"
}
```

**This is the body, not the envelope.** cosign signs these bytes; the in-toto statement that
wraps it is `station-verdict-attestation.schema.json` and building it is lane B's job,
deliberately out of scope here — so the body can be rendered, diffed and reviewed by a human
who is not holding a key.

One difference from the attestation, and it matters: the attestation can only ever carry
`ELIGIBLE`, because a failed verification simply produces no signature. **This body can carry
`REFUSED`**, with `refusals[]` naming the clause and the detail, because a refusal is a fact a
station records for the record even when nothing signs it. *Refuser on the refusal:* the
schema requires `refusals[]` non-empty when the verdict is `REFUSED` — a refusal with no
reason is not reviewable and is indistinguishable from an outage.

The optional `admitted` block carries what this station's own ADMIT verified: the upstream
station, its verdict hash, and the values inherited rather than re-proved. It is what makes
property (a) readable end to end from any single verdict.

## Where the clauses' refusers live, in one table

| Clause | Refuser | Status today |
|---|---|---|
| candidate is a conforming signed consist manifest | **station 2's contract** (`vexa-internal-triage-2026-09` → checks) | ships with this ADR |
| every car carries a founder V-sign row on the manifest sha | station 2's ADMIT | ships with this ADR |
| `not_aboard` present (or explicit sentinel) | `render-manifest.py` refuses to run without it | shipped |
| check roster complete; every drop-off commented | **station 3's contract** (`vexa-internal-checks-2026-09` → staging) | ships with this ADR |
| every `row0_required` image byte-verified | station 3's own PRD rows | ships with this ADR |
| fills parse; malformed lines reported | `spec/fill_line.py --check` | shipped |
| `proven` carries evidence; `waived` names a human | the schema's `if/then`, both copies | shipped |
| every contract-required value has a row | `carriage.require_entry_values_proven`, in-cluster verifier | **lane B, in flight** |
| staging's signed verdict present before prod sync | prod contract's `require_attestations` | **lane B activates it** |
| the signing envelope over the verdict body | lane B | **out of scope here** |

Three rows are not ours to close in this change, and they are named rather than implied.
A clause whose refuser is *"a later change"* is still prose today, and this table is where
that is admitted instead of hidden.

## Consequences

- **Stations 1–3 acquire contracts**, in `DmitriyG228/vexa-stations`
  (`channels/vexa-internal/contracts/`), reviewed like every other contract: by pull request,
  because the sha256 is the identity.
- **Per-train row ids stop.** Existing logs (`t25-01225`, `t26-01226`) keep theirs — they are
  the record — but a new fill uses a contract V-id or compiles to nothing.
- **The consist manifest becomes the approval surface.** Prose descriptions of a consist are
  commentary. A V-sign that does not cite a manifest sha256 is a V-sign against an
  unidentified object.
- **A station that cannot produce its PRD before it starts cannot depart.** That is a real
  constraint on how a train begins, and it is the intended cost.
- The `values_proven` shape now exists in two files. That is a duplication with a named
  refuser (the structural-equality test) rather than a convention someone remembers, which
  is the same treatment `internal-estate.json` gets against its YAML.

<!-- vexa-agent -->
