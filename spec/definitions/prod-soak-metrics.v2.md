# Sealed definition — production-soak metrics, v2

**STATUS: DRAFT — not sealed, not pinned by any contract.** v2 becomes frozen the
moment a contract pins its sha256; until then it may change. v1 remains frozen and
in force for anything already pinned to it.

This document defines every number a Vexa prod-soak attestation may carry. Its sha256 is
embedded in each attestation (`definitions.sha256`), and a verifying contract pins the same
hash — so the consumer verifies the number and its meaning together. Changing one word here
changes the hash and produces a different, incompatible definition version.

## What v2 adds, and why

v1 could say *the software did not break*. It could not say *the software did the job*, and a
subscriber's eligibility question is the second one. v2 adds three things and corrects two
errors in v1.

**Added.** `transcribed` — a meeting that completed and produced transcript output. A completed
meeting with no segments is not a delivered meeting, and v1 had no way to say so.
**`applicable_scope`** — the configurations a subscriber could actually encounter, declared
rather than inferred, so a failure in a configuration they will never meet does not count
against them and a failure in one they will is not hidden by fleet-wide averages.
**`coverage`** — the window must actually contain meetings exercising each declared
configuration. An attestation over a window that never tried the thing proves nothing about it.

**Corrected.** v1 says exits are *"recorded by the product's own lifecycle machine (`ExitReason`,
`meeting_api/lifecycle/machine.py`)"*. **There is no `ExitReason` in that file.** The enums are
`BotStatus` and `CompletionReason`, and they are not parallel: `status` is one of `completed` or
`failed`, and `completion_reason` is a separate field carrying one of ten values. v1's table
presents `completed` as an eleventh peer of the ten. It is not; a run can be
`status=completed, completion_reason=stopped`. v2 models the pair.

## The population

`meetings_dispatched` — every bot dispatch requested against the named platform, in the named
environment, during the attestation window, served by the attested image digests, **within the
declared `applicable_scope`**. No dispatch inside that scope is excluded for any reason.

Source of record: the meeting row's `status` and `data.completion_reason`
(`meeting_api/collector/adapters.py`). **Not** `/api/user-activity-snapshot`, which collapses all
reasons into a single integer and therefore cannot support any number in this document
(`DmitriyG228/biz#391`).

## Outcome taxonomy

Every dispatch ends as a `(status, completion_reason)` pair, server-derived:

| status | completion_reason | Classification |
|---|---|---|
| `completed` | `stopped` · `left_alone` · `startup_alone` · `evicted` · `awaiting_admission_timeout` · `awaiting_admission_rejected` · `max_bot_time_exceeded` | **completed**, non-software |
| `failed` | `join_failure` | **software failure** |
| `failed` | `auth_session_missing` | **software failure** * |
| `failed` | `validation_error` | non-software (the caller's request was malformed) |

\* `auth_session_missing` can originate in operator configuration rather than the software; it is
counted as a software failure **deliberately and conservatively** — ambiguity counts against
Vexa, never in Vexa's favor.

### Retries

`join_failure` is classified TRANSIENT and may be retried (`meeting_api/lifecycle/retry.py`). A
dispatch that failed to join and then succeeded on retry **still counts as a software failure**,
and is additionally counted in `join_failures_recovered`. The user waited. Counting only the
final state would let an unreliable join hide behind a retry loop, which is the failure mode this
number exists to expose.

## Applicability

`applicable_scope` is a declared list of configurations, each naming at minimum the platform and
the join path (for Teams: tenant-guest, anonymous, enterprise short link, or passcode). It is
written into the attestation and pinned; **it is never inferred from the data.** A verifier
encountering an attestation whose scope it does not recognise must refuse it.

The reason it is declared: a failure is only evidence about a subscriber if the subscriber could
have met it. Fleet-wide counts answer a different question and answer it misleadingly in both
directions.

## The numbers

```
software_failures        = count(status=failed AND completion_reason IN
                                 (join_failure, auth_session_missing))
join_failures_recovered  = count(join_failure dispatches that succeeded on a later attempt)
completed                = count(status=completed)
transcribed              = count(status=completed AND transcript_segments > 0)
software_success_rate    = 1 − software_failures / meetings_dispatched
completion_rate          = completed / meetings_dispatched
coverage[c]              = meetings_dispatched within configuration c, for each c in
                           applicable_scope
```

A contract may set a floor on `transcribed`, on `coverage[c]`, and on
`software_success_rate`, and a ceiling of zero on `software_failures`.

`completion_rate` is published alongside for transparency and **must never be read as a
reliability measure**: its complement mixes user actions, host decisions, empty meetings, and
policy caps with software behavior. A contract MUST NOT set a floor on `completion_rate`; a
verifier encountering such a contract term must refuse it as a definition error.

## What an attestation with these numbers claims — and does not

It claims: during this window, in this environment, dispatches against these exact image digests
**within the declared applicable scope** exited as counted above, and produced transcript output
as counted above. It does not claim anything about configurations outside that scope, and it
does not claim the platform cannot change tomorrow.

Where `coverage[c]` is zero for a declared configuration, the attestation says so and the claim
about that configuration is **absent, not satisfied**.
