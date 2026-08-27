# Sealed definition — production-soak metrics, v1

This document defines every number a Vexa prod-soak attestation may carry. Its sha256 is
embedded in each attestation (`definitions.sha256`), and a verifying contract pins the same
hash — so the consumer verifies the number and its meaning together. Changing one word here
changes the hash and produces a different, incompatible definition version. v1 is FROZEN.

## The population

`meetings_dispatched` — every bot dispatch requested against the named platform, in the named
environment, during the attestation window, served by the attested image digests. No dispatch is
excluded for any reason.

## Exit taxonomy

Every dispatch ends in exactly one of eleven states, recorded by the product's own lifecycle
machine (`ExitReason`, `meeting_api/lifecycle/machine.py`), server-derived:

| Exit | Meaning | Classification |
|---|---|---|
| `completed` | the meeting was captured and ended normally | **completed** |
| `STOPPED` | the user stopped the bot | non-software |
| `LEFT_ALONE` | everyone left; the bot left too | non-software |
| `STARTUP_ALONE` | nobody was in the meeting when the bot joined | non-software |
| `EVICTED` | the host removed the bot | non-software |
| `AWAITING_ADMISSION_TIMEOUT` | nobody admitted the bot from the lobby | non-software |
| `AWAITING_ADMISSION_REJECTED` | the host denied admission | non-software |
| `MAX_BOT_TIME_EXCEEDED` | the configured time cap was reached | non-software |
| `VALIDATION_ERROR` | the caller's request was malformed | non-software |
| `JOIN_FAILURE` | the bot could not join | **software failure** |
| `AUTH_SESSION_MISSING` | no auth session available | **software failure** * |

\* `AUTH_SESSION_MISSING` can originate in operator configuration rather than the software; it is
counted as a software failure **deliberately and conservatively** — ambiguity counts against
Vexa, never in Vexa's favor.

## The numbers

```
software_failures      = count(JOIN_FAILURE) + count(AUTH_SESSION_MISSING)
software_success_rate  = 1 − software_failures / meetings_dispatched
completed              = count(completed)
completion_rate        = completed / meetings_dispatched
```

`software_success_rate` is the number a contract may set a floor on: it measures **whether the
software worked**, and only the two software-failure exits count against it.

`completion_rate` is published alongside for transparency and **must never be read as a
reliability measure**: its complement mixes user actions, host decisions, empty meetings, and
policy caps with software behavior. A contract MUST NOT set a floor on `completion_rate`; a
verifier encountering such a contract term must refuse it as a definition error.

## What an attestation with these numbers claims — and does not

It claims: during this window, in this environment, dispatches against these exact image digests
exited as counted above. It does not claim the platform cannot change tomorrow, and it does not
claim anything about environments, windows, platforms, or digests other than the named ones.
