---
title: "vexa_subscriber against a throwaway standalone host"
description: "The rewritten credential tool run end to end — list, every kind of add, revoke, the refusals, and add --park on top — against a throwaway registry:3 + Caddy stack shaped like the channel host, over SSH, through its own code path. The live channel host was not touched."
---

**Date:** 2026-09-07. **Tree under test:** `b091e67`, the first commit of
[#42](https://github.com/Vexa-ai/vexa-delivery/pull/42). **Where:** a
throwaway compose stack on the build host, operated from the publisher's
laptop over SSH exactly as the live host is — `$CHANNEL_REGISTRY_SSH` pointed at
the build host, `$CHANNEL_ROOT` at the throwaway directory, `$CHANNEL_EDGE_URL`
at an SSH tunnel to the throwaway's Caddy. **Issues:**
[vexa-delivery-internal#46](https://github.com/Vexa-ai/vexa-delivery-internal/pull/46)
(private; the standalone-host rewrite this ports) and
[vexa-delivery-internal#35](https://github.com/Vexa-ai/vexa-delivery-internal/issues/35)
(private; the `EDGE_READER_BASIC` manual step).

**Why a throwaway.** Until this change the tool wrote the in-cluster path —
finding 1 of the
[edge deploy receipt](/receipts/2026-09-06-edge-claim-and-channel-page) — and
the founder's instruction was explicit: verify against a throwaway, do not
touch the live channel host. Every proof below is therefore about the tool's
behaviour against a stack of the live host's shape, not about the live host.

---

## 1 · The throwaway

| Piece | What it was |
|---|---|
| Registry | `registry:3` at `sha256:1be55279…` — the same digest the live host runs — htpasswd auth, `htpasswd` bind-mounted as a file, filesystem storage |
| Edge | `caddy:2`, `env_file: env`, the live Caddyfile's four handles: `/healthz`; the anonymous signature-read path presenting `Basic {env.EDGE_READER_BASIC}` upstream; the station-write path with `basic_auth` on `{env.SUB_PILOT_BCRYPT}` / `{env.PUBLISHER_BCRYPT}` and the wrong-station `403`; the publisher-only write gate |
| `env` | `PUBLISHER_BCRYPT`, `EDGE_READER_BASIC`, `SUB_PILOT_BCRYPT` — bcrypt values compose-escaped (`$$`), as on the live host |
| Accounts seeded | `publisher`, `edge-signature-reader`, `pilot` — three throwaway passwords, hashed with the same `htpasswd -nBi` fallback the tool uses, never printed |
| Compose | v5.3 on the build host, the same major as the live host — the `$` interpolation the RUNBOOK § 5.3 scar records behaves the same way |
| Transport | plain HTTP inside an SSH tunnel; TLS is the one thing the live host has that this did not, and nothing in the tool depends on it |

Before anything ran: `/healthz` 200, anonymous `/v2/` 401, the seeded `pilot`
credential 200, and all three hashes 60 characters long inside the Caddy
container — the escaping was right before the tool touched it.

## 2 · The proofs

Every credential the tool printed was captured to a file, used from there, and
deleted; none appears here or in any log. Status codes are what curl saw
through the tunnel.

| Step | Probe | Answer |
|---|---|---|
| `list` | scopes read from the two files | `edge-signature-reader edge-held`, `pilot pull+station`, `publisher push+pull` |
| `add pilot` (rotation of a station-write subscriber) | old credential on `/v2/` · new on `/v2/` | **401** · **200** |
| | new credential: write to its own station · to another station · anywhere else | **202** · **403** · **401** — both halves accepted it, and only where the Caddyfile allows |
| | `SUB_PILOT_BCRYPT` inside the container · on disk | **60 characters** · `$$`-escaped, file mode `0600` |
| `add rehearsal` (new, pull-only) | `/v2/` · station write | **200** · **401** — no Caddyfile line, as the stderr note says; `env` untouched |
| `add edge-signature-reader` | anonymous signature read before · after | **404** · **404** — the edge's upstream credential still accepted; a stale `EDGE_READER_BASIC` answers **401** (proven in § 3) |
| | `EDGE_READER_BASIC` inside the container | **equals** `base64(<account>:<new password>)` |
| | old credential on `/v2/` | **401** |
| `add publisher` | new credential: generic write · any station path | **202** · **202** |
| | old credential: generic write | **401** |
| | `PUBLISHER_BCRYPT` inside the container | **60 characters** |
| `revoke rehearsal` | `/v2/` afterwards | **401** |
| `revoke publisher` · `revoke edge-signature-reader` without `--force` | | refused, exit 2, nothing written; publisher still writes (**202**) |
| `list` at the end | | the three seeded accounts, unchanged scopes |

Each `add` printed exactly one credential-shaped line to stdout and reported
*live auth verified* on stderr **after** the recreate and the proof, never
before.

## 3 · The control: `docker restart` does not re-read `env_file`

The instruction that came with this task was to remember it. It was measured:

1. `EDGE_READER_BASIC` in `env` edited to a bogus value, then `docker restart`
   on the Caddy container → the value **inside** the container was the
   **original**. On the wire the anonymous signature read still answered 404.
2. `docker compose up -d --force-recreate` → the value inside the container
   was the **edited one**, and the anonymous signature read answered **401** —
   which is what a stale edge credential looks like from outside, and what
   RUNBOOK § 5.3 promises: loud, not open.
3. `env` restored, recreated → 404 again.

The tool recreates, and this is why.

## 4 · The refusals write nothing

| Refusal | Observed |
|---|---|
| `env` missing `EDGE_READER_BASIC`, then `add edge-signature-reader` | exit 2, *the channel env file has no 'EDGE_READER_BASIC' line — the host layout differs from what this tool expects*; **stdout empty; `htpasswd` and `env` byte-identical before and after** |
| `$CHANNEL_REGISTRY_SSH` unset · `$CHANNEL_ROOT` unset | each refuses naming the variable and how to set it, with no SSH made |
| `$CHANNEL_EDGE_URL` unset, then `add` | refuses **before the mint** — files byte-identical afterwards |

The last row is the one that earned a code change during this work. The
first draft read the edge URL only where it is used — after the recreate — so
a missing variable would have rotated the account and *then* refused, leaving
it with no working credential and nothing printed: the self-inflicted outage
`park_preflight` already guards against on its own inputs. All three site
coordinates are now demanded up front, and the unit test for it asserts zero
remote commands.

## 5 · `--park` on top of the host path

`add rehearsal-park --park`, with a throwaway edge key, a local spool and a
scratch ledger: two lines on stdout — the credential, then a six-digit code;
the parked credential answered **200** on `/v2/`; the park's ciphertext,
opened with the throwaway edge key, **equals the printed credential**; the
ledger row records `event: park` for the account and **does not contain the
password**. The four park functions are byte-identical to `main`; this proves
the two halves compose, not the park itself — that was proven on the live
edge on 2026-09-06.

## 6 · What this does not prove

- **Nothing here touched the live channel host.** The live `htpasswd`, `env`
  and stack are as they were; the first live `add` with this tool is the next
  rung, and the tool refuses before writing if the live `env` does not carry
  the keys it expects.
- The anonymous signature-read probe used a manifest that does not exist:
  **404 against 401** discriminates whether the edge's upstream credential was
  accepted, which is the question; it does not exercise a real signature.
- One run before this one refused at the health proof because the SSH tunnel
  from the laptop had dropped between the recreate and the probe. The tool
  behaved as designed — rotated, could not prove, printed nothing — and the
  observation is worth carrying: **the operator's own path to the edge is part
  of the proof.** A proof that fails after the recreate means the account is
  rotated with nothing printed; run `add` again once the edge answers.

## What was left behind

Nothing. The throwaway stack was removed with its volume and directory after
this was written; the captured outputs were deleted by the run itself.
