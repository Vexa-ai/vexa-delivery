---
title: "The claim edge and the channel page, deployed on the live channel host"
description: "Both edge services built, wired into the standalone channel host's stack and applied with the RUNBOOK's own procedure. The registry's two invariants held throughout; the six-digit claim path ran end to end against the live edge with a throwaway subscriber; four defects in the deploy notes and one stale rung."
---

**Date:** 2026-09-06. **Tree under deploy:** `36cc1cc` (`edge/claim` at
`65172af`, `edge/page` at `9b3201a`). **Where:** the standalone channel host —
`$CHANNEL_REGISTRY_SSH`, `$CHANNEL_ROOT` (RUNBOOK § 5.1). **Issues:**
`vexa-delivery-internal#66` (claim code, code merged as
[#30](https://github.com/Vexa-ai/vexa-delivery/pull/30)) and `#67` (channel
page, code merged as [#32](https://github.com/Vexa-ai/vexa-delivery/pull/32)).

**Additive only.** Nothing that existed was replaced, rewritten or removed. The
registry and Caddy images, `compose.yaml`, `registry-config.yml` and `env` are
byte-identical to their state before this run; `htpasswd` is byte-identical
again after the rehearsal account was revoked. The one edit to a pre-existing
file is **42 lines added to the Caddyfile** — two `handle` blocks and their
reasoning, above the write gate.

**The pilot subscriber's own account was never touched, and no real code was
parked.** Every claim below was made against throwaway stations minted for this
run and revoked at the end of it.

---

## 1 · Baseline, before anything changed

Taken first, so the rollback has something to be byte-for-byte against.

| Probe | Answer |
|---|---|
| `curl -sI https://<channel host>/v2/` | **401**, `WWW-Authenticate: Basic realm="Vexa channel registry"` |
| `GET /v2/<channel>/signatures/manifests/sha256-<hex>.sig`, **anonymous**, with `Accept` | **200**, `application/vnd.oci.image.manifest.v1+json` |
| the same, **anonymous `HEAD`** | **200** |
| `GET /v2/<channel>/signatures/blobs/sha256:<hex>`, **anonymous** | **200** |
| the same manifest, anonymous, **no `Accept`** | **404** — content negotiation, exactly as RUNBOOK § 5.2 records |
| `GET /vexa/channel/<channel>` | **404**, `text/plain`, `page not found` |
| `GET /` · `GET /healthz` | 200 · 200 |

The signature path was not invented: the `.sig` tag was read out of the
channel's own `signatures` repository with the subscriber credential, and the
blob digests out of the manifest that came back.

**Snapshot.** `$CHANNEL_ROOT` copied whole to
`/opt/channel-snapshots/<ts>/` with a `sha256sum` manifest written outside it —
all eight files: `Caddyfile`, `compose.yaml`, `env`, `htpasswd`,
`registry-config.yml` and the three `.bak-` files from the August rotation.
Recorded alongside it: two containers (`channel-caddy-1`, `channel-registry-1`),
one compose project (`channel`), eight env **key names** and five htpasswd
account names — no value of either was read.

## 2 · What now runs, and where

| Container | Image | Listens | Holds |
|---|---|---|---|
| `channel-registry-1` | `registry@sha256:1be55279…` | `5000` (compose network only) | unchanged |
| `channel-caddy-1` | `caddy@sha256:df7f1c2f…` | `80`, `443` | unchanged image; +42 Caddyfile lines |
| `vexa-claim-edge-claim-edge-1` | `vexa/claim-edge:36cc1cc` · `sha256:870d1621bc9a2a12237c44a13613f73d5f4c3cfc5c415afda3fcab7718251e6a` | `127.0.0.1:8088` + alias `claim-edge` on the stack network | the age identity for parked credentials, and the spool |
| `vexa-page-edge-page-edge-1` | `vexa/page-edge:36cc1cc` · `sha256:95d79f827ce52ea386e4926a9dc932101e2ac43b2d584e928ffba33e6fa87842` | `127.0.0.1:8089` + alias `page-edge` on the stack network | **nothing** — no key, no htpasswd, no credential |

Three compose projects, as `edge/*/compose.yaml` intends: `channel` unchanged,
`vexa-claim-edge` and `vexa-page-edge` beside it, so adding an account never
bounces the registry.

**Where the images were built — corrected the same night.** The first build was
made **on the channel host**, after the build host answered Docker Hub's
anonymous `429` on the pinned base and BuildKit was observed resolving a pinned
`FROM` against the registry even with the bytes already local. That reasoning
was **wrong, and its own source said so**: the
[claim-code rehearsal](/receipts/2026-09-07-claim-code-rehearsal) had hit the
same `429` a day earlier and recorded the way past it — *"built from the
identical digest fetched through the rig's own pull-through cache, using
BuildKit's named-context override"*. The cache was there the whole time; it was
read and not acted on.

So both images were **rebuilt on the build host** through its own pull-through
cache, with `--build-context <the pinned FROM>=docker-image://<the same digest
through the cache>` so `edge/*/Dockerfile` was **not edited**. The base layer of
the result is `sha256:411a8667…`, byte-identical to the pinned base's own. They
were transferred to the channel host by `docker save | docker load`, the two
services swapped onto them, and **every proof in § 4 and the whole claim
exchange in § 5 re-run against the new images** before this was written. The
build context and the builder cache are gone from the channel host.

*A note for whoever pins one of these next:* **an image ID does not survive
`save`/`load`.** The same image arrived on the channel host under a different
`sha256:` than the build host gave it — the layers are identical, the config
digest is not. `CLAIM_EDGE_IMAGE` and `PAGE_EDGE_IMAGE` are therefore pinned to
the **channel host's** id for each, which is immutable there and is what the
compose files' "the digest, not the tag" is protecting, but it is not a
cross-host name. A registry manifest digest would be; the next paragraph is why
there is not one.

**They were deliberately not pushed to the channel registry.** That registry is
the subscribers' distribution copy; putting the edge's own images in it would
make restoring the edge depend on the registry the edge serves, which is § 5.1's
circular dependency one level down. It would also put our infrastructure image
names in a `_catalog` every subscriber credential can read. Both images are
reproducible from `edge/*/Dockerfile` and their pinned base, so nothing is lost
by their living only on the host that runs them and the host that built them.

**The age key pair was minted on the host**, by `age-keygen` inside the
claim-edge image itself so no package was installed on the host to do it. The
private half is `0600`, owned by the service uid, and has never left. The public
half is `age1sngdltu9h4dntuwkvmt4y2pkgglpxar42l9v8wjgq082087q2ewq6479ye` — it is
public by construction: the publisher encrypts to it and cannot decrypt what it
wrote.

## 3 · The routes

Both stanzas sit **above** the station-write and publisher-write gates, which is
load-bearing and is [finding 3](#findings). Applied with the RUNBOOK's own
procedure — `docker compose up -d --force-recreate` from `$CHANNEL_ROOT` — after
`caddy validate` returned `Valid configuration` against the running container's
own environment.

```caddyfile
handle /claim {
    reverse_proxy claim-edge:8088
}

@channel_page path_regexp chanpage ^/vexa/channel/[a-z0-9][a-z0-9-]{1,62}/?$
handle @channel_page {
    reverse_proxy page-edge:8089
}
```

## 4 · The five proofs, after the change

| | Probe | Answer |
|---|---|---|
| **1** | `/v2/`, anonymous | **401** — unchanged |
| **2** | signature manifest `GET` and `HEAD`, and a signature blob `GET`, all **anonymous** | **200**, **200**, **200** — unchanged |
| **3** | `GET /vexa/channel/<channel>`, **no credential** | **200**, one line: *This is a Vexa Delivery channel. Sign in with your subscriber account, or read delivery.vexa.ai* — and `?signin=1` returns `401 WWW-Authenticate: Basic realm="Vexa Delivery channel"`, which is what makes a browser prompt |
| **4** | the same path with the **pilot subscriber's credential** | **200**, the page |
| **5** | the claim path end to end, with a throwaway subscriber | below |

**Proof 4, rendered.** Every value on the page was cross-checked against the
channel's own `channel.yaml` in the stations ledger and matched exactly:

| Row | Value |
|---|---|
| Release | `v0.12.23`, linked to its GitHub release |
| Entry sequence | `4` |
| Published at | `2026-08-24T17:47:22Z` |
| Entry digest | `sha256:ce96f4c1…` — the ledger's `entry_digest`, and the sha256 of the manifest bytes this service read |
| Channel key fingerprint | `sha256:f6aac70e…` |
| Kit version | `v0.1.5` |

Plus the three documentation links, and the perimeter sentence, which **names no
tier**: *"what your side may send back is set by the tier in your own
`contract.yaml`, which lives in your cluster and not on this channel, so this
page cannot state it for you."*

The pilot subscriber's credential answered **200** on `/v2/` and on the
channel's `current` entry before and after every step of this deploy.

## 5 · Proof 5 — the claim path, live

`vexa_subscriber.py add pilot-rehearsal --park` minted, sealed and parked;
`kit/claim.sh` on the build host redeemed the code into a cluster namespace over
the public endpoint. **The value was never on a screen** — not in the mint's
transcript beyond the one deliberate vault line, not in the claim's output, not
in any log.

```
claimed: station pilot-rehearsal
  secret:    vexa-station-credential (keys username, password)
  namespace: vexa-dev
  the code is now spent; the credential is in the cluster and nowhere else
```

Read back from the Secret into a shell variable and never printed:

| Probe with the claimed credential | Answer |
|---|---|
| `GET /v2/` | **200** |
| `GET /v2/<a channel>/manifests/current` | **200** |
| `POST /v2/…/blobs/uploads/` (a write) | **401** — pull-only, as minted |
| `GET /vexa/channel/<a channel>` | **200** — the claim → page chain closes |
| the same after `revoke` | **401** |

The park file was deleted at redemption; the state file left behind reads
`state=redeemed attempts=0/5 terminal_reason=claimed`.

### The refusals, each observed once

A second park was made for these under a **different throwaway account that was
never added to the registry at all**, so the code being guessed unlocked a
credential that authenticates nowhere. A third was parked with `--ttl 60`.

| Probe | On the wire | In the edge's own log |
|---|---|---|
| four wrong codes | four identical `403 {"error": "refused"}` | `wrong-code` ×4 |
| the fifth wrong code | the same `403` | **`burned`**, `attempts 5/5`, park file deleted |
| the **right** code, after that burn | the same `403` | `no-park` |
| the **right** code, 59 s after a 60-second park | the same `403` | **`expired`**, park file deleted |
| a code for a station that was never parked | the same `403` | `no-park` |

Nine attempts, one status, one body. The whole distinction lives in
`attempts.ndjson`, which carries station, outcome, source, time, sequence and
the **park's** `code_sha256` — never the offered code, never a value:

```
2026-09-06T22:16:18Z  pilot-rehearsal          claimed
2026-09-06T22:17:28Z  pilot-rehearsal-burn     wrong-code    (×4, to :29)
2026-09-06T22:17:30Z  pilot-rehearsal-burn     burned
2026-09-06T22:17:31Z  pilot-rehearsal-burn     no-park
2026-09-06T22:20:07Z  pilot-rehearsal-expiry   expired
```

### Both of the rehearsal's open questions are now closed

[The claim-code rehearsal](/receipts/2026-09-07-claim-code-rehearsal) ended with
two things it explicitly had **not** proven. Both were proven here, and only
because this ran on the real edge:

- **Source attribution behind a proxy.** That run had no TLS and no Caddy, so
  `CLAIM_TRUST_FORWARDED_FOR` stayed off and the "source" was a docker peer
  address. Here it is on, behind Caddy, and every one of the nine rows above
  carries the **caller's real public v4 address** — the build host's, not the
  `172.18.0.x` of the Caddy container one hop away. The per-source limit and
  every `source` in the attempts log are worth what the header is worth, and the
  header has now been watched arriving.
- **Expiry has never fired in a running service.** It has now: a park with a
  60-second life, left alone, answered the **correct** code with `expired` and
  retired itself — the TTL branch taken against a wall clock rather than an
  injected one. Expiry is checked before the code, so the correct code cost no
  attempt.

## 6 · Rollback

Stated, and dry-tested before it was needed:

1. `docker compose -f $CHANNEL_ROOT/{claim,page}-edge/compose.yaml -f …/override.yaml down` — the two new projects are separate, so this touches neither registry nor Caddy.
2. `cp -a /opt/channel-snapshots/<ts>/. $CHANNEL_ROOT/` — restores the Caddyfile, and with it the state before the two routes existed.
3. `cd $CHANNEL_ROOT && docker compose up -d --force-recreate`.

Tested dry: every one of the eight snapshot files still verifies against the
`sha256sum` manifest taken **before** the first change, and the snapshot
Caddyfile returns `Valid configuration` from a throwaway Caddy container of the
same pinned image with the live environment. Step 2 is a no-op for
`compose.yaml`, `env` and `registry-config.yml` — they were never edited — and
`htpasswd` is already byte-identical to the snapshot after the revoke.

## Findings

**1 · `publisher/vexa_subscriber.py` does not operate the standalone host, and
two RUNBOOKs say it does.** § 5.3 and § 5.4 describe the tool rewriting
`$CHANNEL_ROOT/htpasswd` and `$CHANNEL_ROOT/env` over SSH and recreating the
stack — *"the manual step … no longer exists on the live path."* The shipped
tool still writes the **in-cluster** path: namespace `channel-registry`, Secret
`registry-htpasswd`, `kubectl rollout restart` on two Deployments that have been
**scaled to 0 since the channel moved off the cluster on 2026-08-25**. The
standalone-host version exists only on an unmerged branch
(`vexa-delivery-internal#46`, open since that same day). An operator following
the RUNBOOK during an incident would edit the rollback path and be handed a
credential that does not authenticate — and it would look like it worked. The
mint and the whole park half were used unmodified here; the two htpasswd lines
were applied to the host by hand and are the only part of this run that was not
the tool's own code.

**2 · Both deploy notes route Caddy to `127.0.0.1`, and Caddy is a container.**
`edge/claim/README.md § Deploy` step 4 and `edge/page/README.md § Deploy` step 3
give `reverse_proxy 127.0.0.1:8088` / `:8089`. On this host Caddy runs in the
`channel` compose project, so that loopback is the Caddy container's own and the
services' loopback publish is unreachable from it. Both services are therefore
also attached to the stack's network under aliases, by a host-local override
file that says why. This is a **silent** failure in the making: the config
validates, Caddy starts, and only a claim fails.

**3 · `/claim` must sit above the write gate, or every claim is a 401.** The
Caddyfile's `@write method PUT POST PATCH DELETE` gate matches **POST on every
path**, and `handle` blocks are mutually exclusive and evaluated in order. A
`/claim` stanza placed after it is shadowed, and the publisher gate answers
`401` — which on the wire is indistinguishable from the endpoint being broken,
during a phone call, while somebody reads six digits aloud. The deploy note says
only "beside the existing stanzas".

**4 · A park delivered by `scp` lands unreadable by the service.**
`deliver_park` scps as the SSH user (root); the deploy note chowns the spool
**directory** to `65532` but nothing chowns the file, so the park arrives
`root:root 0600` inside a `65532`-owned directory and the service — `USER
65532`, correctly not root — cannot open it. Observed exactly so, and fixed by
hand for both parks. It fails at the moment a code is being read aloud, and the
edge answers the uniform `403`, which says nothing.

**5 · The page's one-minute cache, confirmed rather than found.**
`edge/page/README.md § Limits, stated` says a credential revoked ten seconds ago
still renders the page for the rest of the minute. Immediately after `revoke`
the claimed credential got `401` on `/v2/` and `200` on the page. The pull path
is unaffected and revocation there is immediate; the limit is real, documented,
and now observed.

## What was left behind, deliberately

- `$CHANNEL_ROOT/claims/attempts.ndjson` and four `*.state.json` files — the
  edge's own record of this run. No value, no code, no salt, no ciphertext. The
  return leg (`vexa_stations.py record-credential`) has **not** been run against
  the real ledger: these are rehearsal stations, and their park rows went to a
  scratch ledger, not to `vexa-stations`.
- `/opt/channel-snapshots/<ts>/` — the rollback image of `$CHANNEL_ROOT`.

## What is undone

- **Nothing has been parked for a real subscriber.** The claim path is live and
  proven; the first real code is a call, not a deploy.
- **The publisher tooling gap (finding 1) is not fixed here**, only found and
  worked around. Until `vexa-delivery-internal#46` merges, `add` and `revoke`
  against the live host are hand operations and the RUNBOOK overstates them.
- **The four findings above are not fixed in this change** — this is a receipt.
- **The rate limiter is still in memory** and resets on restart; it was reset
  several times by the recreates in this run.
- **A subscriber credential still reads any channel's page**, as
  `edge/page/README.md § Limits, stated` says. Tightening it is the edge's
  `basic_auth` line, and the page inherits it for free.
