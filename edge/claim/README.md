# The claim edge

`POST /claim` — the one endpoint that hands over a channel credential. A
subscriber's cluster presents a short code read aloud on a call; it gets the
credential once, and the code dies.

**Deployed 2026-09-06** on the live channel edge, and the six-digit path ran end
to end against it with a throwaway subscriber before any real code was parked:
[receipt](/receipts/2026-09-06-edge-claim-and-channel-page). That deploy found
four things the note as written got wrong, every one of them failing as the
uniform `403` during the call. Three are now closed in code — the publisher
hands each park to the spool's owner, the service proves its own public route
with `--probe`, and the containerised-Caddy shape ships as a compose override —
and proven against a throwaway rig shaped like the live host:
[receipt](/receipts/2026-09-07-edge-deploy-defects-rig). [§ Deploy](#deploy) is
the corrected note.

| | |
|---|---|
| Endpoint | `POST /claim` · `{"code": "123 456", "station": "pilot"}` |
| Success | `200` · `{"station", "username", "password"}` — once, then the park is gone |
| Every refusal | `403` · `{"error": "refused"}` — one body, one status, no variants |
| Health | `GET /healthz` · `{"ok": true}` |
| Code | **six digits** `0-9`, printed `123 456`, typed with the space or without |
| Window | 15 minutes · one redemption · five failed attempts burn the park |
| Rate limit | 10 attempts per minute per source, then 15 minutes off · 20 per minute per park from everyone |
| At rest | `age`-encrypted to a key whose private half exists only on this host |

## The shape

```
 publisher (add --park)                    the edge                the subscriber
 ──────────────────────                    ────────                ──────────────
 mint / rotate at the registry
 seal to the edge's age key  ── scp ──▶  <station>.park.json
 record the park in the ledger                                     ./kit/claim.sh
 print the code once  ─── read on a call ─────────────────────────▶  POST /claim
                                         verify · decrypt · delete ──▶ Secret
                                         attempts.ndjson ── copied back ──▶ ledger
```

Three files in the spool, one writer each — the invariant the whole thing rests
on:

| File | Written by | Holds |
|---|---|---|
| `<station>.park.json` | the publisher | the ciphertext and the code's salt; never edited, only deleted |
| `<station>.<park_id>.state.json` | the edge | attempts, terminal state |
| `attempts.ndjson` | the edge | every attempt: station, outcome, source, time, sequence |

A new park mints a new `park_id` and therefore a new state file, so parking again
never resets a counter this process does not own. On any terminal outcome —
redeemed, burned, expired — the edge **deletes the park file**: the ciphertext
stops existing, and the identifying facts it carried were copied into the state
file first, so the record survives.

## The cryptography, and why it is this small

**The parked value is encrypted with a key only the edge holds.** `age`, to a
recipients file whose private half exists on this host and nowhere else. The
publisher encrypts and cannot decrypt what it just wrote, which is what makes
the park inert everywhere it travels: on the publisher's disk, in `scp`, in the
spool, in a backup of the spool.

**The code is a lookup key plus counting and rate limiting over TLS. It is not a
key.** It selects a park and is compared against `code_sha256`; it derives
nothing and decrypts nothing.

**Six digits is one of 1,000,000, and the counting is what makes that enough.**
The whole security argument is one paragraph of arithmetic:

- **5 tries per park.** Five failed attempts burn it, from all sources
  together — so an online guesser's odds are **5 in 1,000,000, or 1 in 200,000**,
  once, after which the park is dead and the credential has to be re-parked (and
  re-parking rotates, and shows up in the ledger as a second park nobody asked
  for).
- **10 attempts per minute per source, then 15 minutes off.** The cooling period
  is a code's entire life, so **one address gets one window against one code**.
  Ignoring the burn entirely, that rate would take a single source **over two and
  a half years** to walk 1,000,000 once; the burn stops it in the first minute.
- **20 requests per minute per park, from everyone.** The per-source limit is per
  source, so this is what makes extra addresses worth nothing: a caller with a
  hundred of them does not get a hundred budgets against one station.
- **~139,000 parks for a coin flip.** At 5 in 1,000,000 per park, an attacker
  needs `ln 2 / (5×10⁻⁶)` ≈ 139,000 separate parks for an even chance at one
  credential. Each park is a phone call we made, and each is live for fifteen
  minutes.

Digits, not letters, because the code is **said out loud** — down a phone line,
often between two people who do not share a first language. `B`/`V`/`P` do not
survive that; `1`/`2`/`3` do, and there is no spelling alphabet to agree on
first. That is why the alphabet is not a confusable-safe alphanumeric one: the
question does not arise.

`code_sha256` is a **verifier, not a password hash**, and at six digits it is
**salted**, which is not decoration. A bare SHA-256 of six digits is a
million-candidate search — milliseconds — and this value is copied into the
stations ledger, a git repository read by more people, for longer, than the
spool ever is. Unsalted, that row *would be* the code for as long as the park is
live. The salt (`code_salt`, 128 bits, per park) lives only in the park file:
0600, on the edge host, deleted the moment the park goes terminal. What survives
in the ledger is a commitment that binds an attempt to the park `add --park`
wrote, and nothing an offline reader can invert.

What the design defends, then, is the **online** guess, and it defends it by
counting. The rate limits exist so that the counting cannot be walked around.

**Nothing is composed here.** Both ends shell out to `age` — the same binary the
operator already uses for the encrypt-to-key handoff. There is no hand-rolled
envelope, no primitive assembled from a library, and no place where a subtle
choice about nonces or KDFs could be got wrong.

### One refusal, always the same

Wrong code, expired, already redeemed, burned, never parked, malformed,
rate-limited: identical status, identical body. Which one it was is itself the
oracle — a distinguishable *expired* tells a guesser the station exists and that
a code was recently live, and a distinguishable *wrong code* turns the burn
counter into a progress bar. The distinction is kept for **us**, in
`attempts.ndjson` and the ledger, where it is the whole diagnostic value.

Three ordering rules are load-bearing:

- **Expiry is checked before the code.** A caller arriving late with the *right*
  code retires the park as `expired` rather than spending an attempt on a code
  that was correct.
- **Both rate limits are checked before the state machine.** A request the
  limiter refuses never reaches the park, so it must not cost the subscriber one
  of their five attempts — otherwise anyone could burn a station's code by being
  noisy rather than by guessing. The **station** is read out of the body before
  the limiter rules, and only so the refusal lands in the right station's
  record: `rate-limited` is the outcome that means *one address hammered this
  station*, and it used to be the one outcome that station could not see. The
  park itself is not read on that path — that is a disk access keyed on a name
  the caller chose.
- **Decryption happens before the park is retired.** A decryption failure is our
  misconfiguration — the wrong identity file, a park sealed to a rotated key —
  and burning the subscriber's only code over our own mistake would make them
  wait for a new one for no reason. The service answers `503`, not `403`.

### Why not a PAKE, and what one would add

A PAKE (SPAKE2, the magic-wormhole shape) turns the code into a shared secret
from which both ends derive a session key, so the rendezvous holds only
ciphertext it cannot open.

**What it would add, honestly:** each guess would require a full protocol round
against a live peer with no offline verifier anywhere, so the five-attempt burn
would stop being the only thing standing between a leaked spool and a code —
which at six digits is a millisecond search, because the salt leaks with the
spool that holds it. The rendezvous could also be run by someone we do not
trust, and a park already at rest would not be openable by a later compromise of
this host.

**Why the first version does not need it:** the edge is already inside the trust
boundary. It is our host, on the same machine as the registry's `htpasswd` and
the publisher's bcrypt line, so a compromise of it already yields the channel —
a PAKE would remove the parked credential from a blast radius that still
contains everything else. And the cost is not the maths, it is the shape: **a
PAKE is a rendezvous and a claim code is not.** Both ends must be online at the
same moment. The claim code exists precisely so the credential can be parked on
a call and claimed later, from inside a maintenance window, by a cluster whose
operator is not the person who heard the code.

It becomes the right trade the day the rendezvous stops being ours — a hosted
relay, or an edge in a jurisdiction we would rather not have to trust. Until
then it buys a property we already have, at the cost of one we need.

## Deploy

Not done here. Whoever does it, in order:

**1 · Mint the edge's key pair, on the edge host.** The private half must never
leave it — that is the property the whole scheme rests on.

```bash
umask 077
age-keygen -o $CHANNEL_ROOT/claim-edge.key
grep 'public key:' $CHANNEL_ROOT/claim-edge.key | sed 's/# public key: //' \
  > claim-edge.recipients        # this half is public; it goes to the publisher
mkdir -m 700 $CHANNEL_ROOT/claims
chown 65532:65532 $CHANNEL_ROOT/claims $CHANNEL_ROOT/claim-edge.key
```

The `chown` of the spool is load-bearing twice over: the service runs as
`65532` and must write there, and **the publisher reads this directory's owner
before every mint and hands each park it delivers to that owner** (step 5). A
spool left owned by root is refused by the publisher with this line as the fix,
before anything is rotated.

**2 · Build the image, digest-pinned.** Never on a laptop. The image is two
Python files and `age`; the build context is this directory only.

```bash
docker build -t <registry>/vexa/claim-edge:<tag> edge/claim
```

> **⚠ 2026-09-06, two things the first live build learned.**
>
> **Docker Hub will `429` the anonymous pull of the pinned base**, and BuildKit
> resolves a pinned `FROM` against the registry even when the bytes are already
> in the local store — so transporting the base does not help. Build through a
> pull-through cache with a **named-context override**, which leaves this
> Dockerfile untouched: `--build-context "<the FROM as written
> here>=docker-image://<cache>/library/debian@sha256:<the same digest>"`. Check
> the base layer of the result against the base's own.
>
> **Do not push these to the channel registry.** The edge's own images must not
> live in the registry the edge serves — RUNBOOK § 5.1's circular dependency, one
> level down — and it would list our infrastructure in a `_catalog` every
> subscriber can read. Move the image by `docker save | docker load` and pin
> `CLAIM_EDGE_IMAGE` to the id **on the host that runs it**: an image id does not
> survive `save`/`load`, so the build host's id is not the one to write down.

**3 · Start it, in the shape Caddy has.** `CLAIM_EDGE_IMAGE` must be the
digest, not the tag. **Which shape is decided by where Caddy runs, and the two
look identical until a claim fails:**

```bash
# Caddy is a CONTAINER in the registry stack's compose project — the live edge.
# The override joins that project's network under the alias `claim-edge`.
CLAIM_EDGE_IMAGE=<ref>@sha256:… docker compose \
  -f edge/claim/compose.yaml -f edge/claim/compose.caddy-container.yaml up -d

# Caddy runs ON THE HOST: the base file alone; Caddy reaches 127.0.0.1:8088.
CLAIM_EDGE_IMAGE=<ref>@sha256:… docker compose -f edge/claim/compose.yaml up -d

# Either way:
docker compose -f edge/claim/compose.yaml exec claim-edge \
  python3 /app/claim_edge.py --check
```

[`compose.caddy-container.yaml`](compose.caddy-container.yaml) attaches the
service to the stack's network and changes nothing else; the network name
defaults to `channel_default` and is set with `CHANNEL_STACK_NETWORK` when the
live one differs — a wrong name fails loudly at `up`. It exists because on
2026-09-06 the note said `reverse_proxy 127.0.0.1:8088` and Caddy was a
container: that loopback is the **Caddy container's own**, the publish on the
host's is unreachable from it, the config validates, Caddy starts, and only a
claim fails. `--check` refuses an unwritable spool and names any park this uid
cannot read.

**4 · Route `/claim` through Caddy, ABOVE the write gate.** The Caddyfile has
`@write method PUT POST PATCH DELETE`, gated on the publisher credential, and it
matches **POST on every path**. `handle` blocks are evaluated in order and the
first match wins, so a `/claim` stanza placed *after* that gate is never
reached: every claim is answered `401` by the publisher gate, and `caddy
validate` is happy. The stanza goes **between the station-write block and the
write gate**, like this:

```caddyfile
handle @stationwrite {
    …                                  # unchanged
}

# The claim edge. ABOVE @write, which would otherwise take every POST.
handle /claim {
    reverse_proxy claim-edge:8088      # Caddy in a container: the compose alias
    # reverse_proxy 127.0.0.1:8088     # Caddy on the host: the loopback publish
}

@write method PUT POST PATCH DELETE
handle @write {
    basic_auth {
        publisher {env.PUBLISHER_BCRYPT}
    }
    …
}
```

**Then prove it from inside the service**, which is the only vantage point
that can tell the three wrong shapes apart:

```bash
docker compose -f edge/claim/compose.yaml exec claim-edge \
  python3 /app/claim_edge.py --probe https://<channel host>/claim
```

The probe posts one claim with a station and **no code** to the public URL —
`malformed` to this service: `403`, nothing read from disk, no attempt counted
against anything — and then looks for its own row in the attempts log, under a
station name no real station has. What it says:

| Answer | Verdict |
|---|---|
| `403` with this service's body, **and** the row is in this spool | **OK** — the route reaches this service, and the row's `source` is what Caddy forwards |
| `401` | the stanza is below the write gate |
| `502` / `503` / `504` | the stanza points at a loopback that is not this host's — Caddy is a container |
| `404` | no route to `/claim` at that URL |
| `403` with this service's body, but no row here | a claim service answered, and it was not this one |

`compose.yaml` passes `$CHANNEL_CLAIM_EDGE` in as `CLAIM_PUBLIC_URL`, so
`--probe` with no argument uses the same address the publisher parks against.

`X-Forwarded-For` is set by Caddy, and `CLAIM_TRUST_FORWARDED_FOR=1` is correct
**only** behind it. Reached directly, that header is whatever the caller typed,
and trusting it would hand every guesser a fresh rate-limit bucket per request.

**5 · Give the publisher the public half** as `$CHANNEL_CLAIM_EDGE_RECIPIENT`,
and set `$CHANNEL_CLAIM_EDGE` and `$CHANNEL_CLAIM_SPOOL_SSH` — see
[`config/channel.example.env`](../../config/channel.example.env).

**Each park is handed to the spool's owner by the publisher, before the code is
printed.** `scp` writes as the SSH user — root, on the standalone host — so a
park used to arrive `root:root 0600` inside a spool owned by `65532`, and the
service, correctly not root, could not open it. The 2026-09-06 deploy fixed both
parks by hand. Now `add --park` reads the spool directory's `uid:gid` over SSH
**before the mint** — refusing a spool that is missing, unreachable, or still
owned by root, with nothing rotated — and follows the copy with `chown <that
owner>` and `chmod 600` over the same login. The receipt line reads `park
<target> (owner 65532:65532, the spool's)`. Should a park ever land wrong
anyway, the service answers that claim `503` with an `error:` row naming the
file and the fix, spends no attempt, and `--check` names the file; it is never
the uniform `403`.

**6 · Copy the attempts log back** after a delivery, so the return leg closes:

```bash
scp $CHANNEL_REGISTRY_SSH:$CHANNEL_ROOT/claims/attempts.ndjson .
python3 publisher/vexa_stations.py record-credential \
  --channel <channel> --events attempts.ndjson
```

## Environment

| Variable | Default | |
|---|---|---|
| `CLAIM_SPOOL` | — | required; the park directory, must be writable |
| `CLAIM_IDENTITY` | — | required; the age identity, refused unless mode `600` |
| `CLAIM_LISTEN` | `127.0.0.1:8088` | TLS is Caddy's, upstream of this process |
| `CLAIM_RATE_LIMIT` | `10` | attempts per source per window |
| `CLAIM_RATE_WINDOW` | `60` | seconds |
| `CLAIM_RATE_COOLDOWN` | `900` | seconds a source is refused after tripping the limit — one code's whole life |
| `CLAIM_PARK_RATE_LIMIT` | `20` | requests per park per window, across every source |
| `CLAIM_TRUST_FORWARDED_FOR` | off | `1` **only** behind a proxy that sets it |
| `CLAIM_PUBLIC_URL` | — | the public claim URL, for `--probe` with no argument; `compose.yaml` takes it from `$CHANNEL_CLAIM_EDGE` |

## Limits, stated

- **The rate limiter is in memory**, so it resets on restart. A restart is a
  visible event on a host one person operates, not something a caller can induce
  from here — but it is a real limit and this is where it is written down.
- **The spool is a single directory on one host.** No replication: a lost spool
  loses live parks, and the recovery is to park again, which rotates. Nothing a
  subscriber already claimed is affected.
- **No real credential has been parked yet.** The service is deployed and the
  path is proven, but every claim it has served was for a throwaway station
  minted and revoked inside a rehearsal. The first real code is a phone call,
  not a deploy.

## What the rehearsal proved, and what it did not

On **2026-09-07** the whole path was run end to end against a throwaway rig
before any subscriber could hear a code: parked with `add --park`, claimed by
`kit/claim.sh` into a cluster namespace, the refusals exercised, the attempts log
reduced into a scratch ledger. Made-up credential, throwaway key, nothing real
minted. Receipt: [`#31`](https://github.com/Vexa-ai/vexa-delivery/pull/31). It
found three defects, all fixed on this branch — a non-executable `kit/claim.sh`,
a rate-limited attempt that reached no station's record, and a burst inside one
second that reduced to a single ledger row.

**Two things it did not prove. Both were closed on the live edge on 2026-09-06**
([receipt](/receipts/2026-09-06-edge-claim-and-channel-page)), and only because
that run was behind real TLS and real Caddy:

- **Expiry had never fired in a running service.** It has now: a park given a
  60-second life and left alone answered the **correct** code with `expired` and
  retired itself, the TTL branch taken against a wall clock rather than an
  injected one.
- **Source attribution behind a proxy was unproven.** It is now: with
  `CLAIM_TRUST_FORWARDED_FOR=1` behind Caddy, every row in `attempts.ndjson`
  carried the caller's real public address rather than the proxy's, which is
  what the per-source limit is worth exactly as much as.

**And what the live deploy found, the rig of 2026-09-07 reproduced and then
proved fixed**
([receipt](/receipts/2026-09-07-edge-deploy-defects-rig)): a containerised
Caddy with the real write gate, the service behind it, and `scp` as root into a
`65532`-owned spool. Each of the three defects was observed on the wire in its
original shape first, then closed by the change that added this paragraph.
