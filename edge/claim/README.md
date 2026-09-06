# The claim edge

`POST /claim` — the one endpoint that hands over a channel credential. A
subscriber's cluster presents a short code read aloud on a call; it gets the
credential once, and the code dies.

**Not deployed.** Nobody has built this image or run this service. The live edge
is founder-owned; [§ Deploy](#deploy) is the note for whoever does it.

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
| `attempts.ndjson` | the edge | every attempt: station, outcome, source, time |

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
  noisy rather than by guessing.
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

**2 · Build and push the image, digest-pinned.** On the build host, never on the
laptop. The image is two Python files and `age`; the build context is this
directory only.

```bash
docker build -t <registry>/vexa/claim-edge:<tag> edge/claim
```

**3 · Start it.** `CLAIM_EDGE_IMAGE` must be the digest, not the tag.

```bash
CLAIM_EDGE_IMAGE=<ref>@sha256:… docker compose -f edge/claim/compose.yaml up -d
docker compose -f edge/claim/compose.yaml exec claim-edge \
  python3 /app/claim_edge.py --check
```

**4 · Route `/claim` through Caddy**, so TLS and the single-host rule hold. It
goes beside the existing signature-read and registry stanzas (RUNBOOK § 5.2):

```caddyfile
handle /claim {
    reverse_proxy 127.0.0.1:8088
}
```

`X-Forwarded-For` is set by Caddy, and `CLAIM_TRUST_FORWARDED_FOR=1` is correct
**only** behind it. Reached directly, that header is whatever the caller typed,
and trusting it would hand every guesser a fresh rate-limit bucket per request.

**5 · Give the publisher the public half** as `$CHANNEL_CLAIM_EDGE_RECIPIENT`,
and set `$CHANNEL_CLAIM_EDGE` and `$CHANNEL_CLAIM_SPOOL_SSH` — see
[`config/channel.example.env`](../../config/channel.example.env).

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

## Limits, stated

- **The rate limiter is in memory**, so it resets on restart. A restart is a
  visible event on a host one person operates, not something a caller can induce
  from here — but it is a real limit and this is where it is written down.
- **The spool is a single directory on one host.** No replication: a lost spool
  loses live parks, and the recovery is to park again, which rotates. Nothing a
  subscriber already claimed is affected.
- **Nobody has built this image or run this service.** Every claim about its
  behaviour above is a claim about `claim_edge.py`, which `tests/` exercises
  against a real socket and a fixture spool — not about a running deployment.
