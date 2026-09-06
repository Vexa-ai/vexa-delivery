---
title: "Claim-code rehearsal — six digits, said aloud, into a cluster Secret"
description: "The credential-by-claim-code flow run end to end on our own build host before any subscriber hears a code: parked, claimed into a cluster Secret, the three refusals proven, the attempts log reduced into the ledger. Three findings."
---

**Date:** 2026-09-06/07. **Branch under test:**
[`feat/credential-claim-code`](https://github.com/Vexa-ai/vexa-delivery/pull/30)
at `c52ac273`. **Where:** the `bbb` build host — the throwaway edge, the
publisher and the cluster all on it, nothing on a laptop and nothing on any
live host. **Why now:** the founder's rule for this feature — *"we need to test
the 6 digits flow before"* any subscriber is read a code.

**Nothing real was touched.** No account was minted on the channel registry; no
vaulted secret was decrypted; the age key pair was minted for this run and
shredded at the end; the ledger was a scratch checkout of the
`vexa-stations` *shape*, never the ledger; and the live edge is still not
deployed. The parked credential was a made-up `rehearsal:…` account. **The two
codes appear in full below** — they are spent, and they unlocked a password
this rehearsal invented and then destroyed.

---

## The rig

| | |
|---|---|
| Edge | the branch's `edge/claim` image, built from `edge/claim` on `bbb`, run as a throwaway container: `--read-only`, `--cap-drop ALL`, `no-new-privileges`, published on **`127.0.0.1:18089`** only |
| Reached from the cluster | the same container was attached to the **cluster's own docker network**, so it also answers on `172.24.0.3:8088` from inside the rig. `GET /healthz` returned `{"ok": true}` from the host shell **and** from the cluster node. |
| Cluster | the `kind` rig standing since the OpenShift-parity run — k8s v1.30.0, PSA `restricted`, Kyverno emulating `restricted-v2`. The claim ran against its **tenant** kubeconfig, which can see one namespace and nothing else. |
| Ledger | `~/claim-rehearsal/ledger`, `git init`, channel `rehearsal`, station `bbb-rehearsal` |

Two deviations from the deployed shape, both stated because they change what
the run proves:

1. **No TLS and no Caddy.** The edge was reached over plain HTTP on loopback
   and on the cluster network, so `CLAIM_TRUST_FORWARDED_FOR` stayed **off** —
   correctly, since nothing trustworthy sets that header here. The consequence
   is that the "source" the limiter counts was the docker peer address, not a
   subscriber's real one. Source *separation* is proven; source *attribution
   behind a proxy* is not.
2. **The container ran as the host user, not the image's `65532`.** The
   publisher and the edge shared one spool directory on one machine; in
   production the publisher `scp`s into a spool the edge owns. Nothing in the
   state machine depends on the uid.

And one obstacle worth recording: **`bbb` could not pull the pinned base image
from Docker Hub** — anonymous rate limit, `429`. The image was built from the
**identical digest** fetched through the rig's own pull-through cache, using
BuildKit's named-context override; `edge/claim/Dockerfile` was **not** edited.

---

## 1 · Park — the publisher's own `add --park`

Run as `publisher/vexa_subscriber.py add rehearsal --park --station bbb-rehearsal
--channel rehearsal --edge http://127.0.0.1:18089/claim …`, with a **stub
`kubectl` first on `PATH`** that answers the three calls the mint makes with a
fixture and refuses every other call, so the real registry was never contacted.
The publisher's own receipt, verbatim:

```
# parked for station 'bbb-rehearsal', claimable at http://127.0.0.1:18089/claim
#   park      …/spool/bbb-rehearsal.park.json
#   ledger    …/stations/bbb-rehearsal/credential-events.yaml (f2e4477…)
#   expires   2026-09-06T20:04:24Z (15 minutes), 5 attempts, one redemption
```

Line 1 of stdout was the credential (the vault line, printed once by design);
line 2 was **`165 312`** — six digits, grouped, for reading aloud. The park file
carried the ciphertext and a per-park `code_salt`; the ledger row carried the
salted digest, the expiry, the attempt cap and who parked it, and **nothing
else**.

## 2 · Claim — into the tenant namespace, value never on a screen

```
$ kit/claim.sh --code '165 312' --edge http://127.0.0.1:18089/claim \
    --station bbb-rehearsal --namespace vexa-dev --kubeconfig <tenant kubeconfig>
claimed: station bbb-rehearsal
  secret:    vexa-station-credential (keys username, password)
  namespace: vexa-dev
  the code is now spent; the credential is in the cluster and nowhere else
```

The Secret was written `Opaque`, keys `username`/`password`, labelled
`app.kubernetes.io/name=vexa-station`. Read back:

```
$ kubectl -n vexa-dev get secret vexa-station-credential \
    -o jsonpath='{.data.username}' | base64 -d
rehearsal            # the account that was parked
```

The spool then held **no ciphertext** — the park file was deleted at
redemption, and the state file left behind reads
`state=redeemed attempts=0/5 terminal_reason='claimed'`.

## 3 · The three refusals

| Probe | On the wire | In the edge's own log |
|---|---|---|
| The same code, a second time (`kit/claim.sh --rotate`, exit 1) | `403 {"error": "refused"}` | `no-park` |
| Five wrong codes against a fresh park | five identical `403`s | `wrong-code` ×4, then **`burned`**, `attempts 5/5`, park file deleted |
| The **right** code, after that burn | `403 {"error": "refused"}` | `no-park` |
| Eleven attempts in one minute from one source | eleven identical `403`s | ten `no-park`, then **`rate-limited`** on the 11th |

The wire is the point: **every refusal is the same status and the same body**,
and the eleventh is indistinguishable from the first. The distinction exists
only in `attempts.ndjson`:

```
19:51:12Z  172.24.0.1   wrong-code    park_id=a719ce0050d285ab
19:51:13Z  172.24.0.1   burned        park_id=a719ce0050d285ab
19:52:18Z  172.24.0.2   no-park       (×10)
19:52:18Z  172.24.0.2   rate-limited
```

The eleven came **from inside the cluster** (a different peer address, hence a
different limiter bucket), which is also how the edge's reachability from the
cluster was proven. The burn was run from the host shell and the two buckets
did not touch each other.

**Not exercised live:** expiry. Both parks went terminal by redemption or burn
inside their fifteen minutes; `expired` is covered by the branch's tests only.

## 4 · The return leg

```
$ vexa_stations.py --ledger … record-credential --channel rehearsal --events attempts.ndjson
ledger: rehearsal/bbb-rehearsal credential events +7 of 19 → …/credential-events.yaml (37338ec…)
ledger: 1 attempt(s) named no station this channel knows
$ …same command again
ledger: rehearsal/bbb-rehearsal credential events +0 of 19 → …  (no change)
```

Re-ingesting the same log is a genuine no-op. The station's
`credential-events.yaml` ends up holding two `park` rows and seven `claim` rows
— park id, salted digest, expiry, cap, source, outcome, time — and **no value,
no code, no salt, no ciphertext**.

## The absence assertion

Eighteen files — every transcript this rehearsal captured, the edge container's
own stdout/stderr, the attempts log, both state files, the ledger working tree
and the ledger's full `git log -p` — were searched for both minted passwords,
verbatim and base64:

```
password 1 (32 chars): occurrences = 0 ; base64 of it = 0
password 2 (32 chars): occurrences = 0 ; base64 of it = 0
code 165312 in the ledger = 0 ; in attempts.ndjson = 0
code 373124 in the ledger = 0 ; in attempts.ndjson = 0
code_salt in the ledger = 0     ciphertext in the ledger = 0
ASSERTION: PASS
```

Two surfaces are excluded, by design and named here rather than quietly: the
**Secret in the cluster**, which is where the value is supposed to be, and the
publisher's **line-1 vault print**, which is the one deliberate emission —
captured to a `0600` file, used only as the needle for this search, and
shredded with the age key. The edge's access log carries a source, a method and
a path and never a body.

---

## Findings

**1 · `kit/claim.sh` is committed non-executable (`100644`).** Every other kit
script is `100755`. The documented `./kit/claim.sh --code …` fails with
`Permission denied` out of a fresh clone — the first command a subscriber runs
on this path. Invoked through `bash` here. One `chmod +x` on the branch.

**2 · A rate-limited attempt never reaches the station's record.** The
per-source limiter fires *before* the body is parsed — correct, and the reason
a refused request cannot cost a subscriber one of their five — but the station
is therefore unknown, the event is written with station `-`, and
`record-credential` drops it as unattributed. So the one event class that means
*somebody hammered this station from one address* is the one class the ledger
cannot show. The per-park limiter (`park-rate-limited`) is checked after the
parse and is attributed normally.

**3 · Identical attempts inside the same second collapse to one row.**
Nineteen attributable events reduced to seven rows: ten identical `no-park`
attempts at `19:52:18Z` became one. Dedup-by-content is what makes re-ingest a
no-op, and the timestamps are second-resolution, so a burst is
indistinguishable from a single request in the ledger. Nothing is wrong in the
spool — `attempts.ndjson` has all twenty.

None of the three changes the verdict on the flow itself: **the six-digit code
worked exactly as described, in the order described, and the credential reached
the cluster without appearing anywhere a person or a log could read it.**

## Afterwards

The Secret was deleted, the edge container and its image removed, the age
identity and every credential-bearing scratch file shredded, and the cluster
left as it was found — same pods, same secrets, one namespace, untouched. The
live edge remains undeployed and founder-owned.
