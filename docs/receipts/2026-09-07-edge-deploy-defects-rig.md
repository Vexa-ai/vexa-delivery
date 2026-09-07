---
title: "Three edge-deploy defects, reproduced on a throwaway rig and closed in code"
description: "The three things the 2026-09-06 live deploy got wrong — a park scp'd as root into a 65532-owned spool, /claim below Caddy's write gate, 127.0.0.1 from a Caddy container — each observed in its original shape on a rig built like the live host, then observed fixed by the branch that closes them. Four findings, one a correction to the live receipt."
---

**Date:** 2026-09-07. **Branch under test:**
[`fix/edge-deploy-defects`](https://github.com/Vexa-ai/vexa-delivery/pull/44)
at `eda7269`, closing
[#43](https://github.com/Vexa-ai/vexa-delivery/issues/43). **Where:** the
`bbb` build host — the registry stack's shape, the edge services, the sshd
that stands in for the channel host's login, the publisher and the cluster all
on it. **Nothing on any live host.** The live channel edge was not touched,
read, or reached; it is running the 2026-09-06 deploy exactly as
[that receipt](/receipts/2026-09-06-edge-claim-and-channel-page) left it.

**Provenance, because `main` moved while the rig ran.**
[#42](https://github.com/Vexa-ai/vexa-delivery/pull/42) merged meanwhile and
rewrote the publisher's *mint* path for the standalone host, so the PR's
commits are the rig's tree rebased onto `9c3e69c` and signed. `edge/` is
byte-identical to `eda7269`. Of the park leg — `split_scp_target`,
`remote_spool_owner`, `adopt_spool_owner`, `deliver_park`, `park_preflight`,
`park_credential` — every function is identical too; the one change is the
SSH shell-out: the owner read and the chown now go through #42's `ssh_run`,
given an explicit `target`, instead of a second `subprocess.run(["ssh", …])`
of their own — the same `-o BatchMode=yes`. The stub `kubectl` below stood in
for the mint path *as it
was at `eda7269`*; after #42 the mint is an SSH write to the host, which this
rig did not exercise and #42's own receipt does.

**Nothing real was minted.** The publisher ran against a stub `kubectl` that
answers its three registry calls with a fixture and refuses everything else;
the age key pair was minted for this run and its private half was owned by
`65532` and shredded at the end; the ledger was a scratch checkout of the
`vexa-stations` *shape*; the parked account, `rigacct`, authenticates nowhere.
The two claim codes appear in full below — both are dead: one superseded, one
spent.

---

## The rig

Shaped after what the live receipt found, not after the deploy notes as they
were written — because the notes as written are what was under test.

| | |
|---|---|
| Caddy | the live edge's own image by digest (`caddy@sha256:df7f1c2f…`), **as a container** in a compose project called `channel`, so its network is `channel_default` and its `127.0.0.1` is its own. Plain HTTP on port 18093; TLS is not what is under test |
| Caddyfile | copied from the live shape: anonymous signature reads, the station-write block, the publisher-only **`@write method PUT POST PATCH DELETE`** gate, a default handle to the registry. Four variants, every one of which `caddy validate` accepts (below) |
| Registry | a stand-in that answers `404 page not found` to everything — what distribution/registry says for a path it does not serve |
| The channel host's SSH login | an sshd container (the same pinned `debian:trixie-slim`, plus `openssh-server`), root login by a throwaway key, the spool bind-mounted at `/srv/channel/claims`. So `scp` lands as root, exactly as on the standalone host |
| The spool | `mkdir -m 700` and `chown 65532:65532` — README § Deploy step 1, verbatim, and nothing more |
| Edge images, before | `vexa/claim-edge:36cc1cc` and `vexa/page-edge:36cc1cc`, already on the host: built from `main`'s edge code, which this branch's base (`2283c6a`) differs from only in READMEs |
| Edge images, after | built from this branch through the host's pull-through cache with BuildKit's named-context override; the Dockerfiles untouched; base layer `sha256:411a8667…`, byte-identical to the pinned base's own |
| Publisher | `main`'s `vexa_subscriber.py` for the "before", the branch's for the "after"; both with `--park-ssh rig-edge:/srv/channel/claims` |
| Cluster | the `kind` rig standing since the OpenShift-parity run, through its **tenant** kubeconfig, one namespace |

Three deviations from the live shape, stated because they bound what this
proves:

1. **No TLS.** Every wire observation is over HTTP. The three defects are
   routing and file-ownership defects; none of them is on the TLS side.
2. **The services' "public URL" is Caddy bound on the Docker bridge address**
   (`172.17.0.1:18093`), because the probes run *inside* the containers and
   must reach the same Caddy a subscriber does. On the live host that is the
   public name resolving back to the host, which the page edge already does
   there.
3. **The `channel` network was given an explicit subnet** (`10.222.0.0/24`):
   this build host has exhausted Docker's default address pools (*"all
   predefined address pools have been fully subnetted"*). A rig artefact — the
   live host runs one stack — and finding 4 below.

---

## 1 · Before: the notes as written, `main`'s code

Old images, base compose files only, no network override.

| Caddyfile | Probe from the host shell | Answer |
|---|---|---|
| **v1** — both stanzas *below* `@write`, upstream `127.0.0.1` | `POST /claim` | **401**, `WWW-Authenticate: Basic realm="restricted"` — the publisher gate |
| v1 | `GET /vexa/channel/rig` | **502** |
| **v2** — both stanzas *above* `@write`, upstream `127.0.0.1` | `POST /claim` | **502** |
| v2 | `GET /vexa/channel/rig` | **502** — while `127.0.0.1:8088/healthz` from the *host* answers `{"ok": true}`: the publish is fine, Caddy cannot see it |
| **v3** — above `@write`, upstreams `claim-edge:8088` / `page-edge:8089`, plus the hand-written override the live host used for a day | `POST /claim` | **403** `{"error": "refused"}` — the service, reached |
| v3 | `GET /vexa/channel/rig` | **200**, the one-line page |

Then, with the route working and the spool **empty** (see finding 3), `main`'s
publisher parked:

```
#   park      rig-edge:/srv/channel/claims/rig-station.park.json
-rw------- 1 0 0 912 Sep  7 10:58 rig-station.park.json        # root:root, in a 65532 spool
```

The **right** code against that park, through Caddy, old image:

| | |
|---|---|
| On the wire | **502** — not the 403 the live receipt inferred (finding 1) |
| `attempts.ndjson` | no row: 0 before, 0 after |
| State files | none — the attempt was never counted, which is the one good thing about it |
| The service's own log | `PermissionError: [Errno 13] Permission denied: '/spool/rig-station.park.json'`, a full traceback, the handler thread gone |
| Caddy's access log | `status 502` |

That is defect 1 as the subscriber would have met it: `kit/claim.sh` maps a
502 to *"there is no claim service at this edge… your code is untouched"* —
true, and by accident.

## 2 · After: the branch's images, the shipped override

`docker compose -f compose.yaml -f compose.caddy-container.yaml up -d` for
both services, with the root-owned park from § 1 still in the spool:

```
vexa-claim-edge-claim-edge-1  networks: channel_default (alias claim-edge)  vexa-claim-edge_default
vexa-page-edge-page-edge-1    networks: channel_default (alias page-edge)   vexa-page-edge_default
```

**`--check` names the park before anything is read aloud:**

```
claim-edge: rig-station.park.json is in the spool but uid 65532 cannot read it —
  delivered with the wrong owner; on the host, chown it to the spool's owner
  (README.md § Deploy, step 5)
exit 2
```

**The probe matrix.** One Caddyfile variant at a time; `caddy validate` said
*Valid configuration* for all four; both probes run from inside their service
against the public URL.

| Caddyfile | `claim_edge.py --probe` | `page_edge.py --probe` |
|---|---|---|
| **v0** — no stanzas at all | exit 1 · *answered 401 — the write gate took the request: no `handle /claim` stanza is ABOVE it* (finding 2) | exit 1 · *answered 404 — the registry's own "page not found". No route…* |
| **v1** — below the gate, `127.0.0.1` | exit 1 · *answered 401 — the write gate took the request…* | exit 1 · *answered 502 — the edge has a route but cannot reach this service. If Caddy is a container, `reverse_proxy 127.0.0.1:8089` is Caddy's OWN loopback…* |
| **v2** — above the gate, `127.0.0.1` | exit 1 · *answered 502 — the edge has a route to /claim but cannot reach this service. If Caddy is a container, `reverse_proxy 127.0.0.1:8088` is Caddy's OWN loopback…* | exit 1 · the same 502 |
| **v3** — above the gate, the aliases | **exit 0** · *probe OK: reaches this service — refused the probe as designed (403), and the attempt is in this spool as station `probe-b4b81970` (seq 1, outcome malformed). source as this service saw it: 10.222.0.1* | **exit 0** · *probe OK: anonymous answered with the one line (200), and `?signin=1` is this service's 401* |

The v3 claim probe's row, as the spool holds it — a station no real station
has, `malformed`, no park id, no digest:

```
{"event": "claim", "outcome": "malformed", "park_id": null, "code_sha256": null,
 "seq": 1, "source": "10.222.0.1", "station": "probe-b4b81970", "ts": "2026-09-07T07:59:17Z"}
```

`source` is what Caddy forwarded (`CLAIM_TRUST_FORWARDED_FOR=1`), which is the
one thing about the per-source limiter a probe can show.

## 3 · The publisher, fixed, end to end

**A · A root-owned spool is refused before the mint.** The spool was chowned
to `0:0` and `add --park` run:

```
error: the spool /srv/channel/claims on rig-edge is owned by root. The claim edge
runs as uid 65532 (edge/claim/Dockerfile) and cannot read a park that lands in a
root-owned spool — the code would be read aloud against a file the service cannot
open. On the edge host: chown 65532:65532 /srv/channel/claims
(edge/claim/README.md § Deploy, step 1). Nothing was minted.
```

Exit 2; the stub `kubectl` saw **no `apply`**; stdout was empty. Nothing
rotated.

**B · The park, handed to the spool's owner.** Spool restored to `65532:65532`;
`add --park` again:

```
#   park      rig-edge:/srv/channel/claims/rig-station.park.json (owner 65532:65532, the spool's)
-rw------- 1 65532 65532 911 Sep  7 10:59 rig-station.park.json
```

Line 2 of stdout: **`797 565`**. `--check`: `config OK (spool /spool, identity
mode 600)`, exit 0.

**C · The claim.** `kit/claim.sh --code '797 565' … --namespace vexa-dev` as
the tenant:

```
claimed: station rig-station
  secret:    vexa-station-credential (keys username, password)
  namespace: vexa-dev
  the code is now spent; the credential is in the cluster and nowhere else
```

Username read back from the Secret: `rigacct`. The spool afterwards: no park
file; `rig-station.1153b4d9….state.json` reads `state=redeemed attempts=0/5
terminal_reason='claimed'`.

**D · The wire is unchanged.** The spent code and a wrong one: two identical
`403 {"error": "refused"}`.

**E · The return leg.** Four rows in `attempts.ndjson`; `record-credential`:

```
ledger: rig/rig-station credential events +3 of 3
ledger: 1 attempt(s) named no station this channel knows — probes at the endpoint;
        they stay in attempts.ndjson and enter no station's record
```

The station's record ends `park · claim claimed · park · claim no-park · claim
no-park`; the probe created no directory; the same log again added `+0 of 3`.

## The absence assertion

Every rig log and transcript, both services' container logs, Caddy's access
log, the attempts log, the scratch ledger's working tree and its full `git log
-p`, searched for both minted passwords, verbatim and base64, and for both
codes and the salt:

```
password (before, 32 chars): occurrences = 0 ; base64 of it = 0
code 587706 (before, superseded): in the ledger + attempts.ndjson = 0
password (after, 32 chars):  occurrences = 0 ; base64 of it = 0
code 797565 (after, spent):   in the ledger + attempts.ndjson = 0
code_salt in the ledger = 0
ASSERTION: PASS
```

One pass of this rig was discarded before this one, and it is worth saying
why: its "before" claim answered **200**, because `scp` had overwritten a park
the fixed publisher had already handed to `65532` — and the log therefore held
a credential. That log was deleted, the value is a throwaway that authenticates
nowhere, and the pass recorded here started from an empty spool. It is finding
3.

---

## Findings

**1 · The unreadable park answered `502`, not the uniform `403`.** The
2026-09-06 receipt's finding 4 says the edge answers *"the uniform 403, which
says nothing"*. It does not: the `PermissionError` escaped the handler, the
connection dropped, Caddy answered `502`, and **no row reached the attempts
log**. The subscriber's `kit/claim.sh` reads a 502 as *no claim service at
this edge* — the right instruction by accident. The branch makes it a `503`
with an `error:` row naming the file and the fix, which the kit reads the same
way and the operator can now see.

**2 · A missing `/claim` stanza is the same `401` as one below the gate.**
`@write` matches POST on every path, so with no stanza above it the gate takes
the request either way; the registry's `404` is never reached. The probe's
verdict and the README's table now say *"missing or below"*; a `404` from the
claim probe means there is no write gate either, which is not the channel edge.

**3 · The ownership defect is a first-park defect.** `scp` over an existing
file truncates it in place, and the inode keeps its owner: a re-park onto a
park already owned by `65532` lands readable. That is why the live edge hit it
on two fresh stations, why the discarded pass hid it, and why the fix reads
the *directory's* owner rather than trusting what the file arrived as.

**4 · This build host has no free Docker address pool.** A new compose
project's default network fails with *"all predefined address pools have been
fully subnetted"*; the rig's stack was given an explicit subnet. Not a product
finding — the live host runs one stack — but the next rig on this host will
meet it, and it is silent until `up`.

## Afterwards

Every container, both rig networks, the three rig images, the Secret in
`vexa-dev`, the `Host rig-edge` block in the host user's ssh config, the
throwaway keys, the age identity and every credential-bearing scratch file
were removed. The rig's scripts, logs, and scratch ledger stay under
`~/edge-deploy-rig` on the build host: the assertion above is what says they
may.

## What is undone

- **The live channel host runs the 2026-09-06 deploy unchanged**: the old
  images, the hand-written override, the publisher without the owner check.
  Adopting this branch there is three steps — replace the host-local override
  with the shipped file, recreate the two edge projects on images built from
  this branch, run `--probe` once from each — and the publisher half applies
  on the next `add --park`. That deploy is the founder's, and it is not this
  receipt.
- **The claim probe was run against an HTTP edge.** On the live host it dials
  `https://<channel host>/claim` from inside the container, the way the page
  edge already dials its own origin there.
