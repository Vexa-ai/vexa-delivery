---
title: "Edge read scope — a subscriber credential no longer reads the whole registry"
description: "Reads are now scoped per subscriber at the Caddy edge: each account reads the channels it consumes and its own station path, _catalog is refused, and everything else on the host is closed. The account × path table before and after, the production controls, the claim path re-run end to end, and the rollback tested dry."
---

**Date:** 2026-09-07. **Where:** the live channel edge — the standalone host at
`$CHANNEL_REGISTRY_SSH`, `$CHANNEL_ROOT/`. **Why now:** the finding below was
made yesterday while proving a subscriber's pull scope, and the next thing that
happens on this channel is a subscriber holding one of these credentials.

**What changed on the host: one file.** `$CHANNEL_ROOT/Caddyfile`. `env`,
`htpasswd`, `compose.yaml` and `registry-config.yml` are byte-identical before
and after — no account was minted, no password rotated, no hash rewritten. The
registry container was never stopped and nothing was pruned.

---

## What was true before

The Caddyfile's terminal `handle` carried no `basic_auth` of its own, so every
**read** fell through to the registry, whose htpasswd is all-or-nothing. Writes
had been confined per station since 2026-08-25; reads were not confined at all.
Measured with a subscriber credential, not inferred:

| Probe | Before |
|---|---|
| `GET /v2/_catalog` | **200** — every channel and every station named |
| `GET /v2/vexa/channel/vexa-internal/manifests/current` | **200** — our internal estate's entry |
| `GET …/vexa-internal/images/vexaai/v012-gateway/manifests/…` | **200** — our mirrored images |
| `GET /v2/vexa/stations/vexa-prod/bundles/tags/list` | **200** — another station's evidence |

RUNBOOK § 5.2 promised only that *enumeration stays behind credentials*. It
never promised isolation between subscribers, and there was none.

## The rule

A credential reads the channel(s) it consumes and its own station path. Nothing
else on the host.

| Account | May read |
|---|---|
| `publisher` | everything |
| a subscriber `<s>` | `vexa/channel/<the channels it subscribes to>/**` and `vexa/stations/<s>/**` |
| `edge-signature-reader` | signature paths only — it is not in the read gate at all; its one job is the anonymous signature route, where the edge injects it upstream itself |
| anonymous | the signature paths, and `/healthz` |

The **station** half needs no per-account configuration: as on the submit path,
*the account name is the path segment*, so the expression compares the
authenticated user against the captured segment. The **channel** half cannot be
derived from a name — a channel has many subscribers — so it is an explicit
list at the edge, and admitting an account to a channel is one line, exactly
like granting station-write.

The gate is additive. Caddy authenticates to decide scope and passes the
caller's own `Authorization` upstream; the registry still authenticates every
request that gets through.

```caddyfile
@read {
  method GET HEAD
  path /v2 /v2/*
}
handle @read {
  route {
    basic_auth {
      publisher           {env.PUBLISHER_BCRYPT}
      <subscriber>        {env.SUB_<NAME>_BCRYPT}
      vexa-prod           {env.SUB_VEXA_PROD_BCRYPT}
      vexa-staging-bbb    {env.SUB_VEXA_STAGING_BBB_BCRYPT}
    }

    # 1 · enumeration stays with the publisher
    @catalog_denied expression `path("/v2/_catalog*") && {http.auth.user.id} != "publisher"`
    respond @catalog_denied "403 — …" 403

    # 2 · channel reads — the explicit map
    @channel_denied expression `path("/v2/vexa/channel/*") && !(
           {http.auth.user.id} == "publisher"
        || ({http.auth.user.id} == "<subscriber>"      && path("/v2/vexa/channel/<their channel>/*"))
        || ({http.auth.user.id} == "vexa-prod"         && path("/v2/vexa/channel/vexa-internal/*"))
        || ({http.auth.user.id} == "vexa-staging-bbb"  && path("/v2/vexa/channel/vexa-internal/*", "/v2/vexa/channel/<the channel it rehearses>/*"))
      )`
    respond @channel_denied "403 — …" 403

    # 3 · station reads — the account name IS the path segment
    @stationread path_regexp sta ^/v2/vexa/stations/([^/]+)(/|$)
    handle @stationread {
      @wrong_station_read expression {http.auth.user.id} != "publisher" && {http.auth.user.id} != {re.sta.1}
      respond @wrong_station_read "403 — …" 403
      reverse_proxy registry:5000 { … }
    }

    # 4 · default deny for anything else under /v2/ that is not the ping
    @outside expression `!path("/v2", "/v2/", "/v2/_catalog*", "/v2/vexa/channel/*", "/v2/vexa/stations/*") && {http.auth.user.id} != "publisher"`
    respond @outside "403 — …" 403

    reverse_proxy registry:5000 { … }
  }
}
```

`route` rather than bare directives because the order of the steps *is* the
policy — authenticate, refuse, then proxy — and `route` keeps them in the order
they are written rather than Caddy's directive order. The block sits below both
write gates and above the terminal `handle`, which now receives only the verbs
neither gate claims.

**One account carries two channels**, and it is ours: the ephemeral staging
station consumes the internal estate *and* installs a subscriber's own entry on
a build host before the subscriber ever sees it. That second line is in the map
because the ledger says that station consumed that channel — its ledger name
and its account name differ, so no name rule could have derived it. It was read
out of the ledger, not assumed.

## The table, before → after

Every cell measured against the live edge, the same probe set before and after.

| Path | anon | `edge-signature-reader` | subscriber | `vexa-staging-bbb` | `vexa-prod` | `publisher` |
|---|---|---|---|---|---|---|
| `GET /v2/` (ping) | 401 → 401 | 200 → **401** | 200 → 200 | 200 → 200 | 200 → 200 | 200 → 200 |
| its own channel: entry, chart, kit, verifier, revocations, `tags/list` | 401 → 401 | 200 → **401** | 200 → 200 | 200 → 200 | 200 → **403** | 200 → 200 |
| its own channel: `signatures/manifests/<digest>.sig` | 200 → 200 | 200 → 200 | 200 → 200 | 200 → 200 | 200 → 200 | 200 → 200 |
| `vexa-internal:current` | 401 → 401 | 200 → **401** | 200 → **403** | 200 → 200 | 200 → 200 | 200 → 200 |
| `vexa-internal` mirrored image manifest | 401 → 401 | 200 → **401** | 200 → **403** | 200 → 200 | 200 → 200 | 200 → 200 |
| `vexa-internal/tags/list`, `…/signatures/tags/list` | 401 → 401 | 200 → **401** | 200 → **403** | 200 → 200 | 200 → 200 | 200 → 200 |
| `vexa/stations/vexa-prod/bundles/tags/list` | 401 → 401 | 200 → **401** | 200 → **403** | 200 → **403** | 200 → 200 | 200 → 200 |
| `vexa/stations/vexa-staging-bbb/bundles/tags/list` | 401 → 401 | 200 → **401** | 200 → **403** | 200 → 200 | 200 → **403** | 200 → 200 |
| `vexa/stations/<the subscriber>/bundles/tags/list` | 401 → 401 | 200 → **401** | 200 → 200 | 200 → **403** | 200 → **403** | 200 → 200 |
| `_catalog` | 401 → 401 | 200 → **401** | 200 → **403** | 200 → **403** | 200 → **403** | 200 → 200 |
| `vexa/scratch/**` (publisher fixtures) | 401 → 401 | 200 → **401** | 200 → **403** | 200 → **403** | 200 → **403** | 200 → 200 |
| `/healthz` | 200 → 200 | 200 → 200 | 200 → 200 | 200 → 200 | 200 → 200 | 200 → 200 |
| channel page, its own channel | 200 → 200 | 200 → **401** | 200 → 200 | 200 → 200 | 200 → **401** | 200 → 200 |
| channel page, `vexa-internal` | 200 → 200 | 200 → **401** | 200 → **401** | 200 → 200 | 200 → 200 | 200 → 200 |

The anonymous column is unchanged in every row — including the signature
manifest and its blob, both still 200 with no credential. (An anonymous
signature GET *without* an `Accept` header still answers 404 by content
negotiation, exactly as § 5.2 has said since August. It looks like a policy
failure and is not.)

## The controls

- **Production, and it is the one that would have forced a rollback.**
  `vexa-prod` and `vexa-staging-bbb` still fetch `vexa-internal:current` at
  `sha256:42fcfa3a…` and still read their own station bundles. Checked first,
  within seconds of the recreate, before anything else was measured.
- **Write policy byte-for-byte unchanged.** The same five write probes before
  and after: a subscriber 401 on a publisher path, 403 on another station's
  path, 401 on its own channel's push path; the publisher opens an upload
  session (202) and cancels it (204). Diff of the two runs: empty.
- **Real clients, not just status codes.** With the subscriber credential:
  `oras pull` of its entry returns the four expected files at the entry's own
  digest, and `helm pull` of the chart returns `vexa-0.12.36.tgz`. The same
  clients against `vexa-internal` fail with a clean `403 Forbidden` rather than
  a hang or a mangled manifest.
- **The channel page inherits the scope for free.** It reads `/v2/` back
  through this same edge with the caller's credential, and its refusal branch
  already treated 403 like 401 — so a subscriber asking for another channel's
  page now gets the one-line *"This is a Vexa Delivery channel. Sign in…"*
  instead of that channel's release, entry sequence and digest. No change was
  needed in the page service.
- **`edge-signature-reader` narrowed to what its name says.** It has no bcrypt
  in `env` — only the base64 the edge presents upstream — so it is not in the
  read gate and is refused 401 everywhere except the anonymous signature route
  it exists to serve. Anonymous verification is unaffected: that route is
  above the gate and untouched.

## The claim path, end to end

Re-run on the live edge, because a credential that cannot be claimed is not a
credential:

1. `add <throwaway> --park --channel <channel> --ttl 900 --ledger <scratch>` —
   minted, parked, six digits printed once. The park arrived owned by the
   spool's uid, **not root**: the ownership defect from the 2026-09-06 deploy
   is fixed on the branch this mint ran from, and did not have to be chowned by
   hand.
2. `kit/claim.sh --code … --station <throwaway> --print-once` **from the build
   host** — exit 0, credential returned, `attempts.ndjson` attributing the
   claim to that host's real public address.
3. The claimed credential reproduces the scoped table exactly: its channel's
   entry, chart, kit, verifier, revocations and `tags/list` 200 — with a real
   `oras` fetch at the entry's own digest — and 403 on the internal channel, on
   every station path including the one belonging to the subscriber whose
   channel it shares, on `_catalog` and on scratch.
4. `revoke <throwaway>` — the credential answers 401, and the account is gone
   from `htpasswd`, which is byte-identical to its value before the rehearsal.

**A wrong code was answered exactly like every other refusal.** One attempt in
this run used six digits taken from the wrong line of the tool's output; the
edge answered the uniform `403 {"error":"refused"}` and recorded
`outcome: wrong-code`. That is the design working, and it is also the reason
the operator reading digits aloud cannot distinguish a mistyped code from an
expired one without looking at the spool.

## Rollback, tested dry

The pre-change file was copied beside the live one before anything was applied
and is byte-identical to the snapshot taken at the start
(`sha256:8242b52f…`). It was adapted and provisioned in a throwaway container
with the live `env_file`, so compose's `$$` interpolation was exercised the way
the real stack exercises it: **`Valid configuration`**, exit 0, without touching
the running listener. The rollback is two commands — restore the copy, then
`docker compose up -d --force-recreate` from `$CHANNEL_ROOT` (a plain
`docker restart` does not re-read the file).

## What this changes for the next subscriber

**The edge half of a mint now comes first.** An account the edge has never
heard of is refused 401 on every read — including the `GET /v2/` that
`vexa_subscriber.py add` uses to prove a fresh credential before printing it,
so the mint aborts and reports *"the rotation is broken"* when the truth is
*"this account has no read scope yet"*. Admit the account at the edge first
(one `SUB_<NAME>_BCRYPT` line, one `basic_auth` line, one channel line, then a
recreate), then mint. Rotating an existing account is unchanged — the same env
key the read gate reads is the one `add` rewrites, so a rotation on a call
still works with no edge edit at all, which was verified here.

Making the tool write both halves is the obvious follow-up and is not in this
change.
