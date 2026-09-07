# The channel page

`GET /vexa/channel/<name>` — the address a subscriber is handed, answered as a
page instead of `404 page not found`.

**Deployed 2026-09-06** on the live channel edge:
[receipt](/receipts/2026-09-06-edge-claim-and-channel-page). That deploy found
the note as written routed Caddy to a loopback that was not the host's; the
containerised-Caddy shape now ships as a compose override and the service proves
its own public route with `--probe`, both shown against a throwaway rig:
[receipt](/receipts/2026-09-07-edge-deploy-defects-rig). [§ Deploy](#deploy) is
the corrected note.

| | |
|---|---|
| Route | `GET`/`HEAD` `/vexa/channel/<name>` — one segment, nothing below it |
| With a subscriber credential | `200` · the channel's page |
| Without one | `200` · one line, and a link that fetches the prompt |
| `?signin=1`, no credential | `401` + `WWW-Authenticate: Basic` — what makes a browser ask |
| A credential the registry refuses | `401` + `WWW-Authenticate: Basic`, and the same one line |
| No such channel, no `current`, a bad address, a registry that will not answer | `404`/`502` **as an HTML page with a sentence** — never plain text |
| Health | `GET /healthz` · `{"ok": true}` |
| Cache | one minute, per channel **and per credential** |
| Secrets held | none |

## What the page says

Six facts, and every one of them comes out of the channel's own `current` entry
or the kit artifact beside it:

| | Read from |
|---|---|
| Channel name | `channel.name` in the entry, cross-checked against the URL |
| Release | `release.version`, linked to `release.release_url` |
| Entry sequence | `channel.entry_seq` |
| Published at | `publication.published_at` |
| Entry digest | the sha256 of the manifest bytes this service read |
| Channel key fingerprint | `signing.identity` |
| Kit version | the `kit-<version>.tgz` layer title on `<channel>/kit:latest` |

Then the three documentation links — [install](https://delivery.vexa.ai/install),
[how it works](https://delivery.vexa.ai/how-it-works),
[what is proven](https://delivery.vexa.ai/tested) — and one sentence about what
leaves their perimeter.

**That sentence names no tier, and the omission is the point.** The tier lives
in `report_scope` in the subscriber's own `contract.yaml`, inside their cluster.
It is not in the channel entry, it is not on this registry, and there is no
honest way for this page to state it — so it says that the rung is theirs and
links the [ladder](https://delivery.vexa.ai/telemetry-ladder) rather than
printing a default. A page that guessed would be lying about the one thing the
whole product claim rests on.

**The entry digest is computed, not believed.** A registry returns
`Docker-Content-Digest`, and it is almost always right — but the digest IS the
sha256 of the manifest bytes, so there is nothing to trust. The number on the
page is a statement about the bytes this service read, which is what a
subscriber comparing it against their own `oras resolve` needs it to be.

**A `current` tag pointing at another channel's entry is said out loud.** The
URL names a channel and the signed entry names one; if they disagree the page
refuses to render and says so, because that is the single fact here a subscriber
could not check for themselves.

## The auth split, and who decides it

```
 anonymous visitor          the page             the edge (Caddy)        the registry
 ─────────────────          ────────             ────────────────        ────────────
 GET /vexa/channel/x  ──▶  one line, 200
                           (no upstream call at all)

 GET, Authorization   ──▶  forwards the SAME credential ──▶ /v2/… ──▶ htpasswd
                      ◀──  renders only what came back  ◀── 200/401 ◀──
```

**This service decides nothing about who may read.** It holds no htpasswd, no
key, no allowlist. It takes the caller's `Authorization` header, presents it to
the edge on their behalf, and renders only what came back — so the answer to
*may this credential see this channel* is the registry's, given through the same
door and the same split RUNBOOK § 5.2 already describes for `/v2/`. Two
consequences worth stating:

- The page can never show a subscriber anything they could not have pulled
  themselves with `oras`.
- The day read access is scoped per channel at the edge — the manual
  `basic_auth` line § 5.4 already describes for write paths — this page is
  scoped with it, for free, because it asks rather than knows.

**An anonymous request costs the registry nothing.** There is no upstream call
on that path, so the public route cannot be used to generate load, or attempts,
against the registry behind it.

**Anonymous is answered, not refused, and that is a deliberate choice against a
401.** A `401` in a browser is a credential box over a blank page; on cancel it
is the browser's own error text. The person opening this link is usually being
onboarded and has not been given a credential yet, and what they must not read
is *not found*. So the bare route answers `200` with one line, and the two words
"Sign in" link to `?signin=1`, which is the branch that returns the `401` a
browser needs in order to prompt.

## What it reads, and all it reads

Three upstream `GET`s per uncached render, all under the channel named in the
URL: the manifest at `current`, the `entry.json` blob it points at, and the kit
tag. The channel name is matched against **the entry schema's own pattern**
(`spec/channel-entry.schema.json`, `channel.name`) before it is interpolated
into a registry path, so there is no name a caller can write that reaches
another repository. The pattern is copied into `vexa_page.py` because the build
context is this directory; `tests/test_page.py` reads the schema and fails if
the copy drifts.

The manifest `GET` carries an explicit `Accept`. RUNBOOK § 5.2 records why: a
manifest request without one returns `MANIFEST_UNKNOWN` by content negotiation,
which reads exactly like *this tag does not exist*.

The rendered page loads **no script, no stylesheet, no font and no image from
anywhere**. One host through the firewall is the product claim; a page that
pulled a stylesheet from a CDN would break it in the browser of the person being
onboarded, on the first thing they ever see of us.

## Deploy

Not done here. Whoever does it, in order:

**1 · Build and push the image, digest-pinned.** On the build host, never on the
laptop. The image is two Python files; the build context is this directory only.

```bash
docker build -t <registry>/vexa/page-edge:<tag> edge/page
```

**2 · Start it, in the shape Caddy has.** `PAGE_EDGE_IMAGE` must be the digest,
not the tag. `CHANNEL_EDGE_URL` is the edge's **own** origin — see
[`config/channel.example.env`](../../config/channel.example.env).

```bash
# Caddy is a CONTAINER in the registry stack's compose project — the live edge.
# The override joins that project's network under the alias `page-edge`.
PAGE_EDGE_IMAGE=<ref>@sha256:… docker compose \
  -f edge/page/compose.yaml -f edge/page/compose.caddy-container.yaml up -d

# Caddy runs ON THE HOST: the base file alone; Caddy reaches 127.0.0.1:8089.
PAGE_EDGE_IMAGE=<ref>@sha256:… docker compose -f edge/page/compose.yaml up -d

# Either way:
docker compose -f edge/page/compose.yaml exec page-edge \
  python3 /app/page_edge.py --check
```

[`compose.caddy-container.yaml`](compose.caddy-container.yaml) attaches the
service to the stack's network and changes nothing else; the network name
defaults to `channel_default` and is set with `CHANNEL_STACK_NETWORK` when the
live one differs — a wrong name fails loudly at `up`. On 2026-09-06 the note
said `reverse_proxy 127.0.0.1:8089` and Caddy was a container, whose loopback is
its own: the config validated, Caddy started, and only the page failed.

If the edge's public name does not resolve to the host from inside it, set
`CHANNEL_EDGE_HOST` to that name and point `CHANNEL_EDGE_URL` at the address:
the request then reaches the same Caddy vhost a subscriber does.

**3 · Route `/vexa/channel/*` through Caddy.** It goes beside the existing
signature-read and registry stanzas (RUNBOOK § 5.2), and it carries **no
`basic_auth` of its own** — the split lives in the service, because anonymous
must be answered rather than refused:

```caddyfile
@channel_page path_regexp chanpage ^/vexa/channel/[a-z0-9][a-z0-9-]{1,62}/?$
handle @channel_page {
    reverse_proxy page-edge:8089       # Caddy in a container: the compose alias
    # reverse_proxy 127.0.0.1:8089     # Caddy on the host: the loopback publish
}
```

Order matters: this stanza must not shadow `/v2/…`, and the regexp above cannot
— `/v2/` is a different prefix, and the pattern admits exactly one path segment
after `/vexa/channel/`. Caddy passes the `Authorization` header through by
default; nothing needs to be added for it, and nothing may strip it.

**Then prove it from inside the service:**

```bash
docker compose -f edge/page/compose.yaml exec page-edge \
  python3 /app/page_edge.py --probe
```

Two anonymous `GET`s through the public edge, for a channel that need not
exist — an anonymous request makes no upstream call, so this costs the registry
nothing and needs no credential. The URL defaults to `PAGE_UPSTREAM`, which *is*
the edge's own origin. What it says:

| Answer | Verdict |
|---|---|
| `200` with this service's one line, and `?signin=1` answers this service's `401` | **OK** |
| `404` — the registry's `page not found` | no route reaches this service |
| `502` / `503` / `504` | the stanza points at a loopback that is not this host's — Caddy is a container |
| `401` on the **bare** path | the route carries a `basic_auth` it must not |

**4 · Add the row to RUNBOOK § 5.2's table** — done in the change that added
this directory, before the route existed, so the table describes the edge as it
is intended rather than as it drifted.

## Environment

| Variable | Default | |
|---|---|---|
| `PAGE_UPSTREAM` | — | required; the **edge's** base URL, not the registry's port |
| `PAGE_UPSTREAM_HOST` | — | `Host` header override, when the public name does not resolve from inside the host |
| `PAGE_LISTEN` | `127.0.0.1:8089` | TLS is Caddy's, upstream of this process |
| `PAGE_CACHE_TTL` | `60` | seconds a rendered page is remembered |
| `PAGE_TIMEOUT` | `5` | seconds to wait on the edge |
| `PAGE_DOCS_BASE` | `https://delivery.vexa.ai` | where the three links point |

## Limits, stated

- **The cache holds an accepted read for up to a minute.** A credential revoked
  ten seconds ago can still render this page for the rest of that minute. The
  pull path is unaffected — revocation there is immediate — and only refusals
  are excluded from the cache, so a *rotated* credential works at once.
- **The cache is in memory**, so it resets on restart, and it is keyed by a
  per-process salted hash of the credential rather than by the credential.
- **A subscriber credential reads any channel's page today,** because the
  registry's htpasswd is all-or-nothing on read (RUNBOOK § 5.2) and this service
  delegates rather than deciding. It shows one channel and never enumerates —
  no listing, no `_catalog`, no link to another channel — but the scoping is
  the edge's to tighten, not this service's to claim.
- **The one-minute cache has been observed doing exactly this.** On 2026-09-06 a
  credential revoked seconds earlier got `401` on `/v2/` and `200` on its page.
  The pull path is what matters and it refused at once; the page is a page.
