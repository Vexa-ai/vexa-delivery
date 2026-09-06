#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The channel page's pure half: what to read out of a channel, and how to draw it.

No sockets, no upstream, no environment. `page_edge.py` fetches; this module
decides what a fetched manifest and entry mean and turns them into one
self-contained HTML document.

TWO THINGS THIS FILE IS CAREFUL ABOUT.

**The entry digest is computed, not believed.** A registry returns
`Docker-Content-Digest` on a manifest GET, and it is almost always right — but
the digest IS the sha256 of the manifest bytes, so there is nothing to trust:
`manifest_digest()` hashes what arrived. The number printed on the page is
therefore a statement about the bytes this service read, which is what a
subscriber comparing it against their own `oras resolve` wants it to be.

**Nothing on the page is composed from a second source.** Every value comes out
of the channel's own `current` entry, or out of the kit artifact's manifest.
Where a fact is not on the channel at all — the report tier, which lives in the
subscriber's `contract.yaml` inside their cluster — the page says so rather than
guessing a default. A page that invents a tier is worse than a page that omits
one: the whole product claim is that what leaves is theirs to set.
"""

from __future__ import annotations

import hashlib
import html
import re
import threading
import time

# The channel-name shape, copied from `spec/channel-entry.schema.json`
# (`channel.name`). Copied rather than read because this service's build context
# is this directory and nothing else — there is no `spec/` in the image. The
# copy is held to the original by `tests/test_page.py`, which reads the schema
# and fails if the two ever drift.
#
# It is also the only sanitiser between a URL and an upstream registry path.
# `page_edge` interpolates the parsed name into `/v2/vexa/channel/<name>/...`,
# so a name containing `.` or `/` would be a way to aim this service at another
# repository on the same registry. The alphabet has neither.
CHANNEL_NAME_PATTERN = r"^[a-z0-9][a-z0-9-]{1,62}$"
CHANNEL_NAME_RE = re.compile(CHANNEL_NAME_PATTERN)

# The route Caddy hands over. One path shape, one segment, nothing below it:
# `/vexa/channel/<name>` is the address a subscriber was given, and it is the
# only address this service answers.
ROUTE_RE = re.compile(r"^/vexa/channel/(?P<name>[^/]+)/?$")

ENTRY_FILE = "entry.json"
KIT_TARBALL_RE = re.compile(r"^kit-(?P<version>v[0-9]+\.[0-9]+\.[0-9]+)\.tgz$")
OCI_TITLE = "org.opencontainers.image.title"

DOCS_BASE = "https://delivery.vexa.ai"

ANONYMOUS_LINE = (
    "This is a Vexa Delivery channel. {signin} with your subscriber account, "
    "or read {docs}."
)


class PageError(Exception):
    """A channel we read but could not make a page out of."""


# ------------------------------------------------------------------ routing


def parse_channel(path: str) -> "str | None":
    """The channel name in a request path, or None if this is not that route.

    Query strings are the caller's, not part of the route: `?signin=1` is how
    the anonymous page asks the browser for a credential prompt, and it must not
    change which channel is being addressed.
    """
    m = ROUTE_RE.match(path.split("?", 1)[0].split("#", 1)[0])
    if not m:
        return None
    name = m.group("name")
    return name if CHANNEL_NAME_RE.match(name) else None


# ------------------------------------------------------------------ reading


def manifest_digest(raw: bytes) -> str:
    """The digest of a manifest is the sha256 of its bytes. Compute it."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def layer_by_title(manifest: dict, title: str) -> "dict | None":
    """The layer `oras push` gave this filename, by its OCI title annotation."""
    for layer in manifest.get("layers") or []:
        if (layer.get("annotations") or {}).get(OCI_TITLE) == title:
            return layer
    return None


def entry_blob_digest(manifest: dict) -> str:
    """Where `entry.json` lives in the artifact `current` points at.

    A manifest with no `entry.json` layer is not a channel entry — most likely
    an index, or a tag that was moved onto something else. Refusing here means
    the page never renders half a channel from an artifact it did not recognise.
    """
    layer = layer_by_title(manifest, ENTRY_FILE)
    if layer is None or not layer.get("digest"):
        raise PageError(
            f"the artifact at this channel's `current` tag carries no {ENTRY_FILE} "
            f"layer (media type {manifest.get('mediaType') or 'unstated'})"
        )
    return layer["digest"]


def kit_version(manifest: dict) -> "str | None":
    """The version of the kit artifact, read off the tarball it ships.

    `kit/release.sh` pushes exactly one file, `kit-<version>.tgz`, so the layer
    title carries the version. None when the channel has no kit published — an
    ordinary state for a channel whose subscriber cloned the public repository
    instead, and one the page states rather than hides.
    """
    for layer in manifest.get("layers") or []:
        m = KIT_TARBALL_RE.match((layer.get("annotations") or {}).get(OCI_TITLE, ""))
        if m:
            return m.group("version")
    return None


def entry_facts(entry: dict, digest: str) -> dict:
    """The six facts the page states, out of the signed entry and its digest.

    Missing keys become None rather than raising: an entry from a future schema
    that dropped a field should cost that ROW, not the page. The absence shows
    on the page as `not stated`, which is a true statement about the entry.
    """
    channel = entry.get("channel") or {}
    release = entry.get("release") or {}
    publication = entry.get("publication") or {}
    signing = entry.get("signing") or {}
    return {
        "channel": channel.get("name"),
        "release": release.get("version"),
        "release_url": release.get("release_url"),
        "entry_seq": channel.get("entry_seq"),
        "published_at": publication.get("published_at"),
        "entry_digest": digest,
        "key_fingerprint": signing.get("identity"),
        "signing_mode": signing.get("mode"),
    }


# ---------------------------------------------------------------- rendering

_CSS = """
:root { color-scheme: light dark; }
body { margin: 0; padding: 2.5rem 1.5rem; font: 15px/1.6 ui-sans-serif, system-ui,
  -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
main { max-width: 40rem; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; font-weight: 600;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
p.kind { margin: 0 0 2rem; opacity: .7; }
table { border-collapse: collapse; width: 100%; margin: 0 0 2rem; }
th, td { text-align: left; padding: .45rem .75rem .45rem 0; vertical-align: top;
  border-bottom: 1px solid rgba(128,128,128,.28); }
th { font-weight: 500; opacity: .72; width: 12rem; }
td { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .92em; overflow-wrap: anywhere; }
td.absent { font-family: inherit; opacity: .6; }
nav a { margin-right: 1.25rem; }
p.perimeter { margin: 2rem 0 0; opacity: .85; }
/* A 71-character digest and a 12rem label column do not both fit on a phone.
   Below this width the rows stack instead of the value being crushed into a
   column six characters wide. */
@media (max-width: 34rem) {
  tr, th, td { display: block; width: auto; }
  th { padding: .9rem 0 .1rem; border-bottom: none; }
  td { padding: 0 0 .6rem; }
}
"""


def _document(title: str, body: str) -> str:
    """One self-contained document: no script, no external asset, no font.

    The product promise this channel exists to keep is that a subscriber allows
    ONE host through their firewall. A page that pulls a stylesheet from a CDN
    would break that promise in the browser of the person being onboarded, on
    the first thing they see of us.
    """
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex">'
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
        f"<body><main>{body}</main></body></html>\n"
    )


def _row(label: str, value, mono_absent: str = "not stated") -> str:
    if value in (None, ""):
        cell = f'<td class="absent">{html.escape(mono_absent)}</td>'
    else:
        cell = f"<td>{html.escape(str(value))}</td>"
    return f"<tr><th>{html.escape(label)}</th>{cell}</tr>"


def _links(docs_base: str) -> str:
    base = docs_base.rstrip("/")
    pairs = [("Install", "install"), ("How it works", "how-it-works"),
             ("What is proven", "tested")]
    return "<nav>" + "".join(
        f'<a href="{html.escape(base)}/{slug}">{text}</a>' for text, slug in pairs
    ) + "</nav>"


def _perimeter(docs_base: str) -> str:
    """One sentence, and it declines to name a tier it cannot read.

    The tier lives in `report_scope` in the subscriber's own `contract.yaml`,
    inside their cluster. It is not in the channel entry and not on this
    registry, so this page has no honest way to state it — and stating a default
    would be the one lie that matters here, since the whole claim is that the
    rung is theirs to set.
    """
    ladder = html.escape(docs_base.rstrip("/") + "/telemetry-ladder")
    return (
        '<p class="perimeter">Nothing is required to leave your cluster: what your '
        "side may send back is set by the "
        f'<a href="{ladder}">tier</a> in your own <code>contract.yaml</code>, which '
        "lives in your cluster and not on this channel, so this page cannot state "
        "it for you.</p>"
    )


def render_channel(facts: dict, kit: "str | None", docs_base: str = DOCS_BASE) -> str:
    """The channel's page, for a caller whose credential the registry accepted."""
    name = facts.get("channel") or "this channel"
    release = facts.get("release")
    if release and facts.get("release_url"):
        release_cell = (
            f'<tr><th>Release</th><td><a href="{html.escape(facts["release_url"])}">'
            f"{html.escape(str(release))}</a></td></tr>"
        )
    else:
        release_cell = _row("Release", release)
    body = (
        f"<h1>{html.escape(str(name))}</h1>"
        '<p class="kind">Vexa Delivery channel &middot; current entry</p>'
        "<table>"
        + release_cell
        + _row("Entry sequence", facts.get("entry_seq"))
        + _row("Published at", facts.get("published_at"))
        + _row("Entry digest", facts.get("entry_digest"))
        + _row("Channel key fingerprint", facts.get("key_fingerprint"))
        + _row("Kit version", kit, mono_absent="none published to this channel")
        + "</table>"
        + _links(docs_base)
        + _perimeter(docs_base)
    )
    return _document(f"{name} — Vexa Delivery channel", body)


def render_anonymous(docs_base: str = DOCS_BASE, signin_href: "str | None" = None) -> str:
    """The one line an anonymous visitor gets. Never a 404.

    A person who was handed `channel.vexa.ai/vexa/channel/<name>` and opened it
    in a browser is the reason this service exists. What they must not read is
    `not found`.

    `signin_href` makes the two words "Sign in" a link, because a 200 cannot make
    a browser ask for a credential — only a 401 does, and that link is what
    fetches one. Omitted on the page served AFTER a credential was refused: the
    browser has already prompted, and offering the prompt again as a link reads
    as though the refusal were a navigation mistake.
    """
    base = docs_base.rstrip("/")
    # ANONYMOUS_LINE is a constant with no HTML-special character in it, and both
    # insertions are escaped where they are built — so the format call inserts
    # markup into prose rather than prose into markup.
    docs_link = f'<a href="{html.escape(base)}">{html.escape(base.split("//")[-1])}</a>'
    signin = ("Sign in" if signin_href is None
              else f'<a href="{html.escape(signin_href)}">Sign in</a>')
    return _document(
        "Vexa Delivery channel",
        f"<p>{ANONYMOUS_LINE.format(signin=signin, docs=docs_link)}</p>",
    )


def render_notice(headline: str, sentence: str, docs_base: str = DOCS_BASE) -> str:
    """A channel we could not draw, said in a sentence and never in plain text."""
    return _document(
        headline,
        f"<h1>{html.escape(headline)}</h1><p>{html.escape(sentence)}</p>"
        + _links(docs_base),
    )


# -------------------------------------------------------------------- cache


class Cache:
    """A minute of memory, keyed by channel AND by who asked.

    Keyed by the credential as well as the channel because the authorisation is
    the registry's answer, not ours (see `page_edge.serve`): a cache keyed on
    the channel alone would let one subscriber's accepted read be served to a
    caller the registry would have refused. The key holds a salted hash of the
    header, never the header — the salt is per process, so the stored key is not
    a verifier anyone could test a guessed credential against.

    Only successful renders are cached. Caching a refusal would mean a
    credential rotated a second ago keeps failing for a minute, and the
    complaint would land on the credential rather than here.
    """

    def __init__(self, ttl: float = 60.0, max_entries: int = 512):
        self.ttl = ttl
        self.max_entries = max_entries
        self._salt = hashlib.sha256(repr((id(self), time.time())).encode()).digest()
        self._store: "dict[tuple[str, bytes], tuple[float, bytes]]" = {}
        self._lock = threading.Lock()

    def key(self, channel: str, authorization: str) -> "tuple[str, bytes]":
        return channel, hashlib.sha256(self._salt + authorization.encode()).digest()

    def get(self, key, now: "float | None" = None) -> "bytes | None":
        now = time.monotonic() if now is None else now
        with self._lock:
            hit = self._store.get(key)
            if hit is None:
                return None
            expires, body = hit
            if expires <= now:
                del self._store[key]
                return None
            return body

    def put(self, key, body: bytes, now: "float | None" = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._store) >= self.max_entries:
                # Bounded, and it drops what expires soonest rather than
                # tracking access order: this cache exists to absorb a reload,
                # not to be an eviction policy.
                for k in sorted(self._store, key=lambda k: self._store[k][0])[
                        : max(1, self.max_entries // 4)]:
                    del self._store[k]
            self._store[key] = (now + self.ttl, body)
