#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""page-edge — `GET /vexa/channel/<name>`, the channel's page for the person holding it.

A subscriber is handed one address: `channel.vexa.ai/vexa/channel/<name>`. It is a
registry reference, and until this service existed a browser opening it read
`404 page not found` — the first thing the taker saw of the delivery.

    GET /vexa/channel/<name>                 -> 200 the channel's page (credential)
                                             -> 200 one line          (anonymous)
    GET /vexa/channel/<name>?signin=1        -> 401 + WWW-Authenticate, same one line
    GET /healthz                             -> 200 {"ok": true}

NEVER A BARE 404. Every reachable answer on this route is an HTML page that says
what happened and links to the documentation — including the ones that carry a
404 or a 502 status. The status is for the machine; the sentence is for the
person who was told this address was theirs.

WE DO NOT DECIDE WHO MAY READ. The service holds no htpasswd, no key, no secret
of any kind. It takes the caller's `Authorization` header, presents it to the
edge on the caller's behalf, and renders only what came back — so the answer to
"may this credential see this channel" is the registry's, given through the same
door and the same split that RUNBOOK § 5.2 already describes for `/v2/`. This
page can therefore never show a subscriber anything they could not have pulled
themselves, and the day per-channel scoping is tightened at the edge, it tightens
here for free because this service asks rather than knows.

WHAT IT READS, AND ALL IT READS. Two upstream GETs per uncached render, both
under the channel named in the URL: the manifest at `current`, and the
`entry.json` blob it points at; plus one for the kit tag. The channel name is
matched against the entry schema's own pattern before it is interpolated, so
there is no path a caller can write that reaches another repository.

DEPLOYMENT: see README.md in this directory. This service has NOT been deployed
by the change that introduced it — the live edge is founder-owned.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vexa_page  # noqa: E402

# The four manifest media types a registry may hand back for a tag. RUNBOOK
# § 5.2 records the scar: a manifest GET with no `Accept` header returns
# MANIFEST_UNKNOWN by content negotiation, which reads exactly like "this tag
# does not exist" and cost a session once already.
MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
])

# An entry is a few kilobytes of JSON. Anything larger is not one, and reading it
# into memory before deciding that is how a small service becomes a memory
# exhaustion target — the upstream here is ours, but the limit costs one line.
MAX_BLOB = 4 * 1024 * 1024

REALM = 'Basic realm="Vexa Delivery channel", charset="UTF-8"'

CHANNEL_REPO = "vexa/channel/{name}"
KIT_REPO = "vexa/channel/{name}/kit"


class Config:
    """Where the edge is, how long a page is remembered, and nothing secret."""

    def __init__(self, upstream: str, docs_base: str = vexa_page.DOCS_BASE,
                 cache_ttl: float = 60.0, timeout: float = 5.0,
                 upstream_host: "str | None" = None):
        self.upstream = upstream.rstrip("/")
        self.docs_base = docs_base.rstrip("/")
        self.timeout = timeout
        self.upstream_host = upstream_host
        self.cache = vexa_page.Cache(ttl=cache_ttl)

    @classmethod
    def from_env(cls, env=None) -> "Config":
        env = os.environ if env is None else env
        upstream = env.get("PAGE_UPSTREAM", "").strip()
        if not upstream:
            raise vexa_page.PageError(
                "PAGE_UPSTREAM is not set. It is the edge's own base URL — this "
                "service reads the registry through the same door a subscriber "
                "does, with the subscriber's credential, so that the split in "
                "RUNBOOK § 5.2 governs what it can see.")
        if urllib.parse.urlsplit(upstream).scheme not in ("http", "https"):
            raise vexa_page.PageError(f"PAGE_UPSTREAM is not an http(s) URL: {upstream}")
        return cls(
            upstream=upstream,
            docs_base=env.get("PAGE_DOCS_BASE", vexa_page.DOCS_BASE),
            cache_ttl=float(env.get("PAGE_CACHE_TTL", "60")),
            timeout=float(env.get("PAGE_TIMEOUT", "5")),
            upstream_host=env.get("PAGE_UPSTREAM_HOST") or None,
        )

    def fetch(self, path: str, authorization: str, accept: str) -> "tuple[int, bytes]":
        """One upstream GET, carrying the caller's credential and nothing else.

        Returns (status, body). A refusal is a status, not an exception, because
        401 and 404 are ordinary answers on this path and each has its own page.
        """
        req = urllib.request.Request(self.upstream + path, method="GET")
        req.add_header("Accept", accept)
        req.add_header("Authorization", authorization)
        if self.upstream_host:
            # The edge terminates TLS for a name that may not resolve to itself
            # from inside the host. Dialling by address and naming the vhost here
            # keeps the request on the same Caddy the subscriber reaches.
            req.add_header("Host", self.upstream_host)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status, body = resp.status, resp.read(MAX_BLOB + 1)
        except urllib.error.HTTPError as e:
            return e.code, e.read(MAX_BLOB + 1) if e.fp else b""
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise vexa_page.PageError(f"the channel registry did not answer: {e}") from None
        if len(body) > MAX_BLOB:
            raise vexa_page.PageError(
                f"the registry returned more than {MAX_BLOB} bytes for {path}")
        return status, body


def _answer(status, body: str, headers=None):
    return status, headers or {}, body.encode()


def serve(config: Config, path: str, authorization: str) -> "tuple[int, dict, bytes]":
    """One request, start to finish. Pure enough to test without a socket."""
    name = vexa_page.parse_channel(path)
    if name is None:
        # Something under the route that is not a channel address. Still a page:
        # the person mistyping a channel name is the same person the whole
        # service exists for.
        return _answer(HTTPStatus.NOT_FOUND, vexa_page.render_notice(
            "Not a channel address",
            "A channel address is /vexa/channel/<name>, with the name your "
            "subscription was issued under.", config.docs_base))

    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)

    if not authorization:
        if "signin" in query:
            # The one-line page cannot make a browser ask for a credential — only
            # a 401 does that. So "Sign in" on that line links back to this same
            # address with ?signin, and this branch turns it into a prompt. A
            # visitor who cancels lands back on the same one line.
            return _answer(HTTPStatus.UNAUTHORIZED,
                           vexa_page.render_anonymous(config.docs_base),
                           {"WWW-Authenticate": REALM})
        return _answer(HTTPStatus.OK, vexa_page.render_anonymous(
            config.docs_base, signin_href=f"/vexa/channel/{name}?signin=1"))

    cache_key = config.cache.key(name, authorization)
    cached = config.cache.get(cache_key)
    if cached is not None:
        return HTTPStatus.OK, {}, cached

    repo = CHANNEL_REPO.format(name=name)
    try:
        status, raw = config.fetch(
            f"/v2/{repo}/manifests/current", authorization, MANIFEST_ACCEPT)
        if status in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
            # The registry refused this credential. Ask again rather than
            # explaining: a wrong password in a browser is fixed by the prompt.
            return _answer(HTTPStatus.UNAUTHORIZED,
                           vexa_page.render_anonymous(config.docs_base),
                           {"WWW-Authenticate": REALM})
        if status == HTTPStatus.NOT_FOUND:
            return _answer(HTTPStatus.NOT_FOUND, vexa_page.render_notice(
                "No current entry",
                f"The channel {name} has no entry at its current tag. If you were "
                f"given this address, tell us — it means nothing has been published "
                f"to it yet.", config.docs_base))
        if status != HTTPStatus.OK:
            raise vexa_page.PageError(
                f"the channel registry answered {status} for this channel's current tag")

        manifest = json.loads(raw)
        blob = vexa_page.entry_blob_digest(manifest)
        status, entry_raw = config.fetch(
            f"/v2/{repo}/blobs/{blob}", authorization, "application/json")
        if status != HTTPStatus.OK:
            raise vexa_page.PageError(
                f"this channel's current entry names a blob the registry answered "
                f"{status} for")
        entry = json.loads(entry_raw)

        # The kit is a separate artifact on the same channel and an optional one.
        # A channel without it is ordinary, so its absence is a row on the page
        # and never a failure of the page.
        kit = None
        kit_status, kit_raw = config.fetch(
            f"/v2/{KIT_REPO.format(name=name)}/manifests/latest",
            authorization, MANIFEST_ACCEPT)
        if kit_status == HTTPStatus.OK:
            try:
                kit = vexa_page.kit_version(json.loads(kit_raw))
            except ValueError:
                kit = None
    except vexa_page.PageError as exc:
        return _answer(HTTPStatus.BAD_GATEWAY, vexa_page.render_notice(
            "The channel did not answer", str(exc), config.docs_base))
    except ValueError as exc:
        return _answer(HTTPStatus.BAD_GATEWAY, vexa_page.render_notice(
            "The channel did not answer",
            f"this channel's current entry is not readable JSON ({exc})",
            config.docs_base))

    facts = vexa_page.entry_facts(entry, vexa_page.manifest_digest(raw))
    # The URL names the channel; the signed entry names it too. If they disagree,
    # the tag was moved onto another channel's entry — which is the one thing on
    # this page a subscriber could not detect for themselves, so it is said out
    # loud rather than quietly rendered under the heading they asked for.
    if facts.get("channel") and facts["channel"] != name:
        return _answer(HTTPStatus.BAD_GATEWAY, vexa_page.render_notice(
            "Channel mismatch",
            f"the entry published at {name}'s current tag declares itself to be "
            f"channel {facts['channel']}. Do not act on it; tell us.",
            config.docs_base))

    body = vexa_page.render_channel(facts, kit, config.docs_base).encode()
    config.cache.put(cache_key, body)
    return HTTPStatus.OK, {}, body


class Handler(BaseHTTPRequestHandler):
    server_version = "vexa-page-edge"
    sys_version = ""
    config: Config
    protocol_version = "HTTP/1.1"

    def _respond(self, status, headers: dict, body: bytes, head_only=False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # The page is a credentialed view of a channel. It is not a shared
        # cache's to keep, and it is not a search engine's to index.
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _serve(self, head_only=False) -> None:
        if self.path.split("?", 1)[0] == "/healthz":
            body = json.dumps({"ok": True}).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head_only:
                self.wfile.write(body)
            return
        status, headers, body = serve(
            self.config, self.path, self.headers.get("Authorization", "") or "")
        self._respond(status, headers, body, head_only)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        self._serve()

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(head_only=True)

    def log_message(self, fmt, *args) -> None:
        """The path and the verb. Never the Authorization header.

        The default line is harmless today; this override exists so that the
        obvious next step when debugging a 401 — printing the headers — has to be
        written deliberately rather than uncommented.
        """
        sys.stderr.write(
            f"{self.address_string()} {self.command} {self.path.split('?')[0]}\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="page_edge",
        description="Serve GET /vexa/channel/<name>: the channel's page, behind "
                    "the subscriber credential, one line without it.")
    p.add_argument("--listen", default=os.environ.get("PAGE_LISTEN", "127.0.0.1:8089"),
                   help="host:port to bind (default: $PAGE_LISTEN or 127.0.0.1:8089; "
                        "TLS is Caddy's, upstream of this process)")
    p.add_argument("--check", action="store_true",
                   help="validate configuration and exit, serving nothing")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = Config.from_env()
    except (vexa_page.PageError, ValueError) as exc:
        print(f"page-edge: {exc}", file=sys.stderr)
        return 2
    if args.check:
        print(f"page-edge: config OK (upstream {config.upstream}, "
              f"cache {config.cache.ttl:g}s)")
        return 0

    host, _, port = args.listen.rpartition(":")
    Handler.config = config
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    print(f"page-edge: listening on {args.listen}, upstream {config.upstream}",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
