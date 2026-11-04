# SPDX-License-Identifier: Apache-2.0
"""The channel page over a real socket, against a fixture registry.

`test_page.py` proves what the page says. This proves the SPLIT: that an
anonymous visitor is answered rather than refused, that a credential is what
turns the line into the channel, that no answer on this route is ever plain
text, and that the service decides none of it itself — it presents the caller's
credential to the edge and renders what came back.

Both ends are real sockets, so the credential really crosses a wire, the Accept
header really goes out, and the caching really elides a request. The fixture
registry records every call, which is how the negative assertions are made:
an anonymous request must cost the registry nothing at all.
"""

import base64
import hashlib
import inspect
import json
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import page_edge as pe  # noqa: E402
import vexa_page as vp  # noqa: E402

# Captured before any test silences it: the access line is real behaviour and
# one test reads it, but leaving it on would put forty lines of noise into
# `make test` for no assertion.
REAL_LOG_MESSAGE = pe.Handler.log_message

REPO = pathlib.Path(__file__).resolve().parents[3]
GOLDEN = REPO / "spec" / "goldens" / "v0.12.23" / "entry.json"

CHANNEL = "enterprise-stable"
# The needle: a fact only a credentialed reader may see. Its appearance in an
# anonymous or refused response is a test failure rather than something a
# reviewer has to notice while skimming HTML.
PASSWORD = "PW-FIXTURE-NEVER-REAL"
GOOD = "Basic " + base64.b64encode(f"pilot:{PASSWORD}".encode()).decode()
BAD = "Basic " + base64.b64encode(b"pilot:wrong").decode()


DAY = "0.1.0-estate-20261104"
NEWEST_TAG = f"{DAY}-seq3"


def entry_variant(seq, release, published_at, mode):
    """The golden entry, re-stamped as a later entry on the same channel."""
    e = json.loads(GOLDEN.read_text())
    e["channel"]["entry_seq"] = seq
    e["release"]["version"] = release
    e["release"]["release_url"] = "https://github.com/Vexa-ai/vexa"
    e["publication"]["published_at"] = published_at
    e["publication"]["mode"] = mode
    return json.dumps(e, indent=1).encode()


def entry_manifest(entry):
    blob = "sha256:" + hashlib.sha256(entry).hexdigest()
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.vexa.channel-entry.v1+json",
        "layers": [
            {"mediaType": "application/json", "digest": blob, "size": len(entry),
             "annotations": {vp.OCI_TITLE: "entry.json"}},
            {"mediaType": "text/markdown", "digest": "sha256:" + "cd" * 32, "size": 1,
             "annotations": {vp.OCI_TITLE: "VERIFY.md"}},
        ],
    }).encode()
    return blob, manifest


def build_fixture():
    """One channel, in the shape two publishes on one UTC day leave behind:

        v0.12.23-seq1     seq 1   also `current` — the pointer, moved once, long ago
        <day>-seq2        seq 2   also the day tag — the first publish of the day
        <day>-seq3        seq 3   the NEWEST, on its seq tag and nothing else

    plus the image-signature tag a cosign-signed entry leaves in the same
    repository, and the kit beside it. The page must show seq 3.
    """
    base = f"/v2/vexa/channel/{CHANNEL}"
    routes, tags, manifests = {}, [], {}
    for seq, body, names in (
        (1, GOLDEN.read_bytes(), ["v0.12.23-seq1", "v0.12.23", "current"]),
        (2, entry_variant(2, DAY, "2026-11-04T09:00:00Z", "candidate"), [f"{DAY}-seq2", DAY]),
        (3, entry_variant(3, DAY, "2026-11-04T15:30:00Z", "candidate"), [NEWEST_TAG]),
    ):
        blob, manifest = entry_manifest(body)
        manifests[seq] = manifest
        routes[f"{base}/blobs/{blob}"] = body
        for name in names:
            routes[f"{base}/manifests/{name}"] = manifest
            tags.append(name)
    tags.append("sha256-" + "ab" * 32 + ".sig")
    kit = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [{"mediaType": "application/gzip", "digest": "sha256:" + "ef" * 32,
                    "size": 1, "annotations": {vp.OCI_TITLE: "kit-v1.0.6.tgz"}}],
    }).encode()
    routes[f"{base}/kit/manifests/latest"] = kit
    return manifests, routes, {f"/v2/vexa/channel/{CHANNEL}": sorted(tags)}


MANIFESTS, ROUTES, TAGS = build_fixture()
MANIFEST = MANIFESTS[3]   # the newest entry's manifest: the one the page must show


class FixtureRegistry(BaseHTTPRequestHandler):
    """The edge as this service sees it: everything under /v2/ wants a credential.

    `tags/list` pages the way the distribution registry does when asked to
    (`?n=` and `&last=`, a `Link: <…>; rel="next"` header while more remain);
    PAGE_SIZE None answers in one page.
    """

    protocol_version = "HTTP/1.1"
    calls: list = []
    PAGE_SIZE = None

    def do_GET(self):  # noqa: N802
        self.calls.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "accept": self.headers.get("Accept"),
        })
        auth = self.headers.get("Authorization")
        if auth != GOOD:
            return self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                              {"WWW-Authenticate": 'Basic realm="registry"'})
        path, _, query = self.path.partition("?")
        if path.endswith("/tags/list"):
            return self._tags(path[: -len("/tags/list")], urllib.parse.parse_qs(query))
        body = ROUTES.get(self.path)
        if body is None:
            return self._send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')
        self._send(200, body)

    def _tags(self, repo, query):
        names = TAGS.get(repo)
        if names is None:
            return self._send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}')
        after = (query.get("last") or [""])[0]
        n = int((query.get("n") or [self.PAGE_SIZE or 0])[0]) or len(names)
        rest = [t for t in names if t > after]
        page, more = rest[:n], rest[n:]
        headers = {}
        if more:
            headers["Link"] = f'<{repo}/tags/list?n={n}&last={page[-1]}>; rel="next"'
        self._send(200, json.dumps({"name": repo[4:], "tags": page}).encode(), headers)

    def _send(self, status, body, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class EdgeCase(unittest.TestCase):
    def setUp(self):
        FixtureRegistry.calls = []
        FixtureRegistry.PAGE_SIZE = None
        self.registry = ThreadingHTTPServer(("127.0.0.1", 0), FixtureRegistry)
        threading.Thread(target=self.registry.serve_forever,
                         kwargs={"poll_interval": 0.02}, daemon=True).start()
        upstream = f"http://127.0.0.1:{self.registry.server_address[1]}"

        pe.Handler.config = pe.Config(upstream=upstream)
        pe.Handler.log_message = lambda *a, **k: None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), pe.Handler)
        threading.Thread(target=self.server.serve_forever,
                         kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        pe.Handler.log_message = REAL_LOG_MESSAGE
        for s in (self.server, self.registry):
            s.shutdown()
            s.server_close()

    def get(self, path, authorization=None, method="GET"):
        req = urllib.request.Request(self.base + path, method=method)
        if authorization:
            req.add_header("Authorization", authorization)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    # ------------------------------------------------------------- the split

    def test_anonymous_gets_a_page_never_a_404(self):
        status, headers, body = self.get(f"/vexa/channel/{CHANNEL}")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertIn("This is a Vexa Delivery channel.", body)
        self.assertIn("delivery.vexa.ai", body)

    def test_anonymous_costs_the_registry_nothing(self):
        self.get(f"/vexa/channel/{CHANNEL}")
        self.assertEqual(FixtureRegistry.calls, [])

    def test_anonymous_learns_nothing_about_the_channel(self):
        _, _, body = self.get(f"/vexa/channel/{CHANNEL}")
        for secret in ("v0.12.23", DAY, "Entry digest", "Channel key fingerprint",
                       vp.manifest_digest(MANIFEST)):
            self.assertNotIn(secret, body)

    def test_the_line_can_ask_the_browser_for_a_credential(self):
        # 200 cannot make a browser prompt; the link on the line leads here.
        _, _, line = self.get(f"/vexa/channel/{CHANNEL}")
        self.assertIn(f'href="/vexa/channel/{CHANNEL}?signin=1"', line)
        status, headers, body = self.get(f"/vexa/channel/{CHANNEL}?signin=1")
        self.assertEqual(status, 401)
        self.assertIn("Basic realm=", headers["WWW-Authenticate"])
        self.assertIn("This is a Vexa Delivery channel.", body)

    def test_a_refused_credential_is_asked_again_and_told_nothing(self):
        status, headers, body = self.get(f"/vexa/channel/{CHANNEL}", BAD)
        self.assertEqual(status, 401)
        self.assertIn("Basic realm=", headers["WWW-Authenticate"])
        self.assertIn("This is a Vexa Delivery channel.", body)
        self.assertNotIn("v0.12.23", body)
        self.assertNotIn(DAY, body)
        self.assertNotIn(PASSWORD, body)

    def test_the_credential_is_the_callers_and_the_registry_decides(self):
        self.get(f"/vexa/channel/{CHANNEL}", BAD)
        self.assertEqual([c["authorization"] for c in FixtureRegistry.calls], [BAD])

    def test_a_credential_turns_the_line_into_the_channel(self):
        status, headers, body = self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertIn(CHANNEL, body)
        self.assertIn(DAY, body)                              # release
        self.assertIn(">3<", body)                            # entry sequence
        self.assertIn(NEWEST_TAG, body)                       # the tag it was read at
        self.assertIn("candidate", body)                      # publication mode
        self.assertIn("2026-11-04T15:30:00Z", body)           # published at
        self.assertIn(vp.manifest_digest(MANIFEST), body)     # entry digest
        self.assertIn(json.loads(GOLDEN.read_text())["signing"]["identity"], body)
        self.assertIn("v1.0.6", body)                         # kit version
        self.assertIn("https://delivery.vexa.ai/install", body)
        self.assertIn("Nothing is required to leave your cluster", body)

    # ------------------------------------------------------- the newest entry

    def test_the_page_shows_the_newest_entry_not_current_nor_the_day_tag(self):
        """Two publishes on one day: `current` still names seq 1 and the day tag
        names seq 2, the first of the day. Neither is the newest entry."""
        status, _, body = self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        self.assertEqual(status, 200, body)
        self.assertIn(vp.manifest_digest(MANIFESTS[3]), body)
        self.assertNotIn(vp.manifest_digest(MANIFESTS[1]), body)
        self.assertNotIn(vp.manifest_digest(MANIFESTS[2]), body)
        self.assertNotIn("2026-08-21T11:03:01Z", body)
        self.assertNotIn("2026-11-04T09:00:00Z", body)

    def test_it_reads_neither_current_nor_the_day_tag(self):
        self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        manifests = [c["path"] for c in FixtureRegistry.calls if "/manifests/" in c["path"]]
        base = f"/v2/vexa/channel/{CHANNEL}/manifests/"
        self.assertIn(base + NEWEST_TAG, manifests)
        self.assertNotIn(base + "current", manifests)
        self.assertNotIn(base + DAY, manifests)

    def test_a_tag_list_on_more_than_one_page_is_read_to_the_end(self):
        FixtureRegistry.PAGE_SIZE = 2
        status, _, body = self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        self.assertEqual(status, 200, body)
        self.assertIn(NEWEST_TAG, body)
        pages = [c for c in FixtureRegistry.calls if "/tags/list" in c["path"]]
        self.assertGreater(len(pages), 1)
        for call in pages:
            self.assertEqual(call["authorization"], GOOD)

    def test_a_channel_with_no_seq_tag_has_no_entry_to_show(self):
        """Only the pointer and nothing the publisher has written since seq tags
        exist. The page says there is no entry; it does not fall back to a tag
        that is not the newest entry by construction."""
        repo = "/v2/vexa/channel/pointer-only"
        TAGS[repo] = ["current"]
        ROUTES[f"{repo}/manifests/current"] = MANIFESTS[1]
        try:
            status, headers, body = self.get("/vexa/channel/pointer-only", GOOD)
            self.assertEqual(status, 404)
            self.assertTrue(headers["Content-Type"].startswith("text/html"))
            self.assertIn("has no entry", body)
            self.assertNotIn(f"{repo}/manifests/current",
                             [c["path"] for c in FixtureRegistry.calls])
        finally:
            del TAGS[repo]
            del ROUTES[f"{repo}/manifests/current"]

    def test_a_seq_tag_on_an_entry_with_another_seq_is_said_out_loud(self):
        """The tag says seq 9; the signed entry it points at says seq 1. The
        page would otherwise print a sequence the tag implied and the entry
        never claimed."""
        repo = f"/v2/vexa/channel/{CHANNEL}"
        TAGS[repo].append("v0.12.23-seq9")
        ROUTES[f"{repo}/manifests/v0.12.23-seq9"] = MANIFESTS[1]
        try:
            status, _, body = self.get(f"/vexa/channel/{CHANNEL}", GOOD)
            self.assertEqual(status, 502)
            self.assertIn("Entry mismatch", body)
            self.assertIn("v0.12.23-seq9", body)
        finally:
            TAGS[repo].remove("v0.12.23-seq9")
            del ROUTES[f"{repo}/manifests/v0.12.23-seq9"]

    def test_a_listed_name_that_is_not_a_tag_is_never_requested(self):
        repo = f"/v2/vexa/channel/{CHANNEL}"
        TAGS[repo].append("../../stations/x/bundles/y-seq99")
        try:
            status, _, body = self.get(f"/vexa/channel/{CHANNEL}", GOOD)
            self.assertEqual(status, 200, body)
            self.assertIn(NEWEST_TAG, body)
            for call in FixtureRegistry.calls:
                self.assertNotIn("..", call["path"])
        finally:
            TAGS[repo].remove("../../stations/x/bundles/y-seq99")

    def test_the_page_is_not_a_shared_caches_to_keep(self):
        _, headers, _ = self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertIn("noindex", self.get(f"/vexa/channel/{CHANNEL}", GOOD)[2])

    # ------------------------------------------------------------ never a 404

    def test_an_unknown_channel_is_a_page_with_a_sentence(self):
        status, headers, body = self.get("/vexa/channel/no-such-channel", GOOD)
        self.assertEqual(status, 404)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertIn("has no entry", body)
        self.assertIn("https://delivery.vexa.ai/install", body)

    def test_a_mistyped_address_is_a_page_with_a_sentence(self):
        for path in ("/vexa/channel/", "/vexa/channel/Not_A_Name",
                     "/vexa/channel/pilot/manifests/current"):
            status, headers, body = self.get(path, GOOD)
            self.assertEqual(status, 404, path)
            self.assertTrue(headers["Content-Type"].startswith("text/html"), path)
            self.assertIn("A channel address is", body)

    def test_a_registry_that_will_not_answer_is_a_sentence_not_a_traceback(self):
        pe.Handler.config = pe.Config(upstream="http://127.0.0.1:1")
        status, headers, body = self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        self.assertEqual(status, 502)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertIn("did not answer", body)
        self.assertNotIn("Traceback", body)
        self.assertNotIn(PASSWORD, body)

    def test_a_tag_moved_onto_another_channels_entry_is_said_out_loud(self):
        # The one thing on this page a subscriber could not check for themselves.
        blob = "sha256:" + hashlib.sha256(GOLDEN.read_bytes()).hexdigest()
        TAGS["/v2/vexa/channel/other-channel"] = ["v0.12.23-seq1"]
        ROUTES["/v2/vexa/channel/other-channel/manifests/v0.12.23-seq1"] = MANIFESTS[1]
        ROUTES["/v2/vexa/channel/other-channel/blobs/" + blob] = GOLDEN.read_bytes()
        try:
            status, _, body = self.get("/vexa/channel/other-channel", GOOD)
            self.assertEqual(status, 502)
            self.assertIn("Channel mismatch", body)
            self.assertIn(CHANNEL, body)
        finally:
            del TAGS["/v2/vexa/channel/other-channel"]
            for k in list(ROUTES):
                if "other-channel" in k:
                    del ROUTES[k]

    # ----------------------------------------------------------- the reading

    def test_the_manifest_get_carries_an_accept_header(self):
        # RUNBOOK § 5.2: without one, a manifest GET returns MANIFEST_UNKNOWN by
        # content negotiation, which reads exactly like "this tag does not exist".
        self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        manifest_call = next(c for c in FixtureRegistry.calls
                             if f"manifests/{NEWEST_TAG}" in c["path"])
        self.assertIn("application/vnd.oci.image.manifest.v1+json",
                      manifest_call["accept"])

    def test_it_reads_the_channel_in_the_url_and_nothing_else(self):
        self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        for call in FixtureRegistry.calls:
            self.assertTrue(call["path"].startswith(f"/v2/vexa/channel/{CHANNEL}"),
                            call["path"])

    def test_a_channel_without_a_kit_still_renders(self):
        kit_path = f"/v2/vexa/channel/{CHANNEL}/kit/manifests/latest"
        kept = ROUTES.pop(kit_path)
        try:
            status, _, body = self.get(f"/vexa/channel/{CHANNEL}", GOOD)
            self.assertEqual(status, 200)
            self.assertIn("none published to this channel", body)
        finally:
            ROUTES[kit_path] = kept

    # --------------------------------------------------------------- caching

    def test_a_reload_within_the_minute_does_not_ask_again(self):
        self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        first = len(FixtureRegistry.calls)
        self.assertEqual(self.get(f"/vexa/channel/{CHANNEL}", GOOD)[0], 200)
        self.assertEqual(len(FixtureRegistry.calls), first)

    def test_another_credential_is_asked_about_separately(self):
        self.get(f"/vexa/channel/{CHANNEL}", GOOD)
        FixtureRegistry.calls = []
        self.assertEqual(self.get(f"/vexa/channel/{CHANNEL}", BAD)[0], 401)
        self.assertEqual(len(FixtureRegistry.calls), 1)

    def test_a_refusal_is_not_cached(self):
        # A credential rotated a second ago must not keep failing for a minute.
        self.get(f"/vexa/channel/{CHANNEL}", BAD)
        FixtureRegistry.calls = []
        self.get(f"/vexa/channel/{CHANNEL}", BAD)
        self.assertEqual(len(FixtureRegistry.calls), 1)

    # ----------------------------------------------------------------- plumbing

    def test_head_answers_without_a_body(self):
        status, headers, body = self.get(f"/vexa/channel/{CHANNEL}", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, "")
        self.assertNotEqual(headers["Content-Length"], "0")

    def test_healthz(self):
        status, _, body = self.get("/healthz")
        self.assertEqual(json.loads(body), {"ok": True})
        self.assertEqual(status, 200)

    def test_the_access_log_never_carries_a_credential(self):
        # The line writes address, verb and path with the query stripped. There
        # is no assertion available against stderr that would survive someone
        # adding a header to it, so the assertion is against the line itself.
        src = inspect.getsource(REAL_LOG_MESSAGE)
        self.assertIn("self.path.split('?')[0]", src)
        self.assertNotIn("self.headers", src)


class ConfigCase(unittest.TestCase):
    def test_it_refuses_to_start_without_an_upstream(self):
        with self.assertRaises(vp.PageError):
            pe.Config.from_env({})
        with self.assertRaises(vp.PageError):
            pe.Config.from_env({"PAGE_UPSTREAM": "channel.example.com"})

    def test_the_upstream_is_the_edge_not_the_registry_port(self):
        # Stated here because it is the whole security argument: reading through
        # the edge means this service is governed by the same § 5.2 split as a
        # subscriber's own pull, rather than by a rule of its own.
        c = pe.Config.from_env({"PAGE_UPSTREAM": "https://channel.example.com/",
                                "PAGE_CACHE_TTL": "30"})
        self.assertEqual(c.upstream, "https://channel.example.com")
        self.assertEqual(c.cache.ttl, 30.0)

    def test_check_holds_no_secret_of_any_kind(self):
        c = pe.Config.from_env({"PAGE_UPSTREAM": "https://channel.example.com"})
        self.assertFalse([a for a in vars(c) if "pass" in a or "key" in a
                          or "secret" in a or "htpasswd" in a])


if __name__ == "__main__":
    unittest.main()
