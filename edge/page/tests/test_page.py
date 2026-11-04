# SPDX-License-Identifier: Apache-2.0
"""The channel page's pure half: routing, reading an artifact, and the render.

`test_page_edge.py` proves the SERVICE — the auth split over a real socket. This
proves what the page says once something has been read, against the repository's
own golden entry, so the fixture is a document the publisher actually produced
rather than one written to make these assertions pass.
"""

import hashlib
import json
import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import vexa_page as vp  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[3]
GOLDEN = REPO / "spec" / "goldens" / "v0.12.23" / "entry.json"


def oras_manifest(titles):
    """The shape `oras push` produces: one layer per file, titled by filename."""
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.vexa.channel-entry.v1+json",
        "layers": [
            {"mediaType": "application/json",
             "digest": "sha256:" + hashlib.sha256(t.encode()).hexdigest(),
             "size": 1,
             "annotations": {vp.OCI_TITLE: t}}
            for t in titles
        ],
    }


class RouteCase(unittest.TestCase):
    def test_the_address_a_subscriber_is_handed(self):
        self.assertEqual(vp.parse_channel("/vexa/channel/acme-stable"), "acme-stable")
        self.assertEqual(vp.parse_channel("/vexa/channel/acme-stable/"), "acme-stable")

    def test_query_is_the_callers_not_the_routes(self):
        self.assertEqual(vp.parse_channel("/vexa/channel/pilot?signin=1"), "pilot")

    def test_everything_else_is_not_this_route(self):
        for path in ("/", "/v2/", "/vexa/channel/", "/vexa/channel/a/b",
                     "/vexa/channels/pilot", "/vexa/channel/pilot/manifests/current"):
            self.assertIsNone(vp.parse_channel(path), path)

    def test_a_name_that_could_aim_at_another_repository_is_not_a_name(self):
        # The parsed name is interpolated straight into /v2/vexa/channel/<name>/…
        # so this is the only thing between a URL and the rest of the registry.
        for bad in ("..", "pilot%2f..", "PILOT", "pilot.stable", "-pilot",
                    "a", "x" * 64):
            self.assertIsNone(vp.parse_channel(f"/vexa/channel/{bad}"), bad)
        # `pilot-` IS a legal channel name — the schema permits a trailing
        # hyphen even though `vexa_subscriber.validate_name` forbids one on an
        # account. The two are different namespaces and this service follows the
        # schema, which is what the registry paths are actually built from.
        self.assertEqual(vp.parse_channel("/vexa/channel/pilot-"), "pilot-")

    def test_the_name_pattern_is_the_schemas_own(self):
        # Copied into the service because its build context is edge/page only.
        # This is the thread that keeps the copy honest.
        schema = json.loads((REPO / "spec" / "channel-entry.schema.json").read_text())
        self.assertEqual(
            schema["properties"]["channel"]["properties"]["name"]["pattern"],
            vp.CHANNEL_NAME_PATTERN)


class ReadCase(unittest.TestCase):
    def test_the_entry_digest_is_computed_from_the_bytes(self):
        raw = b'{"schemaVersion":2}'
        self.assertEqual(vp.manifest_digest(raw),
                         "sha256:" + hashlib.sha256(raw).hexdigest())

    def test_entry_json_is_found_by_its_oci_title(self):
        m = oras_manifest(["entry.json", "VERIFY.md", "evidence/candidate-images.json"])
        self.assertEqual(vp.entry_blob_digest(m), m["layers"][0]["digest"])

    def test_an_artifact_without_an_entry_is_refused_not_half_rendered(self):
        # A moved tag, or an index. Either way this is not a channel entry, and
        # drawing a page from it would be drawing a page from something else.
        with self.assertRaises(vp.PageError):
            vp.entry_blob_digest({"mediaType":
                                  "application/vnd.oci.image.index.v1+json"})

    def test_kit_version_comes_off_the_tarball_it_ships(self):
        self.assertEqual(vp.kit_version(oras_manifest(["kit-v1.0.6.tgz"])), "v1.0.6")

    def test_a_channel_with_no_kit_is_an_absence_not_an_error(self):
        self.assertIsNone(vp.kit_version(oras_manifest(["something-else.tgz"])))

    def test_facts_come_out_of_the_golden_entry(self):
        entry = json.loads(GOLDEN.read_text())
        facts = vp.entry_facts(entry, "sha256:" + "ab" * 32)
        self.assertEqual(facts["channel"], "enterprise-stable")
        self.assertEqual(facts["release"], "v0.12.23")
        self.assertEqual(facts["entry_seq"], 1)
        self.assertEqual(facts["published_at"], entry["publication"]["published_at"])
        self.assertEqual(facts["key_fingerprint"], entry["signing"]["identity"])
        self.assertEqual(facts["entry_digest"], "sha256:" + "ab" * 32)

    def test_a_missing_field_costs_its_row_not_the_page(self):
        facts = vp.entry_facts({"channel": {"name": "pilot"}}, "sha256:x")
        self.assertEqual(facts["channel"], "pilot")
        self.assertIsNone(facts["release"])
        self.assertIsNone(facts["key_fingerprint"])


class RenderCase(unittest.TestCase):
    def setUp(self):
        entry = json.loads(GOLDEN.read_text())
        self.digest = vp.manifest_digest(GOLDEN.read_bytes())
        self.facts = vp.entry_facts(entry, self.digest)
        self.html = vp.render_channel(self.facts, "v1.0.6")

    def test_it_states_every_fact_the_page_promises(self):
        for value in ("enterprise-stable", "v0.12.23", self.digest,
                      self.facts["key_fingerprint"], "v1.0.6",
                      self.facts["published_at"]):
            self.assertIn(value, self.html)
        self.assertIn(">Entry sequence<", self.html)
        self.assertIn(">1<", self.html)

    def test_it_links_install_how_it_works_and_tested(self):
        for slug in ("install", "how-it-works", "tested"):
            self.assertIn(f"https://delivery.vexa.ai/{slug}", self.html)

    def test_one_sentence_on_what_leaves_the_perimeter(self):
        self.assertIn("Nothing is required to leave your cluster", self.html)
        self.assertIn("telemetry-ladder", self.html)
        # And it does not invent a tier. The tier lives in the subscriber's own
        # contract.yaml, inside their cluster; it is not on this channel, and a
        # page that guessed one would be lying about the only thing that matters.
        self.assertNotRegex(self.html, r"[Tt]ier\s*[:=]?\s*[0-4]\b")

    def test_nothing_is_fetched_from_anywhere_else(self):
        # One host through the firewall is the product claim. A stylesheet from
        # a CDN would break it in the browser of the person being onboarded.
        self.assertNotIn("<script", self.html)
        for tag in re.findall(r"<(?:link|img|script)[^>]*>", self.html):
            self.fail(f"external asset reference on the page: {tag}")

    def test_absent_facts_say_so_rather_than_showing_blank(self):
        html = vp.render_channel(vp.entry_facts({}, "sha256:x"), None)
        self.assertIn("not stated", html)
        self.assertIn("none published to this channel", html)

    def test_a_hostile_entry_cannot_write_markup_into_the_page(self):
        facts = vp.entry_facts(
            {"channel": {"name": "<script>alert(1)</script>", "entry_seq": 1}},
            "sha256:x")
        html = vp.render_channel(facts, None)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_the_anonymous_line_is_one_line_and_says_what_to_do(self):
        html = vp.render_anonymous(signin_href="/vexa/channel/pilot?signin=1")
        self.assertIn("This is a Vexa Delivery channel.", html)
        self.assertIn("Sign in", html)
        self.assertIn("with your subscriber account", html)
        self.assertIn("delivery.vexa.ai", html)
        self.assertIn('href="/vexa/channel/pilot?signin=1"', html)
        # It names no channel and no entry: the visitor presented no credential.
        self.assertNotIn("Entry digest", html)
        self.assertNotIn("pilot<", html)


class CacheCase(unittest.TestCase):
    def test_a_page_is_remembered_for_a_minute(self):
        c = vp.Cache(ttl=60)
        k = c.key("pilot", "Basic AAA")
        c.put(k, b"page", now=0.0)
        self.assertEqual(c.get(k, now=59.0), b"page")
        self.assertIsNone(c.get(k, now=61.0))

    def test_another_credential_does_not_read_this_ones_page(self):
        # The authorisation is the registry's answer, not ours. A cache keyed on
        # the channel alone would hand one subscriber's accepted read to a caller
        # the registry would have refused.
        c = vp.Cache()
        c.put(c.key("pilot", "Basic AAA"), b"page")
        self.assertIsNone(c.get(c.key("pilot", "Basic BBB")))
        self.assertIsNone(c.get(c.key("other", "Basic AAA")))

    def test_the_key_is_not_a_verifier_for_a_guessed_credential(self):
        # Salted per process, so the stored key cannot be recomputed from a
        # guess by anyone who reads the cache out of a core dump.
        a, b = vp.Cache(), vp.Cache()
        self.assertNotEqual(a.key("pilot", "Basic AAA"), b.key("pilot", "Basic AAA"))
        self.assertNotIn(b"Basic AAA", a.key("pilot", "Basic AAA")[1])

    def test_it_is_bounded(self):
        c = vp.Cache(ttl=60, max_entries=8)
        for i in range(40):
            c.put(c.key(f"c{i}", "Basic AAA"), b"page")
        self.assertLessEqual(len(c._store), 8)


class NewestEntryCase(unittest.TestCase):
    """Which tag names the newest entry. Not `current` — a pointer the publisher
    moves only when it is asked to — and not the release (day) tag, which is
    written once, for the first publish of a day, and never moves. The newest
    entry is the one with the highest `<release>-seq<N>`: entry_seq advances
    on every publish, the seq tag is written for every entry, and it never
    moves either."""

    DAY = "0.1.0-estate-20261104"

    def test_the_highest_seq_tag_wins_over_current_and_the_day_tag(self):
        tags = ["current", "latest", "v0.12.23", "v0.12.23-seq1", self.DAY,
                f"{self.DAY}-seq2", f"{self.DAY}-seq3", "sha256-" + "ab" * 32 + ".sig"]
        self.assertEqual(vp.newest_entry_tag(tags), (f"{self.DAY}-seq3", 3))

    def test_the_sequence_is_compared_as_a_number(self):
        self.assertEqual(vp.newest_entry_tag(["r-seq9", "r-seq10", "r-seq2"]), ("r-seq10", 10))

    def test_a_channel_with_no_seq_tag_has_no_newest_entry(self):
        self.assertIsNone(vp.newest_entry_tag(["current", "v0.12.23"]))
        self.assertIsNone(vp.newest_entry_tag([]))
        self.assertIsNone(vp.newest_entry_tag(None))

    def test_a_tag_that_is_not_a_tag_is_never_a_candidate(self):
        # Interpolated into /v2/<repo>/manifests/<tag>: nothing with a slash, a
        # dot-dot or a non-tag character may get that far.
        for bad in ("../kit-seq99", "a/b-seq99", "x y-seq99", "-seq99", ".hidden-seq99",
                    "x" * 129 + "-seq99", 99, None, {"t": "x-seq99"}):
            self.assertIsNone(vp.newest_entry_tag([bad]), bad)
        self.assertEqual(vp.newest_entry_tag(["../kit-seq99", "r-seq4"]), ("r-seq4", 4))

    def test_two_tags_claiming_the_newest_seq_is_refused_not_chosen(self):
        with self.assertRaises(vp.PageError):
            vp.newest_entry_tag(["a-seq5", "b-seq5", "a-seq4"])

    def test_the_next_page_is_followed_only_inside_the_same_listing(self):
        prefix = "/v2/vexa/channel/pilot/tags/list"
        self.assertEqual(
            vp.next_tags_page(f'<{prefix}?n=2&last=b>; rel="next"', prefix),
            f"{prefix}?n=2&last=b")
        self.assertIsNone(vp.next_tags_page("", prefix))
        self.assertIsNone(vp.next_tags_page(None, prefix))
        for elsewhere in ('</v2/vexa/channel/other/tags/list?last=b>; rel="next"',
                          '<https://evil.invalid/v2/vexa/channel/pilot/tags/list>; rel="next"',
                          f'<{prefix}/../../other/tags/list>; rel="next"'):
            with self.assertRaises(vp.PageError, msg=elsewhere):
                vp.next_tags_page(elsewhere, prefix)

    def test_the_facts_name_the_tag_they_were_read_at_and_the_mode(self):
        entry = json.loads(GOLDEN.read_text())
        facts = vp.entry_facts(entry, "sha256:" + "ab" * 32, tag="v0.12.23-seq1")
        self.assertEqual(facts["entry_tag"], "v0.12.23-seq1")
        self.assertEqual(facts["publication_mode"], entry["publication"]["mode"])
        html = vp.render_channel(facts, None)
        self.assertIn("v0.12.23-seq1", html)
        self.assertIn("newest entry", html)
        self.assertNotIn("current entry", html)


if __name__ == "__main__":
    unittest.main()
