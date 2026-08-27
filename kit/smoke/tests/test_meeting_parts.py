# SPDX-License-Identifier: Apache-2.0
"""Pure-function tests for vexa_smoke._meeting_parts — no cluster, no network.

The parser is the one place where the smoke CLI decides what to POST to /bots. Getting it
wrong produces a 422 the operator has to decode, or worse a 201 for an id no later API call
can address. These cases pin the shapes the gateway's own parser accepts (see the authority
comment above _meeting_parts in vexa_smoke.py).
"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from vexa_smoke import _meeting_parts  # noqa: E402


class GoogleMeet(unittest.TestCase):
    def test_standard_code(self):
        self.assertEqual(
            _meeting_parts("https://meet.google.com/mue-bydo-aaf"),
            ("google_meet", "mue-bydo-aaf", None),
        )

    def test_trailing_slash_and_query_are_stripped(self):
        self.assertEqual(
            _meeting_parts("https://meet.google.com/mue-bydo-aaf/?authuser=0"),
            ("google_meet", "mue-bydo-aaf", None),
        )


class TeamsShortLink(unittest.TestCase):
    """teams.live.com/meet/<numeric id> — the modern "light" link."""

    def test_with_passcode(self):
        self.assertEqual(
            _meeting_parts("https://teams.live.com/meet/32273473894602?p=X8hcQ2vTn4Lm"),
            ("teams", "32273473894602", "X8hcQ2vTn4Lm"),
        )

    def test_without_passcode(self):
        self.assertEqual(
            _meeting_parts("https://teams.live.com/meet/32273473894602"),
            ("teams", "32273473894602", None),
        )

    def test_enterprise_short_link(self):
        self.assertEqual(
            _meeting_parts("https://teams.microsoft.com/meet/9876543210123?p=abcd1234"),
            ("teams", "9876543210123", "abcd1234"),
        )

    def test_passcode_never_rides_on_the_id(self):
        """router.py refuses a native_meeting_id containing '?#&=/' — so the split must happen
        here, not at the gateway."""
        _, native_id, passcode = _meeting_parts(
            "https://teams.live.com/meet/32273473894602?p=X8hcQ2vTn4Lm")
        for ch in "?#&=/":
            self.assertNotIn(ch, native_id)
        self.assertEqual(passcode, "X8hcQ2vTn4Lm")


class TeamsMeetupJoin(unittest.TestCase):
    """Classic teams.microsoft.com /l/meetup-join/ — the id is the percent-encoded thread id."""

    URL = ("https://teams.microsoft.com/l/meetup-join/"
           "19%3ameeting_NjQ0YmQyMTgtOWQzMS00ZmM1LWE5YmMtNWM1ZTI2ZTk5OTk5"
           "%40thread.v2/0?context=%7b%22Tid%22%3a%22aaa%22%7d")

    def test_thread_id_is_decoded(self):
        platform, native_id, passcode = _meeting_parts(self.URL)
        self.assertEqual(platform, "teams")
        self.assertEqual(
            native_id,
            "19:meeting_NjQ0YmQyMTgtOWQzMS00ZmM1LWE5YmMtNWM1ZTI2ZTk5OTk5@thread.v2",
        )
        self.assertIsNone(passcode)

    def test_thread_id_is_a_bare_token(self):
        """It gets embedded back into /l/meetup-join/{id} by the gateway's URL template, and it
        must survive router.py's bare-token guard."""
        _, native_id, _ = _meeting_parts(self.URL)
        for ch in "?#&=/":
            self.assertNotIn(ch, native_id)
        self.assertFalse(any(c.isspace() for c in native_id))
        self.assertLessEqual(len(native_id), 255)


class Rejections(unittest.TestCase):
    def test_garbage_url(self):
        with self.assertRaises(SystemExit) as cm:
            _meeting_parts("https://example.com/not-a-meeting")
        self.assertIn("google_meet and teams supported", str(cm.exception))

    def test_empty(self):
        with self.assertRaises(SystemExit):
            _meeting_parts("   ")

    def test_teams_host_with_no_recognizable_id(self):
        with self.assertRaises(SystemExit) as cm:
            _meeting_parts("https://teams.microsoft.com/_#/school/conversations/General")
        self.assertIn("Teams meeting id", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
