"""Hermetic tests for vexa_subscriber's htpasswd handling.

Nothing here touches a cluster, a registry or the network. The cluster half of
the module (kubectl shell-outs) is deliberately not exercised — the parts worth
testing are the ones where a bug silently locks somebody out or silently grants
them access.
"""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vexa_subscriber as vs  # noqa: E402


# Two bcrypt-SHAPED placeholders. They are not hashes of anything — the parse
# and render code treats a digest as an opaque string, and is_bcrypt() reads
# only the "$2y$" prefix, so a filler body exercises every path a real hash
# would. Written this way on purpose: a realistic-looking digest in a test
# file trips credential scanners and costs a human the check every time.
BC = "$2y$05$" + "A" * 53
BC2 = "$2y$05$" + "B" * 53


class TestParse(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(vs.parse_htpasswd(""), {})
        self.assertEqual(vs.parse_htpasswd("\n\n  \n"), {})

    def test_single_and_multi(self):
        self.assertEqual(vs.parse_htpasswd(f"publisher:{BC}\n"), {"publisher": BC})
        self.assertEqual(
            vs.parse_htpasswd(f"publisher:{BC}\npilot:{BC2}\n"),
            {"publisher": BC, "pilot": BC2},
        )

    def test_comments_and_blank_lines_ignored(self):
        text = f"# minted 2026-08-24\n\npublisher:{BC}\n\n# pilot below\npilot:{BC2}\n"
        self.assertEqual(vs.parse_htpasswd(text), {"publisher": BC, "pilot": BC2})

    def test_hash_containing_colons_is_not_split(self):
        # partition() keeps everything after the first ':' — bcrypt has none,
        # but the guarantee matters if a hash format ever changes.
        self.assertEqual(vs.parse_htpasswd("u:a:b:c\n"), {"u": "a:b:c"})

    def test_missing_separator_rejected(self):
        with self.assertRaises(vs.SubscriberError):
            vs.parse_htpasswd("publishernohash\n")

    def test_empty_user_or_hash_rejected(self):
        with self.assertRaises(vs.SubscriberError):
            vs.parse_htpasswd(":hash\n")
        with self.assertRaises(vs.SubscriberError):
            vs.parse_htpasswd("user:\n")

    def test_duplicate_user_rejected(self):
        # Last-one-wins would be a coin flip on which credential is live.
        with self.assertRaises(vs.SubscriberError):
            vs.parse_htpasswd(f"pilot:{BC}\npilot:{BC2}\n")


class TestRender(unittest.TestCase):
    def test_empty_renders_empty(self):
        self.assertEqual(vs.render_htpasswd({}), "")

    def test_sorted_with_trailing_newline(self):
        out = vs.render_htpasswd({"zeta": BC, "alpha": BC2})
        self.assertEqual(out, f"alpha:{BC2}\nzeta:{BC}\n")

    def test_round_trip_is_stable(self):
        text = f"pilot:{BC2}\npublisher:{BC}\n"
        self.assertEqual(vs.render_htpasswd(vs.parse_htpasswd(text)), text)

    def test_render_is_canonical(self):
        # Unsorted, comment-laden input converges on one byte-identical form,
        # so a no-op `add` produces no spurious Secret change or rollout.
        messy = f"# note\nzeta:{BC}\n\nalpha:{BC2}\n"
        tidy = f"alpha:{BC2}\nzeta:{BC}\n"
        self.assertEqual(
            vs.render_htpasswd(vs.parse_htpasswd(messy)),
            vs.render_htpasswd(vs.parse_htpasswd(tidy)),
        )


class TestAddRemove(unittest.TestCase):
    def test_add_to_empty(self):
        self.assertEqual(vs.add_entry("", "pilot", BC), f"pilot:{BC}\n")

    def test_add_preserves_others(self):
        out = vs.add_entry(f"publisher:{BC}\n", "pilot", BC2)
        self.assertEqual(vs.parse_htpasswd(out), {"publisher": BC, "pilot": BC2})

    def test_add_existing_is_rotation_not_duplicate(self):
        out = vs.add_entry(f"pilot:{BC}\n", "pilot", BC2)
        self.assertEqual(vs.parse_htpasswd(out), {"pilot": BC2})

    def test_remove(self):
        out = vs.remove_entry(f"publisher:{BC}\npilot:{BC2}\n", "pilot")
        self.assertEqual(vs.parse_htpasswd(out), {"publisher": BC})

    def test_remove_last_leaves_empty_file(self):
        self.assertEqual(vs.remove_entry(f"pilot:{BC}\n", "pilot"), "")

    def test_remove_absent_is_an_error(self):
        # Silently succeeding would report a revocation that never happened.
        with self.assertRaises(vs.SubscriberError):
            vs.remove_entry(f"publisher:{BC}\n", "pilot")


class TestNameValidation(unittest.TestCase):
    def test_accepts_plain_names(self):
        for name in ("pilot", "test-sub", "publisher", "a1"):
            self.assertEqual(vs.validate_name(name), name)

    def test_rejects_bad_names(self):
        for name in ("", "PILOT", "a b", "a:b", "-x", "x-", "a/b", "a\nb"):
            with self.subTest(name=name):
                with self.assertRaises(vs.SubscriberError):
                    vs.validate_name(name)

    def test_colon_in_name_cannot_forge_an_entry(self):
        with self.assertRaises(vs.SubscriberError):
            vs.add_entry("", "evil:$2y$fake", BC)


class TestPassword(unittest.TestCase):
    def test_length_and_alphabet(self):
        pw = vs.generate_password()
        self.assertEqual(len(pw), vs.PASSWORD_LENGTH)
        self.assertTrue(set(pw) <= set(vs.PASSWORD_ALPHABET))

    def test_not_repeated(self):
        self.assertEqual(len({vs.generate_password() for _ in range(50)}), 50)


class TestBcryptDetection(unittest.TestCase):
    def test_recognises_bcrypt_prefixes(self):
        for d in ("$2a$05$x", "$2b$05$x", "$2y$05$x"):
            self.assertTrue(vs.is_bcrypt(d))

    def test_rejects_weaker_htpasswd_formats(self):
        # registry:3 refuses these; flagging them beats a silent lockout.
        for d in ("$apr1$abc", "{SHA}abc", "plaintext"):
            self.assertFalse(vs.is_bcrypt(d))


def _has_bcrypt_backend():
    try:
        import bcrypt  # noqa: F401

        return True
    except ImportError:
        pass
    return (
        subprocess.run(
            ["which", "htpasswd"], capture_output=True
        ).returncode
        == 0
    )


@unittest.skipUnless(
    _has_bcrypt_backend(), "no bcrypt module and no htpasswd binary on this host"
)
class TestHashing(unittest.TestCase):
    def test_hash_is_bcrypt_and_parses_back(self):
        digest = vs.bcrypt_hash("hunter2hunter2")
        self.assertTrue(vs.is_bcrypt(digest), digest)
        text = vs.add_entry("", "pilot", digest)
        self.assertEqual(vs.parse_htpasswd(text)["pilot"], digest)

    def test_salted(self):
        self.assertNotEqual(vs.bcrypt_hash("same"), vs.bcrypt_hash("same"))


if __name__ == "__main__":
    unittest.main()
