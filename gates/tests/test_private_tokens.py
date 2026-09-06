"""The private-token gate: it must catch, and it must not echo.

Every fixture token below is invented for the test. The real list lives only as
digests in `gates/private-tokens.sha256`, so these tests can plant a token, prove
the gate refuses it, and prove the refusal never reproduces the token text —
without the repository ever holding a real one.
"""

from __future__ import annotations

import contextlib
import hashlib
import pathlib
import subprocess
import sys
import tempfile
import unittest

GATES = pathlib.Path(__file__).resolve().parent.parent
ROOT = GATES.parent
CHECK = GATES / "check-private-tokens.py"
SHIPPED = GATES / "private-tokens.sha256"

# Invented, and deliberately unlike anything real.
FIXTURE = "quokkamint"
FIXTURE_CHANNEL = "quokkamint-stable"
FIXTURE_DOMAIN = "quokkamint.example"


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class GateHarness(unittest.TestCase):
    def run_gate(self, root: pathlib.Path, tokens: pathlib.Path, *extra: str):
        return subprocess.run(
            [sys.executable, str(CHECK), "--root", str(root),
             "--tokens", str(tokens), *extra],
            capture_output=True, text=True)

    def tree(self, stack, files: dict[str, str], tokens=(FIXTURE,)):
        root = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory()))
        for name, body in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        listing = root.parent / f"{root.name}.sha256"
        listing.write_text("\n".join(sorted(digest(t) for t in tokens)) + "\n")
        return root, listing


class TestItCatches(GateHarness):
    def test_a_planted_token_fails_and_names_the_line(self):
        with contextlib.ExitStack() as stack:
            root, tokens = self.tree(stack, {
                "docs/page.md": f"first line\nsecond line names {FIXTURE} here\n",
                "docs/clean.md": "nothing to see\n",
            })
            done = self.run_gate(root, tokens)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("docs/page.md:2", done.stderr)
        self.assertNotIn("docs/clean.md", done.stderr)

    def test_it_finds_the_token_inside_a_hyphenated_identifier(self):
        with contextlib.ExitStack() as stack:
            root, tokens = self.tree(stack, {
                "spec/a.md": f'"channel": "{FIXTURE_CHANNEL}"\n',
                "spec/b.md": f"mail: someone@{FIXTURE_DOMAIN}\n",
                "spec/c.md": f"an_underscored_{FIXTURE}_identifier\n",
            })
            done = self.run_gate(root, tokens)
        self.assertEqual(done.returncode, 1, done.stderr)
        for hit in ("spec/a.md:1", "spec/b.md:1", "spec/c.md:1"):
            self.assertIn(hit, done.stderr)

    def test_an_untracked_file_is_still_scanned(self):
        """The hole this gate fell into on its own first run.

        `git ls-files` lists TRACKED files. A leak arrives in a file that is not
        staged yet — so a tracked-only scan passes locally at the one moment it
        most needs to refuse, and the leak is only caught after it is pushed.
        """
        with contextlib.ExitStack() as stack:
            root, tokens = self.tree(stack, {
                "docs/brand-new.md": f"never staged, names {FIXTURE}\n",
                ".gitignore": "ignored/\n",
                "ignored/junk.md": f"ignored files never ship: {FIXTURE}\n",
            })
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            done = self.run_gate(root, tokens)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("docs/brand-new.md:1", done.stderr)
        self.assertNotIn("ignored/junk.md", done.stderr)

    def test_a_clean_tree_passes(self):
        with contextlib.ExitStack() as stack:
            root, tokens = self.tree(stack, {
                "docs/page.md": "pilot-stable is the neutral example name\n"})
            done = self.run_gate(root, tokens)
        self.assertEqual(done.returncode, 0, done.stderr)


class TestItDoesNotEcho(GateHarness):
    """The failure message is the leak surface: CI logs are as public as the repo."""

    def assert_no_token_text(self, output: str):
        for form in (FIXTURE, FIXTURE.upper(), FIXTURE.capitalize(),
                     FIXTURE_CHANNEL, FIXTURE_DOMAIN):
            self.assertNotIn(form, output,
                             "the gate reproduced the token it was refusing")

    def test_the_failure_message_contains_no_token_text(self):
        with contextlib.ExitStack() as stack:
            root, tokens = self.tree(stack, {
                "docs/page.md": f"a line about {FIXTURE_CHANNEL} and "
                                f"ops@{FIXTURE_DOMAIN}\n",
            })
            done = self.run_gate(root, tokens)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("docs/page.md:1", done.stderr)
        self.assert_no_token_text(done.stdout + done.stderr)

    def test_a_token_in_a_file_name_is_caught_and_the_name_is_redacted(self):
        with contextlib.ExitStack() as stack:
            root, tokens = self.tree(stack, {
                f"docs/{FIXTURE_CHANNEL}-notes.md": "the body is clean\n"})
            done = self.run_gate(root, tokens)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("docs/<redacted>:0", done.stderr)
        self.assert_no_token_text(done.stdout + done.stderr)


class TestTheShippedList(unittest.TestCase):
    def test_it_is_digests_and_only_digests(self):
        lines = [x.strip() for x in SHIPPED.read_text().splitlines() if x.strip()]
        self.assertTrue(lines, "the shipped token list is empty")
        for line in lines:
            self.assertRegex(line, r"^[0-9a-f]{64}$",
                             "a token list line that is not a lowercase sha256 "
                             "is a token in plain text")

    def test_the_repository_itself_is_clean(self):
        done = subprocess.run([sys.executable, str(CHECK)],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
