# SPDX-License-Identifier: Apache-2.0
"""`push` and the tags it writes: a published tag never moves.

THE DEFECT THIS PINS. `push` used to put every entry at `<ref>:<release>` —
for an estate that is the DAY tag, `<X.Y.Z>-estate-<YYYYMMDD>` — whatever
`--channel-tag` said, and then add `<release>-seq<N>` beside it. Two
publishes on one UTC day therefore wrote the same tag twice: the second one
moved it. Under "a published tag never moves" that allowed exactly one publish
per day, and on a registry that does let a tag move it silently re-pointed a
tag somebody may already have resolved.

What holds now, and what each test below proves:

  - an ESTATE entry lands on its own permanent `<release>-seq<N>` tag only;
  - an estate's release (day) tag is written ONLY on `--release-tag`, and only
    when it does not exist yet. An existing one is refused, before anything is
    signed or pushed, never overwritten;
  - an OSS entry is UNCHANGED: pushed at `v<X.Y.Z>`, which a refresh moves, as
    spec/channel.md § Freshness promises the PreSync gate;
  - for both, a `<release>-seq<N>` that already exists is refused, and
    `--channel-tag` cannot be used to move a permanent tag;
  - for both, every tag written is printed and read back, and a read-back that
    names a different digest is a refusal.

Hermetic. `oras` is replaced by an in-memory registry that, like a stock
registry, WOULD let a tag move — and records it when it does. The assertions
are on that record, so "never moved" is checked against what the publisher
asked for, not against a registry that happened to refuse it.
"""
import contextlib
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_channel as vc    # noqa: E402
import vexa_stations as vs   # noqa: E402

REF = "registry.invalid/vexa/channel/fixture-estate"
DAY = "0.1.0-estate-20261104"


def completed(stdout=""):
    return subprocess.CompletedProcess([], 0, stdout, "")


class FakeRegistry:
    """Tags -> digest, behind the three oras verbs `push` uses.

    It lets a tag move, exactly as a stock registry does, and writes every move
    into `self.moves`. `self.lie` makes `resolve` answer a different digest for
    a tag that exists — a concurrent writer, or a proxy serving something else.
    """

    def __init__(self):
        self.tags = {}
        self.moves = []
        self.calls = []
        self.lie = {}
        self._n = 0

    def __call__(self, cmd, **kw):
        cmd = list(cmd)
        self.calls.append(cmd)
        if cmd[0] != "oras":
            raise AssertionError(f"push ran something other than oras: {cmd}")
        verb, args = cmd[1], [a for a in cmd[2:] if a not in ("--plain-http", "--insecure")]
        if verb == "push":
            i = args.index("--artifact-type")
            del args[i:i + 2]
            ref = args[0]
            self._n += 1
            digest = "sha256:" + hashlib.sha256(f"{ref}#{self._n}".encode()).hexdigest()
            self._write(ref, digest)
            return completed(f"Uploaded entry.json\nPushed [registry] {ref}\n"
                             f"ArtifactType: {vc.ENTRY_MEDIA_TYPE}\nDigest: {digest}\n")
        if verb == "tag":
            src, *new = args
            repo, digest = src.split("@", 1)
            for tag in new:
                self._write(f"{repo}:{tag}", digest)
            return completed("")
        if verb == "resolve":
            ref = args[0]
            if ref not in self.tags:
                raise subprocess.CalledProcessError(
                    1, cmd, output="",
                    stderr=f"Error: failed to resolve {ref.rsplit(':', 1)[-1]}: {ref}: not found\n")
            return completed(self.lie.get(ref, self.tags[ref]) + "\n")
        raise AssertionError(f"unexpected oras verb: {cmd}")

    def _write(self, ref, digest):
        was = self.tags.get(ref)
        if was is not None and was != digest:
            self.moves.append((ref, was, digest))
        self.tags[ref] = digest

    def writes(self):
        """Every ref a push or tag call targeted, in order."""
        out = []
        for c in self.calls:
            args = [a for a in c[2:] if a not in ("--plain-http", "--insecure")]
            if c[1] == "push":
                i = args.index("--artifact-type")
                out.append(args[i + 2])
            elif c[1] == "tag":
                repo = args[0].split("@", 1)[0]
                out.extend(f"{repo}:{t}" for t in args[1:])
        return out


GOLDEN = pathlib.Path(__file__).resolve().parents[2] / "spec" / "goldens" / "v0.12.23"
OSS = "v0.12.23"


def make_entry(root, seq, release=DAY, channel="fixture-estate"):
    """An ESTATE entry: it carries the `estate` block `platform-entry` writes,
    which is what makes it one (docs/verify.mdx)."""
    d = pathlib.Path(root) / f"entry-seq{seq}"
    d.mkdir()
    (d / "entry.json").write_text(json.dumps({
        "schema_version": 1,
        "channel": {"name": channel, "entry_seq": seq, "supersedes": None},
        "release": {"version": release, "source_sha": "c" * 40},
        "publication": {"mode": "candidate", "published_at": "2026-11-04T16:00:00Z"},
        "evidence": [],
        "estate": {"kind": "platform_estate", "release_name": "vexa"},
    }))
    (d / "VERIFY.md").write_text("fixture\n")
    return d


def oss_entry(root):
    """The golden OSS entry, v0.12.23 at seq 1 — no `estate` block."""
    d = pathlib.Path(root) / "oss-seq1"
    d.mkdir()
    shutil.copy(GOLDEN / "entry.json", d / "entry.json")
    shutil.copy(GOLDEN / "VERIFY.md", d / "VERIFY.md")
    return d


def push(registry, entry_dir, *extra):
    """`vexa_channel.py push`, through main(), against the fake. -> (rc, stdout+stderr)."""
    out = io.StringIO()
    with mock.patch.object(vc, "run", side_effect=registry), \
         mock.patch.dict(vc.os.environ, {"VEXA_STATIONS_DIR": ""}), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            rc = vc.main(["push", "--entry", str(entry_dir), "--ref", REF, *extra])
        except SystemExit as e:   # argparse: an unknown flag is exit 2
            rc = e.code
    return rc, out.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vexa-push-")
        self.reg = FakeRegistry()


class TwoPublishesOneDay(Base):

    def test_both_succeed_each_on_its_own_seq_tag(self):
        rc1, out1 = push(self.reg, make_entry(self.tmp, 1))
        rc2, out2 = push(self.reg, make_entry(self.tmp, 2))
        self.assertEqual((rc1, rc2), (0, 0), out1 + out2)
        self.assertEqual(set(self.reg.tags), {f"{REF}:{DAY}-seq1", f"{REF}:{DAY}-seq2"})
        self.assertNotEqual(self.reg.tags[f"{REF}:{DAY}-seq1"],
                            self.reg.tags[f"{REF}:{DAY}-seq2"])
        self.assertEqual(self.reg.moves, [], "a published tag moved")

    def test_the_entry_is_pushed_straight_to_its_seq_tag(self):
        push(self.reg, make_entry(self.tmp, 1))
        pushes = [c for c in self.reg.calls if c[1] == "push"]
        self.assertEqual(len(pushes), 1)
        self.assertIn(f"{REF}:{DAY}-seq1", pushes[0])

    def test_the_day_tag_is_not_written_without_the_flag(self):
        push(self.reg, make_entry(self.tmp, 1))
        push(self.reg, make_entry(self.tmp, 2))
        self.assertNotIn(f"{REF}:{DAY}", self.reg.writes())
        self.assertNotIn(f"{REF}:{DAY}", self.reg.tags)


class ReleaseTagOnRequest(Base):

    def test_created_when_asked_and_absent(self):
        rc, out = push(self.reg, make_entry(self.tmp, 1), "--release-tag")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.reg.tags[f"{REF}:{DAY}"], self.reg.tags[f"{REF}:{DAY}-seq1"])

    def test_an_existing_one_is_refused_and_nothing_is_pushed(self):
        rc, out = push(self.reg, make_entry(self.tmp, 1), "--release-tag")
        self.assertEqual(rc, 0, out)
        first = self.reg.tags[f"{REF}:{DAY}"]
        writes_before = len(self.reg.writes())

        rc, out = push(self.reg, make_entry(self.tmp, 2), "--release-tag")
        self.assertEqual(rc, 3, out)
        self.assertIn("REFUSED", out)
        self.assertIn(f"{REF}:{DAY}", out)
        self.assertIn("never moved", out)
        # Refused BEFORE anything was written: no seq-2 entry, the day tag where it was.
        self.assertEqual(len(self.reg.writes()), writes_before)
        self.assertNotIn(f"{REF}:{DAY}-seq2", self.reg.tags)
        self.assertEqual(self.reg.tags[f"{REF}:{DAY}"], first)
        self.assertEqual(self.reg.moves, [])

    def test_without_the_flag_an_existing_day_tag_is_simply_left_alone(self):
        push(self.reg, make_entry(self.tmp, 1), "--release-tag")
        first = self.reg.tags[f"{REF}:{DAY}"]
        rc, out = push(self.reg, make_entry(self.tmp, 2))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.reg.tags[f"{REF}:{DAY}"], first)
        self.assertEqual(self.reg.moves, [])


class SeqTagIsPermanent(Base):

    def test_republishing_a_seq_is_refused_before_anything_is_written(self):
        entry = make_entry(self.tmp, 1)
        self.assertEqual(push(self.reg, entry)[0], 0)
        first = self.reg.tags[f"{REF}:{DAY}-seq1"]
        writes_before = len(self.reg.writes())
        rc, out = push(self.reg, entry)
        self.assertEqual(rc, 3, out)
        self.assertIn(f"{REF}:{DAY}-seq1", out)
        self.assertEqual(len(self.reg.writes()), writes_before)
        self.assertEqual(self.reg.tags[f"{REF}:{DAY}-seq1"], first)
        self.assertEqual(self.reg.moves, [])


class ChannelTagCannotMoveAPermanentTag(Base):

    def test_the_release_tag_is_not_a_channel_tag(self):
        push(self.reg, make_entry(self.tmp, 1), "--release-tag")
        writes_before = len(self.reg.writes())
        rc, out = push(self.reg, make_entry(self.tmp, 2), "--channel-tag", DAY)
        self.assertEqual(rc, 3, out)
        self.assertIn("--release-tag", out)
        self.assertEqual(len(self.reg.writes()), writes_before)
        self.assertEqual(self.reg.moves, [])

    def test_another_entrys_seq_tag_is_not_a_channel_tag(self):
        push(self.reg, make_entry(self.tmp, 1))
        rc, out = push(self.reg, make_entry(self.tmp, 2), "--channel-tag",
                       f"{REF}:{DAY}-seq1")
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.reg.moves, [])

    def test_the_floating_pointer_still_moves(self):
        """`current` is the one tag the channel spec defines as floating. It moves
        when, and only when, the publisher names it."""
        push(self.reg, make_entry(self.tmp, 1), "--channel-tag", "current")
        rc, out = push(self.reg, make_entry(self.tmp, 2), "--channel-tag", "current")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.reg.tags[f"{REF}:current"], self.reg.tags[f"{REF}:{DAY}-seq2"])


class EveryTagIsPrintedAndReadBack(Base):

    def test_each_tag_written_is_resolved_after_the_push_and_printed(self):
        rc, out = push(self.reg, make_entry(self.tmp, 1), "--release-tag",
                       "--channel-tag", "current")
        self.assertEqual(rc, 0, out)
        digest = self.reg.tags[f"{REF}:{DAY}-seq1"]
        last_write = max(i for i, c in enumerate(self.reg.calls) if c[1] in ("push", "tag"))
        read_back = {c[-1] for c in self.reg.calls[last_write + 1:] if c[1] == "resolve"}
        for tag in (f"{DAY}-seq1", DAY, "current"):
            self.assertIn(f"{REF}:{tag}", read_back, f"{tag} was not read back")
            self.assertRegex(out, rf"{REF}:{tag}\s.*{digest}", f"{tag} not printed")

    def test_a_read_back_that_names_another_digest_is_refused(self):
        entry = make_entry(self.tmp, 1)
        real = self.reg.__call__

        def drifting(cmd, **kw):
            res = real(cmd, **kw)
            if cmd[1] == "push":   # after the write, the registry serves something else
                self.reg.lie[f"{REF}:{DAY}-seq1"] = "sha256:" + "0" * 64
            return res

        out = io.StringIO()
        with mock.patch.object(vc, "run", side_effect=drifting), \
             mock.patch.dict(vc.os.environ, {"VEXA_STATIONS_DIR": ""}), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = vc.main(["push", "--entry", str(entry), "--ref", REF])
        self.assertEqual(rc, 3, out.getvalue())
        self.assertIn("sha256:" + "0" * 64, out.getvalue())


class OssReleaseTagIsUnchanged(Base):
    """AN OSS RELEASE KEEPS THE CONTRACT IT WAS PUBLISHED UNDER.

    spec/channel.md § Freshness: a refresh re-signs the same release at the
    next entry_seq and `push` moves the release tag to it, because the PreSync
    gate of a chart without `verify.entryTag` asks for `:v<appVersion>`
    (kit/verify/chart-template/channel-verify.yaml) and would otherwise keep
    verifying the stale entry until it expired. Only an ESTATE's day tag is
    written on request and never moved; this class pins that the OSS side is
    exactly what it was.
    """

    def refresh(self, src):
        out = pathlib.Path(self.tmp) / "oss-seq2"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vc.main(["refresh", "--entry", str(src), "--out", str(out)]), 0)
        return out

    def test_the_release_tag_is_written_with_no_flag(self):
        rc, out = push(self.reg, oss_entry(self.tmp))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.reg.tags[f"{REF}:{OSS}"], self.reg.tags[f"{REF}:{OSS}-seq1"])

    def test_a_refresh_moves_the_release_tag_and_nothing_else(self):
        src = oss_entry(self.tmp)
        self.assertEqual(push(self.reg, src)[0], 0)
        first = self.reg.tags[f"{REF}:{OSS}"]
        rc, out = push(self.reg, self.refresh(src))
        self.assertEqual(rc, 0, out)
        second = self.reg.tags[f"{REF}:{OSS}-seq2"]
        self.assertNotEqual(first, second)
        self.assertEqual(self.reg.tags[f"{REF}:{OSS}"], second, "the release tag did not move")
        self.assertEqual(self.reg.tags[f"{REF}:{OSS}-seq1"], first, "seq 1's permanent tag moved")
        self.assertEqual(self.reg.moves, [(f"{REF}:{OSS}", first, second)])

    def test_the_entry_is_still_pushed_at_the_release_tag(self):
        push(self.reg, oss_entry(self.tmp))
        pushes = [c for c in self.reg.calls if c[1] == "push"]
        self.assertEqual(len(pushes), 1)
        self.assertIn(f"{REF}:{OSS}", pushes[0])

    def test_both_tags_are_read_back(self):
        rc, out = push(self.reg, oss_entry(self.tmp))
        self.assertEqual(rc, 0, out)
        last_write = max(i for i, c in enumerate(self.reg.calls) if c[1] in ("push", "tag"))
        read_back = {c[-1] for c in self.reg.calls[last_write + 1:] if c[1] == "resolve"}
        self.assertEqual(read_back, {f"{REF}:{OSS}", f"{REF}:{OSS}-seq1"})

    def test_an_existing_seq_tag_is_refused_for_an_oss_release_too(self):
        src = oss_entry(self.tmp)
        self.assertEqual(push(self.reg, src)[0], 0)
        writes_before = len(self.reg.writes())
        rc, out = push(self.reg, src)
        self.assertEqual(rc, 3, out)
        self.assertEqual(len(self.reg.writes()), writes_before)
        self.assertEqual(self.reg.moves, [])

    def test_the_channel_tag_still_cannot_name_another_seq_tag(self):
        src = oss_entry(self.tmp)
        self.assertEqual(push(self.reg, src)[0], 0)
        rc, out = push(self.reg, self.refresh(src), "--channel-tag", f"{OSS}-seq1")
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.reg.moves, [])


class TheLedgerShowsTheSecondEntry(Base):

    def test_show_names_the_newest_row_and_its_seq_tag(self):
        ledger = pathlib.Path(self.tmp) / "ledger"
        ledger.mkdir()
        for args in (["init", "-q", "-b", "main"], ["config", "user.email", "t@vexa.invalid"],
                     ["config", "user.name", "t"], ["commit", "-q", "--allow-empty", "-m", "i"]):
            subprocess.run(["git", "-C", str(ledger), *args], check=True, capture_output=True)
        for seq in (1, 2):
            rc, out = push(self.reg, make_entry(self.tmp, seq), "--ledger", str(ledger))
            self.assertEqual(rc, 0, out)

        shown = io.StringIO()
        with contextlib.redirect_stdout(shown):
            self.assertEqual(vs.main(["--ledger", str(ledger), "show"]), 0)
        self.assertIn(f"{DAY}-seq2", shown.getvalue())


if __name__ == "__main__":
    unittest.main()
