"""vexa_channel.py push --no-release-tag, with a stub oras: which tags does a push write?"""
import json, os, pathlib, stat, subprocess, sys, tempfile, unittest

PUBLISHER = pathlib.Path(__file__).resolve().parents[1] / "vexa_channel.py"
REF = "registry.test/vexa/channel/x"


def push(tmp, seq, *flags):
    tmp = pathlib.Path(tmp)
    stub, log = tmp / "bin", tmp / "oras.log"
    stub.mkdir(exist_ok=True)
    oras = stub / "oras"
    oras.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\necho "Digest: sha256:{seq:064d}"\n')
    oras.chmod(oras.stat().st_mode | stat.S_IEXEC)
    entry = tmp / f"entry{seq}"
    entry.mkdir()
    (entry / "VERIFY.md").write_text("x")
    (entry / "entry.json").write_text(json.dumps(
        {"release": {"version": "1.2.3-estate-20261106"}, "channel": {"entry_seq": seq}, "evidence": []}))
    env = {**os.environ, "PATH": f"{stub}:{os.environ['PATH']}"}
    env.pop("VEXA_STATIONS_DIR", None)
    subprocess.run([sys.executable, str(PUBLISHER), "push", "--entry", str(entry), "--ref", REF, *flags],
                   check=True, env=env, capture_output=True, text=True)
    return log.read_text()


def written(log):
    """Every tag the log writes: a push target, or the last word of `oras tag`."""
    tags = []
    for line in log.splitlines():
        w = line.split()
        if w[0] == "push":
            tags.append(next(x for x in w if x.startswith(REF + ":")).rsplit(":", 1)[-1])
        elif w[0] == "tag":
            tags.append(w[-1])
    return tags


class NoReleaseTag(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup); self.tmp = d.name

    def test_without_the_flag_the_release_tag_is_written_as_before(self):
        self.assertEqual(written(push(self.tmp, 7))[0], "1.2.3-estate-20261106")

    def test_two_pushes_never_write_the_release_tag(self):
        push(self.tmp, 7, "--no-release-tag")
        tags = written(push(self.tmp, 8, "--no-release-tag"))
        self.assertNotIn("1.2.3-estate-20261106", tags)
        self.assertEqual({"1.2.3-estate-20261106-seq7", "1.2.3-estate-20261106-seq8"}, set(tags))

    def test_channel_tag_still_creates_the_day_tag_once_asked(self):
        tags = written(push(self.tmp, 7, "--no-release-tag", "--channel-tag", "1.2.3-estate-20261106"))
        self.assertEqual(tags[0], "1.2.3-estate-20261106-seq7")
        self.assertEqual(tags[-1], "1.2.3-estate-20261106")


if __name__ == "__main__":
    unittest.main()
