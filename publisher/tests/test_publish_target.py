# SPDX-License-Identifier: Apache-2.0
"""`make publish` — the plumbing, in dry run.

WHAT THIS TESTS AND WHY IT RUNS `make`. The target collapses RUNBOOK § 1 into
one line, and everything that can go wrong with it is wiring: a variable the
recipe forgets to forward, a flag that lands on the wrong verb, a step that
silently drops out of the chain, a credential variable that defaults instead of
refusing. None of that is visible from inside publish.sh — the recipe's
forwarding is half the surface — so the test drives the same entry point an
operator does.

It never publishes anything: DRY_RUN=1 prints the resolved chain and executes
nothing, so there is no network, no registry, no key and no ledger write.

THE LOAD-BEARING ASSERTIONS are the ones about refusal, not the ones about the
happy path: an unset signing key must stop the crank by name, and a dry run must
never carry a publication mode that could publish.
"""
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The golden release, so the printed chain names something that exists in this
# repository rather than a version invented for a test.
GOLDEN = sorted(p.parent.name for p in (ROOT / "spec/goldens").glob("*/entry.json"))[-1]

FAKE_ENV = {
    "VEXA_REPO": "/fake/dev/vexa",
    "VEXA_CHANNEL_REF": "registry.invalid/vexa/channel/vexa-internal",
    "VEXA_SIGNATURE_REPOSITORY": "registry.invalid/vexa/channel/vexa-internal/sigs",
    # A PATH, never a key. The point of the variable is that the material stays
    # with the human runner; the test asserts the path is forwarded verbatim.
    "VEXA_CHANNEL_KEY": "/fake/keys/channel.key",
    "VEXA_SIGNING_IDENTITY": "SHA256:fake-fingerprint",
    "VEXA_STATIONS_DIR": "/fake/dev/vexa-stations",
}


def publish(*make_vars, env=None, want_ok=True):
    """`make publish …` with a fake environment; returns (rc, output)."""
    e = {**os.environ, **(FAKE_ENV if env is None else env)}
    # Whatever the developer has exported must not leak into the run.
    for k in FAKE_ENV:
        if env is not None and k not in env:
            e.pop(k, None)
    p = subprocess.run(["make", "publish", *make_vars], cwd=ROOT, env=e,
                       capture_output=True, text=True)
    out = p.stdout + p.stderr
    if want_ok and p.returncode != 0:
        raise AssertionError(f"make publish failed ({p.returncode}):\n{out}")
    return p.returncode, out


def step_line(out, verb):
    """The printed argv for one publisher verb, as a single string."""
    for line in out.splitlines():
        if f"vexa_channel.py {verb} " in line or line.rstrip().endswith(f"vexa_channel.py {verb}"):
            return " ".join(line.split())
    raise AssertionError(f"no '{verb}' step in the printed chain:\n{out}")


class PublishDryRun(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _, cls.out = publish(f"RELEASE={GOLDEN}", "ENTRY_SEQ=7", "DRY_RUN=1")

    def test_the_whole_runbook_sequence_is_there_in_order(self):
        """Four verbs, one order. A crank that quietly lost `sign-images` would
        push an entry whose images admission reports as UNSIGNED."""
        positions = [self.out.index(f"vexa_channel.py {v}")
                     for v in ("fetch", "build", "sign-images", "push")]
        self.assertEqual(positions, sorted(positions), self.out)

    def test_nothing_executes(self):
        """A dry run that reached the network would be the worst of both."""
        self.assertIn("nothing fetched, built, signed or pushed", self.out)
        self.assertNotIn("REFUSED", self.out)
        self.assertNotIn("Traceback", self.out)

    def test_a_dry_run_cannot_carry_a_publishing_mode(self):
        """THE ONE THAT MATTERS on this side. The printed chain is meant to be
        read and re-run by hand; if it carried `--publication-mode published`,
        a copy-paste out of a dry run would publish."""
        build = step_line(self.out, "build")
        self.assertIn("--publication-mode dry_run", build)
        self.assertNotIn("published", build)

    def test_build_gets_the_inputs_fetch_wrote(self):
        """The two steps are joined by a working directory, and that join is
        the commonest hand-typed mistake in the manual sequence."""
        fetch, build = step_line(self.out, "fetch"), step_line(self.out, "build")
        self.assertIn(f"--out work/{GOLDEN}/in", fetch)
        self.assertIn(f"--archive work/{GOLDEN}/in/vexa-core-{GOLDEN}.tar.gz", build)
        self.assertIn(f"--provenance-bundle work/{GOLDEN}/in/source-provenance.sigstore.json", build)
        self.assertIn(f"--trusted-root work/{GOLDEN}/in/trusted-root.jsonl", build)
        self.assertIn("--entry-seq 7", build)
        self.assertIn("--channel vexa-internal", build)

    def test_sign_images_reads_the_map_build_wrote_and_the_signature_repo(self):
        """T2's whole subject: the signatures must land in the repository the
        subscriber's Kyverno asks, and that repository is an input here."""
        sign = step_line(self.out, "sign-images")
        self.assertIn(f"--candidate-map work/{GOLDEN}/entry/evidence/candidate-images.json", sign)
        self.assertIn(f"--signature-repository {FAKE_ENV['VEXA_SIGNATURE_REPOSITORY']}", sign)
        self.assertIn(f"--key {FAKE_ENV['VEXA_CHANNEL_KEY']}", sign)

    def test_push_signs_and_writes_the_ledger(self):
        """`--ledger` is what makes push the sole writer of channel.yaml. A
        packaged crank that dropped it would publish and leave the authority for
        entry_seq behind, silently."""
        push = step_line(self.out, "push")
        self.assertIn(f"--entry work/{GOLDEN}/entry", push)
        self.assertIn(f"--ref {FAKE_ENV['VEXA_CHANNEL_REF']}", push)
        self.assertIn(f"--sign-key {FAKE_ENV['VEXA_CHANNEL_KEY']}", push)
        self.assertIn(f"--ledger {FAKE_ENV['VEXA_STATIONS_DIR']}", push)

    def test_no_check_is_skipped(self):
        """Packaging, not weakening. If a skip flag ever appears in this chain
        it has to appear in this test first."""
        for flag in ("--skip-cosign-verify", "--skip-sign-artifact", "--break-glass",
                     "--plain-http", "--insecure"):
            self.assertNotIn(flag, self.out, f"the packaged crank passes {flag}")

    def test_the_key_is_a_path_and_is_never_read(self):
        """ADR-0001 § 6. The script forwards the location; the material stays
        with the human runner. Nothing key-shaped may reach the output."""
        self.assertNotIn("BEGIN", self.out)
        self.assertIn(FAKE_ENV["VEXA_CHANNEL_KEY"], self.out)


class PublishRefusals(unittest.TestCase):
    """Every missing input refuses BY NAME. A default here is a crank that runs
    against the wrong channel, the wrong ledger or the wrong key."""

    def test_missing_release(self):
        rc, out = publish("DRY_RUN=1", want_ok=False)
        self.assertNotEqual(rc, 0)
        self.assertIn("RELEASE is not set", out)

    def test_missing_entry_seq(self):
        rc, out = publish(f"RELEASE={GOLDEN}", "DRY_RUN=1", want_ok=False)
        self.assertNotEqual(rc, 0)
        self.assertIn("ENTRY_SEQ is not set", out)
        # and it says where the authority is, rather than guessing one
        self.assertIn("vexa_stations.py", out)

    def test_each_credential_variable_refuses_by_name(self):
        for missing in FAKE_ENV:
            env = {k: v for k, v in FAKE_ENV.items() if k != missing}
            rc, out = publish(f"RELEASE={GOLDEN}", "ENTRY_SEQ=7", "DRY_RUN=1",
                              env=env, want_ok=False)
            self.assertNotEqual(rc, 0, f"{missing} unset and the crank ran anyway:\n{out}")
            self.assertIn(f"${missing} is not set", out)

    def test_published_mode_requires_the_named_human(self):
        """RUNBOOK § 2.3: publication approval is ours and it is a person. The
        packaged form must not be the one that forgets to ask."""
        rc, out = publish(f"RELEASE={GOLDEN}", "ENTRY_SEQ=7", "DRY_RUN=1",
                          "PUBLICATION_MODE=published", want_ok=False)
        self.assertNotEqual(rc, 0)
        self.assertIn("APPROVED_BY", out)

    def test_a_false_dry_run_is_off_not_on(self):
        """DRY_RUN=0 must not be a dry run. Present-but-false is exactly how a
        `dry run` publishes for real.

        Proven without touching the network: `python3` is shimmed on PATH to
        announce itself and fail, so a real run stops at step 1 having EXECUTED
        it, while a dry run would have printed the chain and exited 0.
        """
        with tempfile.TemporaryDirectory() as tmp:
            shim = pathlib.Path(tmp, "python3")
            shim.write_text("#!/bin/sh\necho SHIM-EXECUTED \"$@\"\nexit 9\n")
            shim.chmod(0o755)
            env = {**FAKE_ENV, "PATH": f"{tmp}:{os.environ['PATH']}"}
            rc, out = publish(f"RELEASE={GOLDEN}", "ENTRY_SEQ=7", "DRY_RUN=0",
                              env=env, want_ok=False)
        self.assertNotEqual(rc, 0)
        self.assertIn("SHIM-EXECUTED", out, "DRY_RUN=0 printed instead of running")
        self.assertNotIn("nothing fetched, built, signed or pushed", out)


class PublishIsDocumented(unittest.TestCase):
    """The one-liner is only a one-liner if the runbook leads with it."""

    def test_runbook_section_1_leads_with_make_publish(self):
        runbook = (ROOT / "RUNBOOK.md").read_text()
        one = runbook.index("## 1 · Beat one")
        two = runbook.index("## 2 · Beat two")
        section = runbook[one:two]
        self.assertIn("make publish", section)
        m = re.search(r"make publish RELEASE=\S+ ENTRY_SEQ=\S+", section)
        self.assertIsNotNone(m, "RUNBOOK § 1 does not show the invocation")
        # ...before the expanded steps, not after them as a footnote.
        self.assertLess(section.index("make publish"),
                        section.index("vexa_channel.py fetch"),
                        "RUNBOOK § 1 still leads with the manual sequence")


if __name__ == "__main__":
    unittest.main()
