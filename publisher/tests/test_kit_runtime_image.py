# SPDX-License-Identifier: Apache-2.0
"""The kit runtime image's build contract, read off the Dockerfile.

These tests do not build anything — CI holds no registry credentials and this
repository's whole boundary is that nothing here touches a cluster or a
registry. What they CAN hold is the contract: every binary the sender shells
out to is installed, everything it does not need is absent, and the two things
that decide whether a receipt is trustworthy — a pinned base and a checksummed
kubectl — cannot quietly stop being pinned.

Through station chart 1.0.5 there was no image at all: the channel carried the
kit as a TARBALL and `receiptSender.image` had nothing to point at, so the
sender was publishable, renderable and unrunnable.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "kit/runtime/Dockerfile"


class KitRuntimeImage(unittest.TestCase):
    def setUp(self):
        self.text = DOCKERFILE.read_text()

    def test_every_base_is_digest_pinned(self):
        """A tag is not an identity. This image is admission-checked in the
        station namespace; its own inputs get the same discipline."""
        for line in self.text.splitlines():
            if line.startswith("FROM "):
                ref = line.split()[1]
                self.assertRegex(ref, r"@sha256:[a-f0-9]{64}$|^ghcr\.io/.+:v[\d.]+$", line)
        # the python base, specifically, by digest and not by tag alone
        self.assertRegex(self.text, r"FROM python:3\.12-slim-\w+@sha256:[a-f0-9]{64}")

    def test_kubectl_is_version_pinned_and_checksummed(self):
        """A downloaded binary with no checksum is a supply chain with no
        supply chain. The build fails rather than the pod shipping."""
        self.assertRegex(self.text, r"KUBECTL_VERSION=v\d+\.\d+\.\d+")
        self.assertRegex(self.text, r"KUBECTL_SHA256=[a-f0-9]{64}")
        self.assertIn("sha256sum -c -", self.text)

    def test_it_carries_what_the_sender_shells_out_to(self):
        """python3 · PyYAML · jsonschema · kubectl · oras. Miss one and the
        failure lands at 03:17 in somebody else's cluster."""
        self.assertIn("PyYAML==", self.text)
        self.assertIn("jsonschema==", self.text)
        self.assertIn("/usr/local/bin/kubectl", self.text)
        self.assertIn("/usr/local/bin/oras", self.text)

    def instructions(self):
        """The Dockerfile with its commentary stripped. The commentary EXPLAINS
        why cosign is absent, so a naive substring search over the whole file
        would find the word and fail on the explanation."""
        return "\n".join(l for l in self.text.splitlines()
                         if l.strip() and not l.lstrip().startswith("#"))

    def test_it_carries_no_cosign(self):
        """The sender neither signs nor verifies. A cosign binary here would be
        unused attack surface in a pod that holds a channel credential —
        signature verification belongs to Kyverno and the PreSync verifier,
        which have their own images."""
        self.assertNotIn("cosign", self.instructions().lower())

    def test_the_python_deps_are_exactly_pinned(self):
        """`pip install PyYAML` resolves to whatever exists on build day, which
        makes two builds of the same commit two different images."""
        for spec in re.findall(r"pip install[^\n]*", self.instructions()):
            packages = [tok for tok in spec.split()[2:] if not tok.startswith("-")]
            self.assertTrue(packages, spec)
            for pkg in packages:
                self.assertRegex(pkg, r"^[A-Za-z0-9_.-]+==[\w.]+$", spec)

    def test_the_repo_root_is_not_slash(self):
        """The tool reads `station/chart/Chart.yaml` relative to the kit's
        PARENT. Unpacked at /kit the parent is /, and the station chart version
        — the one field saying which machinery produced a receipt — would be
        null on every receipt this image ever sends."""
        self.assertIn("COPY kit /opt/vexa-delivery/kit", self.text)
        self.assertIn("COPY station/chart/Chart.yaml", self.text)
        self.assertIn("ln -s /opt/vexa-delivery/kit /kit", self.text)

    def test_it_runs_as_the_user_the_chart_declares(self):
        """The chart runs this pod runAsNonRoot, runAsUser 65532, read-only
        root, HOME on an emptyDir. The image matches that rather than merely
        tolerating it."""
        self.assertIn("USER 65532:65532", self.text)
        self.assertIn("HOME=/work", self.text)

    def test_the_entrypoint_is_the_tool(self):
        self.assertIn('ENTRYPOINT ["python3", "/kit/validate/vexa_validate.py"]', self.text)

    def test_the_dockerignore_keeps_a_developers_bytecode_out(self):
        ignore = (ROOT / ".dockerignore").read_text()
        self.assertIn("__pycache__", ignore)
        self.assertIn(".git", ignore)


class KitRevisionStamp(unittest.TestCase):
    """`git_revision()` in a pod with no git and no .git.

    The bare `returncode` check that stood here before 1.0.6 would have raised
    FileNotFoundError inside the image — a crash, not a degradation — because a
    missing binary is an OSError and not a non-zero exit.
    """

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "vv", ROOT / "kit/validate/vexa_validate.py")
        self.vv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.vv)

    def test_it_reads_the_build_stamp_when_git_is_absent(self):
        import pathlib as pl
        import tempfile
        tmp = pl.Path(tempfile.mkdtemp())
        (tmp / "KIT_REVISION").write_text("commit=0beb1cf\ndescribe=v0.1.6-3-g0beb1cf\n")
        self.vv.REPO, old = tmp, self.vv.REPO
        try:
            def boom(*a, **k):
                raise FileNotFoundError("git")
            real, self.vv.subprocess.run = self.vv.subprocess.run, boom
            try:
                self.assertEqual(self.vv.git_revision(),
                                 {"commit": "0beb1cf", "describe": "v0.1.6-3-g0beb1cf"})
            finally:
                self.vv.subprocess.run = real
        finally:
            self.vv.REPO = old

    def test_unknown_stays_null_rather_than_being_invented(self):
        import pathlib as pl
        import tempfile
        tmp = pl.Path(tempfile.mkdtemp())
        (tmp / "KIT_REVISION").write_text("commit=unknown\ndescribe=unknown\n")
        self.vv.REPO, old = tmp, self.vv.REPO
        try:
            def boom(*a, **k):
                raise FileNotFoundError("git")
            real, self.vv.subprocess.run = self.vv.subprocess.run, boom
            try:
                self.assertEqual(self.vv.git_revision(), {"commit": None, "describe": None})
            finally:
                self.vv.subprocess.run = real
        finally:
            self.vv.REPO = old


if __name__ == "__main__":
    unittest.main()
