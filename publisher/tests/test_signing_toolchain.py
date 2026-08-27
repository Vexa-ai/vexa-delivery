"""T1/T2 — the signing toolchain pin and the Kyverno-shaped push-time check.

Hermetic: cosign and oras are replaced with stubs. What is asserted here is the
DECISION each check makes, not cosign's behaviour — cosign's behaviour was
measured against live Kyverno 1.19.0 and is recorded in
docs/receipts/2026-08-25-signature-layout.md.
"""
import json
import os
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_channel as vc  # noqa: E402

DIGEST = "sha256:" + "ab" * 32
LEGACY_MANIFEST = json.dumps({
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "layers": [{"mediaType": vc.COSIGN_LEGACY_SIGNATURE_LAYER, "annotations": {}}],
})
REFERRERS_MANIFEST = json.dumps({
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [{"artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json"}],
})


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class Base(unittest.TestCase):
    def setUp(self):
        vc._COSIGN_CACHE.clear()
        self.addCleanup(vc._COSIGN_CACHE.clear)


class ToolchainPin(Base):
    def _version(self, text):
        return mock.patch.object(vc.subprocess, "run", return_value=completed(text))

    def test_pinned_series_is_accepted(self):
        with self._version("GitVersion:    v2.6.5\n"):
            major, full = vc.require_pinned_cosign()
        self.assertEqual(major, 2)
        self.assertEqual(full, "2.6.5")

    def test_wrong_major_refuses_and_says_why(self):
        with self._version("GitVersion:    v3.1.3\n"):
            with self.assertRaises(vc.CheckFailure) as cm:
                vc.require_pinned_cosign()
        msg = str(cm.exception)
        self.assertTrue(msg.startswith("T1:"))
        # The refusal must name the consequence, not just the mismatch.
        self.assertIn("Kyverno 1.19", msg)
        self.assertIn("sha256-<digest>.sig", msg)
        self.assertIn(vc.COSIGN_RECOMMENDED_VERSION, msg)

    def test_unpinned_escape_hatch_is_explicit(self):
        with self._version("GitVersion:    v3.1.3\n"):
            with mock.patch.dict(os.environ, {"VEXA_COSIGN_ALLOW_UNPINNED": "1"}):
                major, full = vc.require_pinned_cosign()
        self.assertEqual((major, full), (3, "3.1.3"))

    def test_unreadable_version_refuses(self):
        with self._version("some other tool\n"):
            with self.assertRaises(vc.CheckFailure):
                vc.require_pinned_cosign()

    def test_missing_binary_refuses(self):
        with mock.patch.object(vc.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(vc.CheckFailure):
                vc.require_pinned_cosign()

    def test_cosign_bin_is_overridable(self):
        with mock.patch.dict(os.environ, {"COSIGN_BIN": "/opt/cosign-2.6.5"}):
            self.assertEqual(vc.cosign_bin(), "/opt/cosign-2.6.5")


class OfflineFlags(Base):
    def _help(self, text):
        return mock.patch.object(vc.subprocess, "run", return_value=completed(text))

    def test_two_x_needs_no_signing_config_flag(self):
        with self._help("--tlog-upload=true:\n--new-bundle-format=false:\n"):
            self.assertEqual(vc.cosign_offline_flags(),
                             ["--tlog-upload=false", "--new-bundle-format=false"])

    def test_three_x_gets_the_signing_config_flag_it_requires(self):
        with self._help("--tlog-upload\n--new-bundle-format\n--use-signing-config\n"):
            self.assertIn("--use-signing-config=false", vc.cosign_offline_flags())


class SignatureTag(unittest.TestCase):
    def test_tag_is_what_kyverno_gets(self):
        self.assertEqual(vc.signature_tag(DIGEST), "sha256-" + "ab" * 32 + ".sig")


class KyvernoReadable(Base):
    """T2 decides on two things only: is the tag there, and is it the right shape."""

    def _fake(self, manifest=None, fetch_fails=False, verify_rc=0):
        def _run(cmd, **kw):
            if cmd[0] == "oras":
                if fetch_fails:
                    raise subprocess.CalledProcessError(1, cmd, stderr="MANIFEST_UNKNOWN")
                return completed(manifest)
            return completed("Verified OK", verify_rc)

        return _run

    def test_legacy_layout_passes(self):
        fake = self._fake(LEGACY_MANIFEST)
        with mock.patch.object(vc, "run", side_effect=fake), \
             mock.patch.object(vc.subprocess, "run", side_effect=lambda c, **k: fake(c)):
            found = vc.check_kyverno_readable("r/i@" + DIGEST, DIGEST, "r/sigs", "k.pub", {})
        self.assertEqual(found["ref"], "r/sigs:" + vc.signature_tag(DIGEST))

    def test_missing_sig_tag_is_refused_as_the_referrers_layout(self):
        fake = self._fake(fetch_fails=True)
        with mock.patch.object(vc, "run", side_effect=fake):
            with self.assertRaises(vc.CheckFailure) as cm:
                vc.check_kyverno_readable("r/i@" + DIGEST, DIGEST, "r/sigs", "k.pub", {})
        msg = str(cm.exception)
        self.assertTrue(msg.startswith("T2:"))
        self.assertIn("UNSIGNED", msg)

    def test_tag_present_but_wrong_shape_is_refused(self):
        fake = self._fake(REFERRERS_MANIFEST)
        with mock.patch.object(vc, "run", side_effect=fake):
            with self.assertRaises(vc.CheckFailure) as cm:
                vc.check_kyverno_readable("r/i@" + DIGEST, DIGEST, "r/sigs", "k.pub", {})
        self.assertIn("not a cosign signature manifest", str(cm.exception))

    def test_signature_that_does_not_verify_is_refused(self):
        fake = self._fake(LEGACY_MANIFEST, verify_rc=1)
        with mock.patch.object(vc, "run", side_effect=fake), \
             mock.patch.object(vc.subprocess, "run", side_effect=lambda c, **k: fake(c)):
            with self.assertRaises(vc.CheckFailure) as cm:
                vc.check_kyverno_readable("r/i@" + DIGEST, DIGEST, "r/sigs", "k.pub", {})
        self.assertIn("does not verify", str(cm.exception))

    def test_no_signature_repository_falls_back_to_the_image_repo(self):
        fake = self._fake(LEGACY_MANIFEST)
        with mock.patch.object(vc, "run", side_effect=fake), \
             mock.patch.object(vc.subprocess, "run", side_effect=lambda c, **k: fake(c)):
            found = vc.check_kyverno_readable("reg/img@" + DIGEST, DIGEST, None, "k.pub", {})
        self.assertTrue(found["ref"].startswith("reg/img:"))


class GeneratedVerifyMd(unittest.TestCase):
    """VERIFY.md is a function of the signing run — never hand-maintained."""

    def _entry(self):
        return {
            "signing": {"identity": "sha256:" + "f" * 64, "mode": "cosign_key"},
            "source": {
                "certificate_oidc_issuer": vc.OIDC_ISSUER,
                "certificate_identity_pattern": vc.SOURCE_IDENTITY_PATTERN,
                "archive_name": "a.tar.gz",
                "archive_sha256": "0" * 64,
            },
            "evidence_absent": [{"kind": "chart", "reason": "none published"}],
        }

    def test_unsigned_entry_marks_itself_provisional(self):
        import tempfile

        out = pathlib.Path(tempfile.mkdtemp())
        vc.write_verify_md(out, self._entry())
        text = (out / "VERIFY.md").read_text()
        self.assertIn("PROVISIONAL", text)

    def test_signed_entry_states_the_tool_that_signed_it(self):
        import tempfile

        out = pathlib.Path(tempfile.mkdtemp())
        record = vc.signing_run_record("2.6.5", ["--tlog-upload=false", "--new-bundle-format=false"])
        vc.write_verify_md(out, self._entry(), record)
        text = (out / "VERIFY.md").read_text()
        self.assertNotIn("PROVISIONAL", text)
        self.assertIn("cosign **2.6.5**", text)
        self.assertIn("--tlog-upload=false", text)
        # The flag pair that made verify fail on every genuine entry must not
        # come back, and the layout the customer's admission reads is stated.
        self.assertIn("--insecure-ignore-tlog=true", text)
        self.assertIn("sha256-<hex>.sig", text)
        self.assertIn("Kyverno 1.19", text)

    def test_record_names_the_layout_and_the_pin(self):
        r = vc.signing_run_record("2.6.5", [], signature_repository="r/sigs")
        self.assertEqual(r["bundle_format"], "legacy")
        self.assertEqual(r["cosign"]["pinned_series"], "2.x")
        self.assertEqual(r["signature_repository"], "r/sigs")


if __name__ == "__main__":
    unittest.main()
