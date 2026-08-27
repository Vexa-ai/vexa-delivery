# SPDX-License-Identifier: Apache-2.0
"""`vexa-channel verify` on a PLATFORM ESTATE entry.

The defect: cmd_verify opened evidence/delivery-receipt.json and
evidence/candidate-images.json unconditionally, so verifying an estate entry
did not report a failure — it CRASHED with FileNotFoundError before printing a
single verdict. An estate has neither file, and its entry says so in
`evidence_absent` with a reason; the tool that reads entries did not read that
field. The control test at the time was that the already-published seq-1 estate
entry crashed identically, so this was a hole in the publisher, not a defect in
any one entry.

The fix must be narrow. Tolerating a declared absence is right; tolerating a
MISSING file is not, and neither is deciding on the subscriber's behalf that
the absence is acceptable — that adjudication belongs to their contract's
`forbid_absent_evidence`, enforced in the in-cluster verifier.
"""
import contextlib
import io
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "publisher"))

import vexa_channel  # noqa: E402
FIX = REPO / "kit/verify/tests/fixtures/estate-entry"


class Args:
    def __init__(self, entry, archive=None, pubkey=None):
        self.entry, self.archive, self.pubkey = entry, archive, pubkey


def run_verify(entry_dir):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = vexa_channel.cmd_verify(Args(str(entry_dir)))
    return rc, buf.getvalue()


class EstateVerify(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="estate-verify-"))
        self.entry = self.tmp / "entry"
        shutil.copytree(FIX, self.entry)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_estate_entry_verifies_instead_of_crashing(self):
        rc, out = run_verify(self.entry)
        self.assertEqual(rc, 0, out)
        self.assertIn("VERIFY OK", out)

    def test_it_says_what_it_did_not_check(self):
        """A silent skip is the same defect wearing a green tick."""
        _, out = run_verify(self.entry)
        self.assertIn("map pin / image consistency NOT CHECKED", out)
        self.assertIn("declared absent", out)
        self.assertIn("forbid_absent_evidence", out)

    def test_image_pins_are_still_checked_without_a_map(self):
        """The map is what normally binds images to a build. Without it, the
        one thing still checkable with no contract is that every image carries
        a digest — and an estate is exactly where a floating tag could slip in,
        because the digests were read off a cluster."""
        _, out = run_verify(self.entry)
        self.assertIn("OK   image pins well-formed", out)

        doc = json.loads((self.entry / "entry.json").read_text())
        doc["images"][0]["index_digest"] = "latest"
        (self.entry / "entry.json").write_text(json.dumps(doc, indent=1))
        rc, out = run_verify(self.entry)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL image pins well-formed", out)

    def test_a_missing_file_is_still_a_failure_when_not_declared_absent(self):
        """The narrowness of the fix, asserted. Drop the `candidate_map` and
        `delivery_receipt` rows from evidence_absent and the entry is claiming
        to be an OSS release with the files simply gone — which must fail, not
        pass."""
        doc = json.loads((self.entry / "entry.json").read_text())
        doc["evidence_absent"] = [r for r in doc["evidence_absent"]
                                  if r["kind"] not in ("candidate_map", "delivery_receipt")]
        (self.entry / "entry.json").write_text(json.dumps(doc, indent=1))
        with self.assertRaises((FileNotFoundError, SystemExit)):
            run_verify(self.entry)


if __name__ == "__main__":
    unittest.main()
