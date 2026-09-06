# SPDX-License-Identifier: Apache-2.0
"""kit/smoke writes a receipt when it FAILS — rehearsal defect 6.

On 2026-09-06, against a half-converged estate, S2 raised an unhandled
`RuntimeError: port-forward to svc/vexa-vexa-admin-api did not come up in 15s`
at vexa_smoke.py:83. The run died there: no verdict, no receipt. Downstream,
`vexa_validate` found no `smoke-receipt-*.md` to read, wrote `smoke_receipt` as
absent, and the publisher's ingest refused the whole station report:

    REFUSED S2: bundle is incomplete; missing smoke_receipt

So the path that broke was the FAILURE-REPORTING path — the one RUNBOOK § 3 says
matters more than the success one, since an un-ingested report is an
unrepresented customer. The README's promise that `--non-interactive` "never
fakes it: no admitted bot -> honest FAIL" covered S3 only; S1 and S2 had no
guard at all, and they are the two a struggling subscriber hits first.

Everything here is offline: kubectl is replaced by a function that fails the way
a real one does.
"""
import contextlib
import io
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_smoke as smoke  # noqa: E402

# What `vexa_validate.phase_smoke` globs for after running this tool. If the
# name ever drifts from this, the receipt exists and the report still says it
# does not — so the pattern is asserted here rather than assumed.
VALIDATE_GLOB = "smoke-receipt-*.md"


@contextlib.contextmanager
def in_tmpdir():
    old = os.getcwd()
    with tempfile.TemporaryDirectory() as d:
        os.chdir(d)
        try:
            yield pathlib.Path(d)
        finally:
            os.chdir(old)


def run_main(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = smoke.main()
    return rc, buf.getvalue()


class Unreachable:
    """Stands in for PortForward so no test ever spawns `kubectl port-forward`
    against whatever context the machine running the suite happens to have."""

    def __init__(self, *a, **kw):
        pass

    def __enter__(self):
        raise RuntimeError("port-forward to svc/vexa-vexa-admin-api did not come up in 15s")

    def __exit__(self, *exc):
        return False


class ReceiptOnFailure(unittest.TestCase):
    def setUp(self):
        self._kc, self._pf, self._argv = smoke.kc, smoke.PortForward, sys.argv
        self.addCleanup(lambda: (setattr(smoke, "kc", self._kc),
                                 setattr(smoke, "PortForward", self._pf),
                                 setattr(sys, "argv", self._argv)))
        smoke.PortForward = Unreachable
        sys.argv = ["vexa_smoke.py", "--namespace", "vexa-dev",
                    "--admin-token", "fixture-token", "--non-interactive"]

    def _receipt(self, d):
        found = sorted(d.glob(VALIDATE_GLOB))
        self.assertEqual(len(found), 1,
                         f"expected exactly one {VALIDATE_GLOB}, found {found}")
        return found[0].read_text()

    def test_a_kubectl_that_refuses_still_produces_a_receipt(self):
        def refusing(a, *args, check=True):
            raise RuntimeError('kubectl get deploy: Error from server (Forbidden): '
                               'deployments.apps is forbidden')
        smoke.kc = refusing
        with in_tmpdir() as d:
            rc, out = run_main(sys.argv)
            text = self._receipt(d)
        self.assertEqual(rc, 1)
        self.assertIn("VERDICT: **FAIL**", text)
        self.assertIn("Forbidden", text)
        self.assertIn("S1", text)
        self.assertNotIn("Traceback", out)

    def test_the_port_forward_failure_that_broke_the_rehearsal(self):
        """The exact shape: S1 fine, S2 raises out of PortForward.__enter__."""
        def kc(a, *args, check=True):
            class R:
                stdout = ('{"items":[{"metadata":{"name":"vexa-vexa-gateway"},'
                          '"spec":{"replicas":1},"status":{"readyReplicas":1}}]}')
                returncode = 0
            return R()
        smoke.kc = kc                      # PortForward is Unreachable, from setUp
        with in_tmpdir() as d:
            rc, out = run_main(sys.argv)
            text = self._receipt(d)
        self.assertEqual(rc, 1)
        self.assertIn("did not come up in 15s", text)
        self.assertIn("| S1 | PASS |", text)          # what DID work is still recorded
        self.assertIn("| S2 | FAIL |", text)
        self.assertIn("VERDICT: FAIL", out)
        self.assertIn("receipt:", out)

    def test_the_receipt_is_non_empty_so_it_lands_as_a_section(self):
        """`Doc.add` routes empty text to `absent`, which is the refusal again."""
        def refusing(a, *args, check=True):
            raise RuntimeError("nope")
        smoke.kc = refusing
        with in_tmpdir() as d:
            run_main(sys.argv)
            text = self._receipt(d)
        self.assertTrue(text.strip(), "an empty receipt is the same as no receipt downstream")
        self.assertGreater(len(text.splitlines()), 5)

    def test_a_phase_that_exits_is_a_finding_not_an_exit(self):
        """An unparseable meeting URL used to take the whole run with it."""
        def kc(a, *args, check=True):
            class R:
                stdout = '{"items":[]}'
                returncode = 0
            return R()
        smoke.kc = kc
        sys.argv += ["--meeting-url", "https://example.invalid/not-a-meeting"]
        with in_tmpdir() as d:
            rc, out = run_main(sys.argv)
            text = self._receipt(d)
        self.assertEqual(rc, 1)
        self.assertIn("| S3 | FAIL |", text)


if __name__ == "__main__":
    unittest.main()
