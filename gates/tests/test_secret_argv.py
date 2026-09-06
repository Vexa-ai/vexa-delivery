"""The credential-in-argv gate: it must catch the three real sites, and not the rest.

The defect it exists for is a fact about this repository, not a hypothetical:
until 2026-09-06 `kit/install.sh` ran `kubectl create secret docker-registry …
--docker-password="$VEXA_CHANNEL_PASS"` at three call sites, two of them under
`--dry-run`, while `/install` said in print that the password is "read from the
environment, never from argv". So the first test below is that exact line.

The second half matters as much: `--from-literal=verdict_sha256="$VERDICT_SHA"`
and `--from-literal=status="$STATUS"` are argv and are not credentials. A gate
that refused those would be a gate somebody turns off.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest

GATES = pathlib.Path(__file__).resolve().parent.parent
ROOT = GATES.parent
CHECK = GATES / "check-secret-argv.py"


def run_gate(root: pathlib.Path):
    return subprocess.run([sys.executable, str(CHECK), "--root", str(root)],
                          capture_output=True, text=True)


def tree(files: dict[str, str]):
    d = tempfile.TemporaryDirectory()
    root = pathlib.Path(d.name)
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return d, root


class TestItCatches(unittest.TestCase):
    def test_the_exact_line_that_shipped(self):
        d, root = tree({"kit/install.sh":
                        'kc -n "$KYVERNO_NS" create secret docker-registry creds \\\n'
                        '  --docker-server="$REGISTRY" --docker-username="$USER" \\\n'
                        '  --docker-password="$VEXA_CHANNEL_PASS" --dry-run=client\n'})
        with d:
            done = run_gate(root)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("kit/install.sh:3", done.stderr)
        self.assertIn("--docker-password", done.stderr)

    def test_from_literal_with_a_credential_shaped_key(self):
        d, root = tree({"kit/x.sh":
                        'kubectl create secret generic s --from-literal=password=hunter2\n'})
        with d:
            done = run_gate(root)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("kit/x.sh:1", done.stderr)

    def test_from_literal_reading_a_credential_shaped_variable(self):
        d, root = tree({"kit/x.sh":
                        'kubectl create secret generic s --from-literal=v="$SUB_PASS"\n'})
        with d:
            done = run_gate(root)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("VARIABLE", done.stderr)

    def test_a_bare_password_flag_on_any_command(self):
        d, root = tree({"kit/x.sh": 'helm registry login r --password "$VEXA_CHANNEL_PASS"\n'})
        with d:
            done = run_gate(root)
        self.assertEqual(done.returncode, 1, done.stdout)


class TestItDoesNotOverreach(unittest.TestCase):
    def test_the_stdin_forms_are_the_fix_not_the_defect(self):
        d, root = tree({"kit/x.sh":
                        'oras login r -u "$U" --password-stdin < pw\n'
                        'kubectl create secret generic s --from-file=password=/dev/stdin\n'})
        with d:
            done = run_gate(root)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_from_literal_of_things_that_are_not_credentials(self):
        d, root = tree({"kit/x.sh":
                        'kubectl create configmap c --from-literal=status="$STATUS" \\\n'
                        '  --from-literal=verdict_sha256="$VERDICT_SHA" \\\n'
                        '  --from-literal=at="$(date -u)"\n'})
        with d:
            done = run_gate(root)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_comment_about_the_defect_is_not_the_defect(self):
        """kit/claim.sh names `--from-literal` in a comment explaining why it
        does not use it. A gate that refused its own documentation would teach
        people to stop writing the documentation."""
        d, root = tree({"kit/claim.sh":
                        '# `kubectl create secret --from-literal` would put the\n'
                        '# password in argv, which is what this design avoids.\n'
                        'kubectl apply -f - <<EOF\nEOF\n'})
        with d:
            done = run_gate(root)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_test_stub_that_parses_argv_is_out_of_scope(self):
        """The stub kubectl in kit/tests reads `--docker-password=` out of its
        own argv to assert on what it was handed. It constructs nothing."""
        d, root = tree({"kit/tests/test_x.sh":
                        'case "$a" in --docker-password=*) pass=${a#*=};; esac\n'})
        with d:
            done = run_gate(root)
        self.assertEqual(done.returncode, 2, done.stderr)  # nothing left to scan


class TestTheRepositoryItself(unittest.TestCase):
    def test_it_is_clean(self):
        done = subprocess.run([sys.executable, str(CHECK)],
                              capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
