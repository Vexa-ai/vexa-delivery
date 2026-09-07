# SPDX-License-Identifier: Apache-2.0
"""`vexa_subscriber` against a FAKE standalone channel host.

The registry moved off the cluster on 2026-08-25 and the tool's `add`, `revoke`
and `list` now operate a Docker host over SSH. Nothing here touches a real host,
a real registry or the network: a temp directory IS `$CHANNEL_ROOT`, and `ssh`,
`docker`, `curl` and `htpasswd` are shims on `PATH`.

The shims run the tool's REAL command lines rather than re-implementing them —
the `ssh` shim executes the remote command locally with `sh -c`, so
`cat $CHANNEL_ROOT/env` reads the fixture and the write pipeline really writes
it. That is what makes these tests worth having: they assert on what the tool
executes, not on what a stand-in was told to expect.

Every shim appends its own argv to one log, which buys the property this file
exists for. `gates/check-secret-argv.py` enforces "never in argv" for the kit's
shell scripts; this is the same promise for the Python tool, checked the only
way that cannot be fooled — by looking at every command line every child
process was actually handed.
"""

import base64
import contextlib
import hashlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vexa_subscriber as vs  # noqa: E402
import vexa_claim as vc  # noqa: E402  (re-exported through vexa_subscriber's path insert)

EDGE = "https://channel.example"

# A bcrypt-SHAPED placeholder for accounts that are already on the fixture host.
# Not a hash of anything: the tool treats a digest as an opaque string and
# is_bcrypt() reads only the prefix. Assembled from parts on purpose — a
# realistic-looking digest in a test file trips credential scanners and costs a
# human the check every time.
BC = "$2y$05$" + "A" * 53

# --------------------------------------------------------------------------
# The shims. Each one logs its argv, one argument per line, so a test can ask
# "did this string ever appear on a command line" and get an exact answer.
# --------------------------------------------------------------------------

LOG_ARGV = 'for a in "$@"; do printf \'%s\\t%s\\n\' "$0" "$a" >> "$ARGV_LOG"; done'

# ssh: log, check the shape we believe we emit, then run the remote command
# HERE. Exit 99 on an unexpected shape rather than guessing which argument the
# command is — a test that silently ran the wrong thing would pass.
SSH_SHIM = f"""#!/bin/sh
{LOG_ARGV}
[ "$1" = "-o" ] || {{ echo "unexpected ssh argv shape" >&2; exit 99; }}
shift 3
exec sh -c "$1"
"""

DOCKER_SHIM = f"""#!/bin/sh
{LOG_ARGV}
exit 0
"""

# htpasswd -nBi <stub>: password on STDIN, "<stub>:<hash>" on stdout. The fake
# hash is derived from the password so it is deterministic, and it carries the
# three '$' of a real bcrypt prefix so compose escaping is exercised end to end.
HTPASSWD_SHIM = f"""#!/bin/sh
{LOG_ARGV}
pw=$(cat)
h=$(printf '%s' "$pw" | shasum -a 256 2>/dev/null || printf '%s' "$pw" | sha256sum)
printf '%s:$2y$05$%s\\n' "$2" "$(printf '%s' "$h" | cut -c1-53)"
"""

# Every case pattern below carries its leading "(": inside $( ) bash 3.2 — which
# is what macOS runs as /bin/sh — cannot parse a pattern without it, and the
# shims must run wherever `make test` does.
#
# curl: log argv AND stdin. The stdin log is positive evidence — it is how a
# test proves the credential travelled over stdin, rather than only that it is
# absent from argv.
CURL_SHIM = """#!/bin/sh
for a in "$@"; do printf '%s\\t%s\\n' "$0" "$a" >> "$ARGV_LOG"; done
url=$(for a in "$@"; do case "$a" in (http*) printf '%s' "$a";; esac; done)
config=""
case " $* " in (*" -K "*) config=$(cat); printf '%s' "$config" >> "$STDIN_LOG";; esac
case "$url" in
  (*/healthz) [ "${HEALTHZ:-0}" = "0" ] || exit 22; exit 0 ;;
esac
if [ -n "$config" ]; then printf '%s' "${V2_WITH:-200}"; else printf '%s' "${V2_WITHOUT:-401}"; fi
exit 0
"""


def fake_bcrypt(password):
    """What HTPASSWD_SHIM will produce for this password."""
    return "$2y$05$" + hashlib.sha256(password.encode()).hexdigest()[:53]


class FakeHost(unittest.TestCase):
    """A temp directory that IS the channel host, plus the shims on PATH."""

    ENV = (
        "# channel stack\n"
        "PUBLISHER_BCRYPT=old-publisher\n"
        "EDGE_READER_BASIC=old-edge-reader\n"
        "SUB_PILOT_BCRYPT=old-pilot\n"
    )
    HTPASSWD = f"publisher:{BC}\npilot:{BC}\n"

    def setUp(self):
        # The host is a subdirectory of the scratch space, so "no file on the
        # host carries the password" scans the host and not this test's own
        # logs beside it — the curl shim's stdin log holds the credential on
        # purpose, as positive evidence that it travelled over stdin.
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="vexa-fake-host-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.root = self.work / "channel"
        self.root.mkdir()
        (self.root / "htpasswd").write_text(self.HTPASSWD)
        (self.root / "env").write_text(self.ENV)

        self.bin = self.work / "bin"
        self.bin.mkdir()
        for name, body in (("ssh", SSH_SHIM), ("docker", DOCKER_SHIM),
                           ("curl", CURL_SHIM), ("htpasswd", HTPASSWD_SHIM)):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)

        self.argv_log = self.work / "argv.log"
        self.stdin_log = self.work / "stdin.log"
        self.argv_log.touch()
        self.stdin_log.touch()

        self._saved_env = dict(os.environ)
        os.environ.update({
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "ARGV_LOG": str(self.argv_log),
            "STDIN_LOG": str(self.stdin_log),
            "CHANNEL_REGISTRY_SSH": "operator@channel.example",
            "CHANNEL_ROOT": str(self.root),
            "CHANNEL_EDGE_URL": EDGE,
        })
        for key in ("CHANNEL_CLAIM_EDGE", "CHANNEL_CLAIM_EDGE_RECIPIENT",
                    "CHANNEL_CLAIM_SPOOL", "CHANNEL_CLAIM_SPOOL_SSH",
                    "VEXA_STATIONS_DIR"):
            os.environ.pop(key, None)
        self.addCleanup(self._restore_env)

        # Force the htpasswd fallback, so the shim is what hashes and the
        # no-argv promise is checked on the path that has a binary to get it
        # wrong. `None` in sys.modules makes `import bcrypt` raise ImportError.
        self._saved_bcrypt = sys.modules.get("bcrypt", "absent")
        sys.modules["bcrypt"] = None
        self.addCleanup(self._restore_bcrypt)

    def _restore_env(self):
        os.environ.clear()
        os.environ.update(self._saved_env)

    def _restore_bcrypt(self):
        if self._saved_bcrypt == "absent":
            sys.modules.pop("bcrypt", None)
        else:
            sys.modules["bcrypt"] = self._saved_bcrypt

    # -- running the tool ---------------------------------------------------

    def run_cli(self, *argv):
        """One CLI run. Returns (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = vs.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    # -- reading the fake host back ----------------------------------------

    def htpasswd(self):
        return vs.parse_htpasswd((self.root / "htpasswd").read_text())

    def env(self):
        return (self.root / "env").read_text()

    def env_value(self, key):
        for line in self.env().splitlines():
            head, _, value = line.partition("=")
            if head.strip() == key:
                return value
        raise AssertionError(f"{key} is not in the env file")

    def argv(self):
        return [tuple(line.split("\t", 1))
                for line in self.argv_log.read_text().splitlines() if line]

    def argv_for(self, program):
        return [arg for prog, arg in self.argv() if prog.endswith("/" + program)]

    def credential_printed(self, stdout):
        return stdout.splitlines()[0]


class Add(FakeHost):
    def test_a_new_account_lands_in_the_htpasswd_file(self):
        code, out, err = self.run_cli("add", "rehearsal")
        self.assertEqual(code, 0, err)
        self.assertIn("rehearsal", self.htpasswd())
        self.assertTrue(vs.is_bcrypt(self.htpasswd()["rehearsal"]))
        # The others are untouched.
        self.assertEqual(self.htpasswd()["publisher"], BC)

    def test_the_credential_is_printed_once_and_only_on_stdout(self):
        _, out, err = self.run_cli("add", "rehearsal")
        account, _, password = self.credential_printed(out).partition(":")
        self.assertEqual(account, "rehearsal")
        self.assertEqual(len(password), vs.PASSWORD_LENGTH)
        self.assertEqual(out.count(password), 1)
        self.assertNotIn(password, err)

    def test_the_stack_is_recreated_not_restarted(self):
        # `docker restart` re-runs the container with its ORIGINAL environment;
        # env_file is read at creation. This is the whole reason the verb is
        # `up -d --force-recreate`.
        self.run_cli("add", "rehearsal")
        self.assertEqual(self.argv_for("docker"),
                         ["compose", "up", "-d", "--force-recreate"])
        remote = [a for a in self.argv_for("ssh") if "docker compose" in a]
        self.assertEqual(len(remote), 1)
        self.assertIn(f"cd {self.root}", remote[0])
        self.assertNotIn("docker restart", " ".join(self.argv_for("ssh")))

    def test_a_new_subscriber_is_minted_pull_only_and_says_so(self):
        _, _, err = self.run_cli("add", "rehearsal")
        self.assertIn("pull-only", err)
        self.assertIn("SUB_REHEARSAL_BCRYPT", err)
        # ...and the env file is not touched, so no Caddyfile promise is
        # implied that nobody made.
        self.assertEqual(self.env(), self.ENV)

    def test_rotating_replaces_the_line_rather_than_duplicating_it(self):
        _, out, _ = self.run_cli("add", "pilot")
        self.assertEqual(len(self.htpasswd()), 2)
        self.assertNotEqual(self.htpasswd()["pilot"], BC)
        password = self.credential_printed(out).partition(":")[2]
        self.assertEqual(self.htpasswd()["pilot"], fake_bcrypt(password))

    def test_an_unchanged_env_file_is_not_rewritten(self):
        # A write of identical bytes is a needless mutation of a file the
        # operator reads by eye, and on this host it is also a 0600 rewrite.
        self.run_cli("add", "rehearsal")
        writes = [a for a in self.argv_for("ssh") if "umask 077" in a]
        self.assertEqual(len(writes), 1)
        self.assertIn("htpasswd", writes[0])

    def test_the_env_file_is_written_atomically_and_locked_down(self):
        self.run_cli("add", "publisher")
        writes = [a for a in self.argv_for("ssh") if "umask 077" in a]
        self.assertEqual(len(writes), 2)
        for command in writes:
            self.assertIn("chmod 600", command)
            self.assertIn("mv ", command)

    def test_a_host_missing_the_publisher_key_refuses_before_writing(self):
        # The cheap way to catch $CHANNEL_ROOT pointing at something that is
        # not the live stack — and it must refuse before the mint, because the
        # mint rotates.
        (self.root / "env").write_text("SOMETHING_ELSE=1\n")
        code, out, err = self.run_cli("add", "rehearsal")
        self.assertEqual(code, 2)
        self.assertIn("PUBLISHER_BCRYPT", err)
        self.assertEqual(out, "")
        self.assertEqual(self.htpasswd(), vs.parse_htpasswd(self.HTPASSWD))
        self.assertEqual(self.argv_for("docker"), [])


class SpecialAccounts(FakeHost):
    def test_add_publisher_rewrites_the_edge_write_gate(self):
        _, out, _ = self.run_cli("add", "publisher")
        password = self.credential_printed(out).partition(":")[2]
        digest = fake_bcrypt(password)
        self.assertEqual(self.htpasswd()["publisher"], digest)
        self.assertEqual(self.env_value("PUBLISHER_BCRYPT"),
                         vs.compose_escape(digest))

    def test_the_env_value_is_compose_escaped_and_the_htpasswd_one_is_not(self):
        # The scar: compose v5 interpolated '$' out of an env_file value and
        # left 57 characters of a 60-character hash. registry:3 reads the
        # htpasswd file directly and must see the hash raw.
        _, out, _ = self.run_cli("add", "publisher")
        digest = fake_bcrypt(self.credential_printed(out).partition(":")[2])
        self.assertNotIn("$$", self.htpasswd()["publisher"])
        self.assertIn("$$", self.env_value("PUBLISHER_BCRYPT"))
        self.assertEqual(self.env_value("PUBLISHER_BCRYPT").replace("$$", "$"),
                         digest)
        self.assertEqual(
            len(self.env_value("PUBLISHER_BCRYPT").replace("$$", "$")),
            len(digest))

    def test_add_edge_signature_reader_rewrites_the_basic_header(self):
        # Closes the manual step: rotating the htpasswd line without this
        # leaves anonymous signature reads answering 401 and Kyverno denying
        # at admission.
        _, out, _ = self.run_cli("add", "edge-signature-reader")
        credential = self.credential_printed(out)
        self.assertEqual(
            base64.b64decode(self.env_value("EDGE_READER_BASIC")).decode(),
            credential)

    def test_the_edge_reader_is_the_one_account_whose_value_lands_in_a_file(self):
        # Structural, documented, and worth a test precisely because it is the
        # exception to "the password touches no file": the edge must PRESENT
        # this credential upstream, not merely check it.
        _, out, _ = self.run_cli("add", "edge-signature-reader")
        password = self.credential_printed(out).partition(":")[2]
        self.assertNotIn(password, self.env())          # base64, not plaintext
        self.assertNotIn(password, (self.root / "htpasswd").read_text())
        self.assertIn(base64.b64encode(
            f"edge-signature-reader:{password}".encode()).decode(),
            self.env())

    def test_a_subscriber_with_a_station_write_line_has_its_hash_maintained(self):
        _, out, _ = self.run_cli("add", "pilot")
        digest = fake_bcrypt(self.credential_printed(out).partition(":")[2])
        self.assertEqual(self.env_value("SUB_PILOT_BCRYPT"),
                         vs.compose_escape(digest))
        self.assertEqual(self.htpasswd()["pilot"], digest)


class Proof(FakeHost):
    def test_the_credential_proved_is_the_credential_printed(self):
        _, out, _ = self.run_cli("add", "rehearsal")
        self.assertIn(f'user = "{self.credential_printed(out)}"',
                      self.stdin_log.read_text())

    def test_both_halves_of_the_proof_run_against_the_live_v2(self):
        self.run_cli("add", "rehearsal")
        urls = [a for a in self.argv_for("curl") if a.startswith("http")]
        self.assertEqual(urls, [f"{EDGE}/healthz", f"{EDGE}/v2/", f"{EDGE}/v2/"])

    def test_a_credential_that_does_not_authenticate_is_never_printed(self):
        # The failure this whole change exists to stop: a rotation that edited
        # a path nothing reads, printed a credential and reported success.
        os.environ["V2_WITH"] = "401"
        code, out, err = self.run_cli("add", "rehearsal")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("do not deliver this password", err)

    def test_an_open_gate_refuses_even_though_the_credential_works(self):
        # A registry with auth off answers 200 to anything, so the positive
        # request alone cannot tell "this authenticates" from "nothing checks".
        os.environ["V2_WITHOUT"] = "200"
        code, out, err = self.run_cli("add", "rehearsal")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("with NO credential", err)

    def test_a_stack_that_does_not_come_back_refuses_before_the_proof(self):
        os.environ["HEALTHZ"] = "fail"
        code, out, err = self.run_cli("add", "rehearsal")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("did not come back", err)
        self.assertNotIn("/v2/", " ".join(self.argv_for("curl")))

    def test_an_unset_edge_url_refuses_and_names_the_variable(self):
        del os.environ["CHANNEL_EDGE_URL"]
        code, out, err = self.run_cli("add", "rehearsal")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("CHANNEL_EDGE_URL", err)

    def test_an_unset_ssh_target_refuses_before_anything_is_read(self):
        del os.environ["CHANNEL_REGISTRY_SSH"]
        code, out, err = self.run_cli("list")
        self.assertEqual(code, 2)
        self.assertIn("CHANNEL_REGISTRY_SSH", err)
        self.assertEqual(self.argv(), [])


class NoCredentialInArgv(FakeHost):
    """`gates/check-secret-argv.py` makes this promise for the kit's shell
    scripts. This makes it for the Python tool, by reading every command line
    every child process was actually handed — local argv and the remote command
    line inside it, which is argv on the far end.

    Argv is world-readable in /proc and in `ps` for the life of the process; on
    a shared operator host that is the whole exposure.
    """

    def assert_absent_from_every_argv(self, needle):
        for program, arg in self.argv():
            self.assertNotIn(needle, arg,
                             f"{needle!r} reached the command line of {program}")

    def test_the_password_reaches_no_command_line_anywhere(self):
        _, out, err = self.run_cli("add", "rehearsal")
        password = self.credential_printed(out).partition(":")[2]
        self.assert_absent_from_every_argv(password)
        # Every child that could have carried it actually ran, so the assertion
        # above is about a populated log rather than an empty one.
        for program in ("ssh", "docker", "curl", "htpasswd"):
            self.assertTrue(self.argv_for(program), f"{program} never ran")

    def test_the_password_reaches_no_command_line_on_the_publisher_path(self):
        # The account with the most moving parts: two files, two writes.
        _, out, _ = self.run_cli("add", "publisher")
        self.assert_absent_from_every_argv(
            self.credential_printed(out).partition(":")[2])

    def test_the_hash_reaches_no_command_line_either(self):
        # It is not a password, but it is offline-crackable and it is what the
        # gate checks; there is no reason for it to be visible in `ps`.
        _, out, _ = self.run_cli("add", "rehearsal")
        digest = fake_bcrypt(self.credential_printed(out).partition(":")[2])
        self.assert_absent_from_every_argv(digest)

    def test_the_hashing_binary_is_fed_over_stdin(self):
        _, out, _ = self.run_cli("add", "rehearsal")
        self.assertEqual(self.argv_for("htpasswd"), ["-nBi", vs.STUB_NAME])
        self.assert_absent_from_every_argv(
            self.credential_printed(out).partition(":")[2])

    def test_the_proof_reads_its_credential_from_a_config_on_stdin(self):
        _, out, _ = self.run_cli("add", "rehearsal")
        self.assertIn("-K", self.argv_for("curl"))
        self.assertIn(self.credential_printed(out), self.stdin_log.read_text())

    def test_the_password_reaches_no_file_on_the_host(self):
        _, out, _ = self.run_cli("add", "rehearsal")
        password = self.credential_printed(out).partition(":")[2]
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(password, path.read_text(errors="replace"),
                                 f"{password!r} was written to {path}")

    def test_the_password_reaches_no_stderr(self):
        # stderr is where the operator's terminal scrollback and any wrapping
        # log ends up; the value belongs on stdout, alone.
        _, out, err = self.run_cli("add", "rehearsal")
        self.assertNotIn(self.credential_printed(out).partition(":")[2], err)


class Revoke(FakeHost):
    def test_revoke_removes_the_line_and_recreates_the_stack(self):
        code, out, err = self.run_cli("revoke", "pilot")
        self.assertEqual(code, 0, err)
        self.assertNotIn("pilot", self.htpasswd())
        self.assertIn("publisher", self.htpasswd())
        self.assertEqual(self.argv_for("docker"),
                         ["compose", "up", "-d", "--force-recreate"])
        self.assertIn("no longer authenticates", out)

    def test_revoke_leaves_the_dangling_env_key_and_says_so(self):
        # The Caddyfile references {env.KEY}; deleting the key alone is a
        # Caddy-start risk. The credential is dead either way — the htpasswd
        # line is gone — so the safe order is: say it, do not do it.
        _, _, err = self.run_cli("revoke", "pilot")
        self.assertIn("SUB_PILOT_BCRYPT", err)
        self.assertEqual(self.env(), self.ENV)

    def test_revoking_the_publisher_needs_force(self):
        code, _, err = self.run_cli("revoke", "publisher")
        self.assertEqual(code, 2)
        self.assertIn("--force", err)
        self.assertIn("publisher", self.htpasswd())
        self.assertEqual(self.argv(), [])

    def test_revoking_the_edge_reader_needs_force(self):
        (self.root / "htpasswd").write_text(
            self.HTPASSWD + f"edge-signature-reader:{BC}\n")
        code, _, err = self.run_cli("revoke", "edge-signature-reader")
        self.assertEqual(code, 2)
        self.assertIn("Kyverno", err)
        self.assertIn("edge-signature-reader", self.htpasswd())

    def test_force_revokes_the_publisher(self):
        code, _, err = self.run_cli("revoke", "publisher", "--force")
        self.assertEqual(code, 0, err)
        self.assertNotIn("publisher", self.htpasswd())

    def test_revoking_an_account_that_is_not_there_changes_nothing(self):
        code, _, err = self.run_cli("revoke", "rehearsal")
        self.assertEqual(code, 2)
        self.assertIn("no account named", err)
        self.assertEqual(self.htpasswd(), vs.parse_htpasswd(self.HTPASSWD))
        self.assertEqual(self.argv_for("docker"), [])


class List(FakeHost):
    def test_list_reads_both_files_and_reports_the_real_scope(self):
        (self.root / "htpasswd").write_text(
            self.HTPASSWD + f"edge-signature-reader:{BC}\nrehearsal:{BC}\n")
        code, out, err = self.run_cli("list")
        self.assertEqual(code, 0, err)
        scopes = {line.split()[0]: line.split()[1] for line in out.splitlines()[1:]}
        self.assertEqual(scopes, {"publisher": "push+pull",
                                  "pilot": "pull+station",
                                  "edge-signature-reader": "edge-held",
                                  "rehearsal": "pull"})

    def test_list_mutates_nothing(self):
        self.run_cli("list")
        self.assertEqual(self.argv_for("docker"), [])
        self.assertNotIn("umask 077", " ".join(self.argv_for("ssh")))

    def test_a_non_bcrypt_hash_is_called_out(self):
        # registry:3 refuses MD5/crypt/SHA1 at startup; a silent lockout is
        # what this column exists to prevent.
        (self.root / "htpasswd").write_text("publisher:{SHA}abc\n")
        _, out, _ = self.run_cli("list")
        self.assertIn("NOT-BCRYPT", out)

    def test_an_empty_registry_says_so(self):
        (self.root / "htpasswd").write_text("")
        code, out, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("no accounts", out)


class ParkSharesTheHostPath(FakeHost):
    """`--park` changes the delivery leg and nothing else — which now means the
    mint underneath it is the host mint, on the same two files."""

    def setUp(self):
        super().setUp()
        self.spool = self.root / "claims"
        self.ledger = self.root / "ledger"
        self.ledger.mkdir()
        for cmd in (["init", "-q", "-b", "main"],
                    ["config", "user.email", "test@vexa.invalid"],
                    ["config", "user.name", "test"]):
            subprocess.run(["git", "-C", str(self.ledger), *cmd], check=True,
                           capture_output=True)
        (self.ledger / "README.md").write_text("ledger\n")
        subprocess.run(["git", "-C", str(self.ledger), "add", "README.md"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.ledger), "commit", "-q", "-m", "init"],
                       check=True, capture_output=True)
        self.recipients = self.root / "edge.recipients"

    def park_argv(self):
        return ["add", "pilot", "--park", "--channel", "pilot-stable",
                "--edge", f"{EDGE}/claim",
                "--edge-recipient", str(self.recipients),
                "--park-out", str(self.spool),
                "--ledger", str(self.ledger),
                "--parked-by", "tester"]

    @unittest.skipUnless(vc.have_age(), "no `age` binary on this host")
    def test_park_mints_on_the_host_and_prints_the_code_after_the_credential(self):
        subprocess.run(["age-keygen", "-o", str(self.root / "edge.key")],
                       capture_output=True, check=True)
        public = [ln.split(": ", 1)[1]
                  for ln in (self.root / "edge.key").read_text().splitlines()
                  if ln.startswith("# public key: ")][0]
        self.recipients.write_text(public + "\n")

        code, out, err = self.run_cli(*self.park_argv())
        self.assertEqual(code, 0, err)
        credential, claim_code = out.splitlines()
        # The mint went to the host, both files, like any other rotation.
        self.assertEqual(self.htpasswd()["pilot"],
                         fake_bcrypt(credential.partition(":")[2]))
        self.assertEqual(self.env_value("SUB_PILOT_BCRYPT"),
                         vs.compose_escape(self.htpasswd()["pilot"]))
        self.assertEqual(self.argv_for("docker"),
                         ["compose", "up", "-d", "--force-recreate"])
        # ...and the delivery leg is unchanged: line 2 is the six digits.
        self.assertRegex(claim_code, r"^[0-9]{3} [0-9]{3}$")

    def test_a_park_preflight_failure_refuses_before_the_host_is_touched(self):
        # `add` rotates. Discovering a missing recipients file after the mint
        # would leave the subscriber locked out with nothing parked.
        code, out, err = self.run_cli(*self.park_argv())
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(self.argv(), [])
        self.assertEqual(self.htpasswd(), vs.parse_htpasswd(self.HTPASSWD))


if __name__ == "__main__":
    unittest.main()
