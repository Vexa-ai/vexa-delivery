"""Hermetic tests for vexa_subscriber's htpasswd and env-file handling, and for
what the verbs do to the standalone host.

Nothing here touches a host, a registry or the network. The pure half is tested
directly; the host half runs against an in-memory stand-in behind ``ssh_run``
that records every remote command line and every byte sent over stdin — so
"the password never reaches a remote argv" and "a refusal writes nothing" are
assertions, not prose. The parts worth testing are the ones where a bug
silently locks somebody out, silently grants them access, or silently rotates
an account and prints nothing.

``test_subscriber_host.py`` covers the same host half one level lower: the
real ``ssh``/``docker``/``curl``/``htpasswd`` shell-outs, against shims on
``PATH`` that log every argv, so the two files cannot agree by construction.
"""

import argparse
import base64
import contextlib
import io
import os
import pathlib
import shlex
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vexa_subscriber as vs  # noqa: E402


# Two bcrypt-SHAPED placeholders. They are not hashes of anything — the parse
# and render code treats a digest as an opaque string, and is_bcrypt() reads
# only the "$2y$" prefix, so a filler body exercises every path a real hash
# would. Written this way on purpose: a realistic-looking digest in a test
# file trips credential scanners and costs a human the check every time.
BC = "$2y$05$" + "A" * 53
BC2 = "$2y$05$" + "B" * 53


class TestParse(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(vs.parse_htpasswd(""), {})
        self.assertEqual(vs.parse_htpasswd("\n\n  \n"), {})

    def test_single_and_multi(self):
        self.assertEqual(vs.parse_htpasswd(f"publisher:{BC}\n"), {"publisher": BC})
        self.assertEqual(
            vs.parse_htpasswd(f"publisher:{BC}\npilot:{BC2}\n"),
            {"publisher": BC, "pilot": BC2},
        )

    def test_comments_and_blank_lines_ignored(self):
        text = f"# minted 2026-08-24\n\npublisher:{BC}\n\n# pilot below\npilot:{BC2}\n"
        self.assertEqual(vs.parse_htpasswd(text), {"publisher": BC, "pilot": BC2})

    def test_hash_containing_colons_is_not_split(self):
        # partition() keeps everything after the first ':' — bcrypt has none,
        # but the guarantee matters if a hash format ever changes.
        self.assertEqual(vs.parse_htpasswd("u:a:b:c\n"), {"u": "a:b:c"})

    def test_missing_separator_rejected(self):
        with self.assertRaises(vs.SubscriberError):
            vs.parse_htpasswd("publishernohash\n")

    def test_empty_user_or_hash_rejected(self):
        with self.assertRaises(vs.SubscriberError):
            vs.parse_htpasswd(":hash\n")
        with self.assertRaises(vs.SubscriberError):
            vs.parse_htpasswd("user:\n")

    def test_duplicate_user_rejected(self):
        # Last-one-wins would be a coin flip on which credential is live.
        with self.assertRaises(vs.SubscriberError):
            vs.parse_htpasswd(f"pilot:{BC}\npilot:{BC2}\n")


class TestRender(unittest.TestCase):
    def test_empty_renders_empty(self):
        self.assertEqual(vs.render_htpasswd({}), "")

    def test_sorted_with_trailing_newline(self):
        out = vs.render_htpasswd({"zeta": BC, "alpha": BC2})
        self.assertEqual(out, f"alpha:{BC2}\nzeta:{BC}\n")

    def test_round_trip_is_stable(self):
        text = f"pilot:{BC2}\npublisher:{BC}\n"
        self.assertEqual(vs.render_htpasswd(vs.parse_htpasswd(text)), text)

    def test_render_is_canonical(self):
        # Unsorted, comment-laden input converges on one byte-identical form,
        # so a no-op `add` produces no spurious Secret change or rollout.
        messy = f"# note\nzeta:{BC}\n\nalpha:{BC2}\n"
        tidy = f"alpha:{BC2}\nzeta:{BC}\n"
        self.assertEqual(
            vs.render_htpasswd(vs.parse_htpasswd(messy)),
            vs.render_htpasswd(vs.parse_htpasswd(tidy)),
        )


class TestAddRemove(unittest.TestCase):
    def test_add_to_empty(self):
        self.assertEqual(vs.add_entry("", "pilot", BC), f"pilot:{BC}\n")

    def test_add_preserves_others(self):
        out = vs.add_entry(f"publisher:{BC}\n", "pilot", BC2)
        self.assertEqual(vs.parse_htpasswd(out), {"publisher": BC, "pilot": BC2})

    def test_add_existing_is_rotation_not_duplicate(self):
        out = vs.add_entry(f"pilot:{BC}\n", "pilot", BC2)
        self.assertEqual(vs.parse_htpasswd(out), {"pilot": BC2})

    def test_remove(self):
        out = vs.remove_entry(f"publisher:{BC}\npilot:{BC2}\n", "pilot")
        self.assertEqual(vs.parse_htpasswd(out), {"publisher": BC})

    def test_remove_last_leaves_empty_file(self):
        self.assertEqual(vs.remove_entry(f"pilot:{BC}\n", "pilot"), "")

    def test_remove_absent_is_an_error(self):
        # Silently succeeding would report a revocation that never happened.
        with self.assertRaises(vs.SubscriberError):
            vs.remove_entry(f"publisher:{BC}\n", "pilot")


class TestNameValidation(unittest.TestCase):
    def test_accepts_plain_names(self):
        for name in ("pilot", "test-sub", "publisher", "a1"):
            self.assertEqual(vs.validate_name(name), name)

    def test_rejects_bad_names(self):
        for name in ("", "PILOT", "a b", "a:b", "-x", "x-", "a/b", "a\nb"):
            with self.subTest(name=name):
                with self.assertRaises(vs.SubscriberError):
                    vs.validate_name(name)

    def test_colon_in_name_cannot_forge_an_entry(self):
        with self.assertRaises(vs.SubscriberError):
            vs.add_entry("", "evil:$2y$fake", BC)


class TestComposeEscape(unittest.TestCase):
    def test_every_dollar_doubles(self):
        # Compose v5 interpolates '$' in env_file values; the un-escaped form
        # once ate three characters of a bcrypt hash (RUNBOOK § 5.3).
        self.assertEqual(vs.compose_escape(BC), BC.replace("$", "$$"))
        self.assertEqual(vs.compose_escape("no-dollars"), "no-dollars")

    def test_escaped_bcrypt_survives_compose_interpolation(self):
        # What compose does to $$ is collapse it back to $ — round trip.
        self.assertEqual(vs.compose_escape(BC).replace("$$", "$"), BC)

    def test_the_escaped_hash_keeps_its_length(self):
        # The scar was a LENGTH: 57 characters where 60 were written. What the
        # container ends up holding must be the hash, character for character.
        self.assertEqual(len(vs.compose_escape(BC).replace("$$", "$")), len(BC))


class TestEnvFile(unittest.TestCase):
    ENV = "# comment\nPUBLISHER_BCRYPT=old\nEDGE_READER_BASIC=abc\nSUB_PILOT_BCRYPT=x\n"

    def test_sub_env_key(self):
        self.assertEqual(vs.sub_env_key("pilot"), "SUB_PILOT_BCRYPT")
        self.assertEqual(vs.sub_env_key("test-sub"), "SUB_TEST_SUB_BCRYPT")

    def test_an_invalid_account_name_cannot_forge_a_key(self):
        # The key is interpolated into an env file; a name carrying '=' or a
        # newline would write a second variable.
        for name in ("a=b", "a\nb", "A"):
            with self.subTest(name=name):
                with self.assertRaises(vs.SubscriberError):
                    vs.sub_env_key(name)

    def test_set_replaces_only_the_target_line(self):
        out = vs.set_env_value(self.ENV, "PUBLISHER_BCRYPT", "new")
        self.assertIn("PUBLISHER_BCRYPT=new\n", out)
        self.assertIn("# comment\n", out)
        self.assertIn("EDGE_READER_BASIC=abc\n", out)
        self.assertIn("SUB_PILOT_BCRYPT=x\n", out)

    def test_missing_key_is_an_error_not_an_append(self):
        # A key we expected but did not find means the host layout drifted.
        with self.assertRaises(vs.SubscriberError):
            vs.set_env_value(self.ENV, "SUB_GHOST_BCRYPT", "v")

    def test_duplicate_key_rejected(self):
        with self.assertRaises(vs.SubscriberError):
            vs.set_env_value("A=1\nA=2\n", "A", "3")

    def test_env_has_key(self):
        self.assertTrue(vs.env_has_key(self.ENV, "SUB_PILOT_BCRYPT"))
        self.assertFalse(vs.env_has_key(self.ENV, "SUB_GHOST_BCRYPT"))
        # A key is a whole key, not a prefix: SUB_PILOT_BCRYPT must not answer
        # for SUB_PILOT_BCRYPT_OLD, and a commented-out line is not a key.
        self.assertFalse(vs.env_has_key("SUB_PILOT_BCRYPT_OLD=x\n", "SUB_PILOT_BCRYPT"))
        self.assertFalse(vs.env_has_key("# SUB_PILOT_BCRYPT=x\n", "SUB_PILOT_BCRYPT"))

    def test_everything_else_is_byte_identical(self):
        # The Caddyfile reads this file by key; the operator reads it by eye.
        out = vs.set_env_value(self.ENV, "PUBLISHER_BCRYPT", "new")
        self.assertEqual(
            [ln for ln in out.splitlines() if not ln.startswith("PUBLISHER_")],
            [ln for ln in self.ENV.splitlines() if not ln.startswith("PUBLISHER_")],
        )

    def test_a_file_with_no_trailing_newline_keeps_not_having_one(self):
        self.assertEqual(vs.set_env_value("A=1", "A", "2"), "A=2")


class TestAccountScope(unittest.TestCase):
    ENV = "PUBLISHER_BCRYPT=x\nEDGE_READER_BASIC=y\nSUB_PILOT_BCRYPT=z\n"

    def test_scope_is_read_from_the_env_file_not_assumed(self):
        self.assertEqual(vs.account_scope("publisher", self.ENV), "push+pull")
        self.assertEqual(vs.account_scope("edge-signature-reader", self.ENV), "edge-held")
        self.assertEqual(vs.account_scope("pilot", self.ENV), "pull+station")
        self.assertEqual(vs.account_scope("rehearsal", self.ENV), "pull")


class TestSiteConfiguration(unittest.TestCase):
    """ADR-0009 § 4: host coordinates are configuration, not repository content.

    None of the three has a default. A defaulted ssh target would operate
    somebody else's host and report success; a defaulted root would fail
    loudly on the first read, but a default that drifts from the example file
    is still a coordinate this module would be asserting about an estate it
    knows nothing of. Each one refuses, and names itself.
    """

    def setUp(self):
        self.saved = {k: os.environ.pop(k, None)
                      for k in ("CHANNEL_REGISTRY_SSH", "CHANNEL_ROOT", "CHANNEL_EDGE_URL")}

    def tearDown(self):
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    def test_no_host_literal_survives_in_the_module(self):
        # The port's whole reason for landing in this repository rather than
        # the private one: no address, and no absolute path held as a constant.
        source = pathlib.Path(vs.__file__).read_text()
        self.assertNotRegex(source, r"\b\w+@\d{1,3}(?:\.\d{1,3}){3}\b")
        self.assertNotRegex(source, r"(?m)^[A-Z_]+ *= *['\"]/")

    def test_each_coordinate_refuses_and_names_its_variable(self):
        for func, var in ((vs.channel_ssh, "CHANNEL_REGISTRY_SSH"),
                          (vs.channel_root, "CHANNEL_ROOT"),
                          (vs.edge_url, "CHANNEL_EDGE_URL")):
            with self.subTest(var=var):
                with self.assertRaises(vs.SubscriberError) as caught:
                    func()
                self.assertIn(var, str(caught.exception))
                self.assertIn("channel.example.env", str(caught.exception))

    def test_a_trailing_slash_does_not_double_up(self):
        os.environ["CHANNEL_ROOT"] = "/srv/channel/"
        self.assertEqual(vs.htpasswd_path(), "/srv/channel/htpasswd")
        self.assertEqual(vs.env_path(), "/srv/channel/env")
        os.environ["CHANNEL_EDGE_URL"] = "https://channel.example/"
        self.assertEqual(vs.edge_url(), "https://channel.example")


class TestPassword(unittest.TestCase):
    def test_length_and_alphabet(self):
        pw = vs.generate_password()
        self.assertEqual(len(pw), vs.PASSWORD_LENGTH)
        self.assertTrue(set(pw) <= set(vs.PASSWORD_ALPHABET))

    def test_not_repeated(self):
        self.assertEqual(len({vs.generate_password() for _ in range(50)}), 50)


class TestBcryptDetection(unittest.TestCase):
    def test_recognises_bcrypt_prefixes(self):
        for d in ("$2a$05$x", "$2b$05$x", "$2y$05$x"):
            self.assertTrue(vs.is_bcrypt(d))

    def test_rejects_weaker_htpasswd_formats(self):
        # registry:3 refuses these; flagging them beats a silent lockout.
        for d in ("$apr1$abc", "{SHA}abc", "plaintext"):
            self.assertFalse(vs.is_bcrypt(d))


def _has_bcrypt_backend():
    try:
        import bcrypt  # noqa: F401

        return True
    except ImportError:
        pass
    return (
        subprocess.run(
            ["which", "htpasswd"], capture_output=True
        ).returncode
        == 0
    )


@unittest.skipUnless(
    _has_bcrypt_backend(), "no bcrypt module and no htpasswd binary on this host"
)
class TestHashing(unittest.TestCase):
    def test_hash_is_bcrypt_and_parses_back(self):
        digest = vs.bcrypt_hash("hunter2hunter2")
        self.assertTrue(vs.is_bcrypt(digest), digest)
        text = vs.add_entry("", "pilot", digest)
        self.assertEqual(vs.parse_htpasswd(text)["pilot"], digest)

    def test_salted(self):
        self.assertNotEqual(vs.bcrypt_hash("same"), vs.bcrypt_hash("same"))


# --------------------------------------------------------------------------
# The host half, against a stand-in. Every remote command line and every byte
# of stdin is recorded, so the assertions below are about what actually left
# this process for the host — not about what the code says it does.
# --------------------------------------------------------------------------

ROOT = "/srv/x"
HTPASSWD = f"edge-signature-reader:{BC}\npilot:{BC}\npublisher:{BC}\n"
ENV = ("# throwaway\n"
       f"PUBLISHER_BCRYPT={BC.replace('$', '$$')}\n"
       "EDGE_READER_BASIC=ZWRnZTpvbGQ=\n"
       f"SUB_PILOT_BCRYPT={BC.replace('$', '$$')}\n")
FAKE_DIGEST = "$2y$05$" + "F" * 53
CREDENTIAL_LINE = r"^[a-z0-9-]+:[A-Za-z0-9]{32}$"


class FakeHost:
    """What the standalone host looks like from behind ``ssh_run``."""

    def __init__(self, htpasswd=HTPASSWD, env=ENV):
        self.files = {f"{ROOT}/htpasswd": htpasswd, f"{ROOT}/env": env}
        self.commands = []   # (remote command line, stdin) in order
        self.events = []     # "recreate" / "healthz" / ("verify", name, pw)

    def ssh_run(self, command, stdin=None):
        self.commands.append((command, stdin))
        if command.startswith("cat "):
            return self.files[shlex.split(command)[1]]
        if command.startswith("umask 077 && cat > "):
            target = shlex.split(command.split("&&")[-1])[-1]
            self.files[target] = stdin
            return ""
        if command.endswith("docker compose up -d --force-recreate"):
            self.events.append("recreate")
            return ""
        raise AssertionError(f"unexpected remote command: {command!r}")

    @property
    def writes(self):
        return [c for c, _ in self.commands if c.startswith("umask 077")]


class HostCase(unittest.TestCase):
    def setUp(self):
        self.saved = {k: getattr(vs, k) for k in
                      ("ssh_run", "verify_healthz", "verify_credential", "bcrypt_hash")}
        self.env_backup = {k: os.environ.get(k) for k in
                           ("CHANNEL_REGISTRY_SSH", "CHANNEL_ROOT", "CHANNEL_EDGE_URL")}
        vs.verify_healthz = lambda: self.host.events.append("healthz")
        vs.verify_credential = lambda n, p: self.host.events.append(("verify", n, p))
        vs.bcrypt_hash = lambda password: FAKE_DIGEST
        self.reset_host()

    def reset_host(self, **files):
        """A fresh host and a complete site environment; originals untouched."""
        self.host = FakeHost(**files)
        vs.ssh_run = self.host.ssh_run
        os.environ.update(CHANNEL_REGISTRY_SSH="operator@channel.invalid",
                          CHANNEL_ROOT=ROOT, CHANNEL_EDGE_URL="https://channel.invalid")

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(vs, k, v)
        for k, v in self.env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def run_verb(self, func, **kw):
        base = dict(park=False, force=False)
        base.update(kw)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = func(argparse.Namespace(**base))
        return rc, out.getvalue(), err.getvalue()

    def printed_credential(self, out):
        lines = [ln for ln in out.splitlines() if not ln.startswith("#")]
        self.assertEqual(len(lines), 1, out)
        self.assertRegex(lines[0], CREDENTIAL_LINE)
        return lines[0].partition(":")[2]

    def env_value(self, key):
        for line in self.host.files[f"{ROOT}/env"].splitlines():
            if line.split("=", 1)[0] == key:
                return line.split("=", 1)[1]
        self.fail(f"{key} missing from env")


class TestAddOnTheHost(HostCase):
    def test_rotating_a_station_subscriber_touches_both_files_then_recreates(self):
        rc, out, _ = self.run_verb(vs.cmd_add, name="pilot")
        self.assertEqual(rc, 0)
        pw = self.printed_credential(out)
        self.assertEqual(vs.parse_htpasswd(self.host.files[f"{ROOT}/htpasswd"])["pilot"],
                         FAKE_DIGEST)
        # Escaped for compose: every '$' doubled, nothing else touched.
        self.assertEqual(self.env_value("SUB_PILOT_BCRYPT"), FAKE_DIGEST.replace("$", "$$"))
        self.assertEqual(self.env_value("PUBLISHER_BCRYPT"), BC.replace("$", "$$"))
        self.assertIn("# throwaway\n", self.host.files[f"{ROOT}/env"])
        # Write, write, recreate, healthz, prove — and only then was it printed.
        self.assertEqual(len(self.host.writes), 2)
        self.assertEqual(self.host.events, ["recreate", "healthz", ("verify", "pilot", pw)])
        self.assertEqual(self.host.files[f"{ROOT}/htpasswd"].count("\n"), 3)

    def test_writes_precede_the_recreate_and_are_atomic_0600(self):
        self.run_verb(vs.cmd_add, name="pilot")
        recreate_at = next(i for i, (c, _) in enumerate(self.host.commands)
                           if c.endswith("--force-recreate"))
        for c in self.host.writes:
            self.assertLess(self.host.commands.index((c, self.host.files[
                shlex.split(c.split("&&")[-1])[-1]])), recreate_at)
            self.assertIn("umask 077 && cat > ", c)
            self.assertIn("chmod 600 ", c)
            self.assertIn(" && mv ", c)

    def test_publisher_rotation_rewrites_the_write_gate(self):
        rc, out, _ = self.run_verb(vs.cmd_add, name="publisher")
        self.assertEqual(rc, 0)
        self.printed_credential(out)
        self.assertEqual(self.env_value("PUBLISHER_BCRYPT"), FAKE_DIGEST.replace("$", "$$"))
        self.assertEqual(self.env_value("SUB_PILOT_BCRYPT"), BC.replace("$", "$$"))

    def test_edge_reader_rotation_rewrites_the_basic_credential_the_edge_presents(self):
        rc, out, _ = self.run_verb(vs.cmd_add, name="edge-signature-reader")
        self.assertEqual(rc, 0)
        pw = self.printed_credential(out)
        expected = base64.b64encode(f"edge-signature-reader:{pw}".encode()).decode()
        self.assertEqual(self.env_value("EDGE_READER_BASIC"), expected)
        # The value legitimately lands in the env file (the edge must PRESENT
        # it), and it travels there over stdin: never on a remote command line.
        for command, _ in self.host.commands:
            self.assertNotIn(pw, command)
            self.assertNotIn(expected, command)
        self.assertNotIn(pw, self.host.files[f"{ROOT}/htpasswd"])

    def test_a_new_pull_only_subscriber_leaves_env_alone_and_says_so(self):
        rc, out, err = self.run_verb(vs.cmd_add, name="rehearsal")
        self.assertEqual(rc, 0)
        self.printed_credential(out)
        self.assertEqual(len(self.host.writes), 1)          # htpasswd only
        self.assertEqual(self.host.files[f"{ROOT}/env"], ENV)
        self.assertIn("pull-only", err)
        self.assertIn("SUB_REHEARSAL_BCRYPT", err)
        self.assertIn("rehearsal", vs.parse_htpasswd(self.host.files[f"{ROOT}/htpasswd"]))
        self.assertEqual(self.host.events, ["recreate", "healthz", ("verify", "rehearsal",
                         self.printed_credential(out))])

    def test_the_password_never_reaches_a_remote_command_line(self):
        for name in ("pilot", "publisher", "edge-signature-reader", "rehearsal"):
            with self.subTest(name=name):
                self.reset_host()
                _, out, _ = self.run_verb(vs.cmd_add, name=name)
                pw = self.printed_credential(out)
                self.assertTrue(all(pw not in c for c, _ in self.host.commands))

    def test_a_missing_env_key_refuses_before_any_write(self):
        self.reset_host(env=ENV.replace("EDGE_READER_BASIC=ZWRnZTpvbGQ=\n", ""))
        with self.assertRaises(vs.SubscriberError) as caught:
            self.run_verb(vs.cmd_add, name="edge-signature-reader")
        self.assertIn("EDGE_READER_BASIC", str(caught.exception))
        self.assertEqual(self.host.writes, [])
        self.assertEqual(self.host.events, [])

    def test_a_root_that_is_not_the_stack_refuses_before_any_write(self):
        # $CHANNEL_ROOT pointing at a directory with an env file but no
        # PUBLISHER_BCRYPT is not the live stack; nothing is rotated there.
        self.reset_host(env="# something else\nOTHER=1\n")
        with self.assertRaises(vs.SubscriberError) as caught:
            self.run_verb(vs.cmd_add, name="pilot")
        self.assertIn("PUBLISHER_BCRYPT", str(caught.exception))
        self.assertEqual(self.host.writes, [])

    def test_site_variables_are_demanded_before_the_mint(self):
        # The edge URL is only USED after the recreate; demanded up front, a
        # missing one refuses with zero remote commands instead of after the
        # htpasswd was rewritten.
        for var in ("CHANNEL_REGISTRY_SSH", "CHANNEL_ROOT", "CHANNEL_EDGE_URL"):
            with self.subTest(var=var):
                self.reset_host()
                os.environ.pop(var)
                with self.assertRaises(vs.SubscriberError) as caught:
                    self.run_verb(vs.cmd_add, name="pilot")
                self.assertIn(var, str(caught.exception))
                self.assertEqual(self.host.commands, [])

    def test_park_preflight_runs_before_any_host_read(self):
        with self.assertRaises(vs.SubscriberError) as caught:
            self.run_verb(vs.cmd_add, name="pilot", park=True, channel=None)
        self.assertIn("--channel", str(caught.exception))
        self.assertEqual(self.host.commands, [])


class TestRevokeOnTheHost(HostCase):
    def test_the_two_edge_accounts_need_force(self):
        for name in ("publisher", "edge-signature-reader"):
            with self.subTest(name=name):
                with self.assertRaises(vs.SubscriberError):
                    self.run_verb(vs.cmd_revoke, name=name)
                self.assertEqual(self.host.commands, [])
        rc, out, _ = self.run_verb(vs.cmd_revoke, name="publisher", force=True)
        self.assertEqual(rc, 0)
        self.assertNotIn("publisher", vs.parse_htpasswd(self.host.files[f"{ROOT}/htpasswd"]))

    def test_revoke_removes_the_line_recreates_and_notes_the_lingering_env_key(self):
        rc, out, err = self.run_verb(vs.cmd_revoke, name="pilot")
        self.assertEqual(rc, 0)
        self.assertNotIn("pilot", vs.parse_htpasswd(self.host.files[f"{ROOT}/htpasswd"]))
        self.assertEqual(len(self.host.writes), 1)
        self.assertEqual(self.host.files[f"{ROOT}/env"], ENV)   # deliberately untouched
        self.assertEqual(self.host.events, ["recreate", "healthz"])
        self.assertIn("SUB_PILOT_BCRYPT", err)
        self.assertIn("revoked pilot", out)

    def test_revoking_an_absent_account_writes_nothing(self):
        with self.assertRaises(vs.SubscriberError):
            self.run_verb(vs.cmd_revoke, name="ghost")
        self.assertEqual(self.host.writes, [])
        self.assertEqual(self.host.events, [])


class TestListOnTheHost(HostCase):
    def test_scope_is_read_from_the_two_files(self):
        rc, out, _ = self.run_verb(vs.cmd_list)
        self.assertEqual(rc, 0)
        rows = {ln.split()[0]: ln.split()[1] for ln in out.splitlines()[1:]}
        self.assertEqual(rows, {"edge-signature-reader": "edge-held",
                                "pilot": "pull+station",
                                "publisher": "push+pull"})
        self.assertTrue(all(c.startswith("cat ") for c, _ in self.host.commands))


if __name__ == "__main__":
    unittest.main()
