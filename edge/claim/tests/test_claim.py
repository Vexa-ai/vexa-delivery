# SPDX-License-Identifier: Apache-2.0
"""The park format and the claim state machine.

Hermetic: no socket, no cluster, no keypair. The transitions decide who gets a
credential, so they are tested WITHOUT age — `decrypt` is injected — and they run
everywhere, including CI, where the `age` binary is not installed. The envelope
itself gets one real round trip below, skipped when the binary is absent, the way
this repository already skips bcrypt hashing.
"""

import datetime
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import vexa_claim as vc  # noqa: E402

# An age-SHAPED placeholder. Not an encryption of anything: the state machine
# treats the ciphertext as opaque and only `age_decrypt` ever opens one, so a
# filler body exercises every path a real envelope would. Written this way on
# purpose — a realistic ciphertext in a test file trips credential scanners and
# costs a human the check every time.
ARMOR = "-----BEGIN AGE ENCRYPTED FILE-----\nnot-a-real-envelope\n-----END AGE ENCRYPTED FILE-----\n"
CREDENTIAL = {"username": "pilot", "password": "not-a-real-password"}


def decrypt_ok(_armor):
    return json.dumps(CREDENTIAL)


def decrypt_broken(_armor):
    raise vc.ClaimError("no identity matched this file")


def at(minute):
    return datetime.datetime(2026, 9, 6, 12, minute, 0, tzinfo=datetime.timezone.utc)


class Alphabet(unittest.TestCase):
    def test_it_is_digits_and_only_digits(self):
        # The code is SAID, down a phone line, between two people who may not
        # share a first language. Letters do not survive that; digits do.
        self.assertEqual(vc.CODE_ALPHABET, "0123456789")

    def test_shape(self):
        self.assertEqual(len(vc.CODE_ALPHABET), 10)
        self.assertEqual(vc.CODE_LENGTH, 6)
        self.assertEqual(10 ** vc.CODE_LENGTH, 1_000_000)
        self.assertEqual(vc.TTL_SECONDS, 900)
        self.assertEqual(vc.MAX_ATTEMPTS, 5)

    def test_generated_codes_use_only_the_alphabet(self):
        for _ in range(200):
            code = vc.generate_code()
            self.assertEqual(len(code), vc.CODE_LENGTH)
            self.assertTrue(set(code) <= set(vc.CODE_ALPHABET))

    def test_codes_are_drawn_across_the_space(self):
        # NOT "all 200 are distinct": at 10^6 the birthday bound puts a
        # collision in 200 draws at about 2%, so that assertion would fail one
        # CI run in fifty and teach everyone to re-run it. What a counter or a
        # constant would fail, and randomness passes with room to spare, is
        # this.
        self.assertGreaterEqual(len({vc.generate_code() for _ in range(200)}), 195)

    def test_normalise_accepts_what_a_human_types(self):
        code = "123456"
        for typed in ("123456", "123 456", "123-456", " 123 456 ", "1 2 3 4 5 6"):
            self.assertEqual(vc.normalise_code(typed), code)

    def test_normalise_refuses_everything_else(self):
        # A character outside the alphabet is not a near miss to be repaired —
        # it is a code this system never issued.
        for bad in ("", "12345", "1234567", "12345O", "1234S6", "12345!", "abcdef"):
            with self.subTest(bad=bad):
                with self.assertRaises(vc.ClaimError):
                    vc.normalise_code(bad)

    def test_format_groups_in_threes_with_a_space(self):
        self.assertEqual(vc.format_code("123456"), "123 456")

    def test_hash_is_over_the_normalised_code(self):
        salt = vc.new_salt()
        self.assertEqual(vc.code_sha256(salt, "123 456"),
                         vc.code_sha256(salt, "123456"))
        self.assertTrue(vc.codes_match(salt, "123-456",
                                       vc.code_sha256(salt, "123456")))
        self.assertFalse(vc.codes_match(salt, "123457",
                                        vc.code_sha256(salt, "123456")))

    def test_the_digest_is_salted_and_a_salt_is_never_reused(self):
        # At six digits an unsalted digest IS the code — a million candidates
        # is milliseconds — and this value is copied into the stations ledger,
        # a git repository that outlives the park. Two parks of the same code
        # must therefore commit to different digests.
        first, second = vc.new_salt(), vc.new_salt()
        self.assertNotEqual(first, second)
        self.assertNotEqual(vc.code_sha256(first, "123456"),
                            vc.code_sha256(second, "123456"))
        self.assertFalse(vc.codes_match(second, "123456",
                                        vc.code_sha256(first, "123456")))

    def test_station_names_cannot_traverse(self):
        for bad in ("../../etc", "/etc/shadow", "..", "Pilot", "a b", "", None):
            with self.subTest(bad=bad):
                with self.assertRaises(vc.ClaimError):
                    vc.validate_station(bad)


class Park(unittest.TestCase):
    def setUp(self):
        self.spool = pathlib.Path(tempfile.mkdtemp(prefix="vexa-park-"))

    def park(self, code, **kw):
        record = vc.build_park(
            station=kw.pop("station", "pilot"), account="pilot", code=code,
            ciphertext=ARMOR, parked_by="tester", edge="https://channel.example/claim",
            now=kw.pop("now", at(0)), **kw,
        )
        vc.write_park(self.spool, record)
        return record

    def test_build_refuses_anything_that_is_not_an_age_file(self):
        # The one guard between "the sealing step was skipped" and a plaintext
        # credential written to a spool on an internet-facing host.
        with self.assertRaises(vc.ClaimError):
            vc.build_park(station="pilot", account="pilot", code=vc.generate_code(),
                          ciphertext="pilot:hunter2", parked_by="t", edge="x")

    def test_record_carries_no_password_field(self):
        record = self.park("123456")
        self.assertNotIn("password", record)
        self.assertEqual(record["ciphertext"], ARMOR)
        self.assertEqual(len(record["code_salt"]), 32)
        self.assertEqual(record["code_sha256"],
                         vc.code_sha256(record["code_salt"], "123456"))
        self.assertEqual(record["expires_at"], "2026-09-06T12:15:00Z")

    def test_park_file_is_not_group_or_world_readable(self):
        self.park("123456")
        mode = vc.park_path(self.spool, "pilot").stat().st_mode
        self.assertFalse(mode & 0o077, oct(mode))

    def test_claim_returns_the_credential_once(self):
        self.park("123456")
        out = vc.redeem(self.spool, station="pilot", code="123 456",
                        decrypt=decrypt_ok, now=at(1))
        self.assertEqual(out["username"], "pilot")
        self.assertEqual(out["password"], CREDENTIAL["password"])
        self.assertEqual(out["station"], "pilot")

    def test_the_ciphertext_stops_existing_on_redemption(self):
        record = self.park("123456")
        vc.redeem(self.spool, station="pilot", code="123456",
                  decrypt=decrypt_ok, now=at(1))
        self.assertFalse(vc.park_path(self.spool, "pilot").exists())
        # ...and the record of it survives, because the identifying facts were
        # copied into the state file before the park file was removed.
        state = vc.read_json(vc.state_path(self.spool, "pilot", record["park_id"]))
        self.assertEqual(state["state"], vc.REDEEMED)
        self.assertEqual(state["code_sha256"], record["code_sha256"])
        self.assertNotIn("ciphertext", state)
        # The salt dies with the park file. What survives — here and in the
        # ledger — is a digest nobody can invert without it.
        self.assertNotIn("code_salt", state)

    def test_second_claim_is_refused(self):
        self.park("123456")
        vc.redeem(self.spool, station="pilot", code="123456",
                  decrypt=decrypt_ok, now=at(1))
        with self.assertRaises(vc.ClaimRefused) as caught:
            vc.redeem(self.spool, station="pilot", code="123456",
                      decrypt=decrypt_ok, now=at(2))
        self.assertEqual(caught.exception.reason, vc.REFUSAL_NO_PARK)

    def test_expiry(self):
        self.park("123456")
        with self.assertRaises(vc.ClaimRefused) as caught:
            vc.redeem(self.spool, station="pilot", code="123456",
                      decrypt=decrypt_ok, now=at(15))
        self.assertEqual(caught.exception.reason, vc.REFUSAL_EXPIRED)
        self.assertFalse(vc.park_path(self.spool, "pilot").exists())

    def test_expiry_is_checked_before_the_code(self):
        # A caller who arrives late with the RIGHT code retires the park as
        # expired rather than spending one of its five attempts on a code that
        # was correct. Ordering, not cosmetics: get it the other way round and a
        # late-but-correct claim reads in the log as a guess.
        record = self.park("123456")
        with self.assertRaises(vc.ClaimRefused):
            vc.redeem(self.spool, station="pilot", code="123456",
                      decrypt=decrypt_ok, now=at(16))
        state = vc.read_json(vc.state_path(self.spool, "pilot", record["park_id"]))
        self.assertEqual(state["state"], vc.EXPIRED)
        self.assertEqual(state["attempts"], 0)

    def test_five_failed_attempts_burn_it(self):
        record = self.park("123456")
        for n in range(1, 5):
            with self.assertRaises(vc.ClaimRefused) as caught:
                vc.redeem(self.spool, station="pilot", code="222222",
                          decrypt=decrypt_ok, now=at(n))
            self.assertEqual(caught.exception.reason, vc.REFUSAL_WRONG_CODE)
            self.assertFalse(caught.exception.burned)
            state = vc.read_json(vc.state_path(self.spool, "pilot", record["park_id"]))
            self.assertEqual(state["attempts"], n)
            self.assertEqual(state["state"], vc.LIVE)

        with self.assertRaises(vc.ClaimRefused) as caught:
            vc.redeem(self.spool, station="pilot", code="222222",
                      decrypt=decrypt_ok, now=at(5))
        self.assertTrue(caught.exception.burned)
        state = vc.read_json(vc.state_path(self.spool, "pilot", record["park_id"]))
        self.assertEqual(state["state"], vc.BURNED)
        self.assertFalse(vc.park_path(self.spool, "pilot").exists())

    def test_the_right_code_after_a_burn_gets_nothing(self):
        self.park("123456")
        for n in range(1, 6):
            with self.assertRaises(vc.ClaimRefused):
                vc.redeem(self.spool, station="pilot", code="222222",
                          decrypt=decrypt_ok, now=at(n))
        with self.assertRaises(vc.ClaimRefused):
            vc.redeem(self.spool, station="pilot", code="123456",
                      decrypt=decrypt_ok, now=at(6))

    def test_a_failed_attempt_on_one_station_does_not_touch_another(self):
        self.park("123456", station="pilot")
        self.park("654321", station="second")
        for n in range(1, 6):
            with self.assertRaises(vc.ClaimRefused):
                vc.redeem(self.spool, station="pilot", code="222222",
                          decrypt=decrypt_ok, now=at(n))
        out = vc.redeem(self.spool, station="second", code="654321",
                        decrypt=decrypt_ok, now=at(6))
        self.assertEqual(out["station"], "second")

    def test_a_code_is_bound_to_its_station(self):
        self.park("123456", station="pilot")
        self.park("654321", station="second")
        with self.assertRaises(vc.ClaimRefused) as caught:
            vc.redeem(self.spool, station="second", code="123456",
                      decrypt=decrypt_ok, now=at(1))
        self.assertEqual(caught.exception.reason, vc.REFUSAL_WRONG_CODE)
        # ...and it cost `second` an attempt, which is the point of counting per
        # park: the guess was aimed at second's park, so second's park counts it.
        self.assertEqual(
            vc.read_json(vc.state_path(self.spool, "second",
                                       vc.read_json(vc.park_path(self.spool, "second"))
                                       ["park_id"]))["attempts"], 1)

    def test_a_malformed_code_is_a_wrong_code_not_an_error(self):
        # It used to escape as a ClaimError, which the service answered 503
        # while a merely wrong code got 403 — a free oracle separating
        # "malformed" from "wrong" on the one value that is secret. Same
        # branch, same answer, and it costs an attempt like any other guess.
        record = self.park("123456")
        # Exactly MAX_ATTEMPTS of them, so the last one is also the burn: five
        # malformed codes cost a park exactly what five wrong ones do.
        bad_codes = ["!!!", "12345", "12345O", None, 123456]
        self.assertEqual(len(bad_codes), vc.MAX_ATTEMPTS)
        for n, bad in enumerate(bad_codes, start=1):
            with self.subTest(bad=bad):
                with self.assertRaises(vc.ClaimRefused) as caught:
                    vc.redeem(self.spool, station="pilot", code=bad,
                              decrypt=decrypt_ok, now=at(n))
                self.assertEqual(
                    caught.exception.reason,
                    vc.REFUSAL_BURNED if n == vc.MAX_ATTEMPTS else vc.REFUSAL_WRONG_CODE)
        state = vc.read_json(vc.state_path(self.spool, "pilot", record["park_id"]))
        self.assertEqual(state["state"], vc.BURNED)

    def test_a_claim_for_a_station_never_parked_is_refused(self):
        with self.assertRaises(vc.ClaimRefused) as caught:
            vc.redeem(self.spool, station="pilot", code="123456",
                      decrypt=decrypt_ok, now=at(1))
        self.assertEqual(caught.exception.reason, vc.REFUSAL_NO_PARK)

    def test_our_own_decryption_failure_does_not_burn_their_code(self):
        # A park sealed to a rotated key is OUR mistake. Burning the
        # subscriber's only code over it would make them wait for a new one for
        # no reason, so the error propagates and the park stays live.
        record = self.park("123456")
        with self.assertRaises(vc.ClaimError):
            vc.redeem(self.spool, station="pilot", code="123456",
                      decrypt=decrypt_broken, now=at(1))
        self.assertTrue(vc.park_path(self.spool, "pilot").exists())
        # Nothing was consumed, so nothing was written: no attempt, no terminal
        # state, not even a state file. The edge still logs the failure to
        # attempts.ndjson as `error:` — an outcome, not a guess.
        self.assertIsNone(
            vc.read_json(vc.state_path(self.spool, "pilot", record["park_id"])))
        # And the right code still works once we fix the identity.
        self.assertEqual(
            vc.redeem(self.spool, station="pilot", code="123456",
                      decrypt=decrypt_ok, now=at(2))["password"],
            CREDENTIAL["password"])

    def test_a_park_without_a_salt_refuses_rather_than_guessing(self):
        # There is no unsalted fallback to fall back to: guessing that a park
        # with no salt means `sha256(code)` would be inventing a scheme, and it
        # would reinstate exactly the million-candidate digest the salt exists
        # to remove. It is OUR problem, so it takes the same path as a bad
        # identity file — the park survives and no attempt is spent.
        record = self.park("123456")
        del record["code_salt"]
        vc.write_park(self.spool, record)
        with self.assertRaises(vc.ClaimError):
            vc.redeem(self.spool, station="pilot", code="123456",
                      decrypt=decrypt_ok, now=at(1))
        self.assertTrue(vc.park_path(self.spool, "pilot").exists())
        self.assertIsNone(
            vc.read_json(vc.state_path(self.spool, "pilot", record["park_id"])))

    def test_reparking_supersedes_and_does_not_inherit_the_counter(self):
        # Re-parking IS the rotation path. The new park gets a new park_id and
        # therefore a NEW state file, rather than this process resetting a
        # counter the edge owns.
        first = self.park("123456")
        for n in range(1, 4):
            with self.assertRaises(vc.ClaimRefused):
                vc.redeem(self.spool, station="pilot", code="222222",
                          decrypt=decrypt_ok, now=at(n))
        second = self.park("654321", now=at(5))
        self.assertNotEqual(first["park_id"], second["park_id"])
        out = vc.redeem(self.spool, station="pilot", code="654321",
                        decrypt=decrypt_ok, now=at(6))
        self.assertEqual(out["password"], CREDENTIAL["password"])
        # The superseded park's own record is untouched and still readable.
        old = vc.read_json(vc.state_path(self.spool, "pilot", first["park_id"]))
        self.assertEqual(old["attempts"], 3)

    def test_attempts_log_is_append_only_and_carries_no_value(self):
        vc.append_attempt(self.spool, vc.attempt_event(
            station="pilot", outcome="wrong-code", source="203.0.113.7", now=at(1)))
        vc.append_attempt(self.spool, vc.attempt_event(
            station="pilot", outcome="claimed", source="203.0.113.7", now=at(2)))
        lines = vc.attempts_path(self.spool).read_text().strip().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            event = json.loads(line)
            self.assertEqual(event["station"], "pilot")
            self.assertIn("outcome", event)
            self.assertIn("source", event)
            self.assertIn("ts", event)
        self.assertNotIn(CREDENTIAL["password"], vc.attempts_path(self.spool).read_text())


@unittest.skipUnless(vc.have_age(), "no `age` binary on this host")
class AgeEnvelope(unittest.TestCase):
    """One real round trip. The transitions above are proved without it; this
    proves the thing that actually protects the value."""

    def setUp(self):
        import subprocess

        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="vexa-age-"))
        self.key = self.dir / "edge.key"
        subprocess.run(["age-keygen", "-o", str(self.key)],
                       capture_output=True, check=True)
        public = [ln.split(": ", 1)[1] for ln in self.key.read_text().splitlines()
                  if ln.startswith("# public key: ")][0]
        self.recipients = self.dir / "edge.recipients"
        self.recipients.write_text(public + "\n")

    def test_round_trip(self):
        armor = vc.age_encrypt(str(self.recipients), json.dumps(CREDENTIAL))
        self.assertTrue(armor.startswith("-----BEGIN AGE ENCRYPTED FILE-----"))
        self.assertNotIn(CREDENTIAL["password"], armor)
        self.assertEqual(json.loads(vc.age_decrypt(str(self.key), armor)), CREDENTIAL)

    def test_another_identity_cannot_open_it(self):
        import subprocess

        other = self.dir / "other.key"
        subprocess.run(["age-keygen", "-o", str(other)], capture_output=True, check=True)
        armor = vc.age_encrypt(str(self.recipients), json.dumps(CREDENTIAL))
        with self.assertRaises(vc.ClaimError):
            vc.age_decrypt(str(other), armor)

    def test_a_missing_or_empty_recipients_file_refuses(self):
        with self.assertRaises(vc.ClaimError):
            vc.age_encrypt(str(self.dir / "nope"), "x")
        empty = self.dir / "empty"
        empty.write_text("\n")
        with self.assertRaises(vc.ClaimError):
            vc.age_encrypt(str(empty), "x")

    def test_identity_permissions_are_checked(self):
        self.assertTrue(vc.identity_is_private(str(self.key)))
        self.key.chmod(0o644)
        self.assertFalse(vc.identity_is_private(str(self.key)))


if __name__ == "__main__":
    unittest.main()
