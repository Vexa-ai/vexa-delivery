# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the station report's load-bearing behaviours: redaction keeps
the structure and drops the values, the leak scan catches a value that survived
into the finished document, and the document itself round-trips — every section
parses back to the exact text its digest was taken over. No cluster, no
network."""
import pathlib
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:                                            # pragma: no cover
    yaml = None

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from vexa_validate import (REDACTED, Doc, digest_of, normalise,  # noqa: E402
                           redact, render_yaml, scan_text_for_leaks, trim_console)

VALUES = {
    "secrets": {
        "existingSecretName": "",
        "adminApiToken": "adm-0123456789abcdef",
        "internalApiSecret": "int-0123456789abcdef",
    },
    "meetingApi": {"transcriptionServiceUrl": "http://whisper.internal:9000"},
    "global": {"imagePullSecrets": [], "tolerations": [{"key": "workload", "value": "vexa"}]},
    "flows": {"enabled": True, "apiKey": "flw-0123456789abcdef",
              "mail": {"address": "ops@bank.example", "appPassword": "pw-0123456789"}},
    "runtime": {"extraEnv": [{"name": "VEXA_RUNNER", "value": "k8s"},
                             {"name": "RUNTIME_SECRET_MOUNT", "value": "/very/secret/path"}]},
    "replicas": 3,
}


class TestRedact(unittest.TestCase):
    def setUp(self):
        self.removed = set()
        self.out = redact(VALUES, removed=self.removed)

    def test_secrets_section_is_gone(self):
        self.assertEqual(self.out["secrets"]["adminApiToken"], REDACTED)
        self.assertEqual(self.out["secrets"]["internalApiSecret"], REDACTED)
        self.assertEqual(self.out["flows"]["apiKey"], REDACTED)
        self.assertEqual(self.out["flows"]["mail"]["appPassword"], REDACTED)

    def test_env_var_named_secret_is_redacted_by_its_sibling_name(self):
        env = {e["name"]: e["value"] for e in self.out["runtime"]["extraEnv"]}
        self.assertEqual(env["RUNTIME_SECRET_MOUNT"], REDACTED)
        self.assertEqual(env["VEXA_RUNNER"], "k8s")

    def test_structure_and_non_secret_config_survive(self):
        self.assertEqual(self.out["meetingApi"]["transcriptionServiceUrl"],
                         "http://whisper.internal:9000")
        self.assertEqual(self.out["flows"]["enabled"], True)
        self.assertEqual(self.out["replicas"], 3)
        self.assertEqual(self.out["global"]["imagePullSecrets"], [])
        self.assertEqual(list(self.out.keys()), list(VALUES.keys()))

    def test_empty_scalars_stay_empty_not_redacted(self):
        # "" means not-set, which is configuration information, not a secret
        self.assertEqual(self.out["secrets"]["existingSecretName"], "")

    def test_a_tolerations_key_named_key_is_redacted_conservatively(self):
        # `tolerations[].key` is harmless, but the rule is blunt on purpose:
        # a false positive costs one line of config, a false negative a credential
        self.assertEqual(self.out["global"]["tolerations"][0]["key"], REDACTED)

    def test_removed_set_carries_exactly_the_plaintext_values(self):
        self.assertIn("adm-0123456789abcdef", self.removed)
        self.assertIn("pw-0123456789", self.removed)
        self.assertNotIn("", self.removed)
        self.assertNotIn("k8s", self.removed)


class TestLeakScan(unittest.TestCase):
    """The scan reads the RENDERED document, so what is checked is the bytes
    that would be sent. The archive bought that property by being re-extracted
    and re-scanned; one file gets it for nothing."""

    def test_a_clean_document_has_no_hits(self):
        text = f"values: |\n  adminApiToken: {REDACTED}\n"
        self.assertEqual(scan_text_for_leaks(text, {"adm-0123456789abcdef"}), [])

    def test_a_survivor_is_caught_in_any_section(self):
        text = "smoke_console: |\n  token adm-0123456789abcdef used\n"
        self.assertEqual(scan_text_for_leaks(text, {"adm-0123456789abcdef"}), [0])

    def test_the_finding_names_the_index_and_never_the_value(self):
        hits = scan_text_for_leaks("x adm-0123456789abcdef", {"adm-0123456789abcdef"})
        self.assertNotIn("adm-", str(hits))

    def test_short_values_are_not_scanned(self):
        self.assertEqual(scan_text_for_leaks('namespace: prod', {"prod"}), [])


class TestSections(unittest.TestCase):
    def test_normalise_is_what_the_digest_is_taken_over(self):
        self.assertEqual(normalise("a  \r\nb\n\n\n"), "a\nb\n")
        self.assertEqual(normalise(""), "")
        self.assertEqual(normalise("\n\n"), "")

    def test_an_empty_section_is_absent_and_never_an_empty_string(self):
        doc = Doc()
        doc.add("smoke_receipt", "   \n\n")
        self.assertNotIn("smoke_receipt", doc.sections)
        self.assertEqual(doc.gaps[0]["what"], "smoke_receipt")

    def test_a_console_is_trimmed_to_its_tail_and_says_so(self):
        text = "".join(f"line {i}\n" for i in range(500))
        kept, note, dropped = trim_console(text, keep=200)
        self.assertEqual(dropped, 300)
        self.assertTrue(kept.startswith("line 300\n"))
        self.assertIn("the last 200 of 500 lines", note)

    def test_a_short_console_is_not_trimmed_and_carries_no_note(self):
        kept, note, dropped = trim_console("one\ntwo\n", keep=200)
        self.assertEqual((kept, note, dropped), ("one\ntwo\n", None, 0))

    def test_the_whole_console_is_kept_locally_when_it_is_trimmed(self):
        doc = Doc()
        doc.add_console("smoke_console", "".join(f"line {i}\n" for i in range(500)))
        self.assertIn("smoke_console", doc.overflow)
        self.assertEqual(len(doc.overflow["smoke_console"].splitlines()), 500)
        row, = doc.manifest
        self.assertEqual(row["lines"], 200)
        self.assertEqual(row["source_lines"], 500)


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestTheDocumentRoundTrips(unittest.TestCase):
    """THE PROPERTY THE WHOLE SHAPE RESTS ON. A section's digest is only worth
    something if the text a reader parses back is the text that was hashed —
    otherwise the ingest refuses every honest report at S3, or worse, accepts
    one that was edited."""

    SECTIONS = {
        "profile": "PROVIDER=lke\nPROFILE_TESTED=no\n",
        "values": "secrets:\n  adminApiToken: REDACTED\nreplicas: 3\n",
        "contract_document": "contract_id: t-1\nrequire:\n  - a\n",
        "preflight_receipt": "P1 ok\n\nP9 ok\nVERDICT: PASS\n",
        "smoke_console": "  leading space is content\n\ttab too\n#hash\n- dash\n",
    }

    def build(self):
        doc = Doc()
        for name, text in self.SECTIONS.items():
            doc.add(name, text)
        report = {"schema_version": 1, "bundle_kind": "install", "station": "s",
                  "generated_at": "2026-08-27T00:00:00+00:00", "generator": "test",
                  "phases": {"smoke": {"verdict": "PASS"}},
                  **doc.sections, "sections": doc.manifest, "absent": doc.gaps,
                  "redaction": {"verified": True, "values_redacted": 1, "leaks": 0}}
        return report, render_yaml(report)

    def test_every_section_parses_back_to_the_bytes_its_digest_covers(self):
        report, text = self.build()
        back = yaml.safe_load(text)
        for row in report["sections"]:
            self.assertEqual(back[row["name"]], report[row["name"]], row["name"])
            self.assertEqual(digest_of(back[row["name"]]), row["sha256"], row["name"])

    def test_it_is_one_document_and_the_manifest_facts_are_top_level(self):
        _, text = self.build()
        self.assertEqual(len(list(yaml.safe_load_all(text))), 1)
        back = yaml.safe_load(text)
        for key in ("schema_version", "station", "phases", "sections", "redaction"):
            self.assertIn(key, back)

    def test_every_section_carries_a_plain_english_comment_above_it(self):
        _, text = self.build()
        for name in self.SECTIONS:
            head = text.split(f"\n{name}: |")[0].rsplit("\n\n", 1)[-1]
            self.assertTrue(head.startswith("#"), f"{name} has no comment above it")


if __name__ == "__main__":
    unittest.main()
