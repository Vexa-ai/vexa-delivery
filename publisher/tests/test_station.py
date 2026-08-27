# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the station lane's checks.

Hermetic: no helm, no network — rendered manifests are synthetic dicts shaped
like `helm template` output, and station reports are written in a tmpdir. The
refusals are the load-bearing tests: a station gate that passes something its
contract did not cover is worse than no gate.
"""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_station as vs  # noqa: E402

DIGEST = "@sha256:" + "a" * 64


def deployment(name="api", image="vexaai/v012-gateway:v0.12.26" + DIGEST, resources=None,
               volumes=None, kind="Deployment"):
    return {
        "kind": kind,
        "metadata": {"name": name},
        "spec": {"template": {"spec": {
            "containers": [{
                "name": name,
                "image": image,
                "resources": resources if resources is not None else {
                    "requests": {"cpu": "100m", "memory": "256Mi"},
                    "limits": {"cpu": "1", "memory": "1Gi"},
                },
            }],
            "volumes": volumes or [],
        }}},
    }


class Resources(unittest.TestCase):
    def test_declared_passes(self):
        self.assertEqual(vs.check_resources([deployment()]), [])

    def test_missing_resources_refused(self):
        bad = vs.check_resources([deployment(resources={})])
        self.assertEqual(len(bad), 4)  # requests/limits x cpu/memory
        self.assertIn("Deployment/api", bad[0])

    def test_requests_without_limits_refused(self):
        bad = vs.check_resources([deployment(resources={"requests": {"cpu": "1", "memory": "1Gi"}})])
        self.assertEqual(len(bad), 2)
        self.assertTrue(all("limits" in b for b in bad))

    def test_init_containers_are_checked_too(self):
        d = deployment()
        d["spec"]["template"]["spec"]["initContainers"] = [
            {"name": "wait", "image": "busybox" + DIGEST}]
        bad = vs.check_resources([d])
        self.assertEqual(len(bad), 4)
        self.assertIn("initContainers/wait", bad[0])

    def test_cronjob_template_is_reached(self):
        cj = {"kind": "CronJob", "metadata": {"name": "floor"}, "spec": {"jobTemplate": {"spec": {
            "template": {"spec": {"containers": [
                {"name": "floor", "image": "vexaai/tool" + DIGEST, "resources": {}}]}}}}}}
        self.assertEqual(len(vs.check_resources([cj])), 4)

    def test_non_workload_kinds_ignored(self):
        self.assertEqual(vs.check_resources([{"kind": "Service", "metadata": {"name": "s"},
                                              "spec": {"ports": []}}]), [])


class HostPath(unittest.TestCase):
    def test_clean_passes(self):
        self.assertEqual(vs.check_no_hostpath([deployment()]), [])

    def test_hostpath_refused(self):
        bad = vs.check_no_hostpath([deployment(
            volumes=[{"name": "docker", "hostPath": {"path": "/var/run/docker.sock"}}])])
        self.assertEqual(len(bad), 1)
        self.assertIn("/var/run/docker.sock", bad[0])

    def test_emptydir_is_not_hostpath(self):
        self.assertEqual(vs.check_no_hostpath([deployment(
            volumes=[{"name": "shm", "emptyDir": {"medium": "Memory"}}])]), [])


class DigestPinning(unittest.TestCase):
    def test_pinned_passes(self):
        self.assertEqual(vs.check_digest_pinned([deployment()]), [])

    def test_mutable_tag_refused(self):
        bad = vs.check_digest_pinned([deployment(image="minio/mc:latest")])
        self.assertEqual(len(bad), 1)
        self.assertIn("not digest-pinned", bad[0])

    def test_digest_must_be_the_whole_suffix(self):
        # a digest-looking substring followed by a tag is not a pin
        bad = vs.check_digest_pinned([deployment(image="repo/x" + DIGEST + ":latest")])
        self.assertEqual(len(bad), 1)

    def test_short_digest_refused(self):
        bad = vs.check_digest_pinned([deployment(image="repo/x@sha256:abc123")])
        self.assertEqual(len(bad), 1)


class Contract(unittest.TestCase):
    def test_all_met(self):
        rows, unmet = vs.check_contract(["a", "b"], ["a", "b", "c"], {})
        self.assertEqual(unmet, [])
        self.assertTrue(all(r[1] == "MET" for r in rows))

    def test_unmet_named(self):
        rows, unmet = vs.check_contract(["a", "b"], ["a"], {})
        self.assertEqual(unmet, ["b"])
        self.assertIn(("b", "UNMET", "no guarantee, no waiver"), rows)

    def test_waiver_satisfies_but_is_recorded(self):
        rows, unmet = vs.check_contract(["a"], [], {"a": "founder accepted, run slips to Tuesday"})
        self.assertEqual(unmet, [])
        self.assertEqual(rows[0][1], "WAIVED")
        self.assertIn("founder accepted", rows[0][2])

    def test_unused_waiver_surfaces(self):
        rows, _ = vs.check_contract(["a"], ["a"], {"z": "stale waiver from last release"})
        self.assertIn("WAIVER-UNUSED", [r[1] for r in rows])

    def test_requirements_must_be_strings(self):
        with self.assertRaises(vs.CheckFailure):
            vs.contract_requirements({"require": [{"item": "a"}]})

    def test_bare_string_requirement_accepted(self):
        self.assertEqual(vs.contract_requirements({"require": "a"}), ["a"])

    def test_no_require_is_an_empty_contract(self):
        self.assertEqual(vs.contract_requirements({"contract_id": "x"}), [])


class Waivers(unittest.TestCase):
    class Args:
        def __init__(self, waive, reason):
            self.waive, self.reason = waive, reason

    def test_paired(self):
        w = vs.parse_waivers(self.Args(["a", "b"], ["reason one here", "reason two here"]))
        self.assertEqual(w, {"a": "reason one here", "b": "reason two here"})

    def test_unpaired_refused(self):
        with self.assertRaises(vs.CheckFailure):
            vs.parse_waivers(self.Args(["a", "b"], ["only one reason"]))

    def test_empty_reason_refused(self):
        with self.assertRaises(vs.CheckFailure):
            vs.parse_waivers(self.Args(["a"], ["ok"]))

    def test_no_waivers(self):
        self.assertEqual(vs.parse_waivers(self.Args(None, None)), {})


class SecretScan(unittest.TestCase):
    """S4, now over SECTIONS. The scan parses each section back into its own
    format — values as YAML, profile as an env file — so a credential inside a
    block scalar is caught by exactly the two scans that used to run over
    files. A scan of the outer document alone would see one long string."""

    def scan(self, **sections):
        report = {"schema_version": 1, "station": "rehearsal", **sections}
        return vs.scan_report_for_secrets(report, sections)

    def test_redacted_values_pass(self):
        self.assertEqual(self.scan(values=(
            "secrets:\n  existingSecretName: vexa-secrets\n  adminApiToken: REDACTED\n"
            "  internalApiSecret: \"\"\n  nextauthSecret: CHANGE_ME_nextauth\n")), [])

    def test_plaintext_value_refused(self):
        f = self.scan(values="secrets:\n  adminApiToken: s3cr3t-live-token-9f2a41cc\n")
        self.assertEqual(len(f), 1)
        self.assertIn("secrets.adminApiToken", f[0])
        self.assertIn("[values]", f[0])

    def test_refusal_never_prints_the_value(self):
        f = self.scan(values="secrets:\n  adminApiToken: s3cr3t-live-token-9f2a41cc\n")
        self.assertNotIn("s3cr3t-live-token", " ".join(f))

    def test_secret_reference_is_not_a_secret(self):
        self.assertEqual(self.scan(values=(
            "secrets:\n  existingSecretName: my-own-precreated-secret\n"
            "postgres:\n  credentialsSecretName: postgres-credentials\n")), [])

    def test_the_profile_section_is_scanned_as_an_env_file(self):
        f = self.scan(profile="STATION_NAME=x\n# comment\nREGISTRY_TOKEN=abcd1234efgh5678\n")
        self.assertEqual(len(f), 1)
        self.assertIn("[profile]:3", f[0])

    def test_env_placeholder_passes(self):
        self.assertEqual(self.scan(profile="REGISTRY_TOKEN=REDACTED\nSTATION_NAME=x\n"), [])

    def test_pattern_scan_catches_pasted_credentials(self):
        for name, blob in (
            ("smoke_receipt", '{"log": "authorization: Bearer '
                              'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij"}'),
            ("preflight_receipt", "aws key AKIAIOSFODNN7EXAMPLE in the log"),
            ("smoke_console", "-----BEGIN RSA PRIVATE KEY-----"),
        ):
            with self.subTest(name):
                self.assertTrue(self.scan(**{name: blob}))

    def test_a_secret_in_a_manifest_field_is_still_caught(self):
        report = {"schema_version": 1, "provider": {"registryToken": "abcd1234efgh5678"}}
        self.assertTrue(vs.scan_report_for_secrets(report, {}))

    def test_unparseable_yaml_refused(self):
        with self.assertRaises(vs.CheckFailure):
            self.scan(values="secrets:\n  a: [unclosed\n")


SECTION_KEYS = ("profile", "values", "contract_document", "preflight_receipt",
                "smoke_receipt", "smoke_console", "install_log")


def make_report(path, sections, station="rehearsal", manifest_sections=None, drop=(),
                station_name=None, **head):
    """Write a station report whose sections[] digests match its own text.

    Hand-rolled rather than driven through the packager: these tests are the
    INGEST's, and a fixture built by the tool under test on the other side of
    the exchange proves the two agree, never that either is right.
    """
    body = {k: v for k, v in sections.items() if k not in drop}
    manifest = {
        "schema_version": 1, "station": station_name or station,
        "generated_at": "2026-08-24T00:00:00Z", "generator": "test",
        "sections": manifest_sections if manifest_sections is not None else [
            {"name": n, "sha256": hashlib.sha256(sections[n].encode()).hexdigest()}
            for n in sorted(sections) if n not in drop],
        **head,
        **body,
    }
    path.write_text(yaml.safe_dump(manifest, sort_keys=False))
    return path


COMPLETE = {
    "profile": "STATION_NAME=rehearsal\nPROVIDER=openshift\n",
    "values": "secrets:\n  adminApiToken: REDACTED\n",
    # report_scope is present because S10 refuses a report whose station
    # contract carries no bound on what may leave. `tier` is deliberately
    # ABSENT here: that is the pre-ladder shape every existing subscriber has,
    # it must keep working, and it reads as tier 1.
    "contract_document": ("contract_id: t-2026-01\nrequire:\n  - images-digest-pinned\n"
                          "report_scope:\n  schema: report.v1\n"
                          "  trigger: explicit-command-only\n"
                          "  destination: channel.vexa.ai\n"),
    "preflight_receipt": "RESULT: PASS (9/9)\n",
    "smoke_receipt": '{"result": "PASS"}\n',
}


class Ingest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ingest-test-"))

    def ingest(self, report, station="rehearsal"):
        return vs.main(["--stations-dir", str(self.tmp / "stations"),
                        "ingest", "--bundle", str(report), "--station", station])

    def test_a_complete_report_ingests(self):
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE))
        self.assertEqual(self.ingest(b), 0)
        dest = self.tmp / "stations" / "rehearsal"
        # ONE artifact plus our own receipt. The sections are not written back
        # out as files: a directory of derived copies is a second version of
        # what the customer sent, and it can disagree with the first.
        self.assertEqual(sorted(p.name for p in dest.iterdir()),
                         ["ingest-receipt.json", "station-report.yaml"])
        receipt = json.loads((dest / "ingest-receipt.json").read_text())
        self.assertTrue(receipt["ingested_at"].endswith("Z"))
        self.assertEqual(receipt["checks_passed"], ["S1", "S2", "S3", "S4", "S10"])
        self.assertEqual([r["name"] for r in receipt["sections"]], sorted(COMPLETE))
        # ...and the receipt records WHICH scope the ingest enforced, so an
        # audit can answer "under what declared rung was this kept?" without
        # re-reading a contract that may since have changed.
        self.assertEqual(receipt["bundle_kind"], "install")
        self.assertEqual(receipt["report_scope"]["declared_tier"], 1)
        self.assertEqual(receipt["report_scope"]["bundle_tier"], 1)

    def test_an_incomplete_report_is_refused(self):
        for role in COMPLETE:
            with self.subTest(role):
                b = make_report(self.tmp / f"{role}.yaml", dict(COMPLETE), drop=(role,))
                self.assertEqual(self.ingest(b), 3)

    def test_an_empty_section_is_as_missing_as_no_section(self):
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE, preflight_receipt="   \n"))
        self.assertEqual(self.ingest(b), 3)

    def test_station_name_must_match(self):
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE))
        self.assertEqual(self.ingest(b, station="someone-else"), 3)

    def test_digest_mismatch_refused(self):
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE), manifest_sections=[
            {"name": n, "sha256": "0" * 64} for n in sorted(COMPLETE)])
        self.assertEqual(self.ingest(b), 3)

    def test_an_edited_section_is_caught_by_its_digest(self):
        b = self.tmp / "b.yaml"
        make_report(b, dict(COMPLETE))
        doc = yaml.safe_load(b.read_text())
        doc["values"] = doc["values"] + "extraKnob: true\n"
        b.write_text(yaml.safe_dump(doc, sort_keys=False))
        self.assertEqual(self.ingest(b), 3)

    def test_an_undeclared_section_is_refused(self):
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE, smoke_console="smuggled\n"),
                        manifest_sections=[
                            {"name": n, "sha256": hashlib.sha256(COMPLETE[n].encode()).hexdigest()}
                            for n in sorted(COMPLETE)])
        self.assertEqual(self.ingest(b), 3)

    def test_an_undeclared_top_level_key_is_refused(self):
        """report.v1 is a closed schema. This is where we hold ourselves to it
        on the side the customer cannot audit — a key nobody enumerated is a
        content channel nobody agreed to."""
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE), transcript="…she said…")
        self.assertEqual(self.ingest(b), 3)

    def test_a_second_yaml_document_is_refused(self):
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE))
        b.write_text(b.read_text() + "---\nstation: elsewhere\n")
        self.assertEqual(self.ingest(b), 3)

    def test_a_report_too_large_to_have_been_read_is_refused(self):
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE))
        b.write_text(b.read_text() + "# padding\n" * (vs.MAX_REPORT_BYTES // 10))
        self.assertEqual(self.ingest(b), 3)

    def test_planted_secret_refused(self):
        b = make_report(self.tmp / "b.yaml", dict(
            COMPLETE, values="secrets:\n  adminApiToken: s3cr3t-live-token-9f2a41cc\n"))
        self.assertEqual(self.ingest(b), 3)
        self.assertFalse((self.tmp / "stations" / "rehearsal").exists())

    def test_re_ingest_needs_force(self):
        b = make_report(self.tmp / "b.yaml", dict(COMPLETE))
        self.assertEqual(self.ingest(b), 0)
        self.assertEqual(self.ingest(b), 3)
        self.assertEqual(vs.main(["--stations-dir", str(self.tmp / "stations"), "ingest",
                                  "--bundle", str(b), "--station", "rehearsal", "--force"]), 0)


class ReportShape(unittest.TestCase):
    """S1. The traversal, link and single-root checks are gone because their
    SUBJECT is gone — nothing is extracted. What is left is the same question
    in the new shape: one document of the kind we accept, small enough that a
    person could have read it."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="shape-test-"))

    def load(self, text, name="r.yaml"):
        p = self.tmp / name
        p.write_text(text)
        return vs.load_report(p)

    def test_one_mapping_passes(self):
        report, _ = self.load("schema_version: 1\nstation: x\n")
        self.assertEqual(report["station"], "x")

    def test_a_list_is_not_a_report(self):
        with self.assertRaises(vs.CheckFailure):
            self.load("- one\n- two\n")

    def test_two_documents_refused(self):
        with self.assertRaises(vs.CheckFailure):
            self.load("schema_version: 1\n---\nschema_version: 1\n")

    def test_unparseable_yaml_refused(self):
        with self.assertRaises(vs.CheckFailure):
            self.load("station: [unclosed\n")

    def test_a_future_schema_version_is_refused_not_guessed(self):
        with self.assertRaises(vs.CheckFailure):
            self.load("schema_version: 2\nstation: x\n")

    def test_a_missing_file_refused(self):
        with self.assertRaises(vs.CheckFailure):
            vs.load_report(self.tmp / "nope.yaml")


class GateReport(unittest.TestCase):
    def test_waivers_are_written_loudly(self):
        out = pathlib.Path(tempfile.mkdtemp()) / "report.md"
        vs.write_gate_report(out, {
            "station": "rehearsal", "date": "2026-08-24", "at": "2026-08-24T00:00:00Z",
            "verdict": "PASS", "chart_name": "vexa-0.12.26.tgz", "chart_sha256": "a" * 64,
            "values_sha256": "b" * 64, "contract_id": "t-2026-01", "contract_sha256": "c" * 64,
            "evidence": "none supplied",
            "env_rows": [("S5", "renders", "PASS")],
            "contract_rows": [("x", "WAIVED", "slips to Tuesday")],
            "waivers": {"x": "slips to Tuesday"}, "failures": [],
        })
        text = out.read_text()
        self.assertIn("WAIVERS", text)
        self.assertIn("slips to Tuesday", text)
        self.assertIn("A waiver is a promise nobody checked", text)


if __name__ == "__main__":
    unittest.main()
