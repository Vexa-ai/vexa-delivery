# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the station lane's checks.

Hermetic: no helm, no network, no tarballs on the network path — rendered
manifests are synthetic dicts shaped like `helm template` output, and bundles
are built in a tmpdir. The refusals are the load-bearing tests: a station gate
that passes something its contract did not cover is worse than no gate.
"""
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest

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
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="station-test-"))

    def write(self, name, text):
        (self.tmp / name).write_text(text)

    def test_redacted_values_pass(self):
        self.write("values.redacted.yaml",
                   "secrets:\n  existingSecretName: vexa-secrets\n  adminApiToken: REDACTED\n"
                   "  internalApiSecret: \"\"\n  nextauthSecret: CHANGE_ME_nextauth\n")
        self.assertEqual(vs.scan_bundle_for_secrets(self.tmp), [])

    def test_plaintext_value_refused(self):
        self.write("values.redacted.yaml", "secrets:\n  adminApiToken: s3cr3t-live-token-9f2a41cc\n")
        f = vs.scan_bundle_for_secrets(self.tmp)
        self.assertEqual(len(f), 1)
        self.assertIn("secrets.adminApiToken", f[0])

    def test_refusal_never_prints_the_value(self):
        self.write("values.redacted.yaml", "secrets:\n  adminApiToken: s3cr3t-live-token-9f2a41cc\n")
        self.assertNotIn("s3cr3t-live-token", " ".join(vs.scan_bundle_for_secrets(self.tmp)))

    def test_secret_reference_is_not_a_secret(self):
        self.write("values.redacted.yaml",
                   "secrets:\n  existingSecretName: my-own-precreated-secret\n"
                   "postgres:\n  credentialsSecretName: postgres-credentials\n")
        self.assertEqual(vs.scan_bundle_for_secrets(self.tmp), [])

    def test_env_file_scanned(self):
        self.write("profile.env", "STATION_NAME=x\n# comment\nREGISTRY_TOKEN=abcd1234efgh5678\n")
        f = vs.scan_bundle_for_secrets(self.tmp)
        self.assertEqual(len(f), 1)
        self.assertIn("profile.env:3", f[0])

    def test_env_placeholder_passes(self):
        self.write("profile.env", "REGISTRY_TOKEN=REDACTED\nSTATION_NAME=x\n")
        self.assertEqual(vs.scan_bundle_for_secrets(self.tmp), [])

    def test_pattern_scan_catches_pasted_credentials(self):
        for name, blob in (("smoke-receipt.json", '{"log": "authorization: Bearer '
                                                  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij"}'),
                           ("preflight-receipt.txt", "aws key AKIAIOSFODNN7EXAMPLE in the log"),
                           ("notes.txt", "-----BEGIN RSA PRIVATE KEY-----")):
            with self.subTest(name):
                for p in self.tmp.iterdir():
                    p.unlink()
                self.write(name, blob)
                self.assertTrue(vs.scan_bundle_for_secrets(self.tmp))

    def test_unparseable_yaml_refused(self):
        self.write("values.redacted.yaml", "secrets:\n  a: [unclosed\n")
        with self.assertRaises(vs.CheckFailure):
            vs.scan_bundle_for_secrets(self.tmp)


def make_bundle(path, files, station="rehearsal", manifest_files=None, drop=()):
    """Build a bundle tar.gz whose station.json digests match its bytes."""
    import hashlib

    root = pathlib.Path(tempfile.mkdtemp(prefix="bundle-")) / station
    root.mkdir()
    for name, text in files.items():
        (root / name).write_text(text)
    manifest = {
        "schema_version": 1, "station": station, "customer": "test",
        "created_at": "2026-08-24T00:00:00Z",
        "files": manifest_files if manifest_files is not None else [
            {"name": n, "sha256": hashlib.sha256((root / n).read_bytes()).hexdigest()}
            for n in sorted(files) if n not in drop],
    }
    (root / "station.json").write_text(json.dumps(manifest, indent=1))
    for n in drop:
        (root / n).unlink()
    with tarfile.open(path, "w:gz") as tf:
        tf.add(root, arcname=station)
    return path


COMPLETE = {
    "profile.env": "STATION_NAME=rehearsal\nPROVIDER=openshift\n",
    "values.redacted.yaml": "secrets:\n  adminApiToken: REDACTED\n",
    # report_scope is present because S10 refuses a bundle whose station
    # contract carries no bound on what may leave. `tier` is deliberately
    # ABSENT here: that is the pre-ladder shape every existing subscriber has,
    # it must keep working, and it reads as tier 1.
    "contract.yaml": ("contract_id: t-2026-01\nrequire:\n  - images-digest-pinned\n"
                      "report_scope:\n  schema: report.v1\n"
                      "  trigger: explicit-command-only\n"
                      "  destination: channel.vexa.ai\n"),
    "preflight-receipt.txt": "RESULT: PASS (9/9)\n",
    "smoke-receipt.json": '{"result": "PASS"}\n',
}


class Ingest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ingest-test-"))

    def ingest(self, bundle, station="rehearsal"):
        return vs.main(["--stations-dir", str(self.tmp / "stations"),
                        "ingest", "--bundle", str(bundle), "--station", station])

    def test_complete_bundle_ingests(self):
        b = make_bundle(self.tmp / "b.tar.gz", dict(COMPLETE))
        self.assertEqual(self.ingest(b), 0)
        dest = self.tmp / "stations" / "rehearsal"
        for name in list(COMPLETE) + ["station.json", "ingest-receipt.json"]:
            self.assertTrue((dest / name).is_file(), name)
        receipt = json.loads((dest / "ingest-receipt.json").read_text())
        self.assertTrue(receipt["ingested_at"].endswith("Z"))
        self.assertEqual(receipt["checks_passed"], ["S1", "S2", "S3", "S4", "S10"])
        # ...and the receipt records WHICH scope the ingest enforced, so an
        # audit can answer "under what declared rung was this kept?" without
        # re-reading a contract that may since have changed.
        self.assertEqual(receipt["bundle_kind"], "install")
        self.assertEqual(receipt["report_scope"]["declared_tier"], 1)
        self.assertEqual(receipt["report_scope"]["bundle_tier"], 1)

    def test_incomplete_bundle_refused(self):
        files = dict(COMPLETE)
        files.pop("contract.yaml")
        b = make_bundle(self.tmp / "b.tar.gz", files)
        self.assertEqual(self.ingest(b), 3)

    def test_missing_declared_file_refused(self):
        b = make_bundle(self.tmp / "b.tar.gz", dict(COMPLETE), drop=("contract.yaml",))
        self.assertEqual(self.ingest(b), 3)

    def test_station_name_must_match(self):
        b = make_bundle(self.tmp / "b.tar.gz", dict(COMPLETE))
        self.assertEqual(self.ingest(b, station="someone-else"), 3)

    def test_digest_mismatch_refused(self):
        b = make_bundle(self.tmp / "b.tar.gz", dict(COMPLETE), manifest_files=[
            {"name": n, "sha256": "0" * 64} for n in sorted(COMPLETE)])
        self.assertEqual(self.ingest(b), 3)

    def test_undeclared_file_refused(self):
        files = dict(COMPLETE)
        files["extra.txt"] = "smuggled\n"
        b = make_bundle(self.tmp / "b.tar.gz", files, manifest_files=None, drop=())
        # declare everything except the extra file
        import hashlib
        root = pathlib.Path(tempfile.mkdtemp()) / "rehearsal"
        root.mkdir()
        for n, t in files.items():
            (root / n).write_text(t)
        (root / "station.json").write_text(json.dumps({
            "schema_version": 1, "station": "rehearsal", "files": [
                {"name": n, "sha256": hashlib.sha256((root / n).read_bytes()).hexdigest()}
                for n in sorted(COMPLETE)]}))
        b = self.tmp / "c.tar.gz"
        with tarfile.open(b, "w:gz") as tf:
            tf.add(root, arcname="rehearsal")
        self.assertEqual(self.ingest(b), 3)

    def test_planted_secret_refused(self):
        files = dict(COMPLETE)
        files["values.redacted.yaml"] = "secrets:\n  adminApiToken: s3cr3t-live-token-9f2a41cc\n"
        b = make_bundle(self.tmp / "b.tar.gz", files)
        self.assertEqual(self.ingest(b), 3)
        self.assertFalse((self.tmp / "stations" / "rehearsal").exists())

    def test_re_ingest_needs_force(self):
        b = make_bundle(self.tmp / "b.tar.gz", dict(COMPLETE))
        self.assertEqual(self.ingest(b), 0)
        self.assertEqual(self.ingest(b), 3)
        self.assertEqual(vs.main(["--stations-dir", str(self.tmp / "stations"), "ingest",
                                  "--bundle", str(b), "--station", "rehearsal", "--force"]), 0)


class BundleShape(unittest.TestCase):
    def members(self, *names):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for n in names:
                info = tarfile.TarInfo(n)
                info.size = 0
                tf.addfile(info, io.BytesIO(b""))
        buf.seek(0)
        return tarfile.open(fileobj=buf)

    def test_traversal_refused(self):
        with self.assertRaises(vs.CheckFailure):
            list(vs.safe_members(self.members("rehearsal/../../etc/passwd")))

    def test_absolute_path_refused(self):
        with self.assertRaises(vs.CheckFailure):
            list(vs.safe_members(self.members("/etc/passwd")))

    def test_two_roots_refused(self):
        with self.assertRaises(vs.CheckFailure):
            list(vs.safe_members(self.members("a/one", "b/two")))

    def test_single_root_passes(self):
        self.assertEqual(len(list(vs.safe_members(self.members("a/one", "a/two")))), 2)


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
