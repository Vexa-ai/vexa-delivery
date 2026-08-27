# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the upgrade state reporter.

Fixture-driven and completely offline: the fake `kubectl`, `psql` and `pg_dump`
in kit/report/tests/bin/ answer out of kit/report/tests/fixtures/<case>/, so the
whole tool runs end to end with no cluster, no database and no network.

What is pinned here is what the docs promise:

  * REDACTION works on structures and on the pg_dump text, and the leak scan
    catches a value that survived — naming files, never values;
  * ABSENT-OVER-ZERO: a cluster that refuses every read produces a report that
    says so, not one that says the namespace is empty;
  * PROBE SHAPE: probes run, carry their SQL verbatim, evaluate against their
    own stated expectation, and are refused before execution if they are not
    an aggregate count;
  * EXIT CODES: 0 written, 2 usage, 3 redaction leak.

The fake psql also asserts that the session was opened read-only, so the
read-only claim is tested rather than asserted in a docstring.
"""
import ast
import contextlib
import io
import json
import os
import pathlib
import shutil
import sys
import tarfile
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import vexa_state_report as sr                                          # noqa: E402

BIN = HERE / "bin"
FIXTURES = HERE / "fixtures"


def extract(archive, dest):
    with tarfile.open(archive) as tar:
        try:
            tar.extractall(dest, filter="data")
        except TypeError:                      # python < 3.12 has no filters
            tar.extractall(dest)
    return pathlib.Path(dest) / "state-report"


class Run:
    """One end-to-end invocation against a fixture directory.

    `probes_dir=None` runs the tool as if it had been copied somewhere on its
    own, without its probes/ directory beside it — which is what an operator
    who scp's one file to a jump box actually does.
    """

    def __init__(self, case, argv, probes_dir=""):
        self.case, self.argv, self.probes_dir = case, argv, probes_dir

    def __enter__(self):
        self.tmp = tempfile.mkdtemp(prefix="vexa-report-test-")
        self.env = dict(os.environ)
        self.here = sr.HERE
        os.environ["PATH"] = str(BIN) + os.pathsep + os.environ.get("PATH", "")
        os.environ["VEXA_TEST_FIXTURES"] = str(FIXTURES / self.case)
        os.environ.pop("VEXA_REPORT_DB_URL", None)
        if self.probes_dir is None:
            sr.HERE = pathlib.Path(self.tmp) / "lonely-copy"
            sr.HERE.mkdir()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.code = sr.main(self.argv + ["--out", self.tmp])
        self.out = buf.getvalue()
        self.archive = pathlib.Path(self.tmp) / "state-report.tar.gz"
        self.root = extract(self.archive, pathlib.Path(self.tmp) / "x")
        return self

    def __exit__(self, *exc):
        sr.HERE = self.here
        os.environ.clear()
        os.environ.update(self.env)
        shutil.rmtree(self.tmp, ignore_errors=True)
        return False

    def json(self, name):
        return json.loads((self.root / name).read_text())

    def text(self, name):
        return (self.root / name).read_text()


# ── redaction ───────────────────────────────────────────────────────────────


class TestRedact(unittest.TestCase):
    VALUES = {
        "secrets": {"existingSecretName": "", "adminApiToken": "adm-0123456789abcdef"},
        "model": "large-v3",
        "env": [{"name": "WHISPER_MODEL", "value": "medium"},
                {"name": "RUNTIME_SECRET_MOUNT", "value": "/very/secret/path"}],
        "replicas": 3,
    }

    def setUp(self):
        self.removed = set()
        self.out = sr.redact(self.VALUES, removed=self.removed)

    def test_secret_values_go_and_structure_stays(self):
        self.assertEqual(self.out["secrets"]["adminApiToken"], sr.REDACTED)
        self.assertEqual(self.out["model"], "large-v3")
        self.assertEqual(self.out["replicas"], 3)
        self.assertEqual(list(self.out.keys()), list(self.VALUES.keys()))

    def test_env_named_secret_is_caught_by_its_sibling_name(self):
        env = {e["name"]: e["value"] for e in self.out["env"]}
        self.assertEqual(env["RUNTIME_SECRET_MOUNT"], sr.REDACTED)
        self.assertEqual(env["WHISPER_MODEL"], "medium")

    def test_empty_scalar_means_not_set_and_is_not_a_secret(self):
        self.assertEqual(self.out["secrets"]["existingSecretName"], "")
        self.assertNotIn("", self.removed)


class TestRedactText(unittest.TestCase):
    def test_assignment_and_quoted_option_forms(self):
        removed = set()
        out = sr.redact_text(
            "ALTER ROLE vexa SET app.api_token = 'tok-abc-123456';\n"
            "OPTIONS (host 'analytics.internal', password 'fdw-secret-9999');\n",
            removed)
        self.assertNotIn("tok-abc-123456", out)
        self.assertNotIn("fdw-secret-9999", out)
        self.assertIn(sr.REDACTED, out)
        self.assertIn("analytics.internal", out)      # not a credential; DDL survives
        self.assertEqual(removed, {"tok-abc-123456", "fdw-secret-9999"})

    def test_ordinary_ddl_is_untouched(self):
        before = 'CREATE TABLE public.meetings (\n    status character varying(50)\n);\n'
        self.assertEqual(sr.redact_text(before), before)


class TestLeakScan(unittest.TestCase):
    def test_survivor_is_found_and_reported_by_path_not_value(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "sub").mkdir()
            (root / "sub" / "workloads.json").write_text('{"image": "x:leaky-value-123456"}')
            hits = sr.scan_for_leaks(root, {"leaky-value-123456"})
            self.assertEqual([p for p, _ in hits], ["sub/workloads.json"])
            self.assertTrue(all(isinstance(i, int) for _, i in hits))

    def test_short_values_are_not_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "db.json").write_text('{"database": "vexa"}')
            self.assertEqual(sr.scan_for_leaks(root, {"vexa"}), [])


class TestEnvAllowlist(unittest.TestCase):
    def test_reproduction_variables_are_allowed(self):
        for name in ("WHISPER_MODEL_SIZE", "DEVICE", "BEAM_SIZE", "LANGUAGE",
                     "WORKERS", "REPLICAS", "COMPUTE_TYPE"):
            self.assertTrue(sr.env_allowed(name), name)

    def test_the_refusal_outranks_the_allowlist(self):
        # MODEL_API_KEY matches "model" AND "key". It must lose.
        for name in ("MODEL_API_KEY", "WHISPER_TOKEN", "DEVICE_SECRET"):
            self.assertFalse(sr.env_allowed(name), name)

    def test_everything_else_is_simply_absent(self):
        for name in ("DATABASE_URL", "REDIS_URL", "SMTP_HOST"):
            self.assertFalse(sr.env_allowed(name), name)


# ── probes ──────────────────────────────────────────────────────────────────


class TestProbeGrammar(unittest.TestCase):
    def test_an_aggregate_count_is_accepted(self):
        self.assertTrue(sr.check_probe_sql("SELECT count(*) FROM meetings WHERE x = 1;"))

    def test_a_row_read_is_refused(self):
        with self.assertRaises(sr.SqlRefusal):
            sr.check_probe_sql("SELECT * FROM meetings")

    def test_a_write_is_refused(self):
        for sql in ("DELETE FROM meetings",
                    "SELECT count(*) FROM meetings; DROP TABLE meetings",
                    "SELECT count(*) FROM meetings WHERE (SELECT 1 FROM x) IS NOT NULL "
                    "UNION SELECT 1 -- create index"):
            with self.assertRaises(sr.SqlRefusal, msg=sql):
                sr.check_probe_sql(sql)

    def test_every_shipped_probe_passes_its_own_grammar(self):
        for path in sorted((sr.HERE / "probes").glob("*.json")):
            doc = json.loads(path.read_text())
            self.assertTrue(doc.get("probes"), path.name)
            for probe in doc["probes"]:
                for field in ("name", "hazard", "expect", "sql", "migration"):
                    self.assertIn(field, probe, "%s: %s" % (path.name, probe.get("name")))
                sr.check_probe_sql(probe["sql"])


class TestExpectation(unittest.TestCase):
    def test_polarity_is_per_probe_not_a_convention(self):
        self.assertTrue(sr.evaluate({"equals": 0}, 0))
        self.assertFalse(sr.evaluate({"equals": 0}, 2))
        self.assertTrue(sr.evaluate({"equals": 1}, 1))
        self.assertFalse(sr.evaluate({"equals": 1}, 0))   # a missing index is NOT ok
        self.assertTrue(sr.evaluate({"at_least": 0}, 418))

    def test_a_count_that_was_never_taken_is_unknown_not_passing(self):
        self.assertIsNone(sr.evaluate({"equals": 0}, None))


# ── end to end ──────────────────────────────────────────────────────────────


class TestHealthyRun(unittest.TestCase):
    ARGV = ["--namespace", "vexa", "--db-pod", "postgres-0",
            "--db-name", "vexa", "--db-user", "vexa"]

    def test_exit_zero_and_every_section_present(self):
        with Run("healthy", self.ARGV) as r:
            self.assertEqual(r.code, 0)
            for name in ("report.json", "workloads.json", "db.json", "schema.sql",
                         "probes.json", "runtime.json", "README.txt"):
                self.assertTrue((r.root / name).is_file(), name)

    def test_workloads_carry_running_digests_and_chart_provenance(self):
        with Run("healthy", self.ARGV) as r:
            w = r.json("workloads.json")
            self.assertEqual(w["kubernetes_server_version"], "v1.28.9")
            whisper = next(x for x in w["workloads"] if x["name"] == "vexa-whisperlive")
            self.assertEqual(whisper["chart"]["helm.sh/chart"], "vexa-0.10.4")
            self.assertEqual(whisper["replicas"], {"desired": 2, "ready": 2, "available": 2})
            self.assertTrue(whisper["running"][0]["digest"].startswith("sha256:"))
            # The per-meeting bot pod belongs to no Deployment and must not be
            # lost — but it is grouped under "(unowned)" rather than under its
            # own name, because a per-meeting pod is named after the meeting.
            orphans = w["unowned_running_images"]
            self.assertEqual(list(orphans), ["(unowned)"])
            self.assertEqual(orphans["(unowned)"][0]["repository"], "vexaai/vexa-bot")
            self.assertNotIn("meeting-xyz", json.dumps(w))

    def test_nodes_are_grouped_by_shape_and_not_named(self):
        with Run("healthy", self.ARGV) as r:
            nodes = r.json("workloads.json")["nodes"]
            self.assertEqual(nodes["total"], 3)
            self.assertEqual(len(nodes["classes"]), 2)
            gpu = next(c for c in nodes["classes"] if c["gpu"])
            self.assertEqual(gpu["gpu"]["nvidia.com/gpu"], "1")
            self.assertNotIn("node-gpu-1", json.dumps(nodes))

    def test_db_reports_the_absent_alembic_table_as_expected_not_broken(self):
        with Run("healthy", self.ARGV) as r:
            db = r.json("db.json")
            self.assertEqual(db["server_version"], "16.3")
            self.assertEqual(db["size_bytes"], 3221225472)
            self.assertIsNone(db["migration"]["revisions"])
            self.assertIn("converges the schema", db["migration"]["note"])
            self.assertEqual([e["name"] for e in db["extensions"]],
                             ["pgcrypto", "plpgsql", "uuid-ossp"])

    def test_a_never_analysed_table_is_null_not_zero(self):
        with Run("healthy", self.ARGV) as r:
            rows = {t["table"]: t for t in r.json("db.json")["tables"]["rows"]}
            self.assertEqual(rows["meetings"]["rows"], 418)
            self.assertIsNone(rows["transcriptions"]["rows"])
            self.assertIn("never analysed", rows["transcriptions"]["reason"])

    def test_schema_is_ddl_and_its_credentials_are_gone(self):
        with Run("healthy", self.ARGV) as r:
            sql = r.text("schema.sql")
            self.assertIn("CREATE TABLE public.meetings", sql)
            self.assertNotIn("tok-should-be-redacted-42", sql)
            self.assertNotIn("fdw-secret-value-9999", sql)
            self.assertEqual(r.json("report.json")["sections"]["schema.sql"]["source"],
                             "pg_dump --schema-only")

    def test_probes_ran_carry_their_sql_verbatim_and_are_judged(self):
        with Run("healthy", self.ARGV) as r:
            probes = {p["name"]: p for p in r.json("probes.json")["probes"]}
            dupes = probes["meeting-active-duplicate-keys"]
            self.assertEqual(dupes["count"], 2)
            self.assertFalse(dupes["holds"])
            self.assertIn("SELECT count(*)", dupes["sql"])
            self.assertIn("HAVING count(*) > 1", dupes["sql"])
            # the index is absent on a pre-0.12.23 estate: expected 1, got 0
            self.assertFalse(probes["meeting-active-index-present-and-valid"]["holds"])
            # a probe that cannot fail is context, not a violation
            self.assertTrue(probes["meetings-non-terminal-total"]["holds"])
            self.assertEqual(sorted(r.json("probes.json")["violations"]),
                             ["meeting-active-duplicate-keys",
                              "meeting-active-duplicate-rows",
                              "meeting-active-index-present-and-valid"])

    def test_runtime_captures_the_model_and_device_and_nothing_else(self):
        with Run("healthy", self.ARGV) as r:
            rt = r.json("runtime.json")
            whisper = next(w for w in rt["workloads"] if w["name"] == "vexa-whisperlive")
            container = whisper["containers"][0]
            self.assertEqual(container["model"]["value"], "medium")
            self.assertEqual(container["inference_device"]["value"], "cuda")
            self.assertEqual(container["gpu_requested"]["nvidia.com/gpu"], "1")
            self.assertEqual(container["image_tag"], "0.10.4")
            names = {e["name"] for e in container["env"]}
            self.assertIn("BEAM_SIZE", names)
            self.assertIn("LANGUAGE", names)
            # allowlist-first: these were never written, not written-then-redacted
            self.assertNotIn("REDIS_URL", names)
            self.assertNotIn("MODEL_API_KEY", names)
            # a valueFrom env records WHERE the value comes from, never the value
            token = next(e for e in container["env"] if e["name"] == "ADMIN_API_TOKEN")
            self.assertEqual(token["from"], "secretKeyRef")
            self.assertNotIn("value", token)

    def test_no_excluded_env_value_survives_anywhere_in_the_archive(self):
        with Run("healthy", self.ARGV) as r:
            blob = "".join(p.read_text() for p in r.root.rglob("*") if p.is_file())
            self.assertNotIn("mk-not-in-the-report-0001", blob)
            self.assertNotIn("hunter2please", blob)
            self.assertTrue(r.json("report.json")["redaction"]["verified"])
            self.assertEqual(r.json("report.json")["redaction"]["leaks"], 0)

    def test_the_report_names_the_source_of_every_section(self):
        with Run("healthy", self.ARGV) as r:
            report = r.json("report.json")
            self.assertEqual(report["tool"], "vexa-state-report")
            sections = report["sections"]
            self.assertEqual(sections["workloads.json"]["source"], "kubectl")
            self.assertEqual(sections["db.json"]["source"], "psql")
            self.assertEqual(sections["probes.json"]["source"],
                             "kit/report/probes/v0.12.23.json")
            self.assertEqual(sections["runtime.json"]["collector"], "collect_runtime")
            self.assertEqual(len(report["refuses"]), 3)


class TestAbsentSources(unittest.TestCase):
    """A cluster that refuses every read, and no database at all."""

    def test_it_still_exits_zero_and_writes_a_bundle(self):
        with Run("empty", ["--namespace", "vexa"]) as r:
            self.assertEqual(r.code, 0)
            self.assertTrue(r.archive.is_file())

    def test_nothing_is_defaulted_to_zero_or_empty(self):
        with Run("empty", ["--namespace", "vexa"]) as r:
            report = r.json("report.json")
            self.assertEqual(report["sections"]["workloads.json"]["source"], "absent")
            self.assertEqual(report["sections"]["db.json"]["source"], "absent")
            self.assertEqual(report["sections"]["schema.sql"]["source"], "absent")
            self.assertEqual(report["sections"]["runtime.json"]["source"], "absent")
            self.assertTrue(report["absent"])
            for row in report["absent"]:
                self.assertTrue(row["reason"], row)
                self.assertTrue(row["section"], row)
            # schema.sql is not written at all rather than written empty
            self.assertFalse((r.root / "schema.sql").exists())

    def test_probes_are_printed_but_not_run_without_a_database(self):
        with Run("empty", ["--namespace", "vexa"]) as r:
            probes = r.json("probes.json")["probes"]
            self.assertTrue(probes)
            for p in probes:
                self.assertIsNone(p["count"])
                self.assertIsNone(p["holds"])
                self.assertIn("no database source", p["reason"])
                self.assertIn("SELECT count(*)", p["sql"])
            self.assertEqual(r.json("probes.json")["violations"], [])

    def test_a_transcription_gap_is_absent_and_not_cpu(self):
        with Run("empty", ["--namespace", "vexa"]) as r:
            reasons = " ".join(a["reason"] for a in r.json("runtime.json")["absent"])
            self.assertIn("ABSENT, not 'CPU inference'", reasons)


class TestRedactionLeakExitsThree(unittest.TestCase):
    def test_a_withheld_value_that_survives_fails_the_run(self):
        with Run("leaky", ["--namespace", "vexa"]) as r:
            self.assertEqual(r.code, 3)
            self.assertTrue(r.archive.is_file(),
                            "the bundle is KEPT for inspection; it just must not be sent")
            redaction = r.json("report.json")["redaction"]
            self.assertFalse(redaction["verified"])
            self.assertGreaterEqual(redaction["leaks"], 1)
            self.assertIn("workloads.json", " ".join(redaction["leaking_files"]))
            # the verdict names files. It must never name the value.
            self.assertNotIn("leaky-value-123456", json.dumps(redaction))


class TestUsageExitsTwo(unittest.TestCase):
    def test_two_database_transports_at_once_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as cm:
            sr.main(["--namespace", "vexa", "--db-url", "postgres://x/y",
                     "--db-pod", "postgres-0"])
        self.assertEqual(cm.exception.code, 2)

    def test_a_container_without_its_pod_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as cm:
            sr.main(["--namespace", "vexa", "--db-container", "postgres"])
        self.assertEqual(cm.exception.code, 2)

    def test_a_probe_set_the_operator_named_and_that_is_missing_exits_two(self):
        # They asked for something specific and did not get it. Reporting
        # absent would answer a question nobody asked.
        with self.assertRaises(SystemExit) as cm:
            sr.load_probe_set("v9.9.9-does-not-exist", explicit=True)
        self.assertEqual(cm.exception.code, 2)

    def test_two_db_transports_at_once_is_a_usage_error(self):
        for pair in (["--db-url", "postgres://x/y", "--db-host", "db.internal"],
                     ["--db-host", "db.internal", "--db-pod", "postgres-0"]):
            with self.assertRaises(SystemExit) as cm:
                sr.main(["--namespace", "vexa"] + pair)
            self.assertEqual(cm.exception.code, 2, pair)

    def test_a_port_without_a_host_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as cm:
            sr.main(["--namespace", "vexa", "--db-port", "5432"])
        self.assertEqual(cm.exception.code, 2)


class TestLonelyCopyStillReports(unittest.TestCase):
    """The tool is one file and gets copied without its probes/ directory.

    Regression: that used to raise SystemExit before anything was collected, so
    a missing DATA FILE cost the operator the whole run — in a tool whose own
    rule is that a broken section must not. It degrades now.
    """

    ARGV = ["--namespace", "vexa", "--db-pod", "postgres-0",
            "--db-name", "vexa", "--db-user", "vexa"]

    def test_it_exits_zero_and_still_writes_the_bundle(self):
        with Run("healthy", self.ARGV, probes_dir=None) as r:
            self.assertEqual(r.code, 0)
            self.assertTrue(r.archive.is_file())

    def test_every_other_section_was_still_collected(self):
        with Run("healthy", self.ARGV, probes_dir=None) as r:
            sections = r.json("report.json")["sections"]
            self.assertEqual(sections["workloads.json"]["source"], "kubectl")
            self.assertEqual(sections["db.json"]["source"], "psql")
            self.assertEqual(sections["schema.sql"]["source"], "pg_dump --schema-only")
            self.assertEqual(sections["probes.json"]["source"], "absent")

    def test_the_probes_section_says_what_to_do_about_it(self):
        with Run("healthy", self.ARGV, probes_dir=None) as r:
            probes = r.json("probes.json")
            reason = " ".join(a["reason"] for a in probes["absent"])
            self.assertIn("--probe-set", reason)
            self.assertIn("kit/report/probes/", reason)
            self.assertEqual(probes["probes"], [])

    def test_the_console_does_not_let_it_pass_quietly(self):
        with Run("healthy", self.ARGV, probes_dir=None) as r:
            self.assertIn("NO INVARIANT PROBES RAN", r.out)
            self.assertIn("reads YOUR data", r.out)
            # ...and it does not claim a count it does not have
            self.assertNotIn("0 of 0", r.out)


class TestClusterOnlyRunIsLoud(unittest.TestCase):
    """A run with no database source succeeds and is nearly worthless.

    Every probe reports `not run` in a column that reads as unremarkable, and
    the probes are the only part of the report that reads the operator's data.
    Exit stays 0 — a bundle was written and the cluster half is worth sending —
    but it does not get to be quiet.
    """

    def test_the_warning_names_every_probe_that_did_not_run(self):
        with Run("healthy", ["--namespace", "vexa"]) as r:
            self.assertEqual(r.code, 0)
            self.assertIn("DID NOT RUN", r.out)
            self.assertIn("5 of 5", r.out)
            for name in [p["name"] for p in r.json("probes.json")["probes"]]:
                self.assertIn(name, r.out)

    def test_it_says_why_it_matters_and_names_all_three_remedies(self):
        with Run("healthy", ["--namespace", "vexa"]) as r:
            self.assertIn("only part of this report that reads YOUR data", r.out)
            self.assertIn("--db-host", r.out)
            self.assertIn("--db-pod", r.out)
            self.assertIn("kit/report/job.yaml", r.out)

    def test_the_bundle_carries_the_same_verdict_as_the_console(self):
        with Run("healthy", ["--namespace", "vexa"]) as r:
            probes = r.json("probes.json")
            self.assertEqual(probes["degraded"], "no-database-source")
            self.assertEqual(len(probes["not_run"]), 5)
            self.assertEqual(probes["violations"], [])

    def test_a_run_with_a_database_carries_no_such_warning(self):
        with Run("healthy", ["--namespace", "vexa", "--db-pod", "postgres-0",
                             "--db-name", "vexa", "--db-user", "vexa"]) as r:
            self.assertNotIn("DID NOT RUN", r.out)
            self.assertIsNone(r.json("probes.json").get("degraded"))


class TestDatabaseTransports(unittest.TestCase):
    """Three ways in, and the docs now name the RBAC each one costs."""

    def setUp(self):
        self.kube = sr.Kube("vexa")

    def test_db_host_puts_no_password_on_the_command_line(self):
        pg = sr.Postgres(self.kube, host="db.internal", port=5432,
                         dbname="vexa", user="vexa_report")
        argv = pg.argv("psql", ["-c", "SELECT count(*) FROM meetings"])
        self.assertEqual(argv[:9],
                         ["psql", "-h", "db.internal", "-p", "5432",
                          "-U", "vexa_report", "-d", "vexa"])
        self.assertNotIn("exec", argv)
        # the password reaches psql through the environment, never argv
        self.assertTrue(all("PGPASSWORD" not in a for a in argv))
        self.assertEqual(pg.transport, "--db-host")

    def test_db_pod_is_the_only_transport_that_uses_exec(self):
        exec_free = (sr.Postgres(self.kube, host="db.internal"),
                     sr.Postgres(self.kube, url="postgres://db/x"))
        for pg in exec_free:
            self.assertNotIn("exec", pg.argv("psql", []))
        pg = sr.Postgres(self.kube, pod="postgres-0")
        self.assertIn("exec", pg.argv("psql", []))
        self.assertEqual(pg.transport, "kubectl exec postgres-0")

    def test_every_transport_opens_the_session_read_only(self):
        for pg in (sr.Postgres(self.kube, host="db.internal"),
                   sr.Postgres(self.kube, url="postgres://db/x"),
                   sr.Postgres(self.kube, pod="postgres-0")):
            self.assertIn("default_transaction_read_only=on", pg.pgoptions)

    def test_no_source_at_all_is_simply_not_configured(self):
        pg = sr.Postgres(self.kube)
        self.assertFalse(pg.configured)
        self.assertIsNone(pg.transport)


class TestNoTransmitPath(unittest.TestCase):
    """The refusal that is easiest to erode, so it is pinned in a test.

    A future edit that adds a submit flag will fail here, which is the point:
    the promise in the docs is 'it prints a path and stops', and a promise
    nothing enforces is a plan.
    """

    def test_the_source_imports_nothing_that_can_reach_the_network(self):
        tree = ast.parse((sr.HERE / "vexa_state_report.py").read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        for module in ("urllib", "urllib.request", "http", "http.client", "socket",
                       "smtplib", "ftplib", "requests", "httpx", "ssl"):
            self.assertNotIn(module, imported, module)

    def test_no_flag_offers_to_send_anything(self):
        tree = ast.parse((sr.HERE / "vexa_state_report.py").read_text())
        flags = [n.value for n in ast.walk(tree)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.value.startswith("--")]
        self.assertIn("--namespace", flags)              # the scan works
        for verb in ("--submit", "--send", "--upload", "--destination", "--push"):
            self.assertNotIn(verb, flags, verb)


if __name__ == "__main__":
    unittest.main()
