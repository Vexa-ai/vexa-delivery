# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the environment state reporter.

Fixture-driven and completely offline: the fake `kubectl` in
kit/report/tests/bin/ answers out of kit/report/tests/fixtures/<case>/, so the
whole tool runs end to end with no cluster and no network.

What is pinned here is what the tool promises:

  * IT ONLY READS. `--dry-run` runs with every subprocess call booby-trapped,
    so "it connects to nothing" is enforced rather than described — and the
    commands it prints are compared against the ones a real run ACTUALLY
    issues, recorded by the fake kubectl. A drifting dry run is a lie about
    safety, so it is a test failure.
  * THERE IS NO DATABASE. No client, no SQL, no flag that takes a password —
    checked against the source, so adding one fails the build.
  * REDACTION works on structures, the leak scan catches a value that survived,
    and it names counts, never values.
  * ABSENT OVER ZERO: a cluster that refuses every read produces a report that
    says so, not one that says the namespace is empty.
  * ONE FILE, and it is a document a person can read: valid YAML, inside its
    line budget, with its explanation carried in comments.
  * EXIT CODES: 0 written, 2 usage, 3 redaction leak.
"""
import ast
import contextlib
import io
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import vexa_state_report as sr                                          # noqa: E402

try:
    import yaml
except ImportError:                                    # the tool needs none
    yaml = None

BIN = HERE / "bin"
FIXTURES = HERE / "fixtures"
SOURCE = (sr.HERE / "vexa_state_report.py").read_text()


class Run:
    """One end-to-end invocation against a fixture directory."""

    def __init__(self, case, argv=()):
        self.case, self.argv = case, list(argv)

    def __enter__(self):
        self.tmp = tempfile.mkdtemp(prefix="vexa-report-test-")
        self.env = dict(os.environ)
        self.log = pathlib.Path(self.tmp) / "kubectl.log"
        os.environ["PATH"] = str(BIN) + os.pathsep + os.environ.get("PATH", "")
        os.environ["VEXA_TEST_FIXTURES"] = str(FIXTURES / self.case)
        os.environ["VEXA_TEST_KUBECTL_LOG"] = str(self.log)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.code = sr.main(["--namespace", "vexa", "--out", self.tmp] + self.argv)
        self.out = buf.getvalue()
        self.path = pathlib.Path(self.tmp) / sr.OUTPUT_NAME
        self.text = self.path.read_text() if self.path.is_file() else ""
        return self

    def __exit__(self, *exc):
        os.environ.clear()
        os.environ.update(self.env)
        shutil.rmtree(self.tmp, ignore_errors=True)
        return False

    @property
    def doc(self):
        return yaml.safe_load(self.text)

    def commands(self):
        return [line for line in self.log.read_text().splitlines() if line.strip()]


class DryRun:
    """A --dry-run invocation with every subprocess call booby-trapped.

    The claim is not "it probably does not connect": it is that nothing is
    executed at all. So `subprocess.run` raises here, and the test fails loudly
    if the code path ever reaches for a cluster.
    """

    def __init__(self, argv=()):
        self.argv = list(argv)

    def __enter__(self):
        self.tmp = tempfile.mkdtemp(prefix="vexa-report-dry-")
        self.real = sr.subprocess.run

        def forbidden(*a, **kw):
            raise AssertionError("--dry-run executed a subprocess: %r" % (a,))

        sr.subprocess.run = forbidden
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                self.code = sr.main(["--namespace", "vexa", "--out", self.tmp,
                                     "--dry-run"] + self.argv)
        finally:
            sr.subprocess.run = self.real
        self.out = buf.getvalue()
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.tmp, ignore_errors=True)
        return False

    def wrote_nothing(self):
        return sorted(pathlib.Path(self.tmp).rglob("*")) == []


# ── it only reads, and it says so truthfully ────────────────────────────────


class TestDryRunTouchesNothing(unittest.TestCase):
    def test_it_exits_zero_having_executed_nothing_and_written_nothing(self):
        with DryRun() as r:
            self.assertEqual(r.code, 0)
            self.assertTrue(r.wrote_nothing(), "a dry run wrote files")

    def test_it_prints_every_command_and_what_each_one_is_for(self):
        with DryRun() as r:
            for _, cmd in sr.cluster_reads(sr.Kube("vexa")):
                self.assertIn(" ".join(cmd), r.out)
            self.assertIn("WHAT IT READS", r.out)
            self.assertIn("state-report.yaml", r.out)

    def test_it_states_the_four_refusals(self):
        with DryRun() as r:
            for claim in ("Send anything", "Touch your database",
                          "Read a Secret or a ConfigMap",
                          "Copy your configuration wholesale"):
                self.assertIn(claim, r.out, claim)


class TestDryRunMatchesTheRealRun(unittest.TestCase):
    """The dry run is a safety claim, so it is checked against reality.

    A hand-maintained "here is what it does" list drifts on the first collector
    somebody adds, and it drifts SILENTLY — which is the exact failure mode this
    tool exists to refuse. The fake kubectl records what a real run executed;
    this compares the two sets.
    """

    def test_a_real_run_issues_exactly_the_commands_dry_run_printed(self):
        with DryRun() as dry:
            printed = [" ".join(cmd) for _, cmd in sr.cluster_reads(sr.Kube("vexa"))]
            for line in printed:
                self.assertIn(line, dry.out)
        with Run("healthy") as r:
            executed = r.commands()
            self.assertEqual(sorted(set(executed)), sorted(set(printed)),
                             "the dry run and the real run disagree about what runs")
            self.assertEqual(len(executed), len(printed),
                             "a command ran a different number of times than announced")

    def test_every_command_is_a_read(self):
        with Run("healthy") as r:
            for line in r.commands():
                verb = line.split()[1]
                self.assertIn(verb, ("get", "version"), line)


class TestThereIsNoDatabase(unittest.TestCase):
    """The refusal that would be easiest to erode, pinned against the source."""

    def test_no_database_client_is_invoked_anywhere(self):
        for token in ("psql", "pg_dump", "pgoptions", "libpq", "postgres://",
                      "postgresql://"):
            self.assertNotIn(token, SOURCE.lower(), token)

    def test_no_sql_statement_appears_in_the_source(self):
        for token in ("select ", "insert ", "pg_catalog", "information_schema"):
            self.assertNotIn(token, SOURCE.lower(), token)

    def test_no_flag_takes_a_password_or_a_connection(self):
        flags = [n.value for n in ast.walk(ast.parse(SOURCE))
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.value.startswith("--")]
        self.assertIn("--namespace", flags)              # the scan works
        for verb in ("--db-url", "--db-host", "--db-pod", "--db-user", "--password",
                     "--probe-set", "--exec"):
            self.assertNotIn(verb, flags, verb)

    def test_the_source_imports_nothing_that_can_reach_the_network(self):
        imported = set()
        for node in ast.walk(ast.parse(SOURCE)):
            if isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        for module in ("urllib", "urllib.request", "http", "http.client", "socket",
                       "smtplib", "ftplib", "requests", "httpx", "ssl", "psycopg2",
                       "sqlite3", "yaml"):
            self.assertNotIn(module, imported, module)

    def test_no_flag_offers_to_send_anything(self):
        flags = [n.value for n in ast.walk(ast.parse(SOURCE))
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.value.startswith("--")]
        for verb in ("--submit", "--send", "--upload", "--destination", "--push"):
            self.assertNotIn(verb, flags, verb)


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


class TestLeakScan(unittest.TestCase):
    def test_a_survivor_is_reported_by_index_and_never_by_value(self):
        hits = sr.scan_text_for_leaks('image: x:leaky-value-123456\n',
                                      {"leaky-value-123456", "not-present-000000"})
        self.assertEqual(hits, [0])
        self.assertTrue(all(isinstance(i, int) for i in hits))

    def test_short_values_are_not_scanned(self):
        self.assertEqual(sr.scan_text_for_leaks("namespace: vexa", {"vexa"}), [])


class TestEnvAllowlist(unittest.TestCase):
    def test_shape_settings_are_allowed(self):
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


# ── the YAML writer ─────────────────────────────────────────────────────────


class TestYamlWriter(unittest.TestCase):
    """It is hand-written, because the tool is one stdlib-only file. So the
    quoting rules are tested rather than assumed."""

    def test_things_that_would_change_meaning_are_quoted(self):
        for value in ("0.10.4", "yes", "no", "true", "null", "3", "16.3-alpine",
                      "a: b", "", " lead"):
            self.assertTrue(sr._scalar(value).startswith("'"),
                            "%r was left bare" % value)

    def test_ordinary_words_stay_bare_and_read_as_prose(self):
        for value in ("vexa", "Linode LKE", "cpu 2 · memory 8Gi", "in-cluster"):
            self.assertFalse(sr._scalar(value).startswith("'"),
                             "%r was needlessly quoted" % value)

    def test_types_survive(self):
        self.assertEqual(sr._scalar(None), "null")
        self.assertEqual(sr._scalar(True), "true")
        self.assertEqual(sr._scalar(4), "4")

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_a_pathological_document_still_round_trips(self):
        doc = {"a: b": ["x: y", "yes", "", "- dash", "#hash", "'quote"],
               "n": {"deep": {"deeper": [{"k": None}]}}, "empty": [], "e2": {}}
        self.assertEqual(yaml.safe_load("\n".join(sr._yaml(doc))), doc)

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_a_folded_long_string_survives_as_one_line_of_text(self):
        long = ("A ResourceQuota covers cpu or memory here and this sentence is "
                "deliberately far longer than the fold threshold so that it wraps.")
        out = yaml.safe_load("\n".join(sr._yaml({"finding": long})))
        self.assertEqual(out["finding"], long)
        self.assertTrue(any(line.endswith(">-") for line in sr._yaml({"f": long})))

    def test_comments_wrap_by_paragraph_not_by_source_line(self):
        lines = sr.comment("one two three\nfour five six\n\nsecond paragraph")
        self.assertTrue(all(line.startswith("#") for line in lines))
        self.assertIn("# one two three four five six", lines)
        self.assertIn("#", lines)


# ── the document a person reads ─────────────────────────────────────────────


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestHealthyRun(unittest.TestCase):
    def test_it_writes_one_file_and_nothing_else(self):
        with Run("healthy") as r:
            self.assertEqual(r.code, 0)
            written = [p.name for p in pathlib.Path(r.tmp).iterdir()
                       if p.name != "kubectl.log"]
            self.assertEqual(written, [sr.OUTPUT_NAME])
            self.assertIn(str(r.path), r.out)

    def test_it_is_a_document_a_person_can_read_end_to_end(self):
        with Run("healthy") as r:
            lines = r.text.splitlines()
            self.assertLess(len(lines), 300, "too long to be read and approved")
            self.assertGreater(len(lines), 100, "suspiciously thin for a real estate")
            comments = [line for line in lines if line.startswith("#")]
            self.assertGreater(len(comments), 30,
                               "the explanation is supposed to be IN the file")
            for heading in ("1 · PLATFORM", "2 · VERSIONS AND VALUES", "3 · RESOURCES",
                            "4 · WIRING", "5 · REGISTRY", "6 · ADMISSION",
                            "7 · NETWORK POLICY", "8 · THE INSTALL ALREADY HERE"):
                self.assertIn(heading, r.text, heading)

    def test_platform_is_read_by_shape_and_never_by_name(self):
        with Run("healthy") as r:
            p = r.doc["platform"]
            self.assertEqual(p["kubernetes"], "v1.28.9")
            self.assertEqual(p["distribution"], "Kubernetes")
            self.assertEqual(p["cloud"], "Linode LKE")
            self.assertEqual(sum(s["count"] for s in p["node_shapes"]), 3)
            self.assertNotIn("node-gpu-1", r.text)       # names are not collected
            self.assertNotIn("12341", r.text)            # nor are instance ids
            gpu = next(s for s in p["node_shapes"] if s["gpu"])
            self.assertIn("nvidia.com/gpu 1", gpu["gpu"])
            self.assertEqual(len(p["volumes"]), 2)
            self.assertTrue(any("DEFAULT" in c for c in p["storage_classes"]))

    def test_versions_carry_the_digest_actually_running(self):
        with Run("healthy") as r:
            whisper = next(w for w in r.doc["workloads"]
                           if w["name"] == "vexa-whisperlive")
            self.assertEqual(whisper["chart"], "vexa-0.10.4")
            self.assertEqual(whisper["replicas"], "2 ready of 2 desired")
            c = whisper["containers"][0]
            self.assertEqual(c["tag"], "0.10.4")
            self.assertTrue(c["running_digest"].startswith("sha256:"))
            self.assertEqual(c["requests"], "cpu 2 · memory 8Gi · nvidia.com/gpu 1")

    def test_the_per_meeting_bot_is_kept_but_never_named(self):
        with Run("healthy") as r:
            orphans = r.doc["running_outside_any_workload"]
            self.assertEqual(list(orphans), ["(unowned)"])
            self.assertTrue(orphans["(unowned)"]["bot"].startswith("sha256:"))
            self.assertNotIn("meeting-xyz", r.text)

    def test_customised_settings_are_captured_and_credentials_are_not(self):
        with Run("healthy") as r:
            whisper = next(w for w in r.doc["workloads"]
                           if w["name"] == "vexa-whisperlive")
            settings = whisper["containers"][0]["settings"]
            self.assertEqual(settings["WHISPER_MODEL_SIZE"], "medium")
            self.assertEqual(settings["DEVICE"], "cuda")
            # allowlist-first: these were never written, not written-then-redacted
            self.assertNotIn("REDIS_URL", settings)
            self.assertNotIn("MODEL_API_KEY", settings)
            self.assertIn("ADMIN_API_TOKEN (from secretKeyRef)",
                          whisper["containers"][0]["provided_externally"])
            for value in ("mk-not-in-the-report-0001", "hunter2please"):
                self.assertNotIn(value, r.text, value)

    def test_the_quota_finding_is_reported_because_it_broke_a_real_upgrade(self):
        with Run("healthy") as r:
            res = r.doc["resources"]
            self.assertEqual(len(res["quotas"]), 1)
            self.assertEqual(res["limit_ranges"], [])
            self.assertEqual(len(res["containers_declaring_no_resources"]), 1)
            self.assertIn("bot", res["containers_declaring_no_resources"][0])
            self.assertIn("stops bots being admitted", res["finding"])

    def test_the_finding_is_absent_when_a_limitrange_covers_the_gap(self):
        # The condition is all three at once. Two of three is not a finding,
        # and reporting one would train the reader to ignore it.
        with Run("with-limitrange") as r:
            self.assertNotIn("finding", r.doc["resources"])
            self.assertTrue(r.doc["resources"]["limit_ranges"])

    def test_wiring_names_the_database_without_connecting_to_it(self):
        with Run("healthy") as r:
            db = r.doc["wiring"]["database"]
            self.assertEqual(db["where"], "in-cluster")
            self.assertEqual(db["workload"], "vexa-postgres")
            self.assertEqual(db["version"], "16.3-alpine")
            self.assertTrue(any("DATABASE_URL" in a for a in db["addressed_by"]))
            self.assertTrue(all("not collected" in a or "from " in a
                                for a in db["addressed_by"]))
            # a password is not an address, and its value is nowhere
            self.assertNotIn("POSTGRES_PASSWORD", json.dumps(db))

    def test_an_absent_component_is_a_gap_and_not_a_zero(self):
        with Run("healthy") as r:
            redis = r.doc["wiring"]["redis"]
            self.assertEqual(redis["where"], "external or managed")
            self.assertIsNone(redis["version"])
            self.assertIn("a gap, not a zero", redis["note"])

    def test_transcription_says_gpu_or_cpu_and_never_assumes(self):
        with Run("healthy") as r:
            t = r.doc["wiring"]["transcription"][0]
            self.assertEqual(t["workload"], "vexa-whisperlive")
            self.assertEqual(t["device"], "DEVICE = cuda")
            self.assertEqual(t["model"], "WHISPER_MODEL_SIZE = medium")

    def test_registry_reachability_is_observed_not_inferred(self):
        with Run("healthy") as r:
            reg = r.doc["registry"]
            self.assertIn("docker.io", reg["registries_referenced"][0])
            self.assertIsNone(reg["cluster_mirror_config"])
            self.assertIn("not observable from here", reg["reachability"])

    def test_a_private_registry_is_called_a_mirror_and_not_a_guess(self):
        with Run("mirrored") as r:
            reg = r.doc["registry"]
            self.assertIn("registry.corp.example", reg["reachability"])
            self.assertIn("mirror or a private registry", reg["reachability"])
            self.assertIn("corp-registry", reg["image_pull_credentials"])

    def test_nothing_in_the_document_was_redacted_after_the_fact(self):
        """Allowlist-first means REDACTED should never need to appear.

        When it does, it is almost always this bug: a field NAMED after secrets
        (`image_pull_secrets`, `from_secret_or_configmap`) carrying names we
        meant to keep, emptied by the blunt redaction rule. Two shipped that way
        and the leak scan caught both. This is the cheap general guard.
        """
        with Run("healthy") as r:
            def walk(node, path="doc"):
                if isinstance(node, dict):
                    for k, v in node.items():
                        walk(v, "%s.%s" % (path, k))
                elif isinstance(node, list):
                    for i, v in enumerate(node):
                        walk(v, "%s[%d]" % (path, i))
                else:
                    self.assertNotEqual(node, sr.REDACTED,
                                        "%s was redacted; rename the key" % path)
            walk(r.doc)

    def test_the_refusals_and_the_verdict_are_in_the_file_itself(self):
        with Run("healthy") as r:
            doc = r.doc
            self.assertEqual(len(doc["refuses"]), 4)
            self.assertTrue(doc["redaction"]["verified"])
            self.assertEqual(doc["redaction"]["leaks"], 0)
            self.assertGreater(doc["redaction"]["withheld_values"], 0)
            # This estate grants nothing next door, which is the normal case:
            # a namespace admin cannot read another namespace. All three of
            # those share ONE row — three near-identical entries would spend
            # six lines of a reader's attention on one fact.
            #
            # `routes` is a gap on plain Kubernetes because the kind and the
            # grant are indistinguishable from here, and the QUESTION row is
            # the other kind of entry: not a read that failed, but one no
            # read-only call could make.
            self.assertEqual([row["what"] for row in doc["absent"]],
                             ["routes",
                              "QUESTION: can this cluster pull a release image by digest",
                              "delivery machinery in argocd, openshift-gitops, kyverno"])
            self.assertTrue(all(row["reason"] for row in doc["absent"]))
            self.assertIn("IT HAS NOT BEEN SENT ANYWHERE", r.text)


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestNodeTaints(unittest.TestCase):
    """A taint is why a delivered workload never schedules, and the values file
    we hand back ships an empty `tolerations: []` for somebody to fill in. So
    the taints have to be IN the report, and grouped rather than per node."""

    def test_a_taint_is_reported_and_splits_the_shape_it_is_on(self):
        with Run("healthy") as r:
            shapes = r.doc["platform"]["node_shapes"]
            gpu = next(s for s in shapes if s["gpu"])
            self.assertEqual(gpu["taints"], "nvidia.com/gpu=true:NoSchedule")
            self.assertEqual(gpu["count"], 1)
            self.assertNotIn("node-gpu-1", r.text)     # still no node names

    def test_untainted_nodes_say_none_and_still_group_as_one_shape(self):
        # "none" rather than a missing field: an absent field reads as "we did
        # not look", which is the one thing this document may not imply.
        with Run("healthy") as r:
            shapes = r.doc["platform"]["node_shapes"]
            plain = next(s for s in shapes if not s["gpu"])
            self.assertEqual(plain["taints"], "none")
            self.assertEqual(plain["count"], 2)
            self.assertTrue(all("taints" in s for s in shapes))

    def test_unreadable_nodes_are_a_gap_and_not_an_untainted_cluster(self):
        with Run("empty") as r:
            self.assertNotIn("node_shapes", r.doc["platform"])
            self.assertIn("node shapes",
                          " ".join(row["what"] for row in r.doc["absent"]))


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestOpenShiftRoutes(unittest.TestCase):
    """Exposure on OpenShift is a Route, and there is normally no Ingress.

    A document that reads `ingresses.networking.k8s.io` and stops does not
    leave a quiet gap on such an estate — it says positively that nothing is
    exposed, which is the exact shape of answer this tool exists to refuse.
    """

    def test_a_route_is_reported_by_shape_and_never_by_host(self):
        with Run("mirrored") as r:
            routes = r.doc["wiring"]["routes"]
            self.assertEqual(len(routes), 2)
            self.assertIn("vexa · to vexa-api-gateway · TLS edge · no wildcard", routes)
            self.assertIn("vexa-admin · to vexa-admin-api · no TLS · wildcard Subdomain",
                          routes)

    def test_the_host_is_a_public_dns_name_and_does_not_reach_the_document(self):
        with Run("mirrored") as r:
            for host in ("vexa.apps.corp.example", "admin.apps.corp.example"):
                self.assertNotIn(host, r.text, host)
            # nor does the redirect policy or anything else from the rule
            self.assertNotIn("insecureEdgeTermination", r.text)

    def test_on_plain_kubernetes_the_absent_kind_is_named_as_indistinguishable(self):
        # Not-present and not-granted are the same read. Saying which one it
        # is would be a guess, and the expensive direction of that guess is
        # "nothing is exposed".
        with Run("healthy") as r:
            routes = r.doc["wiring"]["routes"]
            self.assertTrue(routes.startswith("absent"))
            self.assertIn("not-present and not-granted are the same read", routes)
            gap = next(row for row in r.doc["absent"] if row["what"] == "routes")
            self.assertIn("routes.route.openshift.io", gap["reason"])

    def test_on_openshift_an_unreadable_route_list_is_called_a_missing_grant(self):
        # Here the cluster ANSWERED as OpenShift, so the kind exists and the
        # refusal is a grant we were not given — a different sentence, and the
        # one that gets the operator to send the exposure or the grant.
        with Run("openshift-locked-down") as r:
            self.assertEqual(r.doc["platform"]["distribution"], "OpenShift")
            routes = r.doc["wiring"]["routes"]
            self.assertIn("MISSING GRANT", routes)
            self.assertIn("not an absent kind", routes)

    def test_it_is_never_read_as_nothing_is_exposed(self):
        for case in ("healthy", "openshift-locked-down"):
            with Run(case) as r:
                self.assertNotIn("nothing is exposed", r.text, case)
                self.assertTrue(str(r.doc["wiring"]["routes"]).startswith("absent"), case)


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestPlacement(unittest.TestCase):
    """Taints say which nodes REPEL a workload; placement says where one is
    PINNED. Transcription held to a GPU pool is the case that breaks a bundle
    silently — everything else about the estate looks fine, and the delivered
    pod simply never lands."""

    def test_a_node_selector_and_its_tolerations_are_reported(self):
        with Run("healthy") as r:
            whisper = next(w for w in r.doc["workloads"]
                           if w["name"] == "vexa-whisperlive")
            self.assertIn("nodeSelector vexa.ai/pool=gpu", whisper["placement"])
            self.assertIn("tolerates nvidia.com/gpu:NoSchedule", whisper["placement"])
            self.assertIn("vexa.ai/pool:NoExecute", whisper["placement"])

    def test_affinity_is_reported_by_kind_and_never_by_rule(self):
        with Run("mirrored") as r:
            whisper = next(w for w in r.doc["workloads"]
                           if w["name"] == "vexa-whisperlive")
            self.assertIn("affinity nodeAffinity, podAntiAffinity", whisper["placement"])
            for token in ("matchExpressions", "nodeSelectorTerms", "preferredDuring",
                          "labelSelector"):
                self.assertNotIn(token, r.text, token)

    def test_priority_runtime_and_topology_spread_are_reported(self):
        with Run("mirrored") as r:
            placement = next(w for w in r.doc["workloads"]
                             if w["name"] == "vexa-whisperlive")["placement"]
            self.assertIn("priorityClassName vexa-critical", placement)
            self.assertIn("runtimeClassName nvidia", placement)
            self.assertIn("topologySpread over topology.kubernetes.io/zone", placement)

    def test_a_selector_pinned_to_a_hostname_keeps_the_key_and_drops_the_name(self):
        # The KEY is shape and belongs here. The VALUE is a node name, which
        # is the one piece of inventory this document refuses to carry — and
        # an affinity rule in the mirrored estate names one too.
        with Run("healthy") as r:
            postgres = next(w for w in r.doc["workloads"]
                            if w["name"] == "vexa-postgres")
            self.assertEqual(postgres["placement"],
                             "nodeSelector kubernetes.io/hostname=(node name, "
                             "not collected)")
            self.assertNotIn("node-cpu-1", r.text)
        with Run("mirrored") as r:
            self.assertNotIn("node-gpu-1", r.text)

    def test_a_workload_that_pins_nothing_carries_no_empty_scaffolding(self):
        with Run("healthy") as r:
            admin = next(w for w in r.doc["workloads"] if w["name"] == "vexa-admin-api")
            self.assertNotIn("placement", admin)
            self.assertGreaterEqual(
                sum(1 for w in r.doc["workloads"] if "placement" in w), 1)


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestPullCredentialsAndAllocatable(unittest.TestCase):
    """Two gaps the sufficiency sweep found: a pull credential that lives on a
    ServiceAccount rather than in a pod spec, and the difference between a
    node's capacity and what a scheduler actually has left."""

    def test_a_credential_on_a_service_account_is_found_and_named_as_such(self):
        # It serves every pod that uses the account and appears in NO pod
        # spec, so reading only pod specs reports a namespace with no pull
        # credentials at all — a positive claim, and the wrong one.
        with Run("mirrored") as r:
            found = r.doc["registry"]["image_pull_credentials"]
            self.assertIn("corp-registry-ca (on serviceaccount vexa)", found)
            # `corp-registry` is attached BOTH ways in that estate. It is one
            # credential, so it is named once, from the pod specs.
            self.assertIn("corp-registry", found)
            self.assertNotIn("corp-registry (on serviceaccount vexa)", found)

    def test_no_service_account_credentials_is_not_the_same_as_no_read(self):
        with Run("healthy") as r:
            self.assertIsNone(r.doc["registry"]["image_pull_credentials"])
            self.assertNotIn("service-account pull credentials",
                             " ".join(row["what"] for row in r.doc["absent"]))
        with Run("with-limitrange") as r:
            gap = next(row for row in r.doc["absent"]
                       if row["what"] == "service-account pull credentials")
            self.assertIn("appears in no pod spec", gap["reason"])

    def test_allocatable_sits_beside_capacity_because_it_is_what_schedules(self):
        # The preflight measures the bot's 2560Mi limit and its 2Gi
        # Memory-medium /dev/shm against allocatable, not capacity. One line,
        # because it is one fact.
        with Run("healthy") as r:
            shapes = r.doc["platform"]["node_shapes"]
            gpu = next(s for s in shapes if s["gpu"])
            self.assertEqual(gpu["capacity"],
                             "cpu 8 (7900m allocatable) · memory 32Gi "
                             "(30Gi allocatable) · pods 110")


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestNamedQuestions(unittest.TestCase):
    """The gaps that are not gaps in the READ — nothing read-only can answer
    them, so they are asked by name rather than silently assumed."""

    def test_whether_a_pull_by_digest_succeeds_is_asked_not_assumed(self):
        with Run("healthy") as r:
            gap = next(row for row in r.doc["absent"]
                       if row["what"].startswith("QUESTION: can this cluster pull"))
            self.assertIn("probe pod, which is a write", gap["reason"])

    def test_a_private_registry_adds_the_ca_question(self):
        with Run("mirrored") as r:
            asked = [row["what"] for row in r.doc["absent"]]
            self.assertIn("QUESTION: does the registry need a CA bundle, or plain HTTP",
                          asked)
        with Run("healthy") as r:
            # public registries, no pull credentials: the question does not
            # apply and is not asked. Noise trains a reader to skip the list.
            self.assertFalse(any("CA bundle" in row["what"]
                                 for row in r.doc["absent"]))

    def test_restricted_egress_asks_what_is_actually_allowed(self):
        with Run("mirrored") as r:
            gap = next(row for row in r.doc["absent"]
                       if row["what"].startswith("QUESTION: does policy allow DNS"))
            self.assertIn("rule bodies", gap["reason"])
        with Run("with-limitrange") as r:
            self.assertFalse(any("DNS" in row["what"] for row in r.doc["absent"]))


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestAdmission(unittest.TestCase):
    """The namespace's own admission posture — the whole OpenShift rejection
    class, and invisible from every other section of the document."""

    def test_pod_security_labels_are_read_off_the_namespace(self):
        with Run("healthy") as r:
            admission = r.doc["admission"]
            self.assertIn("enforce baseline (v1.28)", admission["pod_security"])
            self.assertIn("audit restricted", admission["pod_security"])
            self.assertIn("warn restricted", admission["pod_security"])

    def test_openshift_scc_ranges_are_reported_when_they_are_there(self):
        with Run("mirrored") as r:
            admission = r.doc["admission"]
            self.assertEqual(admission["pod_security"], "enforce restricted (v1.28)")
            self.assertIn("uid-range 1000660000/10000", admission["openshift_scc"])
            self.assertIn("supplemental-groups 1000660000/10000",
                          admission["openshift_scc"])

    def test_no_labels_is_said_plainly_and_the_default_is_not_guessed(self):
        with Run("with-limitrange") as r:
            posture = r.doc["admission"]["pod_security"]
            self.assertIn("no pod-security.kubernetes.io labels", posture)
            self.assertIn("cannot see what that is", posture)

    def test_an_unreadable_namespace_is_absent_and_never_permissive(self):
        with Run("empty") as r:
            self.assertTrue(r.doc["admission"]["pod_security"].startswith("absent"))
            gap = next(row for row in r.doc["absent"]
                       if row["what"] == "admission posture")
            self.assertIn("NOT assumed permissive", gap["reason"])


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestNetworkPolicy(unittest.TestCase):
    """Whether this namespace can reach a registry at all — by shape, because
    the rule bodies carry internal addresses and nothing here needs them."""

    def test_a_default_deny_egress_policy_is_named_as_what_it_is(self):
        with Run("mirrored") as r:
            netpol = r.doc["network_policy"]
            self.assertEqual(len(netpol["policies"]), 2)
            self.assertIn("default-deny-egress · Egress · selects every pod",
                          netpol["policies"][0])
            self.assertIn("denies ALL egress", netpol["egress"])

    def test_rule_bodies_never_reach_the_document(self):
        # The fixture's rules name kube-system and port 53. The shape is
        # reported; the rule is not, because a rule body carries addresses.
        with Run("mirrored") as r:
            rendered = json.dumps(r.doc["network_policy"])
            for token in ("kube-system", "namespaceSelector", "matchLabels", "UDP"):
                self.assertNotIn(token, rendered, token)

    def test_an_ingress_only_policy_does_not_read_as_blocked_egress(self):
        with Run("healthy") as r:
            netpol = r.doc["network_policy"]
            self.assertIn("selects some pods", netpol["policies"][0])
            self.assertIn("no policy here restricts egress", netpol["egress"])

    def test_no_policies_at_all_is_a_different_sentence_from_unreadable(self):
        with Run("with-limitrange") as r:
            self.assertEqual(r.doc["network_policy"]["policies"], [])
            self.assertIn("no NetworkPolicies", r.doc["network_policy"]["egress"])
        with Run("empty") as r:
            self.assertTrue(r.doc["network_policy"]["egress"].startswith("absent"))
            gap = next(row for row in r.doc["absent"]
                       if row["what"] == "network policies")
            self.assertIn("NOT read as 'nothing blocks'", gap["reason"])


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestTheExistingInstall(unittest.TestCase):
    """The release name is the documented footgun: a `--release-name` that
    matches nothing installs a second copy of the estate, and succeeds."""

    def test_the_release_name_is_read_from_the_labels_that_carry_it(self):
        with Run("healthy") as r:
            install = r.doc["install"]
            self.assertEqual(install["release_names"], ["vexa (2 workloads)"])
            self.assertEqual(install["managed_by"], "Helm")
            self.assertNotIn("finding", install)

    def test_two_release_names_in_one_namespace_are_flagged_plainly(self):
        with Run("mirrored") as r:
            install = r.doc["install"]
            self.assertEqual(install["release_names"],
                             ["vexa (1 workload)", "vexa-preprod (1 workload)"])
            self.assertIn("MORE THAN ONE release name", install["finding"])
            self.assertIn("second copy", install["finding"])

    def test_no_release_label_anywhere_is_a_gap_rather_than_a_guess(self):
        with Run("empty") as r:
            self.assertIsNone(r.doc["install"]["release_names"])
            gap = next(row for row in r.doc["absent"]
                       if row["what"] == "helm release name")
            self.assertIn("not guessed", gap["reason"])

    def test_no_helm_binary_and_no_secret_read_produced_this(self):
        with Run("healthy") as r:
            for line in r.commands():
                self.assertNotIn("secret", line)
                self.assertFalse(line.startswith("helm "), line)

    def test_argo_cd_and_kyverno_are_reported_where_they_run(self):
        with Run("mirrored") as r:
            install = r.doc["install"]
            self.assertIn("present in namespace argocd", install["argo_cd"])
            self.assertIn("v2.11.3", install["argo_cd"])
            self.assertIn("present in namespace kyverno", install["kyverno"])
            self.assertIn("v1.12.5", install["kyverno"])

    def test_a_namespace_we_cannot_read_is_absent_and_not_not_installed(self):
        # "not installed" and "no RBAC over there" look identical from inside
        # one namespace, and only one of them is safe to act on. All three
        # unreadable namespaces collapse into ONE gap row naming them, rather
        # than three rows and three near-identical lines in `install`.
        with Run("healthy") as r:
            for key in ("argo_cd", "openshift_gitops", "kyverno"):
                self.assertNotIn(key, r.doc["install"], key)
            gap = next(row for row in r.doc["absent"]
                       if row["what"].startswith("delivery machinery"))
            for namespace in ("argocd", "openshift-gitops", "kyverno"):
                self.assertIn(namespace, gap["what"], namespace)
            self.assertIn("same read from here", gap["reason"])

    def test_the_openshift_gitops_operator_counts_as_argo_already_here(self):
        # On OpenShift the supported Argo is the GitOps OPERATOR's instance,
        # which lives in `openshift-gitops` and never in `argocd`. Checking
        # only `argocd` reports Argo absent on the exact estate where
        # installing a second one does the most damage.
        with Run("mirrored") as r:
            self.assertIn("present in namespace openshift-gitops",
                          r.doc["install"]["openshift_gitops"])
            self.assertIn("v1.12.4", r.doc["install"]["openshift_gitops"])

    def test_cluster_scope_is_derived_from_what_this_run_could_read(self):
        # It picks between the bundle's cluster-wide admission and its
        # namespaced form, and it costs no extra read: the cluster-scoped
        # reads already succeeded or already failed.
        with Run("healthy") as r:
            self.assertIn("admission can ship cluster-wide",
                          r.doc["install"]["cluster_scope"])
        with Run("empty") as r:
            scope = r.doc["install"]["cluster_scope"]
            self.assertIn("namespace tenant", scope)
            self.assertIn("stay unknown rather than assumed", scope)

    def test_the_reads_next_door_are_scoped_to_those_namespaces(self):
        with Run("healthy") as r:
            executed = "\n".join(r.commands())
            self.assertIn("get deployments.apps -n argocd -o json", executed)
            self.assertIn("get deployments.apps -n openshift-gitops -o json", executed)
            self.assertIn("get deployments.apps -n kyverno -o json", executed)
            # the namespace's own object is read BY NAME: the other namespaces
            # in the cluster are never listed
            self.assertIn("get namespace vexa -o json", executed)
            self.assertNotIn("get namespaces -o json", executed)


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestAbsentOverZero(unittest.TestCase):
    """A cluster that refuses every read says so, rather than reporting empty."""

    def test_it_still_exits_zero_and_still_writes_the_file(self):
        with Run("empty") as r:
            self.assertEqual(r.code, 0)
            self.assertTrue(r.path.is_file())

    def test_every_gap_is_named_with_a_reason(self):
        with Run("empty") as r:
            gaps = r.doc["absent"]
            self.assertTrue(gaps)
            for row in gaps:
                self.assertTrue(row["what"], row)
                self.assertTrue(row["reason"], row)
            named = " ".join(row["what"] for row in gaps)
            for what in ("node shapes", "workloads", "storage classes"):
                self.assertIn(what, named, what)

    def test_it_stays_inside_the_budget_when_there_is_nothing_to_report(self):
        # A cluster that refuses EVERY read is the one case where the document
        # is mostly the gap list, and every gap costs its own line plus a
        # reason. It is still shorter than a real estate's report; the budget
        # that matters is the healthy one, which is checked at 300.
        with Run("empty") as r:
            self.assertLess(len(r.text.splitlines()), 240)

    def test_a_section_with_nothing_to_say_is_omitted_rather_than_faked(self):
        with Run("empty") as r:
            self.assertNotIn("running_outside_any_workload", r.doc)


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestRedactionLeakExitsThree(unittest.TestCase):
    def test_a_withheld_value_that_survives_fails_the_run(self):
        with Run("leaky") as r:
            self.assertEqual(r.code, 3)
            self.assertTrue(r.path.is_file(),
                            "the file is KEPT for inspection; it just must not be sent")
            self.assertFalse(r.doc["redaction"]["verified"])
            self.assertGreaterEqual(r.doc["redaction"]["leaks"], 1)
            self.assertIn("DO NOT SEND IT", r.out)
            # the verdict counts. It must never name the value.
            self.assertNotIn("leaky-value-123456", r.out)


class TestUsageExitsTwo(unittest.TestCase):
    def test_no_namespace_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as cm:
            sr.main([])
        self.assertEqual(cm.exception.code, 2)

    def test_an_unknown_flag_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as cm:
            sr.main(["--namespace", "vexa", "--db-host", "db.internal"])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
