"""Unit tests for the four hardening features that live in signed artifacts or
customer-pinned config: entry expiry, the revocation list, delivery_scope, and
the report.v1 payload the submit path validates.

Hermetic — no network, no registry, no helm. The REFUSALS are the load-bearing
tests here: every one of these features is worthless if it passes something it
should have stopped, and three of the four fail open by default if the check is
subtly wrong (an expiry never compared, a missing revocation list read as
"nothing revoked", a scope clause nobody implemented).
"""
import copy
import datetime
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "publisher"))
sys.path.insert(0, str(ROOT / "spec"))
import vexa_channel as vc          # noqa: E402
import vexa_station as vs          # noqa: E402
import validate as spec_validate   # noqa: E402

from test_publisher import synthetic_map, synthetic_receipt, SHA  # noqa: E402

DIGEST = "@sha256:" + "a" * 64


# ═══════════════════════════════════════════════════ 1 · entry expiry


class Args:
    """Just enough of the build namespace for assemble_entry."""
    channel = "test-channel"
    entry_seq = 1
    supersedes = "none"
    release = "v9.9.9"
    archive = None
    signing_mode = "test_key"
    identity = "sha256:" + "f" * 64
    signing_note = "unit test"
    publication_mode = "dry_run"
    publisher = "unit test"
    approved_by = None
    approval_receipt = None
    chart_ref = None
    chart_digest = None
    chart_version = None
    expires_days = 30

    def __init__(self, archive, **kw):
        self.archive = str(archive)
        for k, v in kw.items():
            setattr(self, k, v)


def built_entry(tmp, **kw):
    archive = pathlib.Path(tmp) / "vexa-core-v9.9.9.tar.gz"
    archive.write_bytes(b"not really a tarball")
    m = synthetic_map()
    map_bytes = json.dumps(m).encode()
    receipt = synthetic_receipt(map_bytes)
    args = Args(archive, **kw)
    return vc.assemble_entry(args, "d" * 40, SHA, m, receipt, [
        {"name": "candidate-images.json", "kind": "candidate_map", "sha256": "0" * 64,
         "media_type": "application/json", "description": "map"},
        {"name": "delivery-receipt.json", "kind": "delivery_receipt", "sha256": "1" * 64,
         "media_type": "application/json", "description": "receipt"},
        {"name": "source-provenance.sigstore.json", "kind": "source_provenance",
         "sha256": "2" * 64, "media_type": "application/json", "description": "prov"},
        {"name": "trusted-root.jsonl", "kind": "trusted_root", "sha256": "3" * 64,
         "media_type": "application/jsonl", "description": "root"},
    ], [])


class EntryExpiry(unittest.TestCase):
    def test_build_stamps_an_expiry_thirty_days_out_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            e = built_entry(tmp)
        delta = vc.parse_ts(e["expires"]) - vc.parse_ts(e["publication"]["published_at"])
        self.assertEqual(delta.days, 30)

    def test_expires_days_override_is_honoured(self):
        with tempfile.TemporaryDirectory() as tmp:
            e = built_entry(tmp, expires_days=1)
        delta = vc.parse_ts(e["expires"]) - vc.parse_ts(e["publication"]["published_at"])
        self.assertEqual(delta.days, 1)

    def test_the_schema_requires_expires(self):
        """Not optional: a field the schema tolerates as absent is a field half
        the fleet will not carry, and freshness that some entries opt out of is
        not freshness."""
        schema = spec_validate.load_schema()
        self.assertIn("expires", schema["required"])
        with tempfile.TemporaryDirectory() as tmp:
            e = built_entry(tmp)
        vc.schema_validate(e)                      # valid as built
        del e["expires"]
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)

    def test_a_malformed_expiry_is_refused_by_the_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            e = built_entry(tmp)
        e["expires"] = "2026-08-25"                # date, not an instant
        with self.assertRaises(vc.CheckFailure):
            vc.schema_validate(e)

    def test_is_expired_boundary_is_exclusive(self):
        """The instant itself is still live. A publisher and a verifier that
        disagree by one second must not disagree about the verdict."""
        t = "2026-08-25T12:00:00Z"
        at = vc.parse_ts(t)
        self.assertFalse(vc.is_expired(t, now=at))
        self.assertFalse(vc.is_expired(t, now=at - datetime.timedelta(seconds=1)))
        self.assertTrue(vc.is_expired(t, now=at + datetime.timedelta(seconds=1)))

    def test_refresh_advances_seq_and_horizon_without_touching_the_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "entry"
            (src / "evidence").mkdir(parents=True)
            e = built_entry(tmp, expires_days=1)
            (src / "entry.json").write_text(json.dumps(e))
            (src / "entry.json.sigstore.json").write_text("{}")
            out = pathlib.Path(tmp) / "refreshed"

            class RA:
                entry = str(src)
                expires_days = 45
                entry_seq = None
                publisher = None
            RA.out = str(out)
            self.assertEqual(vc.cmd_refresh(RA), 0)

            after = json.loads((out / "entry.json").read_text())
        self.assertEqual(after["channel"]["entry_seq"], e["channel"]["entry_seq"] + 1)
        self.assertGreater(after["expires"], e["expires"])
        # the release is untouched — that is the whole point of a refresh
        self.assertEqual(after["release"], e["release"])
        self.assertEqual(after["images"], e["images"])
        # and the old signature does not survive beside new bytes
        self.assertFalse((out / "entry.json.sigstore.json").exists())

    def test_refresh_refuses_a_seq_that_does_not_advance(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "entry"
            (src / "evidence").mkdir(parents=True)
            e = built_entry(tmp)
            e["channel"]["entry_seq"] = 7
            (src / "entry.json").write_text(json.dumps(e))

            class RA:
                entry = str(src)
                out = str(pathlib.Path(tmp) / "out")
                expires_days = 30
                entry_seq = 7
                publisher = None
            with self.assertRaises(vc.CheckFailure) as cm:
                vc.cmd_refresh(RA)
        self.assertIn("does not exceed", str(cm.exception))


# ═══════════════════════════════════════════════════ 2 · revocation


def revocation_list(entries=(), **kw):
    doc = {"schema_version": 1, "channel": "pilot-stable", "updated_at": vc.utcnow(),
           "expires": vc.utcplus(30), "entries": list(entries)}
    doc.update(kw)
    return doc


class RevocationSchema(unittest.TestCase):
    def test_an_empty_list_is_valid(self):
        """The capability goes live BEFORE it is needed. If an empty list were
        invalid, the first thing anyone published would be a real revocation."""
        vc.revocations_schema_validate(revocation_list())

    def test_a_row_needs_a_digest_or_a_version(self):
        with self.assertRaises(vc.CheckFailure):
            vc.revocations_schema_validate(revocation_list([
                {"reason": "something bad happened", "severity": "high",
                 "date": vc.utcnow()}]))

    def test_a_row_needs_a_reason_a_human_can_act_on(self):
        with self.assertRaises(vc.CheckFailure):
            vc.revocations_schema_validate(revocation_list([
                {"version": "v0.12.23", "reason": "bad", "severity": "high",
                 "date": vc.utcnow()}]))

    def test_severity_is_closed(self):
        with self.assertRaises(vc.CheckFailure):
            vc.revocations_schema_validate(revocation_list([
                {"version": "v0.12.23", "reason": "leaks credentials to logs",
                 "severity": "catastrophic", "date": vc.utcnow()}]))

    def test_a_well_formed_revocation_validates(self):
        vc.revocations_schema_validate(revocation_list([
            {"version": "v0.12.23", "reason": "admin token written to gateway logs",
             "severity": "critical", "date": vc.utcnow(), "supersedes": "v0.12.24",
             "advisory": "https://example.invalid/advisory"},
            {"digest": "sha256:" + "b" * 64, "reason": "image built from a poisoned base",
             "severity": "high", "date": vc.utcnow()},
        ]))

    def test_unknown_fields_are_refused(self):
        with self.assertRaises(vc.CheckFailure):
            vc.revocations_schema_validate(revocation_list([
                {"version": "v0.12.23", "reason": "a good enough reason",
                 "severity": "high", "date": vc.utcnow(), "quietly": "ignored"}]))


class RevocationPublish(unittest.TestCase):
    """cmd_revoke via --dry-run: everything up to the oras push."""

    def _run(self, out, **kw):
        class A:
            ref = "example.invalid/vexa/channel/pilot-stable"
            channel = "pilot-stable"
            version = digest = reason = supersedes = advisory = None
            severity = "high"
            expires_days = 30
            key = None
            unsigned = True
            dry_run = True
            plain_http = insecure = False
        A.out = str(out)
        for k, v in kw.items():
            setattr(A, k, v)
        # No list published yet -> pull returns None. Stubbed rather than
        # reached: the real call shells out to `oras`, which these fixture
        # tests must never need (the Makefile promises no target touches a
        # registry, and a runner without oras got a FileNotFoundError here).
        with unittest.mock.patch.object(vc, "pull_revocations", return_value=None):
            return vc.cmd_revoke(A)

    def test_publishing_an_empty_list_is_a_first_class_act(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            self.assertEqual(self._run(out), 0)
            doc = json.loads((out / "revocations.json").read_text())
        self.assertEqual(doc["entries"], [])
        self.assertEqual(doc["channel"], "pilot-stable")
        vc.revocations_schema_validate(doc)

    def test_revoking_a_version_records_the_operator_facing_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            self._run(out, version="v0.12.23", severity="critical",
                      reason="admin token written to gateway logs")
            doc = json.loads((out / "revocations.json").read_text())
        self.assertEqual(len(doc["entries"]), 1)
        self.assertEqual(doc["entries"][0]["version"], "v0.12.23")
        self.assertEqual(doc["entries"][0]["severity"], "critical")

    def test_revoking_without_a_reason_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                self._run(pathlib.Path(tmp), version="v0.12.23")

    def test_an_unsigned_list_needs_the_explicit_fixture_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as cm:
                self._run(pathlib.Path(tmp), unsigned=False)
        self.assertIn("--key is required", str(cm.exception))


# ═══════════════════════════════════════════════════ 3 · delivery_scope


def deployment(name="api", image="channel.vexa.ai/vexa/gateway" + DIGEST, ns=None,
               spec_extra=None, sc=None, pod_sc=None, volumes=None, requests=None,
               replicas=None):
    d = {
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {"template": {"spec": {
            "containers": [{
                "name": name, "image": image,
                "resources": {"requests": requests or {"cpu": "100m", "memory": "256Mi"},
                              "limits": {"cpu": "1", "memory": "1Gi"}},
                "securityContext": sc if sc is not None else {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
            "volumes": volumes if volumes is not None else [{"name": "tmp", "emptyDir": {}}],
        }}},
    }
    if ns:
        d["metadata"]["namespace"] = ns
    if pod_sc:
        d["spec"]["template"]["spec"]["securityContext"] = pod_sc
    if spec_extra:
        d["spec"]["template"]["spec"].update(spec_extra)
    if replicas is not None:
        d["spec"]["replicas"] = replicas
    return d


SCOPE = {
    "allowed_namespaces": ["vexa-staging"],
    "allow_cluster_scoped": False,
    "pod_security": "restricted",
    "allowed_image_registries": ["channel.vexa.ai/"],
    "resource_ceiling": {"cpu": "8", "memory": "16Gi"},
}


class DeliveryScope(unittest.TestCase):
    def test_a_conforming_render_passes_every_clause(self):
        docs = [deployment(ns="vexa-staging")]
        for _cid, _what, bad in vs.delivery_scope_checks(SCOPE, docs):
            self.assertEqual(bad, [], _cid)

    def test_namespace_outside_the_scope_is_refused(self):
        bad = vs.check_namespaces([deployment(ns="kube-system")], {"vexa-staging"})
        self.assertEqual(len(bad), 1)
        self.assertIn("kube-system", bad[0])

    def test_cluster_scoped_objects_are_refused_when_not_allowed(self):
        crd = {"kind": "CustomResourceDefinition", "metadata": {"name": "vexas.vexa.ai"}}
        webhook = {"kind": "ValidatingWebhookConfiguration", "metadata": {"name": "v"}}
        self.assertEqual(len(vs.check_cluster_scoped([crd, webhook], allowed=False)), 2)
        self.assertEqual(vs.check_cluster_scoped([crd, webhook], allowed=True), [])

    def test_hostpath_hostnetwork_and_privileged_are_refused_at_both_levels(self):
        """There is no setting that permits these. A contract that could opt in
        would be a contract whose strictest value still admits the thing a
        reviewer is actually worried about."""
        docs = [deployment(volumes=[{"name": "h", "hostPath": {"path": "/etc"}}],
                           spec_extra={"hostNetwork": True},
                           sc={"privileged": True})]
        for level in ("baseline", "restricted"):
            found = " ".join(vs.check_pod_security(docs, level))
            self.assertIn("hostPath", found)
            self.assertIn("hostNetwork", found)
            self.assertIn("privileged", found)

    def test_restricted_requires_what_baseline_does_not(self):
        docs = [deployment(sc={})]
        self.assertEqual(vs.check_pod_security(docs, "baseline"), [])
        strict = vs.check_pod_security(docs, "restricted")
        joined = " ".join(strict)
        self.assertIn("allowPrivilegeEscalation", joined)
        self.assertIn("drop ALL", joined)
        self.assertIn("runAsNonRoot", joined)
        self.assertIn("seccompProfile", joined)

    def test_a_pod_level_securitycontext_satisfies_runasnonroot(self):
        docs = [deployment(sc={"allowPrivilegeEscalation": False,
                               "capabilities": {"drop": ["ALL"]},
                               "seccompProfile": {"type": "RuntimeDefault"}},
                           pod_sc={"runAsNonRoot": True})]
        self.assertEqual(vs.check_pod_security(docs, "restricted"), [])

    def test_capabilities_beyond_the_baseline_set_are_refused(self):
        docs = [deployment(sc={"capabilities": {"add": ["SYS_ADMIN"], "drop": ["ALL"]},
                               "allowPrivilegeEscalation": False, "runAsNonRoot": True,
                               "seccompProfile": {"type": "RuntimeDefault"}})]
        self.assertIn("SYS_ADMIN", " ".join(vs.check_pod_security(docs, "baseline")))

    def test_hostport_is_refused(self):
        d = deployment()
        d["spec"]["template"]["spec"]["containers"][0]["ports"] = [{"hostPort": 8080}]
        self.assertIn("hostPort", " ".join(vs.check_pod_security([d], "baseline")))

    def test_an_image_from_an_unlisted_registry_is_refused(self):
        bad = vs.check_image_sources([deployment(image="docker.io/evil/thing" + DIGEST)],
                                     ["channel.vexa.ai/"])
        self.assertEqual(len(bad), 1)
        self.assertIn("docker.io/evil/thing", bad[0])

    def test_resource_ceiling_counts_replicas(self):
        one = [deployment(requests={"cpu": "2", "memory": "4Gi"}, replicas=1)]
        many = [deployment(requests={"cpu": "2", "memory": "4Gi"}, replicas=5)]
        self.assertEqual(vs.check_resource_ceiling(one, {"cpu": "8", "memory": "16Gi"}), [])
        over = vs.check_resource_ceiling(many, {"cpu": "8", "memory": "16Gi"})
        self.assertEqual(len(over), 2)
        self.assertIn("above the", over[0])

    def test_quantities_parse_the_way_kubernetes_writes_them(self):
        self.assertAlmostEqual(vs.parse_quantity("100m"), 0.1)
        self.assertEqual(vs.parse_quantity("2"), 2)
        self.assertEqual(vs.parse_quantity("256Mi"), 256 * 1024 ** 2)
        self.assertEqual(vs.parse_quantity("16Gi"), 16 * 1024 ** 3)

    def test_short_image_refs_are_normalised_the_way_a_runtime_does(self):
        """`vexaai/x` IS `docker.io/vexaai/x` and `postgres` IS
        `docker.io/library/postgres`. Matching the raw string refused eight
        perfectly good images on the real v0.12.23 render (2026-08-25)."""
        self.assertEqual(vs.normalize_image_ref("vexaai/v012-gateway:v1"),
                         "docker.io/vexaai/v012-gateway:v1")
        self.assertEqual(vs.normalize_image_ref("postgres:17-alpine"),
                         "docker.io/library/postgres:17-alpine")
        self.assertEqual(vs.normalize_image_ref("harbor.example.invalid/m/x:1"),
                         "harbor.example.invalid/m/x:1")
        self.assertEqual(vs.normalize_image_ref("localhost:5000/x:1"),
                         "localhost:5000/x:1")
        self.assertEqual(vs.check_image_sources(
            [deployment(image="vexaai/v012-gateway" + DIGEST)], ["docker.io/vexaai/"]), [])

    def test_a_clause_of_the_wrong_shape_refuses_the_contract_rather_than_crashing(self):
        """A YAML list item ending in ':' loses its quotes and parses as a
        mapping. Found writing the fixture for this PR: the check crashed with
        a TypeError, and the near-miss is a check that quietly matches nothing."""
        for scope in (
            {"allowed_image_registries": [{"postgres": None}]},
            {"allowed_namespaces": "vexa-staging"},
            {"allow_cluster_scoped": "false"},
            {"resource_ceiling": {"cpu": "eight"}},
            {"resource_ceiling": {"disk": "1Ti"}},
        ):
            with self.subTest(scope=scope):
                with self.assertRaises(vs.CheckFailure):
                    vs.delivery_scope_of({"delivery_scope": scope})

    def test_an_unimplemented_clause_refuses_the_CONTRACT(self):
        """A clause nobody enforces is worse than no clause: the customer who
        wrote it believes it is being checked. Refuse the contract, loudly, and
        do not publish under it."""
        scope = dict(SCOPE, network_egress=["10.0.0.0/8"])
        with self.assertRaises(vs.CheckFailure) as cm:
            vs.delivery_scope_of({"delivery_scope": scope})
        self.assertIn("network_egress", str(cm.exception))
        self.assertIn("under-enforce", str(cm.exception))

    def test_no_delivery_scope_is_not_an_error(self):
        self.assertIsNone(vs.delivery_scope_of({"require": ["a"]}))

    def test_an_invalid_pod_security_level_refuses_the_contract(self):
        with self.assertRaises(vs.CheckFailure):
            vs.check_pod_security([deployment()], "paranoid")


# ═══════════════════════════════════════════════════ 4 · report.v1 + submit

sys.path.insert(0, str(ROOT / "kit" / "validate"))
import vexa_validate as vv  # noqa: E402


def station_doc(**kw):
    doc = {
        "schema_version": 1,
        "station": "pilot",
        "generated_at": "2026-08-25T10:00:00+00:00",
        "generator": "kit/validate/vexa_validate.py",
        "kit": {"commit": "abc1234", "describe": "v0.1.5", "station_chart_version": "0.1.0"},
        "kubernetes": {"server_version": "v1.36.3"},
        "provider": {"name": "lke", "profile_env_present": True, "profile_tested": "2026-08-24"},
        "namespaces": {"target": "vexa-staging", "release_prefix": "vexa-vexa"},
        "contract": {"source": "policy.example.yaml", "kit_default": True,
                     "contract_id": "example-2026-01", "sha256": "e" * 64},
        "phases": {"preflight": {"verdict": "PASS", "exit_code": 0,
                                 "receipt": "preflight-receipt.txt"},
                   "install": {"skipped": True, "reason": "not requested"},
                   "smoke": {"verdict": "FAIL", "exit_code": 1,
                             "receipt": "smoke-receipt-20260825.md"}},
        "tiers": {"flows": False},
        "redaction": {"verified": True, "values_redacted": 4, "leaks": 0},
        "contract_document": "contract_id: example-2026-01\nrequire: []\n",
        "profile": "PROVIDER=lke\nPROFILE_TESTED=2026-08-24\n",
        "sections": [{"name": "contract_document", "sha256": "a" * 64, "lines": 2},
                     {"name": "profile", "sha256": "b" * 64, "lines": 2}],
    }
    doc.update(kw)
    return doc


class ReportV1(unittest.TestCase):
    def test_the_kit_copy_of_the_schema_is_byte_identical_to_the_spec(self):
        """The kit tarball ships kit/ and nothing else, so the schema is
        duplicated. A duplicate that drifts is a second, laxer contract nobody
        agreed to — so the drift is a test failure, not a review item."""
        self.assertEqual((ROOT / "spec" / "report.v1.schema.json").read_bytes(),
                         (ROOT / "kit" / "validate" / "report.v1.schema.json").read_bytes())

    def test_a_real_station_document_validates(self):
        vv.validate_report(station_doc())

    def test_there_is_nowhere_to_put_content(self):
        """The claim is structural: additionalProperties:false everywhere means
        the permitted field set IS the whole field set. Not 'we would not send
        a transcript' — 'the document cannot carry one'."""
        for where, doc in (
            ("root", station_doc(transcript="…she said…")),
            ("root", station_doc(meeting_title="Q3 planning")),
            ("phases.smoke", station_doc(phases={"smoke": {
                "verdict": "FAIL", "output": "…the log said…"}})),
            ("redaction", station_doc(redaction={"verified": True, "values": ["hunter2"]})),
            ("sections[]", station_doc(sections=[{"name": "profile", "sha256": "c" * 64,
                                                 "body": "…"}])),
            ("a section nobody enumerated", station_doc(meeting_transcript="…")),
        ):
            with self.subTest(where=where):
                with self.assertRaises(SystemExit):
                    vv.validate_report(doc)

    def test_a_missing_required_field_is_refused(self):
        doc = station_doc()
        del doc["station"]
        with self.assertRaises(SystemExit):
            vv.validate_report(doc)

    def test_a_receipt_field_may_only_be_a_filename(self):
        doc = station_doc()
        doc["phases"]["smoke"]["receipt"] = "../../etc/passwd"
        with self.assertRaises(SystemExit):
            vv.validate_report(doc)


class ReportScope(unittest.TestCase):
    SCOPE = {"schema": "report.v1", "trigger": "explicit-command-only",
             "destination": "channel.vexa.ai",
             "allowed_sections": ["contract_document", "profile", "values",
                                  "smoke_receipt"],
             "require_redaction_verified": True}

    def test_a_conforming_submission_passes(self):
        vv.check_report_scope(self.SCOPE,
                              ["contract_document", "profile", "smoke_receipt"],
                              "channel.vexa.ai", station_doc())

    def test_the_old_allowed_files_clause_is_refused_and_not_ignored(self):
        """A customer who wrote down which FILES may leave wrote a bound. The
        report is one file now, so that clause can no longer be satisfied —
        and a bound we quietly stop reading is worse than one we cannot meet.
        The refusal names the new spelling."""
        scope = {k: v for k, v in self.SCOPE.items() if k != "allowed_sections"}
        scope["allowed_files"] = ["station.json", "contract.yaml"]
        with self.assertRaises(SystemExit):
            vv.check_report_scope(scope, ["contract_document"], "channel.vexa.ai",
                                  station_doc())

    def test_a_second_destination_is_refused(self):
        with self.assertRaises(SystemExit):
            vv.check_report_scope(self.SCOPE, ["contract_document"],
                                  "telemetry.example.invalid", station_doc())

    def test_a_section_outside_the_allowed_roles_is_refused(self):
        with self.assertRaises(SystemExit):
            vv.check_report_scope(self.SCOPE, ["contract_document", "meeting_transcript"],
                                  "channel.vexa.ai", station_doc())

    def test_an_unverified_redaction_blocks_the_send_when_the_contract_says_so(self):
        doc = station_doc(redaction={"verified": False, "values_redacted": 4, "leaks": 0})
        with self.assertRaises(SystemExit):
            vv.check_report_scope(self.SCOPE, ["contract_document"], "channel.vexa.ai", doc)

    def test_a_trigger_this_tool_does_not_implement_is_refused_not_ignored(self):
        scope = dict(self.SCOPE, trigger="hourly")
        with self.assertRaises(SystemExit):
            vv.check_report_scope(scope, ["contract_document"], "channel.vexa.ai", station_doc())

    def test_a_contract_with_no_report_scope_at_all_now_refuses_the_send(self):
        """CHANGED 2026-08-25, with the telemetry ladder, and deliberately.

        This test previously asserted the opposite: an empty scope fell back to
        `explicit-command-only` and the submission went ahead. That was
        defensible while the ingest side accepted whatever arrived — the
        fallback was strict about the trigger and the payload was schema-bound
        either way.

        It stopped being defensible the moment ingest gained S10 and started
        REFUSING a bundle whose station contract carries no report_scope. A
        packager that sends and an ingest that refuses is the worst available
        arrangement: the bytes have already crossed the customer's perimeter
        under no declared bound, and the only thing the refusal achieves is
        that we then throw them away. If we would not keep it, we must not ask
        them to send it.

        Note the narrowness — a report_scope that EXISTS but names no `tier` is
        still fine, and reads as tier 1. That is every pre-ladder contract, and
        breaking those would be gratuitous.
        """
        with self.assertRaises(SystemExit):
            vv.check_report_scope({}, ["contract_document"], "channel.vexa.ai", station_doc())

    def test_a_scope_without_a_tier_is_tier_one_not_a_refusal(self):
        scope = {k: v for k, v in self.SCOPE.items()}
        scope.pop("tier", None)
        vv.check_report_scope(scope, ["contract_document", "profile", "smoke_receipt"],
                              "channel.vexa.ai", station_doc())

    def test_a_payload_above_the_declared_tier_is_refused(self):
        scope = dict(self.SCOPE, tier=2)
        doc = station_doc()
        doc["tier"] = 3
        with self.assertRaises(SystemExit):
            vv.check_report_scope(scope, ["contract_document"], "channel.vexa.ai", doc)

    def test_a_block_above_the_declared_tier_is_refused_whatever_the_label_says(self):
        """The block is the payload; the tier field is only a label, and a
        label cannot authorise its own contents."""
        scope = dict(self.SCOPE, tier=2)
        doc = station_doc()
        doc["tier"] = 2
        doc["usage"] = {"activated_users": 7}
        with self.assertRaises(SystemExit):
            vv.check_report_scope(scope, ["contract_document"], "channel.vexa.ai", doc)

    def test_a_silent_station_sends_nothing(self):
        scope = dict(self.SCOPE, tier=0)
        with self.assertRaises(SystemExit):
            vv.check_report_scope(scope, ["contract_document"], "channel.vexa.ai", station_doc())

    def test_scheduled_is_an_accepted_trigger_and_hourly_still_is_not(self):
        """The timer is authorised by the customer's own file, or not at all."""
        vv.check_report_scope(dict(self.SCOPE, trigger="scheduled"),
                              ["contract_document", "profile", "smoke_receipt"],
                              "channel.vexa.ai", station_doc())
        with self.assertRaises(SystemExit):
            vv.check_report_scope(dict(self.SCOPE, trigger="hourly"),
                                  ["contract_document"], "channel.vexa.ai", station_doc())


if __name__ == "__main__":
    unittest.main()
