# SPDX-License-Identifier: Apache-2.0
"""Attestation machinery: consistency refusals are the load-bearing tests —
an attestation with numbers its own definition cannot reproduce must never
be signed (the meetings_failed lesson, applied at the source)."""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vexa_channel as vc  # noqa: E402


def soak_predicate():
    return {
        "release": "v9.9.9",
        "environment": "test",
        "window": {"from": "2026-08-20T00:00:00Z", "to": "2026-08-21T00:00:00Z"},
        "platforms": {
            "ms_teams": {
                "meetings_dispatched": 100,
                "software_failures": 1,
                "software_success_rate": 0.99,
                "completed": 80,
                "completion_rate": 0.8,
                "exit_reasons": {
                    "completed": 80, "STOPPED": 10, "LEFT_ALONE": 5, "STARTUP_ALONE": 2,
                    "EVICTED": 1, "AWAITING_ADMISSION_TIMEOUT": 1, "AWAITING_ADMISSION_REJECTED": 0,
                    "MAX_BOT_TIME_EXCEEDED": 0, "VALIDATION_ERROR": 0,
                    "JOIN_FAILURE": 1, "AUTH_SESSION_MISSING": 0,
                },
            }
        },
        "definitions": {"document": "prod-soak-metrics.v1", "sha256": "0" * 64},
    }


class SoakConsistency(unittest.TestCase):
    def test_consistent_passes(self):
        vc.check_soak_consistency(soak_predicate())

    def test_wrong_rate_refused(self):
        p = soak_predicate()
        p["platforms"]["ms_teams"]["software_success_rate"] = 0.999
        with self.assertRaises(vc.CheckFailure):
            vc.check_soak_consistency(p)

    def test_exit_reasons_must_sum_to_dispatched(self):
        p = soak_predicate()
        p["platforms"]["ms_teams"]["exit_reasons"]["STOPPED"] = 11
        with self.assertRaises(vc.CheckFailure):
            vc.check_soak_consistency(p)

    def test_software_failures_must_match_taxonomy(self):
        p = soak_predicate()
        p["platforms"]["ms_teams"]["software_failures"] = 2
        with self.assertRaises(vc.CheckFailure):
            vc.check_soak_consistency(p)


class HardeningConsistency(unittest.TestCase):
    def pred(self):
        return {
            "findings": {
                "confirmed": {"critical": 0, "high": 1, "medium": 3, "low": 5},
                "fixed": {"critical": 0, "high": 1, "medium": 2, "low": 3},
                "open": {"critical": 0, "high": 0, "medium": 1, "low": 2},
            }
        }

    def test_consistent_passes(self):
        vc.check_hardening_consistency(self.pred())

    def test_open_must_equal_confirmed_minus_fixed(self):
        p = self.pred()
        p["findings"]["open"]["medium"] = 0
        with self.assertRaises(vc.CheckFailure):
            vc.check_hardening_consistency(p)

    def test_fixed_cannot_exceed_confirmed(self):
        p = self.pred()
        p["findings"]["fixed"]["low"] = 9
        with self.assertRaises(vc.CheckFailure):
            vc.check_hardening_consistency(p)


class SealedDefinitions(unittest.TestCase):
    def test_definition_documents_exist_and_are_pinned_by_name(self):
        spec = pathlib.Path(__file__).resolve().parent.parent.parent / "spec"
        for kind, meta in vc.ATTEST_KINDS.items():
            if meta["definitions_file"] is None:
                continue  # station-verdict: the contract is its definition
            path = spec / meta["definitions_file"]
            self.assertTrue(path.exists(), f"{kind}: sealed definition file missing")
            self.assertIn("FROZEN", path.read_text(), f"{kind}: definition not marked frozen")


if __name__ == "__main__":
    unittest.main()
