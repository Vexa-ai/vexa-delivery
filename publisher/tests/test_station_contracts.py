# SPDX-License-Identifier: Apache-2.0
"""The station chart's entry contract is an INPUT, taken from the ledger.

THE DEFECT. Through station chart 1.0.7 the chart carried
`files/contracts/internal-prod.json` and rendered it into the ConfigMap the
PreSync verify gate reads. Both ledger records say that copy must not bind an
estate — the live contract for `vexa-internal` is a record in the vexa-stations
ledger, and `contracts/README.md` in this repository already said "when they
disagree, the record wins". Nothing enforced it.

A vendor-side copy that drifts from the record does not error. It renders, it
admits, and it produces verdicts naming a contract id whose bytes exist in no
ledger — so "which promise was this deployment admitted under" has no answer.
Same failure class as every other one in this repository's history: two writers
on one meaning, a plausible result, and the losing writer's intent gone.

WHAT NOW HOLDS
  1. the repository carries no contract instance inside the chart;
  2. `station-chart` copies the record's BYTES in and pins each by sha256 in a
     receipt;
  3. anything found in the chart's contract directory must byte-match a named
     ledger record — id equality is not enough, because the drift that matters
     keeps the id and moves a threshold;
  4. a chart with no contract injected FAILS to render, loudly. It does not fall
     back: an empty `policy.json` makes a verifier print OK for every check it
     never ran.
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "publisher"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import vexa_channel  # noqa: E402
from station_chart_fixture import (  # noqa: E402
    CHART_SRC as CHART, LEDGER, PROD_REC, STAGING_REC, stage,
)

BASE = [
    "--set", "channelPublicKey=x",
    "--set", "floor.image=reg.invalid/tools/kubectl@sha256:" + "a" * 64,
]


def helm_template(chart, extra=()):
    return subprocess.run(["helm", "template", "st", str(chart), *BASE, *extra],
                          capture_output=True, text=True)


class TheRepositoryCarriesNoInstance(unittest.TestCase):

    def test_the_charts_contract_directory_holds_no_json(self):
        """THE ONE THAT MATTERS. A committed instance is a second binding that
        can drift from the record, and the render would pick it silently."""
        found = sorted(p.name for p in (CHART / "files/contracts").glob("*.json"))
        self.assertEqual(found, [], f"contract instances committed into the chart: {found}")

    def test_anything_that_appears_there_must_be_a_ledger_record(self):
        """The check as a function, run against the chart as committed. It
        passes vacuously today and stops being vacuous the moment somebody adds
        a file back."""
        self.assertEqual(vexa_channel.check_chart_contracts(CHART, LEDGER), [])


class Injection(unittest.TestCase):

    def test_the_bytes_are_the_records_bytes(self):
        """Byte-for-byte, never re-serialised. The verifier hashes the file it
        reads and every verdict names that hash, so a reordered key or a dropped
        trailing newline would produce a contract id matching no record."""
        chart, _ = stage()
        self.assertEqual((chart / "files/contracts/prod.json").read_bytes(),
                         PROD_REC.read_bytes())
        self.assertEqual((chart / "files/contracts/staging.json").read_bytes(),
                         STAGING_REC.read_bytes())

    def test_the_receipt_pins_each_contract_by_sha256_and_names_its_source(self):
        _, rows = stage()
        by_slot = {r["slot"]: r for r in rows}
        self.assertEqual(by_slot["prod"]["contract_id"], "vexa-fixture-prod-2026-09")
        self.assertEqual(by_slot["prod"]["sha256"],
                         vexa_channel.sha256_file(PROD_REC))
        self.assertEqual(by_slot["prod"]["configmap"], "vexa-contract-prod")
        self.assertEqual(by_slot["prod"]["source"], str(PROD_REC))

    def test_an_injected_chart_matches_the_ledger(self):
        chart, _ = stage()
        matched = vexa_channel.check_chart_contracts(chart, LEDGER)
        self.assertEqual({m["file"] for m in matched}, {"prod.json", "staging.json"})

    def test_one_changed_byte_is_refused_by_name(self):
        """Not an id comparison. The drift that matters keeps the contract_id
        and moves a threshold — here, one day of max_entry_age_days."""
        chart, _ = stage()
        doc = json.loads((chart / "files/contracts/prod.json").read_text())
        doc["carriage"]["max_entry_age_days"] = 31
        (chart / "files/contracts/prod.json").write_text(json.dumps(doc, indent=2))
        with self.assertRaises(vexa_channel.CheckFailure) as e:
            vexa_channel.check_chart_contracts(chart, LEDGER)
        self.assertIn("prod.json", str(e.exception))
        self.assertIn("matches no", str(e.exception))

    def test_injecting_over_an_existing_instance_refuses(self):
        """Two candidate bindings is the state this whole change removes; the
        packaging command must not be able to create it."""
        chart, _ = stage()
        with self.assertRaises(vexa_channel.CheckFailure) as e:
            vexa_channel.inject_station_contracts(chart, {"prod": PROD_REC})
        self.assertIn("already carries", str(e.exception))

    def test_a_contract_with_no_id_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = pathlib.Path(tmp, "bad.json")
            bad.write_text('{"require_publication_mode": "candidate"}')
            dest = pathlib.Path(tmp, "chart")
            dest.mkdir()
            with self.assertRaises(vexa_channel.CheckFailure) as e:
                vexa_channel.inject_station_contracts(dest, {"prod": bad})
            self.assertIn("contract_id", str(e.exception))


@unittest.skipUnless(shutil.which("helm"), "helm not installed")
class TheRender(unittest.TestCase):

    def test_an_uninjected_chart_refuses_to_render(self):
        """No fallback. An empty `.Files.Get` would render a ConfigMap with an
        empty policy.json, and a verifier handed an empty policy reports OK for
        every check it never ran — a false green at admission time."""
        r = helm_template(CHART)
        self.assertNotEqual(r.returncode, 0, r.stdout[-2000:])
        self.assertIn("no staging entry contract was injected", r.stderr)
        self.assertIn("station-chart", r.stderr,
                      "the refusal does not say how to fix it")

    def test_a_missing_slot_names_the_slot(self):
        chart, _ = stage(contracts=("staging",))
        r = helm_template(chart)
        self.assertNotEqual(r.returncode, 0, r.stdout[-2000:])
        self.assertIn("no prod entry contract was injected", r.stderr)

    def test_the_configmap_carries_the_records_bytes(self):
        """What lands in the argocd namespace must be the record, not a
        re-encoding of it: the verifier's sha256 of this file IS the contract's
        identity in every verdict and approval record.

        THIS ASSERTION USED TO END IN `.rstrip("\\n")`, and that one call was
        the bug (seq-6 station, 2026-08-29). The template rendered the record
        through a `|-` block scalar, which strips the trailing newline, and the
        test asserted the stripped form — so the test passed BECAUSE of the
        defect, which is the worst shape a test can have. It is now an exact
        byte comparison, and the sha256 assertion below is the one that
        actually matters, because the hash is what a verdict names."""
        import yaml
        chart, _ = stage()
        r = helm_template(chart)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        cms = {d["metadata"]["name"]: d for d in yaml.safe_load_all(r.stdout)
               if d and d.get("kind") == "ConfigMap"}
        for slot, rec in (("prod", PROD_REC), ("staging", STAGING_REC)):
            rendered = cms[f"vexa-contract-{slot}"]["data"]["policy.json"]
            self.assertEqual(rendered, rec.read_text(), slot)
            self.assertEqual(
                hashlib.sha256(rendered.encode()).hexdigest(),
                hashlib.sha256(rec.read_bytes()).hexdigest(),
                f"{slot}: the ConfigMap's sha256 must be the record's sha256 — "
                f"it is what every verdict rendered against this contract names")

    def test_the_trailing_newline_survives_the_render(self):
        """THE SEQ-6 DEFECT, PINNED (2026-08-29).

        The record `internal-estate-2026-09.json` hashes to
        `a76cef3c62c21d0e…`. The in-cluster gate, hashing the ConfigMap it had
        mounted, recorded `355eddae4f036662…`. The two inputs differ by one
        byte: the single `0a` that `|-` strips off the end. The stations
        ledger's own README exists to prevent exactly that — "every historical
        gate report would start pointing at a hash nothing matches."

        A file ending in a newline is the ONLY shape the real records have, so
        it is the shape that must not regress."""
        import yaml
        rec = self._record_ending_in(b"\n")
        chart = self._chart_carrying(rec)
        r = helm_template(chart)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        rendered = next(d for d in yaml.safe_load_all(r.stdout)
                        if d and d.get("kind") == "ConfigMap"
                        and d["metadata"]["name"] == "vexa-contract-prod"
                        )["data"]["policy.json"]
        self.assertTrue(rendered.endswith("\n"),
                        "the trailing newline was stripped — this is the seq-6 defect")
        self.assertEqual(rendered.encode(), rec.read_bytes())

    def test_every_trailing_shape_round_trips_byte_for_byte(self):
        """AND NOT ONLY THE COMMON ONE, which is why the fix is `toJson` and
        not `|`.

        Clip chomping (`|`) fixes the observed case and is what the station
        report proposed. It is byte-exact only for a file ending in exactly one
        newline: it APPENDS one to a file ending in none, and COLLAPSES two to
        one. That trades a defect that always fires for a defect that fires on
        an input nobody thinks to test — and the whole point of hashing the
        record is that nobody has to think about its bytes. A quoted scalar has
        no input shape left to get wrong."""
        import yaml
        for label, tail in (("one newline", b"\n"),
                            ("no newline", b""),
                            ("two newlines", b"\n\n")):
            with self.subTest(label):
                rec = self._record_ending_in(tail)
                r = helm_template(self._chart_carrying(rec))
                self.assertEqual(r.returncode, 0, r.stderr[-2000:])
                rendered = next(d for d in yaml.safe_load_all(r.stdout)
                                if d and d.get("kind") == "ConfigMap"
                                and d["metadata"]["name"] == "vexa-contract-prod"
                                )["data"]["policy.json"]
                self.assertEqual(
                    hashlib.sha256(rendered.encode()).hexdigest(),
                    hashlib.sha256(rec.read_bytes()).hexdigest(),
                    f"{label}: the rendered ConfigMap does not hash to the record")

    # -- helpers for the two tests above ------------------------------------
    #
    # They build their own record rather than reusing the fixture ledger,
    # because the shape under test IS the file's trailing bytes and the ledger
    # fixtures all end the one legal way.

    def _record_ending_in(self, tail):
        body = json.dumps({"contract_id": "fixture-estate-2026-09",
                           "carriage": {"min_entry_seq": 1}}, indent=2)
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="contract-bytes-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        rec = tmp / "prod.json"
        rec.write_bytes(body.rstrip("\n").encode() + tail)
        return rec

    def _chart_carrying(self, prod_record):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="contract-bytes-chart-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        dest = tmp / "chart"
        shutil.copytree(CHART, dest)
        vexa_channel.inject_station_contracts(
            dest, {"staging": STAGING_REC, "prod": prod_record})
        return dest

    def test_a_station_that_follows_no_channel_needs_no_contract(self):
        """The gate is on the subscription, and it stays there. An estate that
        installs the bundle for its machinery alone renders with no contract at
        all — as it did before this change."""
        r = helm_template(CHART, ["--set", "subscription.enabled=false"])
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertNotIn("vexa-contract-", r.stdout)


if __name__ == "__main__":
    unittest.main()
