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
        identity in every verdict and approval record."""
        import yaml
        chart, _ = stage()
        r = helm_template(chart)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        cms = {d["metadata"]["name"]: d for d in yaml.safe_load_all(r.stdout)
               if d and d.get("kind") == "ConfigMap"}
        self.assertEqual(cms["vexa-contract-prod"]["data"]["policy.json"],
                         PROD_REC.read_text().rstrip("\n"))
        self.assertEqual(cms["vexa-contract-staging"]["data"]["policy.json"],
                         STAGING_REC.read_text().rstrip("\n"))

    def test_a_station_that_follows_no_channel_needs_no_contract(self):
        """The gate is on the subscription, and it stays there. An estate that
        installs the bundle for its machinery alone renders with no contract at
        all — as it did before this change."""
        r = helm_template(CHART, ["--set", "subscription.enabled=false"])
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertNotIn("vexa-contract-", r.stdout)


if __name__ == "__main__":
    unittest.main()
