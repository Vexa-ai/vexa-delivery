# SPDX-License-Identifier: Apache-2.0
"""The station chart as it actually ships — with its contracts injected.

Since 2026-08-29 the entry-verification contracts are PUBLISH INPUTS, copied out
of the vexa-stations ledger by `vexa_channel.py station-chart`, and a chart with
none injected refuses to render. So `station/chart` in the source tree is no
longer a renderable shape, and a test that renders it directly is testing
something that never reaches a cluster.

Every render test in this repository therefore goes through `PACKAGED_CHART`
below: one staged copy per process, contracts injected from the fixture ledger,
cleaned up at exit. The fixture ledger stands in for vexa-stations — the real
records are private, and a test that needed them could not run.

Not named `test_*`, so unittest discovery does not collect it.
"""
import atexit
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "publisher"))

import vexa_channel  # noqa: E402

CHART_SRC = ROOT / "station/chart"

# The stand-in ledger. `fixture-prod.json` carries the 2026-09 contract SHAPE —
# `required_values[]` beside a `carriage{}` block — because that is what a real
# record looks like now and a fixture in the old flat shape would let a
# regression through.
LEDGER = pathlib.Path(__file__).resolve().parent / "fixtures/ledger"
STAGING_REC = LEDGER / "channels/fixture-stable/contracts/fixture-staging.json"
PROD_REC = LEDGER / "channels/fixture-stable/contracts/fixture-prod.json"
RECORDS = {"staging": STAGING_REC, "prod": PROD_REC}


def stage(contracts=("staging", "prod")):
    """A packaged copy of the station chart. Returns (chart_dir, receipt rows).

    The caller owns the temporary directory; use `PACKAGED_CHART` unless the
    test needs a chart with something deliberately missing.
    """
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="station-chart-fixture-"))
    dest = tmp / "chart"
    shutil.copytree(CHART_SRC, dest)
    rows = vexa_channel.inject_station_contracts(
        dest, {k: RECORDS[k] for k in contracts})
    atexit.register(shutil.rmtree, tmp, True)
    return dest, rows


PACKAGED_CHART, PACKAGED_ROWS = stage()
