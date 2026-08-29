<!-- SPDX-License-Identifier: Apache-2.0 -->
# This directory is EMPTY on purpose

The two entry-verification contracts (`staging.json`, `prod.json`) are **publish
inputs**, not files in this repository. They are written here at packaging time
by:

```bash
python3 publisher/vexa_channel.py station-chart \
  --contract staging=$VEXA_STATIONS_DIR/channels/<channel>/contracts/<record>.json \
  --contract prod=$VEXA_STATIONS_DIR/channels/<channel>/contracts/<record>.json \
  --out-dir work/station-chart
```

which copies each record's **bytes** verbatim and pins them by `sha256` in
`station-chart-receipt.json`. `templates/contracts.yaml` `fail`s the render when
a slot it needs was never injected — there is no fallback, because an empty
`policy.json` makes a verifier print OK for every check it never ran.

Until 2026-08-29 an `internal-prod.json` sat here and the chart bound it. Both
ledger records say that copy must not bind an estate; nothing enforced it, and a
copy that drifts from the record produces verdicts naming a contract id whose
bytes are in no ledger. `publisher/tests/test_station_contracts.py` now refuses
any `*.json` in this directory that is not a byte-copy of a named ledger record.

See [`contracts/README.md`](../../../../contracts/README.md) for where the
records live.
