# Golden: a station's departure verdict

`station-verdict.json` is what `publisher/vexa_station_verdict.py render`
emits for the fixture station, and `values-proven.json` is the proof block it
signs over — the same block `publisher/vexa_values_proven.py` builds from
`kit/verify/tests/fixtures/values-proven/row-fills.log`.

It is a golden and not an example: `publisher/tests/test_station_verdict.py`
re-renders both files from those committed inputs and byte-compares, so a
change to the renderer's output — a renamed field, a different hash rule, a
different serialisation — cannot land without this file changing with it.

`rendered_at` is the one field excluded from the comparison, because it is the
clock. Everything else, including `contract_sha256` and
`values_proven_sha256`, is a pure function of the committed inputs; if one of
those hashes moves, either a fixture changed or the canonical form did, and
both are things a reviewer should be shown rather than told about.

Regenerate (only when the change is intended):

```sh
python3 publisher/vexa_values_proven.py \
  --contract kit/verify/tests/fixtures/contracts/estate-station-verdict.json \
  --fills    kit/verify/tests/fixtures/values-proven/row-fills.log \
  --map      kit/verify/tests/fixtures/values-proven/rows.json \
  --station  vexa-staging-fixture \
  --out      spec/goldens/station-verdict/values-proven.json

python3 publisher/vexa_station_verdict.py render \
  --station vexa-staging-fixture \
  --candidate-sha 0000000000000000000000000000000000000000 \
  --manifest-sha256 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  --contract kit/verify/tests/fixtures/contracts/estate-station-verdict.json \
  --values-proven spec/goldens/station-verdict/values-proven.json \
  --out spec/goldens/station-verdict
```
