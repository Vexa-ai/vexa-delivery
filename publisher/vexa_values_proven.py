#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-values-proven — build an entry's `values_proven` block from a station's
own committed fills.

WHY IT IS NOT TYPED BY HAND. The block this writes is what a contract's
`carriage.require_entry_values_proven` clause demands, and the in-cluster
verifier now refuses an entry that omits it. A human transcribing "V-est-1:
proven" into JSON is producing an unbacked claim in the exact shape of a backed
one — the same defect `--verdict-out` was written to remove from the station
verdict. So the evidence is COPIED, verbatim, out of the station's row-fills
log: a line that already exists, is already committed to the stations ledger,
and can be re-read at the `ref` this tool records.

WHAT MAKES A LINE PROOF. The station log's own convention is one row per line:

    2026-08-30T08:0xZ E0 PASS  vexa-verify.sh --station laptop-preflight …

...a timestamp, a station row id, a verdict token, and the finding. A line
proves a contract value when its row id is mapped to that value AND its verdict
token is exactly `PASS`. `PART`, `PASS*`, `FINDING`, `NOTE` and anything else do
NOT prove: they are the station saying "not entirely", and a tool that reads
them as proof is a tool that launders a caveat into a green tick. If a partial
row should nonetheless be accepted, that is a human's decision and it is written
as a `waived` row with the human's name on it — which this tool deliberately
cannot mint. A machine does not get to waive.

REFUSES RATHER THAN UNDER-DELIVERS. A required contract value with no mapped
PASS line produces NO output at all: the tool exits 3 and names what is
missing. Writing a partial block would hand the publisher a file that looks
complete and fails at the subscriber's PreSync hook instead.

  usage: python3 publisher/vexa_values_proven.py \
             --contract contracts/internal-estate-2026-09.json \
             --fills   <stations ledger>/stations/estate-seq12/row-fills.log \
             --map     seq12-rows.json \
             --station estate-seq12 \
             --out     values-proven.json

  --map is a flat JSON object mapping STATION ROW ID -> CONTRACT VALUE ID,
  e.g. {"E0": "V-est-1", "P2": "V-est-2", "F0": "V-est-7"}. Several rows may
  map to one value; each contributes an evidence row. A value named in the map
  that the contract does not declare is a refusal, not a warning — it is the
  shape a typo takes, and a typo here proves nothing while looking like proof.

Exit 0 wrote the block · 2 usage · 3 refused, and says what is unproven.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from vexa_channel import CheckFailure, check_values_proven  # noqa: E402

# timestamp · row id · verdict token · the rest of the line
FILL_LINE = re.compile(r"^(?P<ts>\S+)\s+(?P<row>\S+)\s+(?P<verdict>\S+)(?:\s+(?P<rest>.*))?$")

PROOF_VERDICT = "PASS"


def parse_stamp(token):
    """The station writes a COARSE stamp: `2026-08-30T08:0xZ` — no seconds, and
    an `x` standing for a digit nobody wrote down. The entry schema wants a full
    ISO-8601 Z instant, so `x` becomes `0` and a missing seconds field becomes
    `:00`. Both round DOWN, which is the safe direction: the recorded stamp is
    never later than the event it describes. A token that still does not parse
    is not silently defaulted — the line is refused as evidence.
    """
    candidate = token.replace("x", "0").replace("X", "0")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z", candidate):
        candidate = candidate[:-1] + ":00Z"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", candidate):
        return candidate
    return None


def read_contract(path):
    doc = json.loads(pathlib.Path(path).read_text())
    values = doc.get("required_values")
    if not isinstance(values, list) or not values:
        raise CheckFailure("V1", f"{path}: contract declares no required_values[]")
    rows = []
    for v in values:
        vid = v.get("id")
        if not isinstance(vid, str) or not vid:
            raise CheckFailure("V1", f"{path}: a required_values[] row has no id")
        rows.append((vid, v.get("enforcement", "advisory"), v.get("claim", "")))
    return doc.get("contract_id", "unnamed"), rows


def read_map(path, known_ids):
    mapping = json.loads(pathlib.Path(path).read_text())
    if not isinstance(mapping, dict) or not mapping:
        raise CheckFailure("V2", f"{path}: expected a non-empty JSON object of row-id -> value-id")
    for row, vid in mapping.items():
        if not isinstance(row, str) or not row.strip():
            raise CheckFailure("V2", f"{path}: a key is not a station row id")
        if not isinstance(vid, str) or not vid.strip():
            raise CheckFailure("V2", f"{path}: row {row!r} maps to {vid!r}, which is not a value id")
        if vid not in known_ids:
            raise CheckFailure(
                "V2",
                f"{path}: row {row!r} maps to {vid!r}, which this contract does not declare. "
                f"Known values: {', '.join(sorted(known_ids))}. A map that names a value the "
                "contract has never heard of proves nothing while looking like proof.",
            )
    return mapping


def collect(fills_path, mapping):
    """Every mapped row id -> the fill lines that PASS it, and the ones that did
    not, so a refusal can say what was there instead of nothing."""
    proofs, rejected = {}, {}
    text = pathlib.Path(fills_path).read_text()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = FILL_LINE.match(line)
        if not m:
            continue
        row = m.group("row")
        if row not in mapping:
            continue
        vid = mapping[row]
        if m.group("verdict") != PROOF_VERDICT:
            rejected.setdefault(vid, []).append(f"{row} {m.group('verdict')}")
            continue
        stamp = parse_stamp(m.group("ts"))
        if stamp is None:
            rejected.setdefault(vid, []).append(f"{row} PASS (unreadable timestamp {m.group('ts')!r})")
            continue
        proofs.setdefault(vid, []).append({
            "what": line,
            "ref": str(fills_path),
            "tested_at": stamp,
        })
    return proofs, rejected


def build(args):
    contract_id, values = read_contract(args.contract)
    known = {vid for vid, _, _ in values}
    mapping = read_map(args.map, known)
    proofs, rejected = collect(args.fills, mapping)

    rows, unproven, skipped = [], [], []
    for vid, enforcement, _claim in values:
        evidence = proofs.get(vid)
        if evidence:
            rows.append({
                "id": vid,
                "verdict": "proven",
                "evidence": evidence,
                "station": args.station,
            })
            continue
        looked_for = sorted(r for r, v in mapping.items() if v == vid)
        detail = (f"mapped rows {', '.join(looked_for)}" if looked_for
                  else "no station row is mapped to it")
        instead = rejected.get(vid)
        if instead:
            detail += f"; found instead: {', '.join(instead)}"
        (unproven if enforcement == "required" else skipped).append(f"{vid} ({detail})")

    if unproven:
        raise CheckFailure(
            "V3",
            f"contract {contract_id} REQUIRES these values and no PASS fill proves them:\n  "
            + "\n  ".join(unproven)
            + "\n\nNothing was written. Run the missing station row, or have a named human "
              "add a waived row by hand — this tool does not mint waivers.",
        )

    check_values_proven(rows, str(args.out))
    pathlib.Path(args.out).write_text(json.dumps(rows, indent=1) + "\n")

    print(f"values_proven for contract {contract_id}, station {args.station} -> {args.out}")
    for row in rows:
        print(f"  {row['id']}: proven, {len(row['evidence'])} evidence row(s)")
    for s in skipped:
        print(f"  skipped (advisory, unproven): {s}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="vexa-values-proven", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--contract", required=True,
                   help="the channel contract whose required_values[] are being answered")
    p.add_argument("--fills", required=True,
                   help="the station's committed row-fills.log; quoted verbatim as evidence")
    p.add_argument("--map", required=True,
                   help="JSON object mapping station row id -> contract value id")
    p.add_argument("--station", required=True,
                   help="the station making the claim; recorded on every row")
    p.add_argument("--out", required=True,
                   help="where to write the values_proven JSON array")
    args = p.parse_args(argv)
    try:
        return build(args)
    except CheckFailure as e:
        print(f"REFUSED {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
