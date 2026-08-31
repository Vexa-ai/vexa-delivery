#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-station-verdict — render and sign a station's departure verdict.

THE OBJECT THIS WRITES. The delivery line's station cell is ADMIT (verify the
upstream station's verdict) -> MINT (the PRD) -> PROVE (the fills) -> DEPART.
Lane A built the currency that DEPART compiles: the `values_proven` block, out
of the station's committed fills. This is the signature over it. A downstream
contract that sets

    require_attestations: [ { kind: station-verdict, station: <S> } ]

refuses cargo that never departed S.

WHY IT IS NOT `vexa_station.py`. That tool is about a CUSTOMER's station — it
ingests a station report and gates a publish on that customer's contract (S1..
S10). The word "station" means a different thing there: an installation we
deliver to, not a stop on our own line. Putting a verdict renderer inside it
would make one 1200-line tool answer two unrelated questions, and every reader
would have to work out which sense of "station" a given check meant. Separate
file, separate verb namespace.

  render  compute the verdict from the contract and the proof block, and write
          station-verdict.json
  sign    cosign key-mode over that file, offline, same flags as every other
          signature this repo makes

THE VERDICT IS COMPUTED, NEVER SUPPLIED. There is no --verdict flag and there
will not be one. ELIGIBLE iff every `required_values[]` row the contract marks
`enforcement: required` is answered by a `proven` or human-`waived` row in the
values_proven block. That rule is lane A's and it is IMPORTED, not restated:
`read_contract` decides what "required" means, `check_values_proven` decides
what a well-formed row is. A second copy of either would drift, and the drift
would show up as a station signing ELIGIBLE for a block the subscriber's
verifier then refuses.

A REFUSED VERDICT IS STILL AN OBJECT, and it is signable. A station that finds
a required value unproven could simply write nothing — that is what the older
accumulated-attestation path does, and it is why "no attestation" is ambiguous
downstream between "the station said no" and "the station never ran". A
REFUSED verdict names the values that caused it. `platform-entry` refuses to
carry one into an entry: an entry does not carry a station's no.

WHAT `values_proven_sha256` HASHES. The CANONICAL form of the block — keys
sorted recursively, no whitespace, no trailing newline, UTF-8 — not the bytes
of the file on disk. The block is re-serialised when `platform-entry` embeds
it, so a file hash would never match what a subscriber actually holds, and the
check would fail on every honest entry. The verifier recomputes the same string
with `jq -Sc '.values_proven'`; that agreement is tested, not assumed.

  usage:
    python3 publisher/vexa_station_verdict.py render \\
        --station vexa-staging-bbb \\
        --candidate-sha 0f9e...  --manifest-sha256 4c1d... \\
        --contract <ledger>/channels/vexa-internal/contracts/internal-estate-2026-09.json \\
        --values-proven values-proven.json \\
        --out work/verdict

    python3 publisher/vexa_station_verdict.py sign \\
        --verdict work/verdict/station-verdict.json --key cosign.key

Exit 0 wrote it · 2 usage · 3 refused, and says what is wrong.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from vexa_channel import (  # noqa: E402
    CheckFailure,
    canonical_values_proven_sha256,
    check_values_proven,
    cosign_bin,
    cosign_env,
    cosign_offline_flags,
    require_pinned_cosign,
    run,
    sha256_file,
    utcnow,
)
from vexa_values_proven import read_contract  # noqa: E402

SPEC = pathlib.Path(__file__).resolve().parent.parent / "spec"
SCHEMA = SPEC / "station-verdict.schema.json"
VERDICT_NAME = "station-verdict.json"

# Verdicts that ANSWER a required value. `proven` is a station claim with
# evidence; `waived` is a named human accepting it unproven. Both are answers;
# the difference is who is on the hook, and check_values_proven already refuses
# a waiver with nobody's name on it.
ANSWERING = ("proven", "waived")


def load_values_proven(path):
    rows = json.loads(pathlib.Path(path).read_text())
    check_values_proven(rows, str(path))  # lane A's shape rules, imported
    return rows


def schema_validate(verdict):
    import jsonschema

    schema = json.loads(SCHEMA.read_text())
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(verdict),
        key=lambda e: list(e.absolute_path),
    )
    if errors:
        locs = "; ".join(
            f"{'/'.join(str(x) for x in e.absolute_path) or '(root)'}: {e.message}"
            for e in errors[:4]
        )
        raise CheckFailure("SV1", f"verdict does not validate against {SCHEMA.name}: {locs}")


def compute(contract_path, values_proven_path, station):
    """(contract_id, contract_sha256, rows, verdict, unanswered).

    The whole adjudication, in one function, so the test that proves REFUSED is
    reachable does not have to drive a CLI to get at it.
    """
    contract_id, values = read_contract(contract_path)
    rows = load_values_proven(values_proven_path)

    answered = {}
    for row in rows:
        if row["verdict"] in ANSWERING:
            answered[row["id"]] = row

    declared = {vid for vid, _enf, _claim in values}
    stray = sorted(set(answered) - declared)

    unanswered = []
    for vid, enforcement, claim in values:
        if enforcement != "required":
            continue
        row = answered.get(vid)
        if row is None:
            unanswered.append({
                "id": vid,
                "reason": f"no proven or waived row answers it ({claim or 'no claim text'})",
            })

    verdict = "REFUSED" if unanswered else "ELIGIBLE"
    return contract_id, sha256_file(contract_path), rows, verdict, unanswered, stray


def cmd_render(args):
    contract_id, contract_sha, rows, verdict, unanswered, stray = compute(
        pathlib.Path(args.contract), pathlib.Path(args.values_proven), args.station
    )

    doc = {
        "schema_version": 1,
        "station": args.station,
        "candidate_sha": args.candidate_sha,
        "manifest_sha256": args.manifest_sha256,
        "contract_id": contract_id,
        "contract_sha256": contract_sha,
        "values_proven_sha256": canonical_values_proven_sha256(rows),
        "verdict": verdict,
        "rendered_at": utcnow(),
    }
    if unanswered:
        doc["unanswered_values"] = unanswered
    schema_validate(doc)

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / VERDICT_NAME
    path.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n")

    print(f"station verdict for {args.station} -> {path}")
    print(f"  contract {contract_id} @ sha256:{contract_sha[:12]}…")
    print(f"  values_proven: {len(rows)} row(s), "
          f"canonical sha256:{doc['values_proven_sha256'][:12]}…")
    print(f"  candidate {args.candidate_sha[:12]}… · manifest sha256:{args.manifest_sha256[:12]}…")
    for s in stray:
        print(f"  note: the block answers {s}, which contract {contract_id} does not declare — "
              "it proves nothing here and does not affect the verdict")
    print(f"  VERDICT: {verdict}")
    for u in unanswered:
        print(f"    unanswered: {u['id']} — {u['reason']}")
    if verdict == "REFUSED":
        print("  A REFUSED verdict is a real object and it is signable, but "
              "`platform-entry --station-verdict` will not carry one: an entry "
              "does not carry a station's no. Run the missing station row, or "
              "have a named human add a waived row by hand.")
    return 0


def cmd_sign(args):
    """cosign key-mode over the verdict file — the same invocation, flags and
    environment contract as every other signature in this repo (COSIGN_BIN
    picks the binary, COSIGN_PASSWORD is read by cosign itself and defaults to
    empty). Mirrors `vexa_channel.py attest`: pinned toolchain check first,
    then the offline flags, then sign-blob into a legacy bundle beside the
    file. The bundle's name is what the verifier looks for."""
    path = pathlib.Path(args.verdict)
    if path.is_dir():
        path = path / VERDICT_NAME
    if not path.is_file():
        raise CheckFailure("SV2", f"no verdict to sign at {path}")
    doc = json.loads(path.read_text())
    schema_validate(doc)

    _major, full = require_pinned_cosign()                                 # T1
    flags = cosign_offline_flags()
    bundle = path.with_name(path.name + ".sigstore.json")
    print(f"signing station verdict with cosign {full}; offline flags: {' '.join(flags)}")
    run([cosign_bin(), "sign-blob", "--yes", "--key", args.key, *flags,
         "--bundle", str(bundle), str(path)], env=cosign_env())
    print(f"signed {path} -> {bundle}")
    print(f"  station {doc['station']} · verdict {doc['verdict']}")
    print("  carry it with: python3 publisher/vexa_channel.py platform-entry "
          f"--station-verdict {path.parent}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="vexa-station-verdict", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("render", help="compute and write a station's departure verdict")
    r.add_argument("--station", required=True,
                   help="the station making the claim; matched by a downstream "
                        "contract's require_attestations[].station")
    r.add_argument("--candidate-sha", required=True,
                   help="source commit of the candidate this station exercised; "
                        "must equal the entry's release.source_sha")
    r.add_argument("--manifest-sha256", required=True,
                   help="sha256 of the consist manifest this station ran against")
    r.add_argument("--contract", required=True,
                   help="the contract THIS station adjudicated against; its bytes are hashed in")
    r.add_argument("--values-proven", required=True,
                   help="the values_proven block compiled at DEPART "
                        "(publisher/vexa_values_proven.py)")
    r.add_argument("--out", required=True, help="directory to write station-verdict.json into")

    s = sub.add_parser("sign", help="cosign key-mode over a rendered verdict, offline")
    s.add_argument("--verdict", required=True,
                   help="station-verdict.json, or the directory holding it")
    s.add_argument("--key", required=True, help="cosign private key file")

    args = p.parse_args(argv)
    try:
        return {"render": cmd_render, "sign": cmd_sign}[args.cmd](args)
    except CheckFailure as e:
        print(f"REFUSED {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
