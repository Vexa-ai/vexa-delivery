#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""fill_line - the parser for the append-only station fills log.

The grammar is one line per exercised row:

    <ts> <V-id> <VERDICT> [tested@<digest>] <evidence...>

    2026-08-31T12:35:00Z V-est-2 PASS tested@sha256:<64hex> compose PROBE FULL PASS ...

Normative regex, also carried as `line_grammar` in spec/fill-line.schema.json so
the two cannot drift into separate files:

    ^(?P<ts>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)[ \\t]+
     (?P<value_id>V-[A-Za-z0-9][A-Za-z0-9._-]*)[ \\t]+
     (?P<verdict>PASS|FAIL|PART|WAIVED)
     (?:[ \\t]+tested@(?P<digest>sha256:[0-9a-f]{64}))?[ \\t]+
     (?P<evidence>\\S.*)$

Blank lines and `#` comments are skipped. Anything else is a MALFORMED line and
`parse_log` reports it rather than dropping it: a line the parser silently
ignored is a fill that exists in the log and not in the compiled values, which
is precisely the gap the log exists to close.

Usage:  python3 spec/fill_line.py row-fills.log        # NDJSON to stdout
        python3 spec/fill_line.py --check row-fills.log # parse only, exit 1 on malformed
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
    r"[ \t]+(?P<value_id>V-[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"[ \t]+(?P<verdict>PASS|FAIL|PART|WAIVED)"
    r"(?:[ \t]+tested@(?P<digest>sha256:[0-9a-f]{64}))?"
    r"[ \t]+(?P<evidence>\S.*)$"
)

VERDICTS = ("PASS", "FAIL", "PART", "WAIVED")


class MalformedFill(ValueError):
    """A non-blank, non-comment line that is not a fill."""


def parse_line(line: str, *, lineno: int | None = None, source: str | None = None) -> dict | None:
    """Parse one line. Returns None for a blank or comment line.

    Raises MalformedFill for anything else that does not match the grammar -
    never returns None for it, because a silently dropped fill is the failure
    mode this parser exists to make impossible.
    """
    stripped = line.rstrip("\n").rstrip()
    if not stripped.strip() or stripped.lstrip().startswith("#"):
        return None
    m = LINE_RE.match(stripped)
    if not m:
        where = f"line {lineno}: " if lineno else ""
        raise MalformedFill(f"{where}{stripped[:120]!r} does not match the fill grammar")
    rec = {
        "ts": m.group("ts"),
        "value_id": m.group("value_id"),
        "verdict": m.group("verdict"),
        "evidence": m.group("evidence").strip(),
    }
    if m.group("digest"):
        rec["digest"] = m.group("digest")
    if lineno is not None:
        rec["source_line"] = lineno
    if source is not None:
        rec["source_file"] = source
    return rec


def parse_log(text: str, *, source: str | None = None) -> tuple[list[dict], list[str]]:
    """Parse a whole log. Returns (records, malformed_messages)."""
    records: list[dict] = []
    malformed: list[str] = []
    for i, line in enumerate(text.splitlines(), start=1):
        try:
            rec = parse_line(line, lineno=i, source=source)
        except MalformedFill as exc:
            malformed.append(str(exc))
            continue
        if rec is not None:
            records.append(rec)
    return records, malformed


def parse_file(path) -> tuple[list[dict], list[str]]:
    p = pathlib.Path(path)
    return parse_log(p.read_text(), source=str(path))


def compile_values_proven(records, station, *, waived_by_of=None):
    """Compile parsed fills into a values_proven document.

    One row per value id. PASS and WAIVED compile; FAIL and PART do NOT produce
    a `proven` row - a partial exercise is not a proof, and the missing row is
    what refuses departure. `waived_by_of` maps a value id to the named human
    who accepted it; a WAIVED fill with no name is refused here rather than
    compiled into an anonymous waiver.
    """
    waived_by_of = waived_by_of or {}
    by_id: dict[str, dict] = {}
    for rec in records:
        vid = rec["value_id"]
        if rec["verdict"] == "PASS":
            row = by_id.setdefault(vid, {"id": vid, "verdict": "proven", "evidence": [], "station": station})
            if row["verdict"] != "proven":
                row.update({"verdict": "proven", "evidence": row.get("evidence", []), "station": station})
                row.pop("waived_by", None)
            ev = {
                "what": rec["evidence"],
                "ref": f"{rec.get('source_file', 'row-fills.log')}#L{rec.get('source_line', 0)}",
                "tested_at": rec["ts"],
            }
            if rec.get("digest"):
                ev["subject_digest"] = rec["digest"]
            row["evidence"].append(ev)
        elif rec["verdict"] == "WAIVED":
            if vid in by_id and by_id[vid]["verdict"] == "proven":
                continue
            who = waived_by_of.get(vid)
            if not who:
                raise ValueError(
                    f"{vid}: WAIVED fill carries no named human; an anonymous waiver is "
                    "indistinguishable from an omission"
                )
            by_id[vid] = {"id": vid, "verdict": "waived", "station": station, "waived_by": who}
    return [by_id[k] for k in sorted(by_id)]


def main(argv):
    check_only = "--check" in argv
    paths = [a for a in argv if not a.startswith("-")]
    if not paths:
        print(__doc__)
        return 2
    failed = False
    for path in paths:
        records, malformed = parse_file(path)
        for msg in malformed:
            failed = True
            print(f"MALFORMED {path}: {msg}", file=sys.stderr)
        if not check_only:
            for rec in records:
                print(json.dumps(rec, sort_keys=True))
        else:
            print(f"{path}: {len(records)} fills, {len(malformed)} malformed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
