#!/usr/bin/env python3
"""check-private-tokens — refuse a public tree that names a private thing.

Some names are private by contract: a subscriber's channel, the subscriber's
own name, its abbreviation, its mail domain. They are easy to type by accident
into a spec, an example, a receipt or a fixture, and once pushed to a public
repository the mistake is permanent.

The list of what is forbidden CANNOT live here in plain text — a gate that
carries its own secrets publishes them. So the record is
`gates/private-tokens.sha256`: one lowercase sha256 per line, nothing else.
This script hashes every word and every hyphenated / dotted / underscored
identifier it finds (and each delimited part of one) and compares digests. It
can therefore refuse a token it cannot name, which is the point.

A finding prints **file:line and nothing else** — never the token, never the
line, never the surrounding text. A gate that echoes what it caught leaks it
into CI logs, which are as public as the repository. Where a *path segment*
itself matches, that segment is redacted too.

The default scan covers tracked files **and** untracked ones git would let you
add — a leak arrives in a file that is not staged yet, which is precisely when a
developer runs this.

Usage
  python3 gates/check-private-tokens.py                 whole tree (default)
  python3 gates/check-private-tokens.py --diff origin/main   changed files only
  python3 gates/check-private-tokens.py --root DIR --tokens FILE

Exit 0 clean, 1 with findings, 2 on a usage or configuration error.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOKENS = pathlib.Path(__file__).resolve().parent / "private-tokens.sha256"

# A run of identifier characters, unicode-aware: `pilot-stable`,
# `pilot.example`, `some_name`, `Ünicode`. Split afterwards on the
# delimiters, so a token buried inside a longer identifier is still caught.
WORD = re.compile(r"[^\W]+(?:[.\-_][^\W]+)*", re.UNICODE)
DELIM = re.compile(r"[.\-_]+")

SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Only walked when the tree is not a git checkout; the git path enumerates the
# files git knows about and needs none of this.
SKIP_DIRS = {".git", ".worktrees", "node_modules", ".venv", "venv", "__pycache__"}

# Read enough to decide binary-or-not without pulling a large asset into memory.
SNIFF = 8192


def load_digests(path: pathlib.Path) -> set[str]:
    if not path.is_file():
        sys.stderr.write(f"check-private-tokens: no token list at {path}\n")
        raise SystemExit(2)
    digests = set()
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not SHA256.match(line):
            sys.stderr.write(
                f"check-private-tokens: {path}:{n} is not a lowercase sha256 — "
                "this file holds digests only, never a token in plain text\n")
            raise SystemExit(2)
        digests.add(line)
    if not digests:
        sys.stderr.write(f"check-private-tokens: {path} lists no digests\n")
        raise SystemExit(2)
    return digests


def candidates(text: str):
    """Every token a line offers: each identifier, and each delimited part."""
    for match in WORD.finditer(text):
        raw = match.group(0).lower()
        yield raw
        stripped = raw.strip(".-_")
        if stripped and stripped != raw:
            yield stripped
        for part in DELIM.split(raw):
            if part:
                yield part


def hits(text: str, digests: set[str]) -> set[str]:
    return {d for token in candidates(text)
            if (d := hashlib.sha256(token.encode()).hexdigest()) in digests}


def safe_path(rel: str, digests: set[str]) -> str:
    """The path, with any segment that itself carries a token redacted."""
    return "/".join("<redacted>" if hits(seg, digests) else seg
                    for seg in rel.split("/"))


def git_files(root: pathlib.Path) -> list[str] | None:
    """Tracked files AND untracked ones git would let you add.

    Tracked alone is the tempting answer and it is wrong: a brand-new file is
    untracked until it is staged, which is exactly when a leak is introduced and
    exactly when a developer runs the gate. This gate caught nothing in its own
    first draft for that reason. Ignored files stay out — they never reach the
    public tree.
    """
    names: list[str] = []
    for extra in (["-z"], ["-z", "--others", "--exclude-standard"]):
        try:
            out = subprocess.run(["git", "-C", str(root), "ls-files", *extra],
                                 capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            return None
        names += [p for p in out.decode("utf-8", "replace").split("\0") if p]
    return sorted(set(names))


def changed_files(root: pathlib.Path, base: str) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "diff", "--name-only",
             "--diff-filter=ACMR", base],
            capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.stderr.write(f"check-private-tokens: cannot diff against {base}: {exc}\n")
        raise SystemExit(2)
    return [p for p in out.decode("utf-8", "replace").splitlines() if p]


def walked_files(root: pathlib.Path) -> list[str]:
    found = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root)
        if SKIP_DIRS.intersection(rel.parts):
            continue
        found.append(str(rel))
    return found


def scan(root: pathlib.Path, files: list[str], digests: set[str]) -> list[str]:
    findings = []
    for rel in files:
        path = root / rel
        if not path.is_file():
            continue
        display = safe_path(rel, digests)
        if display != rel:
            findings.append(f"{display}:0  private token in the file name")
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        if b"\0" in blob[:SNIFF]:
            continue
        for n, line in enumerate(blob.decode("utf-8", "replace").splitlines(), 1):
            for digest in sorted(hits(line, digests)):
                findings.append(f"{display}:{n}  private token (sha256 {digest[:8]}…)")
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(
        description="refuse a public tree that names a private thing")
    ap.add_argument("--root", default=str(ROOT), help="tree to scan")
    ap.add_argument("--tokens", default=str(TOKENS), help="sha256 list")
    ap.add_argument("--diff", metavar="BASE",
                    help="scan only files changed against BASE (faster; the "
                         "whole tree is the default and the honest answer)")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    digests = load_digests(pathlib.Path(args.tokens))

    if args.diff:
        files, scope = changed_files(root, args.diff), f"changed vs {args.diff}"
    else:
        known = git_files(root)
        files = known if known is not None else walked_files(root)
        scope = "tracked + untracked" if known is not None else "whole tree"

    findings = scan(root, files, digests)
    if findings:
        sys.stderr.write(
            f"check-private-tokens: {len(findings)} finding(s) — a private name is "
            "in the public tree.\nThe token is deliberately not printed; open the "
            "line and compare it against the private record.\n")
        for line in findings:
            sys.stderr.write(f"  {line}\n")
        return 1

    print(f"check-private-tokens: {len(files)} files ({scope}), "
          f"{len(digests)} forbidden tokens, no hits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
