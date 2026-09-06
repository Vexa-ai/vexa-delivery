#!/usr/bin/env python3
"""check-secret-argv — refuse a shell script that puts a credential in argv.

`/install` promises, of the channel password: **"read from the environment,
never from argv."** For three call sites in `kit/install.sh` that was false —
each ran

    kubectl create secret docker-registry … --docker-password="$VEXA_CHANNEL_PASS"

and two of them ran under `--dry-run` as well, inside the very command that was
hardened so a render would carry no credential. Argv is world-readable in
`/proc` and in `ps` output for the life of the process; on a shared jump host
that is the whole exposure, and it is why `kit/claim.sh` writes its Secret from
stdin and says so in a comment. A promise a reviewer can grep for should be a
promise a gate enforces, so this is that gate.

WHAT IT REFUSES — a credential-shaped VALUE on a command line:

  --docker-password=…      no stdin form exists; the flag is the defect
  --password=… / --token=… (never `--password-stdin`, which is the fix)
  --from-literal=<k>=<v>   where the KEY looks like a credential
                           (pass/password/secret/token/credential/apikey), or
                           the VALUE reads a variable whose name does

WHAT IT DOES NOT REFUSE, and why. `--from-literal=verdict_sha256="$VERDICT_SHA"`
is a digest; `--from-literal=status="$STATUS"` is a word. Both are argv and
neither is a secret, so a rule of "no `--from-literal` at all" would be a rule
this repository cannot keep — and a gate that cannot be kept gets suppressed.
The key/value shapes above are the line the promise is actually about.

SCOPE: `*.sh` in the tracked tree, excluding `*/tests/*`. A test's stub kubectl
*parses* `--docker-password=` out of argv to check what it was handed; it does
not construct it. This gate is about what the kit hands to a child process.

Usage
  python3 gates/check-secret-argv.py          the tracked tree (default)
  python3 gates/check-secret-argv.py --root DIR

A finding prints file:line, the flag, and why — never the surrounding line,
because the line is where the credential would be. Exit 0 clean, 1 with
findings, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Anything whose NAME says credential. Deliberately broad on the name and
# narrow on where it is looked for.
SECRETISH = re.compile(r"(?i)(pass(wd|word)?|secret|token|credential|apikey|api_key)")

# `--password-stdin` and `--password-file` are the fixes, not the defect.
STDIN_FORM = re.compile(r"(?i)-(stdin|file|env-file)\b")

# --flag=value or --flag value, capturing the flag and whatever follows it.
FLAG_EQ = re.compile(r"(--[A-Za-z0-9][A-Za-z0-9-]*)=(\S+)")
FLAG_SP = re.compile(r"(--[A-Za-z0-9][A-Za-z0-9-]*)\s+(\"?\$\{?[A-Za-z_][A-Za-z0-9_]*)")

# A shell variable reference, `$FOO` or `${FOO:-}`, so a value can be judged by
# the name of what it reads.
VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")

# The flags whose value IS a credential by definition.
CREDENTIAL_FLAGS = {"--docker-password", "--password", "--token", "--api-key",
                    "--apikey", "--registry-password", "--admin-token"}


def findings_in_line(line: str) -> list[str]:
    """Why this line puts a credential on a command line, or []."""
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return []                      # a comment about the defect is not it
    out = []
    for flag, value in FLAG_EQ.findall(line) + FLAG_SP.findall(line):
        if STDIN_FORM.search(flag):
            continue
        if flag in CREDENTIAL_FLAGS:
            out.append(f"{flag}= puts a credential in argv (world-readable in "
                       f"/proc and in `ps`)")
            continue
        if flag == "--from-literal":
            key, _, val = value.partition("=")
            if SECRETISH.search(key):
                out.append("--from-literal with a credential-shaped KEY puts the "
                           "value in argv")
            elif any(SECRETISH.search(v) for v in VAR.findall(val)):
                out.append("--from-literal reading a credential-shaped VARIABLE "
                           "puts its value in argv")
    return out


def shell_files(root: pathlib.Path) -> list[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "*.sh"],
                             capture_output=True, check=True).stdout
        names = [p for p in out.decode("utf-8", "replace").split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        names = [str(p.relative_to(root)) for p in root.rglob("*.sh")
                 if ".git" not in p.parts]
    return sorted(n for n in names if "/tests/" not in f"/{n}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="refuse a shell script that puts a credential in argv")
    ap.add_argument("--root", default=str(ROOT), help="tree to scan")
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()

    files = shell_files(root)
    if not files:
        sys.stderr.write("check-secret-argv: no *.sh found — the pathspec matched "
                         "nothing, which would pass silently\n")
        return 2

    findings = []
    for rel in files:
        path = root / rel
        if not path.is_file():
            continue
        for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            for why in findings_in_line(line):
                findings.append(f"{rel}:{n}  {why}")

    if findings:
        sys.stderr.write(
            f"check-secret-argv: {len(findings)} finding(s) — a credential reaches "
            "a child process on its command line.\n"
            "Render the object and apply it from stdin instead; "
            "kit/install.sh § render_registry_secret and kit/claim.sh § "
            "vexa_claim_write_secret are the two worked examples.\n")
        for line in findings:
            sys.stderr.write(f"  {line}\n")
        return 1

    print(f"check-secret-argv: {len(files)} shell scripts, no credential on any "
          "command line")
    return 0


if __name__ == "__main__":
    sys.exit(main())
