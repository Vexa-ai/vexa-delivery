#!/usr/bin/env python3
"""gen-cli-reference — the CLI reference is GENERATED, never written by hand.

Docs describe what the code IS. The same principle as the entry's VERIFY.md:
the artifact that tells you what happened is produced BY the thing that
happened, so it cannot drift from it. A hand-written flag table is a claim
about the code; a table emitted from the code's own `--help` is the code.

What it does
  1. Invokes every delivery tool's own `--help` (top level, and once per
     subcommand for the tools that have subcommands), plus the kit's bash
     scripts (their `--help`, falling back to a static parse of `usage()`
     when the script gates on state before it parses argv).
  2. Renders one `docs/reference/<tool>.mdx` per tool, plus a generated
     `docs/reference/index.mdx` naming every verb in the system.
  3. GATES. Every verb must carry a hand-written "when you use this" line in
     `docs/reference/annotations.yaml`. A verb with no annotation FAILS the
     run — which is the coverage gate: adding a verb to the code breaks the
     build until a human says what it is for. `--help` is what a flag does;
     the annotation is when an operator reaches for it, and no generator can
     invent that.
  4. GATES the nav split. Customer-facing tools must appear in both
     `docs.json` and `docs.public.json`; publisher tools must appear in
     `docs.json` ONLY — a publisher verb leaking into the public nav is how
     a customer ends up reading the operator's manual.

Usage
  python3 docs/gen-cli-reference.py            regenerate the pages
  python3 docs/gen-cli-reference.py --check    fail on drift or a missing
                                               annotation; write nothing

`--check` is what `make test` and CI run. Running the generator twice
produces a zero-length diff; that is a tested property, not an aspiration.

Exit 0 clean, 1 with findings.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

import yaml

DOCS = pathlib.Path(__file__).resolve().parent
ROOT = DOCS.parent
REFERENCE = DOCS / "reference"
ANNOTATIONS = REFERENCE / "annotations.yaml"

# argparse wraps help to the terminal width, so the same code emits different
# text on a different terminal. Pin it, or "idempotent" is a lie that only
# holds on the machine that last ran the generator.
HELP_ENV = {**os.environ, "COLUMNS": "100", "TERM": "dumb", "NO_COLOR": "1"}

# The interpreter is the other half of that pin. argparse changed how it wraps
# the usage line between 3.12 and 3.13, so the same code on a different Python
# produces bytes that differ from the committed pages and --check calls it
# drift. CI runs GEN_PYTHON; generate on anything else and the diff you get is
# the interpreter, not the code.
GEN_PYTHON = (3, 12)

PUBLISHER = "publisher"
CUSTOMER = "customer"


class Tool:
    """One executable, its audience, and how to ask it what it does."""

    def __init__(self, doc_id, path, invocation, audience, kind, blurb):
        self.doc_id = doc_id            # docs/reference/<doc_id>.mdx
        self.path = path                # repo-relative path to the executable
        self.invocation = invocation    # how the docs spell the command
        self.audience = audience        # PUBLISHER | CUSTOMER
        self.kind = kind                # "argparse-sub" | "argparse-flat" | "bash"
        self.blurb = blurb              # frontmatter description


TOOLS = [
    Tool("vexa-channel", "publisher/vexa_channel.py",
         "python3 publisher/vexa_channel.py", PUBLISHER, "argparse-sub",
         "Turn a released Vexa version into a signed channel entry."),
    Tool("vexa-station", "publisher/vexa_station.py",
         "python3 publisher/vexa_station.py", PUBLISHER, "argparse-sub",
         "Ingest a customer station bundle, then gate publishes on its contract."),
    Tool("vexa-stations", "publisher/vexa_stations.py",
         "python3 publisher/vexa_stations.py", PUBLISHER, "argparse-sub",
         "Read and write the channel/station ledger that outlives the bucket."),
    Tool("vexa-subscriber", "publisher/vexa_subscriber.py",
         "python3 publisher/vexa_subscriber.py", PUBLISHER, "argparse-sub",
         "Manage credentials on the channel registry."),
    Tool("kit-release", "kit/release.sh",
         "kit/release.sh", PUBLISHER, "bash",
         "Package and publish a signed version of the customer kit."),
    Tool("vexa-preflight", "kit/preflight/vexa_preflight.py",
         "python3 kit/preflight/vexa_preflight.py", CUSTOMER, "argparse-flat",
         "Will this cluster run what the channel delivers?"),
    Tool("vexa-smoke", "kit/smoke/vexa_smoke.py",
         "python3 kit/smoke/vexa_smoke.py", CUSTOMER, "argparse-flat",
         "Did the installed release actually work here?"),
    Tool("vexa-validate", "kit/validate/vexa_validate.py",
         "python3 kit/validate/vexa_validate.py", CUSTOMER, "argparse-flat",
         "Preflight, install, smoke and bundle in one command."),
    Tool("kit-bootstrap", "kit/bootstrap.sh",
         "kit/bootstrap.sh", CUSTOMER, "bash",
         "Fetch and signature-verify the kit tree from the channel."),
    Tool("kit-install", "kit/install.sh",
         "kit/install.sh", CUSTOMER, "bash",
         "Install the station: Argo subscription plus admission policy."),
    Tool("kit-self-update", "kit/self-update.sh",
         "kit/self-update.sh", CUSTOMER, "bash",
         "Move a bootstrapped kit tree to a newer signed kit version."),
]

SUBCOMMANDS = re.compile(r"\{([a-z0-9][a-z0-9,\s-]*)\}")
USAGE_BLOCK = re.compile(r"^usage\(\)\s*\{\s*\n\s*cat\s*<<'?EOF'?\s*\n(.*?)\n\s*EOF",
                         re.S | re.M)


def run(argv: list[str]) -> str:
    """Ask a tool what it does. No network, no cluster: --help is a pure read."""
    proc = subprocess.run(argv, cwd=ROOT, env=HELP_ENV,
                          capture_output=True, text=True)
    return (proc.stdout or proc.stderr).rstrip()


def bash_usage(tool: Tool) -> tuple[str, str]:
    """`--help` if the script answers it; otherwise its literal usage() body.

    kit/self-update.sh refuses before it parses argv when the tree was not
    bootstrapped from a channel, so `--help` there reports that instead of
    usage. That is the script's real behaviour and not something the docs
    should paper over — we fall back, and we say which source we used.
    """
    live = run(["bash", str(ROOT / tool.path), "--help"])
    if live.startswith("usage:"):
        return live, f"`{tool.invocation} --help`"
    body = USAGE_BLOCK.search((ROOT / tool.path).read_text())
    if not body:
        fail(f"{tool.path}: no --help output and no parseable usage() block")
    return body.group(1).rstrip(), f"the `usage()` block in `{tool.path}`"


FINDINGS: list[str] = []


def fail(message: str) -> None:
    FINDINGS.append(message)


def verbs_of(tool: Tool) -> list[str]:
    if tool.kind != "argparse-sub":
        return []
    top = run([sys.executable, str(ROOT / tool.path), "--help"])
    match = SUBCOMMANDS.search(top)
    if not match:
        fail(f"{tool.path}: declared as a subcommand tool but --help lists none")
        return []
    return [v.strip() for v in match.group(1).split(",") if v.strip()]


def fence(text: str) -> str:
    return "```text\n" + text + "\n```"


def render(tool: Tool, annotations: dict) -> str:
    """One page. Every verb: the annotation first, then the tool's own words."""
    lines = [
        "---",
        f'title: "{tool.invocation.split()[-1].split("/")[-1]}"',
        f'description: "{tool.blurb}"',
        "---",
        "",
        "{/* GENERATED by docs/gen-cli-reference.py — do not edit. */}",
        "{/* Prose belongs in docs/reference/annotations.yaml; flags belong to the code. */}",
        "",
        f"Source: `{tool.path}` · audience: {tool.audience}",
        "",
    ]

    if tool.kind == "bash":
        text, source = bash_usage(tool)
        note = annotations.get(tool.doc_id)
        if not note:
            fail(f"annotations.yaml: no 'when you use this' line for `{tool.doc_id}`")
        lines += ["## When you use this", "", note or "", "",
                  "## Usage", "", f"Emitted from {source}.", "", fence(text), ""]
        return "\n".join(lines)

    if tool.kind == "argparse-flat":
        note = annotations.get(tool.doc_id)
        if not note:
            fail(f"annotations.yaml: no 'when you use this' line for `{tool.doc_id}`")
        text = run([sys.executable, str(ROOT / tool.path), "--help"])
        lines += ["## When you use this", "", note or "", "",
                  "## Usage", "",
                  f"Emitted from `{tool.invocation} --help`.", "", fence(text), ""]
        return "\n".join(lines)

    verbs = verbs_of(tool)
    top = run([sys.executable, str(ROOT / tool.path), "--help"])
    lines += ["## Overview", "",
              f"Emitted from `{tool.invocation} --help`.", "", fence(top), ""]
    for verb in verbs:
        key = f"{tool.doc_id} {verb}"
        note = annotations.get(key)
        if not note:
            fail(f"annotations.yaml: no 'when you use this' line for `{key}`")
        text = run([sys.executable, str(ROOT / tool.path), verb, "--help"])
        lines += [f"## `{verb}`", "", note or "", "",
                  fence(text), ""]
    return "\n".join(lines)


def render_index(annotations: dict) -> str:
    """Every verb in the system, on one page, with what it is for."""
    rows = []
    for tool in TOOLS:
        verbs = verbs_of(tool) or [None]
        for verb in verbs:
            key = f"{tool.doc_id} {verb}" if verb else tool.doc_id
            command = f"{tool.invocation} {verb}" if verb else tool.invocation
            note = (annotations.get(key) or "").replace("|", "\\|")
            rows.append(f"| [`{command}`](/reference/{tool.doc_id}) "
                        f"| {tool.audience} | {note} |")
    return "\n".join([
        "---",
        'title: "CLI reference"',
        'description: "Every verb the delivery chain exposes, generated from the code."',
        "---",
        "",
        "{/* GENERATED by docs/gen-cli-reference.py — do not edit. */}",
        "",
        "Every page under `/reference` is emitted from the tool's own `--help`.",
        "The one-line \"when you use this\" beside each verb is hand-written in",
        "`docs/reference/annotations.yaml`, and a verb without one fails the build.",
        "",
        "| Command | Audience | When you use this |",
        "|---|---|---|",
        *rows,
        "",
    ])


def check_nav() -> None:
    """The nav split is a gate, not a convention.

    Customer tools belong in both navs. Publisher tools belong in the internal
    nav only: the public site is the customer's manual, and a publisher verb
    in it is an invitation to run something only we can run.
    """
    def pages(config: pathlib.Path) -> set[str]:
        found: set[str] = set()

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "pages" and isinstance(value, list):
                        found.update(p for p in value if isinstance(p, str))
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(json.loads(config.read_text()).get("navigation", {}))
        return found

    internal = pages(DOCS / "docs.json")
    public = pages(DOCS / "docs.public.json")
    for tool in TOOLS:
        page = f"reference/{tool.doc_id}"
        if page not in internal:
            fail(f"docs.json: reference page '{page}' is in no nav group")
        if tool.audience == CUSTOMER and page not in public:
            fail(f"docs.public.json: customer page '{page}' is missing from the public nav")
        if tool.audience == PUBLISHER and page in public:
            fail(f"docs.public.json: publisher page '{page}' must not be in the public nav")
    # The index names every verb including the publisher's, so it is internal
    # for the same reason the publisher pages are.
    if "reference/index" not in internal:
        fail("docs.json: 'reference/index' is in no nav group")
    if "reference/index" in public:
        fail("docs.public.json: 'reference/index' names publisher verbs "
             "and must not be in the public nav")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="fail on drift or a missing annotation; write nothing")
    args = ap.parse_args()

    annotations = yaml.safe_load(ANNOTATIONS.read_text()) or {}
    if not isinstance(annotations, dict):
        print(f"{ANNOTATIONS}: expected a flat mapping of verb -> sentence")
        return 1

    pages = {f"{tool.doc_id}.mdx": render(tool, annotations) for tool in TOOLS}
    pages["index.mdx"] = render_index(annotations)

    known = {f"{t.doc_id} {v}" for t in TOOLS for v in verbs_of(t)}
    known |= {t.doc_id for t in TOOLS if t.kind != "argparse-sub"}
    for orphan in sorted(set(annotations) - known):
        fail(f"annotations.yaml: '{orphan}' annotates no verb that exists "
             f"(the code dropped it, or the key is misspelled)")

    check_nav()

    if args.check:
        for name, body in sorted(pages.items()):
            path = REFERENCE / name
            if not path.is_file():
                fail(f"docs/reference/{name} has not been generated "
                     f"(run: make docs-reference)")
            elif path.read_text() != body:
                fail(f"docs/reference/{name} is stale against the code "
                     f"(run: make docs-reference)")
                if sys.version_info[:2] != GEN_PYTHON:
                    fail(f"  ...and this is python {sys.version_info.major}."
                         f"{sys.version_info.minor}, not the "
                         f"{GEN_PYTHON[0]}.{GEN_PYTHON[1]} the pages were "
                         f"generated on — regenerate on {GEN_PYTHON[0]}."
                         f"{GEN_PYTHON[1]} before believing this is drift")
    else:
        REFERENCE.mkdir(exist_ok=True)
        for name, body in sorted(pages.items()):
            (REFERENCE / name).write_text(body)

    if FINDINGS:
        print("gen-cli-reference: FAILED")
        for finding in FINDINGS:
            print(f"  - {finding}")
        return 1
    verb_count = len(known)
    print(f"gen-cli-reference: {len(pages)} pages, {verb_count} verbs, "
          f"every verb annotated"
          + (" (checked, no drift)" if args.check else " (written)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
