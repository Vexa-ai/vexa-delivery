#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pull the CustomResourceDefinition documents out of an upstream manifest,
BYTE FOR BYTE.

Why not parse the YAML and re-emit it: because then the pack would carry
objects that are *equivalent* to upstream v3.5.1 rather than *identical* to
it, and "identical to the pinned upstream" is the property a platform team
reviewing this file wants to check — with sha256, or with a diff against the
URL printed in the pack's own header. A round-trip through a YAML library
reorders keys, rewrites block scalars and normalises quoting. The Argo
ApplicationSet CRD alone is 1.4MB of schema; nobody reviews that by reading it,
they review it by comparing it.

So this is a document splitter, not a parser: it cuts on the YAML document
marker at column 0 and decides from two top-level lines whether to keep a
document. Everything kept is emitted exactly as it arrived.

    python3 extract-crds.py <manifest> <group-suffix>   e.g. argoproj.io

Exit 0 with the documents on stdout; 1 if the file holds none.
"""

from __future__ import annotations

import re
import sys

# Top-level keys only — column 0. `kind:` nested inside a schema is indented,
# and matching it would keep half the file.
KIND = re.compile(r"^kind:\s*CustomResourceDefinition\s*$", re.M)
NAME = re.compile(r"^\s{2}name:\s*(\S+)\s*$", re.M)


def documents(text: str):
    """Split on a line that is exactly `---`, keeping each document's bytes."""
    current: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.rstrip("\n") == "---":
            if current:
                yield "".join(current)
            current = []
        else:
            current.append(line)
    if current:
        yield "".join(current)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    path, group = sys.argv[1], sys.argv[2]
    text = open(path, encoding="utf-8").read()

    kept = []
    for doc in documents(text):
        if not KIND.search(doc):
            continue
        name = NAME.search(doc)
        if name and name.group(1).endswith(group):
            kept.append(doc.strip("\n"))

    if not kept:
        print(f"extract-crds: no CustomResourceDefinition in '{group}' found in {path}",
              file=sys.stderr)
        return 1

    sys.stdout.write("\n---\n".join(kept) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
