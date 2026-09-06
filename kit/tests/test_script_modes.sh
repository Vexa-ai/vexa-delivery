#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Every kit script is executable IN THE TREE — not in somebody's working copy.
#
# `kit/claim.sh` shipped mode 100644. The kit documents `./kit/claim.sh --code
# …` and that is the FIRST command on the credential path, so out of a fresh
# clone the first thing a subscriber typed was `Permission denied` — with a
# fifteen-minute code already read aloud and running. Found by the 2026-09-07
# claim-code rehearsal.
#
# THE CHECK IS ON THE INDEX, DELIBERATELY. A local `chmod +x` fixes the machine
# it is run on, does not appear in `git status -s` unless it is staged, and
# changes nothing about what a clone gets. What a clone gets is the mode
# recorded in the tree, so that is the only mode worth asserting; the working
# copy is checked afterwards only to catch a checkout that has drifted from it.
#
# Kit-scoped on purpose: the kit is the thing a subscriber clones and runs BY
# PATH. Our own scripts (`publisher/publish.sh`, the chart's `files/floor.sh`)
# are invoked through `sh`/`make`/a container entrypoint, where the mode does
# not decide whether the command works.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

fail() { echo "FAIL: $1" >&2; exit 1; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || fail "not a git checkout — the recorded mode is what this test reads, and there is none here"

# `git ls-files --stage` prints "<mode> <object> <stage>\tpath", so the tab is
# the field separator and the mode is the first word of field one.
listing=$(git ls-files --stage -- kit | awk -F'\t' '$2 ~ /\.sh$/ {print}')
[ -n "$listing" ] || fail "no kit/**/*.sh found — the pathspec matched nothing, which would pass silently"

bad=$(printf '%s\n' "$listing" | awk -F'\t' '{split($1, m, " "); if (m[1] != "100755") print $2 " (" m[1] ")"}')
if [ -n "$bad" ]; then
  echo "FAIL: kit scripts are not executable in the tree:" >&2
  printf '  %s\n' "$bad" >&2
  echo "  fix: chmod +x <path> && git update-index --chmod=+x <path>" >&2
  exit 1
fi

# And the checkout agrees with the tree. A `core.fileMode=false` clone, or a
# copy through a tarball or a Windows share, can hold 100755 in the index and a
# non-executable file on disk — which is the same Permission denied.
while IFS= read -r path; do
  [ -x "$path" ] || fail "$path is 100755 in the tree but not executable in this checkout"
done < <(printf '%s\n' "$listing" | awk -F'\t' '{print $2}')

count=$(printf '%s\n' "$listing" | wc -l | tr -d ' ')
echo "PASS: kit script modes ($count scripts, all 100755 in the tree and executable on disk)"
