#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Every test cleans up after itself.
#
# Until 2026-11-04 a run of `make test` left some 175 dirs and files in /tmp:
# git ledgers, spools, age keys, rendered charts, token lists. The suite runs
# on fixtures, but the same habit in the code under test is how a chart copy
# holding real keys outlived a publish run. This runs every test target with
# TMPDIR set to an empty dir of its own and fails, naming each entry, if
# anything is left in it. Under CI it also fails on a new entry in /tmp itself
# (a test that ignores TMPDIR); on a shared host that part only reports, since
# other processes write there too.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TARGETS="${TEMP_HYGIENE_TARGETS:-test-publisher test-preflight test-smoke test-validate test-report test-kit test-platform test-verify test-edge test-gates}"
BASE="${TMPDIR:-/tmp}"
H="$(mktemp -d "$BASE/vexa-temp-hygiene.XXXXXX")"
LOG="$(mktemp "$BASE/vexa-temp-hygiene-log.XXXXXX")"
MARK="$(mktemp "$BASE/vexa-temp-hygiene-mark.XXXXXX")"
trap 'rm -rf "$H" "$LOG" "$MARK"' EXIT

# shellcheck disable=SC2086  # TARGETS is a word list on purpose
if ! TMPDIR="$H" make -s $TARGETS > "$LOG" 2>&1; then
  grep -E '^(FAIL|ERROR)(:| )|^FAIL|Error [0-9]' "$LOG" >&2 || true
  tail -20 "$LOG" >&2
  echo "check-temp-hygiene: the test targets failed; fix that first" >&2
  exit 1
fi

status=0
left="$(cd "$H" && find . -mindepth 1 -maxdepth 1 | sed 's#^\./##' | sort)"
if [ -n "$left" ]; then
  echo "check-temp-hygiene: the tests left $(printf '%s\n' "$left" | wc -l | tr -d ' ') entries in TMPDIR:" >&2
  printf '  %s\n' "$left" >&2
  status=1
fi

new="$(find /tmp -mindepth 1 -maxdepth 1 -user "$(id -u)" -newer "$MARK" ! -name 'vexa-temp-hygiene*' 2>/dev/null | sort)"
if [ -n "$new" ]; then
  echo "check-temp-hygiene: new entries in /tmp during the run (a test that ignores TMPDIR, or another process):" >&2
  printf '  %s\n' "$new" >&2
  [ "${CI:-}" = true ] && status=1
fi

[ "$status" = 0 ] && echo "check-temp-hygiene: $TARGETS left nothing behind"
exit "$status"
