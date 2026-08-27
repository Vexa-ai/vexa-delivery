# Probe sets

<!-- SPDX-License-Identifier: Apache-2.0 -->

A probe set is a **data file**, one per release, naming the invariants an
upgrade to that release has to clear. `vexa_state_report.py --probe-set
<name>` loads `<name>.json` from this directory (or a path you give it) and
runs each probe against your database.

They are data and not code for one reason: **you should be able to read every
statement before you run it**. Each probe's SQL appears verbatim in the
`probes.json` your report produces, beside the number it returned, so the name
of a probe never has to be taken on trust.

## The grammar, which is enforced

Every probe is checked before it goes near a connection. It must:

- begin with `SELECT count(` — aggregate counts only, no rows;
- be a single statement (no `;` inside it);
- contain none of `insert · update · delete · drop · alter · create · grant ·
  revoke · truncate · copy · vacuum · reindex · lock · merge · prepare ·
  execute · listen · notify`.

A probe that fails the check is refused with its reason, is still printed in
full, and does not stop the rest of the run. The session itself is opened
`default_transaction_read_only=on`, so the grammar is the first of two locks
rather than the only one.

## Fields

| Field | |
|---|---|
| `name` | stable identifier; it appears in the console line and in `probes.json` |
| `migration` | which migration or change introduces the hazard |
| `hazard` | what breaks if this does not hold, in plain language |
| `expect` | `{"equals": N}` · `{"at_least": N}` · `{"at_most": N}` — explicit per probe, because a duplicate-row probe expects 0 and an index-exists probe expects 1, and inferring polarity from a convention is how a green report gets printed for a missing index |
| `if_violated` | what the operator does about it |
| `sql` | the statement, printed verbatim whether or not it ran |
| `todo` | optional. Marks the probe as **unverified against the shipped schema**: it is printed but never executed, and reports `not run` rather than a number. A wrong zero reads as *your data is clean*, which is the most expensive thing this file could say |

## Adding one

Copy the newest file, change `probe_set`, and add probes. Then send it back —
the kit is Apache-2.0, and a probe for a hazard you hit in your own estate is
the most useful patch this repository can receive. Sign off with `-s` (DCO).
