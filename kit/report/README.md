# `kit/report/` — the upgrade state reporter

<!-- SPDX-License-Identifier: Apache-2.0 -->

`vexa_state_report.py` is what an operator runs on a deployment that already
has history, before anyone plans an upgrade to it. It reads the cluster and the
database, writes `state-report.tar.gz`, prints the path and stops. The operator
reads the files and sends them by hand; we reproduce that state on a throwaway
environment, rehearse their upgrade against it until it is green, and publish
the rehearsed upgrade as the first entry of their channel.

Operator-facing page: [`docs/upgrade.mdx`](../../docs/upgrade.mdx),
including the minimal read-only RBAC.

```
vexa_state_report.py   the tool. stdlib only, Python 3.9+
probes/                per-release invariant probes — data, not code
probes/README.md       the probe grammar and how to add one
tests/                 fixture-driven, offline
tests/bin/             fake kubectl · psql · pg_dump
tests/fixtures/<case>/ the estate each case describes
```

`make test-report` runs the tests. There is no cluster and no database
anywhere in them: the fixture directory *is* the estate, and the fake `psql`
refuses to answer unless the session was opened read-only, so the read-only
claim in the docs is tested rather than asserted.

## Extending it

This will meet estates nobody here has seen, and the first thing it does in
some of them is miss something. Two extension points, both deliberately small:

- **a collector** — one function taking `ctx`, returning a dict with a
  `"source"` key, plus one line in `COLLECTORS`. The full contract is in the
  *Adding a collector* block at the top of `vexa_state_report.py`. A collector
  that raises costs its own section and nothing else; the other five still run
  and the report names the one that failed.
- **a probe set** — a JSON file in `probes/`. Aggregate counts only, enforced
  before anything reaches a connection.

Patches welcome, DCO sign-off (`git commit -s`). A probe for a hazard you hit
in your own estate is the most useful thing this directory can receive.
