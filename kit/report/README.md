# `kit/report/` — the environment state reporter

<!-- SPDX-License-Identifier: Apache-2.0 -->

`vexa_state_report.py` is a **read-only `kubectl get` sweep of one namespace,
written to one file**. No database connection, no `pods/exec`, no credentials
of any kind, no SQL.

An operator runs it on a deployment that already exists and gets
`state-report.yaml`: roughly 150–250 lines of commented YAML describing the
shape of their environment. They read it, then they send it by hand — or they
do not. Nothing in the tool transmits.

**Why we ask for it.** We want their configuration, their setup and above all
their environment, so what gets built for them works with what they already
have and asks for nothing they do not.

Operator-facing page: [`docs/upgrade.mdx`](../../docs/upgrade.mdx).

## What it collects, and the list is complete

| | |
|---|---|
| **1 platform** | Kubernetes or OpenShift, version, the cloud underneath, node shapes, storage classes and volumes |
| **2 wiring** | which components exist and how they are connected — the database and transcription especially: in-cluster or external, how each is addressed, versions, GPU or CPU |
| **3 resources** | requests and limits per container, and the namespace's ResourceQuotas and LimitRanges |
| **4 versions** | the image tags and digests **actually running** |
| **5 values** | the settings this deployment has customised |
| **6 registry** | Docker Hub or a mirror — as observed, never inferred |

**Never collected:** schema, rows, row counts, SQL of any kind, transcripts,
meeting content, credentials. Also not collected, because they are inventory
rather than shape: node names, service addresses, ingress hostnames.

The database appears only as a *component* — engine, version, in-cluster or
external, how it is addressed, its resources — and every one of those facts is
read from the cluster, never by connecting to it.

## Two things worth knowing before you read the code

**`--dry-run` is the flag the trust story rests on.** It connects to nothing,
writes nothing, exits 0, and prints every `kubectl` command a real run would
issue. It is built from the same argv builder the run uses, and the test suite
records what a real run actually executed and fails if the two disagree — a
drifting dry run is a lie about safety, so it is a build failure.

**One file, and that is the design.** The person who approves this before it
leaves their perimeter has to read *all* of it. A pile of JSON files is a
cross-referencing exercise; one commented YAML document is a scroll. YAML
because the reader is a Kubernetes engineer, and because comments let each
block explain itself in the same file rather than in a second one that drifts.

## Layout

```
vexa_state_report.py   the tool. stdlib only, Python 3.9+ — including the
                       YAML writer, so there is nothing to install
tests/                 fixture-driven, offline
tests/bin/kubectl      a fake kubectl that answers from a fixture directory
                       and logs every invocation
tests/fixtures/<case>/ the estate each case describes
```

`make test-report` runs them. There is no cluster and no network anywhere in
them: the fixture directory *is* the estate.

## Extending it

Two extension points, both deliberately small:

- **a collector** — one function taking `ctx`, returning a dict, plus one line
  in `SECTIONS` carrying the comment a reader will see above the block. The
  full contract is in the *Adding a collector* block at the top of the source.
  A collector that raises costs its own section and nothing else.
- **the allowlist** — `ENV_ALLOW_RE` decides which settings are recorded at
  all. Everything else is dropped before it is written, so redaction is the
  second net rather than the only one.

Two rules a patch has to respect:

- **Does it describe the shape we must fit into?** Node shapes, quotas, ingress
  class, resource limits, GPU-vs-CPU, image digests, replica counts,
  allowlisted non-secret settings — yes. Anything describing their *data* — no,
  and no amount of usefulness changes that.
- **Do not name a field after a secret.** The redaction rule is deliberately
  blunt and empties anything under a key matching
  `password|token|secret|key|apikey`. Two fields shipped named that way and lost
  the very names that made them useful; the leak scan caught both. Call it
  `provided_externally`, not `from_secret_or_configmap`.

Patches welcome, DCO sign-off (`git commit -s`).
