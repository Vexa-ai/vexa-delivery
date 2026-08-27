# `kit/report/` — the environment state reporter

<!-- SPDX-License-Identifier: Apache-2.0 -->

`vexa_state_report.py` is a **read-only `kubectl get` sweep of one namespace,
written to one file**. No database connection, no `pods/exec`, no credentials
of any kind, no SQL.

An operator runs it on a deployment that already exists and gets
`state-report.yaml`: roughly 200–300 lines of commented YAML describing the
shape of their environment. They read it, then they send it by hand — or they
do not. Nothing in the tool transmits.

**Why we ask for it.** We want their configuration, their setup and above all
their environment, so what gets built for them works with what they already
have and asks for nothing they do not.

Operator-facing page: [`docs/upgrade.mdx`](../../docs/upgrade.mdx).

## What it collects, and the list is complete

| | |
|---|---|
| **1 platform** | Kubernetes or OpenShift, version, the cloud underneath, node shapes **with the taints on them and what is allocatable**, storage classes and volumes |
| **2 wiring** | which components exist and how they are connected — the database and transcription especially: in-cluster or external, how each is addressed, versions, GPU or CPU — and how the estate is **exposed: Ingress and, on OpenShift, `Route`** |
| **3 resources** | requests and limits per container, and the namespace's ResourceQuotas and LimitRanges |
| **4 versions** | the image tags and digests **actually running**, and **where each workload is pinned** — node selector, affinity kinds, tolerations, priority and runtime class, topology spread |
| **5 values** | the settings this deployment has customised |
| **6 registry** | Docker Hub or a mirror — as observed, never inferred; pull credentials on the pod specs **and on the ServiceAccounts** |
| **7 admission** | the namespace's Pod Security labels and, on OpenShift, its SCC UID and group ranges — what it will let run at all |
| **8 network** | the NetworkPolicies, by shape: whether anything default-denies egress. Rule bodies are not read |
| **9 install** | the Helm release name already here, and whether Argo CD — **including the OpenShift GitOps operator's own instance** — or Kyverno already run |

Rows 7–9 were added because the sibling preflight
([`kit/preflight/`](../preflight/)) checks all of them — P1 taints, P4 pod
security, P5 NetworkPolicy — while the report collected none of them, so the
document could not be built against. Each answers a question that changes what
we ship: a taint needs a matching toleration in the values file we hand back
(which ships `tolerations: []` for exactly that); `restricted` admission or an
SCC range decides whether workloads run non-root with a seccomp profile and no
capabilities, and whether they may pin a UID at all; a default-deny egress
policy decides whether the cluster can reach a registry; and the release name
decides whether an upgrade lands on the running estate or installs a **second
copy of it beside the first, against the same database**.

## The sufficiency sweep — how the list stopped being a guess

Finding a missing lens one at a time is a losing game, so the list above is now
backed by a **coverage argument** rather than by inspection. Every input that
decides what goes in a bundle was enumerated from its source in this repo —
[`kit/profiles/vexa/customer-values.example.yaml`](../profiles/vexa/customer-values.example.yaml),
every [`kit/providers/*/profile.env`](../providers/), all nine checks in
[`kit/preflight/vexa_preflight.py`](../preflight/vexa_preflight.py), every flag
of [`kit/install.sh`](../install.sh), the station chart's
[`values.yaml`](../../station/chart/values.yaml) and its templates' `.Values`
references, and the contract fields in
[`kit/verify/policy.example.yaml`](../verify/policy.example.yaml) — and each
was marked *supplied by the report*, *the customer's own secret*, or *a gap*.

The gaps it found, and what closed them:

| Gap | Where it came from | Now |
|---|---|---|
| Exposure on OpenShift | an estate with `Route` and no `Ingress` reads as **nothing exposed** | `routes.route.openshift.io`, by shape |
| `global.tolerations`, `floor.tolerations`, `receiptSender.tolerations`, `nodeSelector` | the values file ships them empty for the customer to fill | `placement`, per workload |
| Node **allocatable** | P6 measures the bot's 2560Mi limit and its 2Gi `/dev/shm` against allocatable, not capacity | beside `capacity`, on the same line |
| A pull credential on a **ServiceAccount** | it serves every pod and appears in no pod spec | read and merged into `image_pull_credentials` |
| Argo CD in `openshift-gitops` | on OpenShift the supported Argo is the GitOps **operator's** instance; checking only `argocd` reports Argo absent where a second one does the most damage | a third machinery namespace |
| `scope: cluster` vs `scope: namespace` | the station chart ships admission cluster-wide or namespaced | `cluster_scope`, derived from which cluster-scoped reads succeeded — no extra call |

Three inputs turned out to be **unreadable by any read-only call**, and those
are asked as **named questions** in `absent` rather than assumed: whether a
pull by digest actually succeeds (proving it needs a probe pod, which is a
write — P7), whether a restricted egress policy lets DNS and the registry out
(the rule bodies carry internal addresses and are refused), and whether the
registry needs a CA bundle or plain HTTP (TLS trust lives in the container
runtime, in no API object). A stated gap beats a silent one; an unasked
question is indistinguishable from an answered one.

Everything else was either already supplied or is the customer's own secret —
`secrets.*`, the channel public key, the registry credential, the contract
terms in `policy.example.yaml` — which the report does not read and never
should.

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
tests/fixtures/<case>/<ns>/
                       a read in ANOTHER namespace (`-n argocd`) is answered
                       only from here, never from the flat file — a fixture
                       without the directory is an estate where the operator
                       has no RBAC next door
```

The estates: `healthy` (an ordinary LKE namespace), `mirrored` (OpenShift
behind a corporate mirror — Routes, SCC ranges, default-deny egress, the
GitOps operator, two release names), `with-limitrange` (the quota finding's
negative case), `empty` (every read refused), and `openshift-locked-down` (an
OpenShift cluster that grants almost nothing, which is the one place a missing
`Route` grant can be told apart from an absent kind).

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

Three rules a patch has to respect:

- **Does it describe the shape we must fit into?** Node shapes, quotas, ingress
  class, resource limits, GPU-vs-CPU, image digests, replica counts,
  allowlisted non-secret settings — yes. Anything describing their *data* — no,
  and no amount of usefulness changes that.
- **Stay inside the budget.** The whole document has to be read end to end by
  the person deciding whether to send it, so ~300 lines on a real estate is the
  ceiling, not a guideline. Prefer one line to five: shape over rule bodies,
  a grouped count over a list of names, one sentence in the section comment
  over a field repeating it. When a new lens pushes past it, **summarise rather
  than split the file** — allocatable moved onto the capacity line, three
  unreadable machinery namespaces collapsed into one gap row, and three
  separate "addresses are not collected" notes became one. A second file would
  turn a scroll back into a cross-referencing exercise.
- **Do not name a field after a secret.** The redaction rule is deliberately
  blunt and empties anything under a key matching
  `password|token|secret|key|apikey`. Two fields shipped named that way and lost
  the very names that made them useful; the leak scan caught both. Call it
  `provided_externally`, not `from_secret_or_configmap`.

Patches welcome, DCO sign-off (`git commit -s`).
