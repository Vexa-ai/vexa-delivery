# OpenShift — the delta story

What is different about OpenShift, why, and exactly how far the evidence goes.

## Rung: rehearsed against recorded constraints, not live-installed

`PROFILE_TESTED=no`, and that is the accurate value.

| Claim | Status |
|---|---|
| The SCC/PSA/LimitRange logic this kit applies has been checked against the constraints an OpenShift project actually imposes | **yes** — offline, in `kit/preflight/tests/test_openshift_profile.py`, using values recorded from a genuine OpenShift SCC admission rehearsal (MicroShift 4.18, 2026-08-21) and from the customer's own measurements on their cluster |
| The chart's objects were admitted by genuine OpenShift SCC admission | **yes** — 25 chart objects admitted stock, zero SCC rejects, random-UID contexts injected on all 21 pods |
| `kit/install.sh --provider openshift` has been run against an OpenShift cluster | **no** — never |
| Vexa has been observed converging and running on OpenShift | **no** — and there is a known blocker below |

"Tested" in this kit means the profile was exercised end-to-end by `install.sh`
against a live cluster (today: `lke` only). This profile has not been, so it
says `no`. What it has is a rehearsal against recorded constraints — a
different and weaker thing, stated as such.

Evidence: [`docs/engineering/openshift-parity.mdx`](../../../docs/engineering/openshift-parity.mdx),
[`docs/environments/openshift.mdx`](../../../docs/environments/openshift.mdx),
[`docs/receipts/2026-08-21-m2-throwaway-test.md`](../../../docs/receipts/2026-08-21-m2-throwaway-test.md).

## SCC `restricted-v2` — what admission does to you

`restricted-v2` is the default SCC and the one the target environment enforces.
It behaves in two stages, and the second stage is where installs die:

1. **It mutates.** It sets `seccompProfile: RuntimeDefault`, drops all
   capabilities, and assigns a UID from the namespace's
   `openshift.io/sa.scc.uid-range` annotation. Measured on a real admitted bot
   pod in the customer's project: `runAsUser 1000920000`, `runAsNonRoot true`,
   `capabilities drop ALL`, `seccompProfile RuntimeDefault`, `fsGroup` set.
2. **Then it rejects.** An explicit `runAsUser`, `runAsGroup` or `fsGroup`
   outside the namespace range is refused (`MustRunAsRange`).

**The operational rule follows directly: deliver no `securityContext` at all.**
A spec that hardens itself is more likely to be rejected than one that arrives
bare — the hardened workloads are exactly the rejected ones. This inverts the
habit every other platform teaches, which is why the preflight's P4 names it.

Two consequences worth naming before you hit them:

- **Upstream Argo CD does not install clean.** Its own images hard-code UIDs
  (dex 1001, redis 999) and restricted-v2 rejects them. Use the **OpenShift
  GitOps operator** — it is Argo CD, it is SCC-clean, and it is already the
  house standard in the environments that run OpenShift — or strip `runAsUser`
  from a namespace install.
- **SCC-clean is not PSA-clean.** Where a cluster also enforces Pod Security
  Admission `restricted`, `runAsNonRoot: true` is *validated*, never mutated
  in — so a stock spec that SCC admits happily is refused by PSA. If both are
  enforced, the delivered set has to satisfy the union.

## Random UID — and the `HOME` caveat (open, not fixed)

Every container runs as an unpredictable per-namespace UID that exists in no
`/etc/passwd`. Anything that writes to `$HOME`, or that resolves `$HOME` from
the passwd database, breaks.

**This is an open product defect, not something this profile fixes.** At the
`v0.12.23` digests, `HOME` is absent from the bot and agent-worker images. The
observed failure is not cosmetic: the minio-init sync hook fails with
`mkdir /.mc: permission denied`, so the Argo Application never converges and no
later release can be delivered. `HOME=/tmp` is the one-variable fix; it is
tracked upstream and it has not shipped.

Nothing in the preflight detects this. **A P4 PASS means admission will accept
the pod, not that the process inside it can run** — the offline test asserts
exactly that boundary so nobody reads the green as more than it is.

## Quota and LimitRange

The project is a tenant grant: `ResourceQuota` + `LimitRange` + runtime RBAC,
issued by a platform team you do not control.

- **Size the quota for the app *plus* Argo** if Argo shares the project — a
  namespace-scoped Argo is ~7 pods of real quota, and it needs a namespaced
  `*/*/*` Role beyond `admin`, created by the platform team (escalation
  prevention blocks the tenant from creating it themselves).
- **The LimitRange max must be ≥ 2560Mi.** The bot's memory-backed `/dev/shm`
  (2Gi) counts against its 2560Mi memory limit. Against the recorded rig
  LimitRange (default 64Mi, max 1Gi) the bot is refused at admission — P2 and
  P6 both name it.
- Spawned meeting bots inherit the LimitRange defaults today; first-class
  resource fields on spawned workloads are tracked upstream, and the LimitRange
  is the documented interim.

## Harbor: artifact ingress

Cluster workloads pull only from Harbor, configured as a pull-through cache of
Docker Hub plus internal projects. Two lanes:

- **Public lane** (`vexaai` on Docker Hub through an anonymous
  `dockerhub-proxy` project) — needs nothing.
- **Private channel lane** — one Harbor registry endpoint holding the
  read-only subscriber token, plus a proxy-cache project. Validated against a
  literal Harbor v2.15.2 configured the same way: entries, charts, signature
  tags and attestations all flow through, and revoking the subscriber
  credential fails closed for the verdict-carrying artifacts (ORAS artifacts
  are never cached; cached images keep serving).

Pass the corporate CA with `--registry-ca <pem>`: Kyverno needs it as a trust
bundle for signature fetch, and `--allowInsecureRegistry` does not cover that
TLS path. Do **not** set `REGISTRY_INSECURE` — this ingress is TLS.

## Installing where there is no CLI

The target shape has no CLI for the app team: deploys are commits an Argo CD
syncs. `install.sh` is therefore not the install path there. Its work arrives
as **one merge into the GitOps config repo** — an Argo Application carrying the
station bundle reference, the contract, and the channel public key. See
[`station/profiles/TEMPLATE/`](../../../station/profiles/TEMPLATE/) for the
profile shape; filled per-customer profiles are not committed (ADR-0008).

`install.sh --provider openshift` remains the path for an OpenShift cluster
where you *do* hold a CLI, and is what this profile parameterises.

## What remains untested without a live OpenShift cluster

Stated as gaps, not as risks-we-have-mitigated:

- **`install.sh` end-to-end on OpenShift.** Never run. Every step after
  preflight — Argo install, Kyverno install, admission policy, repo secrets,
  ApplicationSet — is untried against real SCC and real OpenShift RBAC.
- **Vexa converging and running.** Blocked today by the `HOME` defect above.
- **The OpenShift GitOps operator as the engine.** Recommended on evidence
  about upstream Argo's images, not on a run of the operator with this kit.
- **`Route` instead of `LoadBalancer`.** Bare-metal OpenShift has no
  LoadBalancer; the chart has no Route support today (chart gap).
- **Test/prod cluster policy deltas, general egress beyond Harbor, and the
  cross-project firewall to the model-serving project.** These exist only on
  the customer's clusters. They are survey items — ours to ask, not to assume.
