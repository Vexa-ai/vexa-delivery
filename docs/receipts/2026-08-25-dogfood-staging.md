# Dogfood, day one — what was proven, and what stopped

**Date:** 2026-08-25 · **Order:** founder pivot, [`Vexa-Delivery.md` § PIVOT](https://github.com/DmitriyG228/biz/blob/main/graph/sg/Vexa-Delivery.md) (private) — *vexa-platform becomes subscriber #1; staging first, prod later by ceremony.*

COMMITMENTS IN THIS RECEIPT — none.

## Verdict up front

| Phase | Rung reached |
|---|---|
| Channel storage → S3 | **done, live, verified** |
| Channel moved off the product cluster | **done, live, verified** |
| Publisher can build the platform chart | **PR open**, not published |
| Channel carries the exact prod estate | **not started** — inventory in flight; the content question was reopened the same day |
| vexa-staging subscribes + adoption rehearsal | **BLOCKED** — see below. Staging left at zero, untouched |
| Prod migration plan | **written**, not executed |

Nothing was published to a channel. `vexa-production` was never written to.

## What was proven

### The channel is stateless and no longer lives inside production

Storage moved from a 20 Gi block volume to Linode Object Storage (`vexa-channel`,
us-sea-1) as a **copy, not a re-push** — both drivers use the same
`docker/registry/v2` key tree, so all 590 objects moved verbatim and every digest
still resolves. That made the second move nearly free: `channel.vexa.ai` now runs
on a dedicated host outside the cluster, reading the same bucket, so **no content
moved at all**.

The reason is a circular dependency the founder named: production delivered *from*
a channel living *inside* production's cluster means a cluster outage removes the
mechanism needed to restore it.

Verified after each move — catalog and every tag list identical, blob digests equal
at byte level, subscriber `helm pull` returning the same chart digest, anonymous
signature reads (the Kyverno path) still 200, enumeration and entries still 401,
station writes scoped to the writing subscriber. Full evidence in
[`vexa-platform#352`](https://github.com/Vexa-ai/vexa-platform/pull/352) (private).

### Three failures that would each have shipped silently

**1. The S3 driver breaks the one-host promise by default.** A blob GET answers
**307 to a presigned `vexa-channel.us-sea-1.linodeobjects.com` URL**. That is
correct S3 practice and wrong for this product: mirroring images into the channel
exists so a customer allows *one* host through their firewall. Our own clients
follow redirects without complaint, so it would have looked green in every test we
run and failed **at the customer**. `redirect: disable: true` is therefore
load-bearing configuration, not tuning.

**2. Docker Compose v5 interpolates `$` in `env_file`.** On the relocated host the
`pilot` bcrypt hash arrived **57 characters** (`$2y$05/`) instead of 60 — three
characters silently eaten. The *publisher* hash happened to survive, so the
publisher could write and one subscriber could not. A smoke test that only
exercised the publisher would have passed. Caught only because the same request was
run against the old edge as a control and returned 202 where the new one returned
401.

**3. The namespace's egress comment had become false.** `30-networkpolicy.yaml`
stated the registry *"can reach nothing but DNS"* — true of a local volume, false
the moment storage became S3. The allow is now explicit and bounded (every
in-cluster range excepted), and honestly labelled as what it is: TCP/443 to
arbitrary external hosts, because NetworkPolicy selects on IP and Linode publishes
no address to pin.

### The digest pins are not where anyone thought

The dispatch assumed `vexa-platform/release/registry.yaml` held the platform's
digest pins. It does not: it is a 126-entry *evidence-check* registry, containing
the string `sha256:` exactly once, inside a prose `proves:` field. The chart's
values files reference images by **tag**.

**The pin set exists only in the live cluster** — the last release train resolved
tags to digests at deploy time. Publishing it into a signed entry is precisely the
value this exercise buys: it turns cluster-only state into an artifact. Two
corollaries surfaced while building the publisher change
([`vexa-delivery#40`](https://github.com/Vexa-ai/vexa-delivery/pull/40)):
`postgres:17-alpine` has **two different digests live in staging** (the tag was
re-pushed), and `vexaai/v012-mcp` **runs in staging but is not in the chart at
all** — so a chart-derived entry cannot, today, describe what actually runs.

## What stopped

### Part B — the adoption rehearsal did not happen, and should not have been forced

The delicate thing worth rehearsing is Argo CD **taking ownership of live,
helm-deployed resources without destroying them**. `vexa-staging` cannot rehearse
it:

- **zero workloads running** — all 15 objects at `replicas: 0` under the stage hold;
- **the Helm release is `failed`** — revision **203**, after 202 failed on
  `pre-upgrade hooks failed` and 203 on `context deadline exceeded`, both on
  2026-08-25. Last good state is revision 201, itself a rollback to 198.

Adopting an empty, failed release is a **fresh install**. It rehearses none of the
risk and would produce a green receipt for a thing never tested — the worst
available outcome, because prod would then be the first real adoption. Staging was
therefore left exactly as found, at zero.

Two further hazards were found in the prod plan work that would have bitten the
rehearsal even had staging been healthy, and both must close before any adoption:

- **All 13 prod Deployments carry `app.kubernetes.io/instance` inside their
  immutable `.spec.selector`.** Argo's *default* tracking rewrites that label to
  the Application name. At defaults, adoption is **rejected on the selector** and
  orphans the pods. `application.resourceTrackingMethod: annotation` must be set
  before the Application exists.
- **`kit/argocd/applicationset.yaml` hardcodes `helm: releaseName: vexa`** while the
  live release is `vexa-platform`. As shipped, Argo would adopt nothing and create a
  **second parallel set of workloads in the live namespace against the live
  database.**

### Amendment, same day: the content question reopened

The founder then ruled that the channel must carry **the exact production estate** —
*"everything that services prod"*, including monitoring and analytics — not the
idealized chart. Publishing a chart-derived entry before that inventory exists would
have published the wrong thing. The inventory and its gap analysis against what the
chart renders are the prerequisite, and are not finished.

## Where things stand

| Thing | State |
|---|---|
| `channel.vexa.ai` | Live on dedicated host `<registry-host>` (`channel-registry-host`, tag `channel-infra`), S3-backed, valid LE certificate |
| In-cluster `channel-registry` | Scaled to **0**, PVC retained, manifests kept as rollback |
| `vexa-staging` | **Untouched**, at zero, Helm release still `failed` at 203 |
| `vexa-production` | **Untouched.** Generations diffed at session start and after every step — identical |
| `pilot-stable` | Intact and served; 8 catalog entries dropped, all of them **empty** scratch directories with no tags |

## Rollback

DNS A record back to `<in-cluster address>`, scale the two Deployments back to 1. For
storage, restore the `filesystem` stanza and remount the retained PVC — it holds the
complete pre-migration tree as a point-in-time image.

{/* vexa-agent */}
