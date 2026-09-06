# The platform pack — one file, applied once

**For the platform engineer.** An application team in your estate is
subscribing to a Vexa channel. Everything they need is inside their own
project except six objects that are cluster-scoped by construction. This
directory renders those six into one file. You apply it once and never hear
about cluster scope again.

If the team's own credential holds cluster rights, you do not need this at
all — `kit/install.sh` creates the same objects itself, and that is the
default. This exists for the shape where it does not.

## Render it

```bash
./kit/platform/render.sh --provider openshift \
  --project vexa-app --channel acme-stable --channel-pubkey channel.pub
```

`--provider kubernetes` renders the same pack for every non-OpenShift platform
(EKS, AKS, GKE, LKE, on-prem): identical objects, minus the OpenShift-specific
annotations. `--print-plan` shows the object list and the sizing arithmetic and
writes nothing. Full flag list: `render.sh --help`.

The output is `platform-<provider>.yaml`. It is a pure function of its inputs —
no timestamp, no hostname — so re-rendering the same inputs gives you the same
bytes, and a re-review only has to look at what changed.

## Apply it

```bash
oc apply --server-side --force-conflicts -f platform-openshift.yaml     # OpenShift
kubectl apply --server-side --force-conflicts -f platform-kubernetes.yaml
```

**`--server-side` is not decoration.** The Argo `ApplicationSet` CRD is larger
than the 256KB `last-applied-configuration` annotation a client-side apply
writes, and a plain `apply -f` fails on it.

**If the first apply reports `no matches for kind "ClusterPolicy"`, run the
same command again.** The two policies at the foot of the file need Kyverno's
own CRD, which arrives earlier in the same file, and `kubectl` does not wait
for a CRD to be established before it continues. Every object here is
idempotent, so a second run is free.

The file is large — around 7.7MB — because 7.6MB of it is upstream Argo CD and
Kyverno, verbatim. Ours is the last few hundred lines.

## What is in it, and why

| Object | Why it must be yours |
|---|---|
| **Argo CD CRDs** ×3 (`applications`, `applicationsets`, `appprojects`) | CRDs are cluster-scoped. Argo's own `namespace-install.yaml` ships none, so a team installing Argo inside their project still cannot create these. Without them there is no Argo and nothing for the subscription to be. |
| **Kyverno** (namespace, 22 CRDs, controllers, RBAC, webhooks) | cluster-scoped throughout. It is the admission engine the two policies below run on. If your estate already runs Kyverno at this version, applying this is a no-op; if it runs a different version, apply the rest of the pack and leave Kyverno to your own lifecycle. |
| **ClusterRole + binding** `vexa-argocd-cluster-cache-reader` | Argo's cluster cache loads the initial state of every cluster-scoped kind before it syncs anything, and that load is **not** gated by `resource.inclusions`/`resource.exclusions`. Without this grant a namespace-scoped Argo never syncs: every Application sits `Unknown` on `volumeattachments.storage.k8s.io is forbidden`. Read-only — `get`, `list`, `watch` — and it grants no write anywhere. |
| **Two projects**, with PSA labels (and OpenShift SCC handling) | namespaces are cluster-scoped. One for the staging tier, which follows the channel; one for production, which moves only when the team's approver moves a pin. |
| **LimitRange** with a memory ceiling | a project admin is read-only on limits, by design. See below — this is the object that decides whether the delivered set runs at all. |
| **ResourceQuota** | same: theirs to live inside, yours to set. |
| **Two Kyverno `ClusterPolicy` objects** | cluster-scoped. `vexa-require-digest-pinning` refuses any Vexa image referenced by a mutable tag; `vexa-verify-channel-signature` refuses any Vexa image not signed by the channel key pinned inside the policy. They are the customer-owned half of the delivery chain: **we cannot override them**, and they verify our artifacts before a byte runs. |

The pack installs no Vexa workload, creates no credential, and grants nothing
to Vexa. The only network access it needs happened on the machine that
rendered it: fetching the two pinned upstream manifests.

## The memory ceiling is read from the chart, not chosen

`LimitRange.max.memory` defaults to **the largest single container limit in the
delivered Vexa chart** — today **4Gi**, which is postgres.

This is the object a 2026-09-06 rehearsal died on. The project's ceiling had
been sized at 2560Mi, correctly, for the meeting bot: the bot's memory-backed
`/dev/shm` counts against its own limit. Postgres then arrived asking 4Gi and
admission refused it:

```
pods "vexa-postgres-0" is forbidden: maximum memory usage per Container
is 2560Mi, but limit is 4Gi
```

A ceiling that clears the bot does not clear the delivered set. So the number
is read from the chart rather than remembered: `kit/platform/chart-sizing.env`
records it with its exact provenance (repository, path, blob), and
`render.sh --chart-values <values.yaml>` recomputes it from a real file. Set it
yourself with `--memory-ceiling`, bearing in mind it is a **floor**: below the
chart's largest container limit, the delivered set is refused at admission
after a green install.

The `default` and `defaultRequest` in the same LimitRange exist for one
reason: a LimitRange with a `max` and no `default` refuses every container that
declares none, and upstream Argo CD declares none. All thirteen delivered
containers declare requests *and* limits, so no delivered container is ever
assigned a default.

The ResourceQuota is derived and shows its working — each line's arithmetic is
an annotation on the object itself:

```
limits.memory  = the chart's own declared limits
               + concurrent meeting bots  (--concurrent-bots, default 4)
               + concurrent agent workers (--concurrent-workers, default 2)
               + Argo CD's pods at the LimitRange default
```

The spawned bots and workers are the term people forget. They are Pods the
runtime creates at meeting time, they are not in the chart, and they carry
request == limit. A quota that omits them does not fail the install — it fails
the meeting.

## The SCC annotations

On OpenShift, project creation is where the SCC UID range is decided.
**`render.sh` does not write one by default**: OpenShift's own project
lifecycle assigns `openshift.io/sa.scc.uid-range`, `.supplemental-groups` and
`.mcs` at creation, and a range invented by a renderer would be a fabricated
constraint — one that collided with another project's would be worse than
none. The rendered Namespace names the three annotations in a comment where
they would go.

If your estate pins ranges by policy, pass `--uid-range <START>/<SIZE>` and
they are written. Either way the kit's preflight reads the range off the live
namespace, so nothing downstream depends on the choice.

PSA labels are always written, at `enforce: baseline` with `audit`/`warn` at
`restricted` — what the delivered set is proven against. Raise `enforce` to
`restricted` if your estate requires it, and read
[`kit/providers/openshift/README.md`](../providers/openshift/README.md) first:
SCC mutates a security context in, PSA only validates one, so SCC-clean is not
PSA-clean and a delivered set has to satisfy the union.

## Access for the app team

The pack creates the projects but grants nobody access to them, because most
platform teams do that through their own mechanism:

```bash
oc adm policy add-role-to-group admin vexa-app-team -n vexa-app
```

If you would rather it were in the file, `--app-team-subject Group/vexa-app-team`
(or `User/…`, or `ServiceAccount/…`) renders the RoleBinding into both
projects, and `--app-team-role` picks the role. It is deliberately **one
identity in both** — a ServiceAccount resolved per-project would name two
different accounts and give the team admin on staging and nothing on
production. Write `ServiceAccount/<namespace>/<name>` if you want it elsewhere.

## What the app team does afterwards, without you

Everything. Their next command is the installer in the mode that knows the
cluster-scoped objects are already there:

```bash
./kit/install.sh --provider openshift --cluster-scope platform-pack \
  --registry <registry> --channel acme-stable --channel-pubkey channel.pub \
  --staging-ns vexa-app --prod-ns vexa-app-prod
```

Under that flag the installer creates no namespace, installs no Argo CD, no
Kyverno and no ClusterPolicy. It **checks the pack landed first** and refuses,
naming this file and the render command, if it did not — because a run that
continued would report success while the subscription could never sync and
nothing would verify a signature. Where its credential cannot read a
cluster-scoped object it reports `UNKNOWN` rather than guessing: not being
allowed to look is not the same as finding nothing.

After that they subscribe, upgrade, smoke-test and send their station report
entirely inside their two projects. They come back to you only if the chart's
largest container limit rises above the ceiling you set — which the kit's
preflight (P2) tells them before an install, not after.

## Testing

`make test-platform` runs it all offline: the render is deterministic, the
object set is complete and correctly ordered, no placeholder survives, the
LimitRange clears the chart's largest container limit, and the two
ClusterPolicies are **diffed against what `kit/install.sh` renders from the
same inputs** — so a subscriber's admission gate and their platform team's
admission gate can never become two different policies with one name. The
rendered pack is linted with `kubeconform` when it is present.

The validation that matters is a real cluster-admin apply followed by a tenant
install that needs no cluster rights; that is a receipt, not a unit test. See
[`docs/receipts/`](../../docs/receipts/).
