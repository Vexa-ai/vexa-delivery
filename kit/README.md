# kit — the customer side of the channel

**Apache-2.0** (see [LICENSE](LICENSE), [NOTICE](NOTICE) — local copies, because the kit ships as a
standalone signed tarball; the whole repository is under the same license per
[ADR-0008](../docs/adr/0008-repository-apache-2.md)). This is the part that runs inside a
customer's perimeter: readable and modifiable there, line by line.

Bring your own cluster, run this command:

```
./kit/install.sh --provider lke \
  --registry <channel-registry-host> \
  --channel acme-stable \
  --channel-pubkey channel.pub \
  --customer-values my-values.yaml \
  --claim-code <the code read to you on the call> \
  [--registry-ca corporate-ca.pem] [--prod-pin 0.12.24]
```

`--claim-code` is how the channel credential reaches the cluster: six digits,
read to you on a call as `123 456`, exchanged for the credential over TLS and
written to a Secret. Type them with the space or without. Nobody types the
credential and nobody sees it. (Already
installed, or adding it later? [`claim.sh`](claim.sh) does the same exchange on
its own. Holding the credential already? `--registry-user` with
`VEXA_CHANNEL_PASS` is unchanged.)

What it does, in order: **conformance preflight** (refuses on FAIL) → pinned **Argo CD** → pinned
**Kyverno** → **admission policy** (digest pinning + channel-signature verification, customer-owned)
→ the **channel subscription** (an ApplicationSet with two elements: the staging Application, in
`vexa-staging`, follows the channel pointer automatically; the production Application, in
`vexa-prod`, follows a pin **you** move — that pin move is your gate, and nothing on the vendor
side can move it).

Everything installed is stock upstream plus rendered configuration; the whole kit is readable in
one sitting. Nothing here phones home; verification is offline (see `spec/channel.md` and the
VERIFY.md inside every channel entry).

## The kit is delivered the way releases are

The kit is delivered the same way everything else on the channel is: as a versioned, signed OCI
artifact, pulled by digest and **verified against your pinned key before a single byte is
unpacked**.

Two layouts, and which one you are on decides the paths below. `git clone` of this repository is
the default first step ([install step 1](../docs/install.mdx)) and leaves the kit at `kit/`. The
signature-verified bootstrap unpacks to `./vexa-kit`, so read `vexa-kit/...` for `kit/...`
throughout.

```
# the verified path: clone, read, then let bootstrap pull the pinned signed kit
git clone https://github.com/Vexa-ai/vexa-delivery && cd vexa-delivery
bash kit/bootstrap.sh --registry <channel-registry-host> \
  --channel acme-stable --pubkey channel.pub

# later, refresh the kit itself; refuses to touch the tree on a bad signature
./kit/self-update.sh               # cloned layout
./vexa-kit/self-update.sh          # bootstrap layout — add --check to see what would move
```

| Piece | File | Note |
|---|---|---|
| Release | [`release.sh`](release.sh) | publisher side: packages the tree, `oras push` as `application/vnd.vexa.kit`, cosign-signs the digest, moves `latest` |
| Bootstrap | [`bootstrap.sh`](bootstrap.sh) | customer side: resolve tag → digest, **verify, then** pull by digest and unpack; self-contained so it is curl-able |
| Self-update | [`self-update.sh`](self-update.sh) | re-pull `latest`, verify, atomic tree swap; on signature failure the existing tree is untouched |
| Version marker | `VERSION` (in the package, not the repo) | what `self-update` compares and what a support ticket quotes |

The tag is only ever used to discover a digest; every byte is fetched by digest and the signature is
checked against your key before the tarball is opened. A moved `latest` therefore buys an attacker
nothing: an unsigned or wrong-key artifact is refused with nothing written to disk, and a refused
`self-update` leaves the running tree exactly as it was.

| Piece | File | Note |
|---|---|---|
| Claim | [`claim.sh`](claim.sh) | turn the six-digit single-use code read to you on a call into the `vexa-station-credential` Secret; the value never reaches your terminal. `install.sh --claim-code` sources this file, so a first install takes the code directly |
| Validate | [`validate/vexa_validate.py`](validate/vexa_validate.py) | one command: preflight → (optional install) → smoke → `station-report.yaml`, the one secret-free file you read and send back |
| Preflight | [`preflight/vexa_preflight.py`](preflight/vexa_preflight.py) | P1–P9, each anchored to an observed incident; air-gapped `--snapshot` mode; probe pods are PSA-restricted-compliant |
| Subscription | [`argocd/applicationset.yaml`](argocd/applicationset.yaml) | ServerSideApply always; volumeClaimTemplates ignoreDifferences |
| Admission | [`policy/kyverno-vexa-admission.yaml`](policy/kyverno-vexa-admission.yaml) | your policy — tighten at will; we cannot override it |
| Providers | [`providers/*/profile.env`](providers/) | `PROFILE_TESTED` says honestly which profiles were exercised end-to-end by `install.sh` (today: lke). [`providers/openshift/`](providers/openshift/) is one rung below that — rehearsed against recorded constraints, asserted offline in [`preflight/tests/test_openshift_profile.py`](preflight/tests/test_openshift_profile.py), never live-installed; its README states the deltas and the open `HOME` finding |
| Node profile | [`profiles/vexa/`](profiles/vexa/) | `node-baseline.yaml` = delivered toggles (image digests are baked per release by the publisher, never here); `customer-values.example.yaml` = the file you edit and keep |

## The two registry Secrets, and the rename that separated them

`install.sh` creates two Secrets that both concern the channel registry, and
they answer to different consumers. They used to share a name.

| Secret | Namespace | Type | Read by |
|---|---|---|---|
| `vexa-channel-registry` | `ARGOCD_NAMESPACE` (default `argocd`) | `Opaque`, labelled `argocd.argoproj.io/secret-type: repository` | Argo's repo-server, to fetch entries and charts |
| `vexa-channel-pull` | each workload namespace | `kubernetes.io/dockerconfigjson` | the **kubelet**, to pull images, via `spec.imagePullSecrets` |

Until 2026-09-06 the second was also called `vexa-channel-registry`. The two
never collided *only because the namespaces differ by default*. On a
single-project tenant — the shape [`providers/openshift/`](providers/openshift/)
exists for — they are one object, the second create fails with `type: Invalid
value: "kubernetes.io/dockerconfigjson": field is immutable`, and every
ServiceAccount is left pointing its `imagePullSecrets` at an `Opaque` secret the
kubelet cannot use. `ImagePullBackOff`, on a sync Argo reports as fully
Succeeded. A name that is unique only because of a default is not unique.

**Carrying an existing install over: re-run the installer (or
`self-update.sh`), then delete one Secret.** The ServiceAccount patch is a merge
patch on a list, so it replaces `imagePullSecrets` wholesale — every account
moves to the new name on the next run, with nothing to find by hand. That
leaves the old pull Secret unreferenced:

```bash
# in each workload namespace: confirm nothing still points at the old name,
kubectl -n vexa-staging get sa -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.imagePullSecrets[*].name}{"\n"}{end}'
# check you are looking at the KUBELET's secret and not Argo's repository one
kubectl -n vexa-staging get secret vexa-channel-registry -o jsonpath='{.type}'   # kubernetes.io/dockerconfigjson
# then, and only then:
kubectl -n vexa-staging delete secret vexa-channel-registry
```

If that `type` comes back `Opaque`, you are on a single-namespace tenant and
that object is **Argo's repository Secret** — deleting it stops the
subscription syncing. Leave it; the new `vexa-channel-pull` sits beside it,
which is the whole point of the rename.

Proven end-to-end on 2026-08-21 against throwaway LKE clusters — install, pull, verify, admit,
deny-unsigned, deny-mutable-tag, the prod gate, and every preflight failure class
([kit receipt](../docs/receipts/2026-08-21-m2-throwaway-test.md)); then the full Vexa stack
delivered through the channel at v0.12.23, digest-pinned and admission-gated
([MVP0 receipt](../docs/receipts/2026-08-21-mvp0-implementation.md)).
