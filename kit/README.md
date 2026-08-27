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
  [--registry-ca corporate-ca.pem] [--prod-pin 0.12.24]
```

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
| Validate | [`validate/vexa_validate.py`](validate/vexa_validate.py) | one command: preflight → (optional install) → smoke → `station.tar.gz`, the secret-free record you send back |
| Preflight | [`preflight/vexa_preflight.py`](preflight/vexa_preflight.py) | P1–P9, each anchored to an observed incident; air-gapped `--snapshot` mode; probe pods are PSA-restricted-compliant |
| Subscription | [`argocd/applicationset.yaml`](argocd/applicationset.yaml) | ServerSideApply always; volumeClaimTemplates ignoreDifferences |
| Admission | [`policy/kyverno-vexa-admission.yaml`](policy/kyverno-vexa-admission.yaml) | your policy — tighten at will; we cannot override it |
| Providers | [`providers/*/profile.env`](providers/) | `PROFILE_TESTED` says honestly which profiles were exercised end-to-end by `install.sh` (today: lke). [`providers/openshift/`](providers/openshift/) is one rung below that — rehearsed against recorded constraints, asserted offline in [`preflight/tests/test_openshift_profile.py`](preflight/tests/test_openshift_profile.py), never live-installed; its README states the deltas and the open `HOME` finding |
| Node profile | [`profiles/vexa/`](profiles/vexa/) | `node-baseline.yaml` = delivered toggles (image digests are baked per release by the publisher, never here); `customer-values.example.yaml` = the file you edit and keep |

Proven end-to-end on 2026-08-21 against throwaway LKE clusters — install, pull, verify, admit,
deny-unsigned, deny-mutable-tag, the prod gate, and every preflight failure class
([kit receipt](../docs/receipts/2026-08-21-m2-throwaway-test.md)); then the full Vexa stack
delivered through the channel at v0.12.23, digest-pinned and admission-gated
([MVP0 receipt](../docs/receipts/2026-08-21-mvp0-implementation.md)).
