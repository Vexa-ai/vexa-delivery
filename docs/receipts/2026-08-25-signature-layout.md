---
title: "The signature layout the customer's admission controller can read"
description: "Measured against live Kyverno 1.19.0: which cosign writes which layout, which layouts admit, which deny, and what the live pilot-stable channel was left holding."
---

**Date:** 2026-08-25. **Registry:** `channel.vexa.ai` — the **live** channel.
**Kyverno:** 1.19.0, the version `kit/providers/*` pins, running on LKE
**646792**. Every result below is `kubectl` output, not reasoning.

The [week-exit rehearsal](/receipts/2026-08-24-week-exit-rehearsal) ended with one
blocker: *a correctly signed release is denied at admission with a message that
says it is unsigned*. It had to delete the `vexa-verify-channel-signature`
ClusterPolicy to continue, so everything after its §6 was proven with image
signature admission **off**. This is that blocker, measured and closed.

---

## 1 · What actually decides the layout

The rehearsal attributed the layout to cosign's **major version**. Measured, it
is the **`--new-bundle-format` flag**, whose *default* moved between majors:

| cosign | flags | tag written into `COSIGN_REPOSITORY` | shape |
|---|---|---|---|
| 2.6.5 | default | `sha256-<hex>.sig` | image manifest, layer `application/vnd.dev.cosign.simplesigning.v1+json` |
| 3.1.3 | default | `sha256-<hex>` (no suffix) | OCI **referrers index** over a sigstore bundle v0.3 |
| 3.1.3 | `--new-bundle-format=false` | `sha256-<hex>.sig` | the 2.x shape, byte-for-byte the same kind |

That distinction matters more than it sounds, because it says the defect is **not
"we are on the wrong cosign"** — the publisher already passed
`--new-bundle-format=false`. It says the correctness of every signature this
product ships rested on **a deprecated flag of an unpinned binary**. cosign 3.x
prints, on every run:

```
Flag --new-bundle-format has been deprecated, this will be the only supported
format in future versions
```

And it had already drifted in production. On the morning of 2026-08-25 the live
`pilot-stable/signatures` repository held **15 tags: 14 in the referrers layout
and one `.sig`** — i.e. the images a customer would admit were signed by
something that did not pass the flag, and nothing anywhere checked the result.

## 2 · What Kyverno 1.19 does with each layout

Same image (`docker.io/vexaai/v012-gateway@sha256:514ba270…`), same key, same
policy — only the signature repository's layout changes. `ClusterPolicy`
`verifyImages` with `repository:`, `imageReferences: ["*vexaai/*"]`,
`failureAction: Enforce`, the channel public key, `rekor.ignoreTlog: true`.

| | signed by | layout | result |
|---|---|---|---|
| **A** | cosign 2.6.5, default | `.sig` | `pod/sigfix-signed created` — **ADMITTED** |
| **B** | cosign 3.1.3, default | referrers | **DENIED** — `no signatures found` |
| **C** | *not signed in this repo* | — | **DENIED** — `no signatures found` |
| **D** | cosign 2.6.5, correct layout, **wrong pinned key** | `.sig` | **DENIED** — `no matching signatures: invalid signature when validating ASN.1 encoded signature` |
| **E** | cosign 3.1.3 **with** `--new-bundle-format=false` | `.sig` | **ADMITTED** |
| **F** | the exact manifest now live on `pilot-stable` | `.sig` (two layers) | **ADMITTED** |

Verbatim, B:

```
resource Pod/sigfix-test/sigfix-signed was blocked due to the following policies

sigfix-verify-channel-signature:
  vexa-images-signed-by-channel: 'failed to verify image
  docker.io/vexaai/v012-gateway@sha256:514ba270…:
  .attestors[0].entries[0].keys: no signatures found'
```

**B and C are indistinguishable.** That is the whole severity of this defect: the
admission layer's report on a correctly signed image is identical to its report
on an unsigned one, and the correct one is the release we sent.

Kyverno's own request, observed on the wire, is what fixed the shape of the
push-time check — it asks for exactly one thing:

```
GET https://<registry>/v2/<signature-repository>/manifests/sha256-<hex>.sig
```

## 3 · The fix

Two named checks in the publisher, both inside the push path so neither can be
skipped:

- **T1 — the toolchain is pinned.** `push`, `sign-images` and `attest` refuse to
  sign with a cosign outside the 2.x series, naming the consequence rather than
  the mismatch. `publisher/install-cosign.sh` installs 2.6.5 against the
  release's published checksum; `COSIGN_BIN` points at it.
  `VEXA_COSIGN_ALLOW_UNPINNED=1` overrides, loudly, and the signing-run record
  then says what actually signed.
- **T2 — verify the way Kyverno verifies.** After signing, assert the
  `sha256-<digest>.sig` tag exists in the signature repository, holds a cosign
  signature manifest, and verifies against the channel key. Refuse the push
  otherwise. Run against the live channel's stale entries, T2 says:

```
REFUSED: T2: the tag Kyverno 1.19 will ask for does not exist:
  channel.vexa.ai/vexa/channel/pilot-stable/signatures:sha256-e98025e2….sig.
  This is the cosign 3.x referrers layout; admission would report the image as
  UNSIGNED. Sign with cosign 2.6.5
```

And **VERIFY.md is generated from the signing run** — tool, version, flags,
bundle format, layout — at push time, replacing prose that had drifted out of
agreement with both the publisher's own `verify` and
`onboarding/credential-delivery.md`.

## 4 · The live channel

All **ten** image digests the `pilot-stable:current` entry names were re-signed
with the pinned toolchain and each verified Kyverno-style at push:

```
all 10 image digests signed and verified Kyverno-style
```

Three things were deliberately **not** touched, and each for a reason:

- **The 14 stale referrers-layout tags remain** in the signature repository. They
  are the same signatures in a layout nothing successfully reads; deleting live
  channel content is a publication act and buys nothing.
- **The entry artifact was not re-pushed.** Its own signature is already in the
  `.sig` shape and verifies. Re-signing would change `entry.json.sigstore.json`,
  hence the artifact digest, hence `current` — a new entry seq, which is a
  publication decision. The **VERIFY.md now on the channel is therefore still
  the hand-maintained one**; the generated one ships with the next entry.
- **The chart was not signed.** `charts/vexa:0.12.35` is pinned by digest inside
  the signed entry, which is its integrity guarantee; nothing in the kit verifies
  a separate chart signature, and the admission policy matches `*vexaai/*`
  container images only.

## 5 · What this does NOT prove, and one new blocker

**Kyverno 1.19 could not authenticate to the channel registry, in any
configuration tried.** With `--imagePullSecrets=channel-creds` (the bare name,
resolved in Kyverno's own namespace) and the credential proven good by `curl`
(HTTP 200) and by `oras` from the same secret's contents, every admission attempt
against `channel.vexa.ai` returned:

```
GET https://channel.vexa.ai/v2/vexa/channel/pilot-stable/signatures/manifests/
  sha256-514ba270….sig: UNAUTHORIZED: authentication required
```

The controller logs confirm the client was built with the secret
(`setup registry client... insecure=true secrets=channel-creds`) and with
`allowInsecureRegistry=true` — yet the verification path used **neither**: a
plain-HTTP signature repository failed with `http: server gave HTTP response to
HTTPS client` despite that flag. The working hypothesis is that Kyverno's
`verifyImages.repository` override does not inherit the configured registry
client. **It is a hypothesis, not a finding** — it was not confirmed in Kyverno's
source, and it is exactly the kind of thing that should be asked before it is
built on.

So the admit/deny matrix above was obtained against a **TLS, anonymous-read**
registry inside the cluster, with its CA mounted into Kyverno. What is proven is
the *layout* question, in both directions, on real Kyverno 1.19.0. What is **not**
proven is that a customer whose channel registry requires a credential can read
our signatures at all — and every enterprise channel requires one.

Two things point at the same gap and belong together:

1. `kit/install.sh` passes `--imagePullSecrets="$KYVERNO_NS/channel-registry-creds"`
   — the **namespaced** form the rehearsal receipt itself identifies as silently
   ignored. The bare name is what the flag takes. That is a real bug and it is
   still in the tree; it is *not*, on this evidence, sufficient to make the fetch
   authenticate.
2. Nothing in the kit ever asserts that admission can actually read a signature.
   The preflight proves the cluster; the gate proves the chart; no check stands
   between "we published a signature" and "your controller found it".

Also still unproven, unchanged from the rehearsal: transcription and capture, the
flows/agent tier, OpenShift, scale, rollback, and break-glass.

## Cleanup

The in-cluster scratch registry, its TLS material, the test namespace and the
test ClusterPolicy were removed, and the Kyverno admission controller's arguments
and volumes were restored to what they were before this session. LKE 646792 is
not ours and was left running.

{/* vexa-agent */}
