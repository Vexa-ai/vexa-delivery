---
title: "Verifying our signatures on the real authenticated channel"
description: "Kyverno 1.19.0, stock, holding no registry credential of any kind, verifying against live channel.vexa.ai: signed ADMITTED, unsigned DENIED, wrong key DENIED. The fix is anonymous signature reads at the Caddy edge."
---

**Date:** 2026-08-25. **Registry:** `channel.vexa.ai` — the **live** channel,
production LKE 590708. **Kyverno:** 1.19.0, the version `kit/providers/*`
pins, on LKE **646792**. Every result below is `kubectl`, `curl` or Caddy
access-log output.

The [signature-layout fix](/receipts/2026-08-25-signature-layout) proved the layout
question in both directions, but only against an **anonymous in-cluster
registry** — because Kyverno could not be made to authenticate to
`channel.vexa.ai` in any configuration that session tried. Every enterprise
channel is authenticated, so that gap was the last unknown before sending a
kit.

## The fix

**Serve the signature read paths anonymously at the edge; keep everything else
authenticated.** Signatures are verification material, not secrets. A reviewer
who can check them without holding a credential is a feature, and it removes
Kyverno's registry-authentication path from the critical path entirely.

Implemented in
[`Vexa-ai/vexa-platform#350`](https://github.com/Vexa-ai/vexa-platform/pull/350) (private).

## The paths, discovered rather than guessed

An access log was added to the channel's Caddy edge (it redacts
`Authorization`, so it records method, path and status and never a
credential). A real `cosign verify` and then a real Kyverno admission
verification were run against the live host, and the log was read back.

Both clients issue exactly the same three requests — they are the same
`go-containerregistry` under the hood:

```
GET   401 /v2/                                          [cosign/v2.6.5 … go-containerregistry/v0.20.7]
GET   200 /v2/vexa/channel/pilot-stable/signatures/manifests/sha256-514ba270….sig
GET   200 /v2/vexa/channel/pilot-stable/signatures/blobs/sha256:532cbe8c…
GET   200 /v2/vexa/channel/pilot-stable/signatures/blobs/sha256:aa914d6b…
```

```
GET   401 anon /v2/                                     [Kyverno/v1.19.0+dirty (linux; amd64) go-containerregistry…]
GET   200 anon /v2/vexa/channel/pilot-stable/signatures/manifests/sha256-514ba270….sig
GET   200 anon /v2/vexa/channel/pilot-stable/signatures/blobs/sha256:532cbe8c…
GET   200 anon /v2/vexa/channel/pilot-stable/signatures/blobs/sha256:aa914d6b…
```

Two things fall out of that and neither was obvious in advance:

* **The `/v2/` ping may stay authenticated.** Both clients take the `401` and
  carry on — they read only the `WWW-Authenticate` challenge from it. So
  `/v2/` is *not* in the anonymous set, and the registry still refuses to
  confirm anything to an unauthenticated caller there.
* **Only `manifests/` and `blobs/` are needed.** `tags/list` and `_catalog`
  are never touched, so enumeration stays behind credentials.

The rule made anonymous is therefore exactly:

```
@sigread {
  method GET HEAD
  path_regexp sig ^/v2/.+/signatures/(manifests|blobs|referrers)/[^/]+$
}
```

`referrers` is included so the modern cosign layout works the day we move to
it.

## The matrix, on the real channel

Kyverno **1.19.0**, restored to stock upstream before the run — **no
`--imagePullSecrets` flag, `--allowInsecureRegistry=false`, no registry Secret
in the namespace, no custom CA bundle**:

```
$ kubectl -n kyverno get deploy kyverno-admission-controller \
    -o jsonpath='{…args}' | tr ',' '\n' | grep -ci imagePullSecrets
0
$ kubectl -n kyverno get secrets | grep -c channel-registry-creds
0
```

Policy: the kit's own `kit/policy/kyverno-vexa-admission.yaml` shape —
`verifyImages` with `repository: channel.vexa.ai/vexa/channel/pilot-stable/signatures`,
`imageReferences: ["*vexaai/*"]`, `failureAction: Enforce`, `rekor.ignoreTlog:
true`, `useCache: false` — with the live pilot channel public key.

| | image | pinned key | signature repository | result |
|---|---|---|---|---|
| **A** | `vexaai/v012-gateway@sha256:514ba270…`, signed on the channel | channel key | `…/signatures` (anonymous) | **ADMITTED** |
| **B** | `vexaai/v012-gateway@sha256:3474c9dc…`, not signed | channel key | `…/signatures` (anonymous) | **DENIED** — `no signatures found` |
| **C** | A's image | **wrong** key | `…/signatures` (anonymous) | **DENIED** — `invalid signature` |
| **D** | A's image | channel key | a copy at `…/scratch-sigs` (**authenticated**) | **DENIED** — `UNAUTHORIZED: authentication required` |

**D is the control.** It is the same image, the same key and the same
signature bytes, differing only in whether the edge serves that path
anonymously — which is what makes A a result about the fix rather than about
the day.

Verbatim, A and B in one run:

```
--- A · correctly signed, digest-pinned, channel key ---
pod/anon-signed created

--- B · unsigned image ---
resource Pod/sigfix-test/anon-unsigned was blocked due to the following policies

sigfix-verify-channel-signature:
  vexa-images-signed-by-channel: 'failed to verify image
  docker.io/vexaai/v012-gateway@sha256:3474c9dc957193dd1c3a83358eebc3c19d5256b45b4f49622c2e0d741ddb1306:
  .attestors[0].entries[0].keys: no signatures found'
```

C:

```
failed to verify image docker.io/vexaai/v012-gateway@sha256:514ba270…:
  .attestors[0].entries[0].keys: no matching signatures: invalid signature when
  validating ASN.1 encoded signature
```

D:

```
failed to verify image docker.io/vexaai/v012-gateway@sha256:514ba270…:
  .attestors[0].entries[0].keys: GET
  https://channel.vexa.ai/v2/vexa/channel/pilot-stable/scratch-sigs/manifests/sha256-514ba270….sig:
  UNAUTHORIZED: authentication required
```

## The authentication hypothesis is DISPROVEN

[#33](https://github.com/Vexa-ai/vexa-delivery/pull/33) recorded, unconfirmed,
that `verifyImages.repository` may not inherit Kyverno's configured registry
client. It does. On the authenticated `…/scratch-sigs` path, **both flag forms
worked**:

| | flag | result |
|---|---|---|
| **E** | `--imagePullSecrets=kyverno/channel-registry-creds` (namespaced — the form the kit ships, and the form [#31's receipt](/receipts/2026-08-24-week-exit-rehearsal) calls silently ignored) | **ADMITTED** |
| **F** | `--imagePullSecrets=channel-registry-creds` (bare name) | **ADMITTED** |

and the edge log shows Kyverno actually sending the credential:

```
GET   401 anon /v2/
GET   200 AUTH /v2/vexa/channel/pilot-stable/scratch-sigs/manifests/sha256-514ba270….sig
GET   200 AUTH /v2/vexa/channel/pilot-stable/scratch-sigs/blobs/sha256:532cbe8c…
GET   200 AUTH /v2/vexa/channel/pilot-stable/scratch-sigs/blobs/sha256:aa914d6b…
```

**So the flag was never the defect, and neither was the flag's form.** Two
sessions' worth of conclusions about `--imagePullSecrets` are withdrawn here.
What the earlier session actually had wrong is not recoverable from its
artifacts; what is recoverable is that its Kyverno was not in the state it
believed. Which leads to:

**G** — with the credential present *and* the policy pointed back at the
anonymous `…/signatures` path, A still admits. Anonymous serving and a held
credential do not conflict.

## A defect found in the environment, not by looking for it

The demo cluster's Kyverno admission controller had been **crash-looping since
roughly 12:16 UTC**, before this session touched it:

```
ERR please define the environment variable  error="environment variable must be defined" name=KYVERNO_NAMESPACE
```

[#33](https://github.com/Vexa-ai/vexa-delivery/pull/33) states its Kyverno
arguments and volumes "were restored to their pre-session state". They were
not: the restore dropped the controller's environment block, and left a
`ca-bundle` volume pointing at a `channel-registry-ca` ConfigMap that stock
Kyverno does not have. Admission was **down** on that cluster for the
intervening half hour and nothing said so.

Repaired here by re-applying stock `kyverno/v1.19.0/install.yaml` and removing
the leftover volume and mount by JSON patch (server-side apply does not prune
a list entry another field manager owns). Verified stock afterwards:

```
volumes: ['sigstore', 'apicall-token'] mounts: ['sigstore', 'apicall-token']
```

## The edge policy itself

Anonymous, against the live host:

```
GET    /v2/…/signatures/manifests/sha256-514ba270….sig    -> 200
HEAD   /v2/…/signatures/manifests/sha256-514ba270….sig    -> 200
GET    /v2/…/signatures/blobs/sha256:532cbe8c…            -> 200
GET    /v2/vexa/channel/pilot-stable/manifests/current     -> 401
GET    /v2/…/charts/vexa/manifests/0.12.35                -> 401
GET    /v2/…/kit/manifests/latest                         -> 401
GET    /v2/…/signatures/tags/list                         -> 401
GET    /v2/_catalog                                       -> 401
GET    /v2/                                               -> 401
POST   /v2/…/signatures/blobs/uploads/                    -> 401
PUT    /v2/…/signatures/manifests/evil                    -> 401
DELETE /v2/…/signatures/manifests/sha256-514ba270….sig    -> 401
PATCH  /v2/…/signatures/blobs/uploads/x                   -> 401
POST   /v2/…/blobs/uploads/                               -> 401
```

Credentialed, same run:

```
subscriber  GET /v2/                                  -> 200
subscriber  GET …/manifests/current                   -> 200
subscriber  GET …/charts/vexa/manifests/0.12.35       -> 200
subscriber  GET …/kit/manifests/latest                -> 200
subscriber  POST …/blobs/uploads/                     -> 401   (write gate holds)
publisher   POST …/blobs/uploads/                     -> 202
publisher   POST …/signatures/blobs/uploads/          -> 202
publisher   oras push …/scratch/anon-edge-check:probe -> Pushed
subscriber  oras pull …/pilot-stable:current           -> Pulled (VERIFY.md, entry.json, entry.json.sigstore.json, evidence)
```

Two `404`s worth recording because they look like a policy failure and are
not: an anonymous manifest GET **without an `Accept` header** returns

```
{"errors":[{"code":"MANIFEST_UNKNOWN","message":"OCI manifest found, but accept header does not support OCI manifests"}]}
```

That is content negotiation, not authorisation — with the OCI media types in
`Accept`, the same request is `200`. And an anonymous GET of a signature that
does not exist is `404`, which is how B reaches Kyverno.

## What this does NOT solve — mirrored images

**Anonymous signature reads say nothing about pulling the images themselves.**
Today Vexa's container images live on Docker Hub and are public, so the only
thing admission needs from the channel is the signature. The day the images
are mirrored **into** the channel — which is the whole point of an air-gapped
delivery and is on the roadmap — two separate things become true again:

1. **The kubelet needs an `imagePullSecrets` for the channel** on every pod
   that pulls a mirrored image. Nothing here provides that; it is a chart and
   namespace concern, per-namespace, and the chart does not do it today.
2. **Kyverno needs channel read access for digest resolution.** A policy that
   resolves a mutable tag to a digest, or any `mutateDigest: true` rule, reads
   the *image* manifest, not the signature — a path that is not anonymous and
   must not become anonymous.

This is why `install.sh` keeps `--registry-user` wiring the Kyverno credential
even though our own channel no longer needs it for verification. Do not read
this receipt as "the channel is solved for admission"; read it as "the
signature half is solved, on the real channel, with no credential."

## State the channel was left in

`pilot-stable` unchanged: 24 tags in `…/signatures` before and after. The two
scratch repositories created for D/E/F (`…/scratch/anon-edge-check`,
`…/scratch-sigs`) were deleted and return `404`. On LKE 646792 the
`sigfix-test` namespace and the test ClusterPolicy were deleted; Kyverno was
left stock and running; the cluster's two pre-existing ClusterPolicies were
untouched. No cluster was created or destroyed by this work.

{/* vexa-agent */}
