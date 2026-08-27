# The channel — layout, signing, verification

One channel is one ordered stream of **channel entries**. An entry is one release: the exact
image-digest set plus the evidence bundle proving that set earned promotion. The customer's
cluster pulls entries; nothing on our side pushes. This file is the channel's contract; the
machine-checkable half is [`channel-entry.schema.json`](channel-entry.schema.json), and the golden
under [`goldens/`](goldens/) is the spec in the P8 sense.

## Registry layout

```
<registry>/<base>/
├── channel/<channel-name>          OCI artifact per entry
│     tags:  v0.12.23               immutable, one per release — never moved
│            current                the channel pointer — moved same-byte between entries
├── charts/vexa                     Helm chart as OCI (digest named in entry.json.chart)
└── images/...                      optional mirror; images may equally stay at their
                                    canonical registry and be pulled by digest
```

- **Immutable tags carry identity; one floating tag carries position.** `current` moves by
  descriptor copy (the same-byte alias discipline of `vexa:scripts/registry-manifest-alias.mjs`) —
  no re-push, no re-wrap. A puller that resolved `current` records the digest it resolved and the
  `entry_seq` inside; it refuses an entry whose seq does not exceed what it holds (rollback of the
  channel pointer is a signed, visible act, not a silent downgrade).
- **The entry artifact** (artifactType `application/vnd.vexa.channel-entry.v1+json`) contains
  `entry.json` plus the evidence files it digest-lists. Config media type carries the schema id.

## The evidence chain, and exactly what it claims

```
entry.json  (signed subject)
  ├─ images[].index_digest / platform_manifests     ← the digest set, verbatim from the tag's
  │       candidate map; the map file itself is in the bundle and its sha256 must equal the
  │       internal delivery receipt's packet pin (one carrier per fact — the map is the carrier,
  │       everything else points at it)
  ├─ evidence[]: candidate_map · delivery_receipt · source_provenance · trusted_root [· readiness
  │       · storm · witness · soak · sbom]           ← each digest-listed; bundle verifies offline
  ├─ evidence_absent[]                               ← the boundary of the claim, stated
  ├─ prod_soak                                       ← the soak claim + where its evidence lives
  └─ source                                          ← SLSA provenance parameters for the archive
```

**The provenance rung today, honestly:** SLSA Provenance v1 (GitHub Artifact Attestations,
Sigstore keyless) covers the **release source archive**. Images bind to that source through the
candidate map: the map records each image's index digest, per-platform manifest and config
digests, and the build/validation run URLs, and the map's sha256 is pinned by the internal
delivery receipt and by this entry. **Per-image SLSA attestations do not exist yet** (verified
2026-08-21: the GitHub attestation store 404s on the image digests) — so every entry lists
`image_provenance` under `evidence_absent` until the OSS pipeline attests images (vexa PRD §12
C1). What the customer's admission layer verifies about images today is the **channel signature**
over the digest set plus digest-pinning; what it verifies about source is real SLSA.

## Signing

- The entry artifact is signed with **cosign**; image digests named by the entry are cosign-signed
  into the channel registry as part of publication (signature repository = the channel registry,
  so admission can verify signatures without our canonical registry being reachable).
- **The production signing model — keyless vs long-lived key, rotation, revocation (TUF) — is an
  open decision** recorded in [ADR-0002](../docs/adr/0002-channel-format.md). Until it is taken,
  every entry uses `signing.mode: test_key`, which the schema restricts to `publication.mode:
  dry_run`. The first real publication is founder-gated and requires that ADR closed.

## Offline verification (no call to Vexa; both commands proven against v0.12.23)

The bundle carries the Sigstore trusted-root snapshot, so verification needs no network:

```
# 1 · entry signature (key mode; the identity to pin is entry.json.signing.identity)
cosign verify-blob --key channel.pub --signature entry.json.sig entry.json

# 2 · every evidence file: sha256 must equal its evidence[] row
sha256sum -c <(python3 -c "...emit name+sha256 rows from entry.json...")

# 3 · source provenance against the archive (vendor-neutral path)
cosign verify-blob-attestation \
  --bundle source-provenance.sigstore.json --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/Vexa-ai/vexa/' \
  vexa-core-vX.Y.Z.tar.gz

#    equivalent, gh tooling path:
gh attestation verify vexa-core-vX.Y.Z.tar.gz --repo Vexa-ai/vexa \
  --bundle source-provenance.sigstore.json --custom-trusted-root trusted-root.jsonl

# 4 · candidate map pin: sha256(candidate-images.json) == the map row in evidence[]
#     AND == the delivery receipt's packet.sha256 (strip the sha256: prefix)
```

The publisher's `verify` subcommand runs all four; a customer change board can run them by hand.

## Freshness — every entry expires

`entry.json.expires` is a required ISO-8601 instant inside the signed subject. Past it, the
publisher's `verify` and the customer's PreSync verifier both refuse the entry — **and they refuse
it with a different message from a signature failure**, because they are different events. A bad
signature means someone may be attacking you. An expired entry means *nobody has published to this
channel*, and from the inside a supply chain that has stopped looks exactly like a healthy one.

- Set at build time: `--expires-days`, default 30.
- **Republishing the same release with a fresh horizon needs no version bump.** `vexa_channel.py
  refresh --entry <dir> --out <dir> --expires-days N` re-stamps `expires` and `published_at`,
  increments `channel.entry_seq`, and drops the old signature; `push` then re-signs and moves the
  release tag to the new entry. The superseded entry keeps a permanent `<version>-seq<N>` tag and
  was never mutable by digest.
- **The release tag therefore names the current entry for that release, not one immutable
  artifact.** Rollback protection is `entry_seq` monotonicity, which lives inside the signature;
  tag immutability never carried it. The PreSync hook asks for the entry at the release tag, so
  the alternative — a new tag per refresh — would have quietly kept every cluster on the stale one.
- A customer may tighten this from their side with `max_entry_age_days` in their contract: refuse
  anything published more than N days ago regardless of the horizon we stamped.

## Revocation

We can publish and we cannot un-publish. An immutable tag stays resolvable and a cached chart
stays installable, so withdrawing a release is a **positive, signed statement** the verifier goes
and reads — never a deletion.

```
<registry>/<base>/<channel>/revocations:latest    revocations.v1, cosign-signed with the channel key
```

Schema: [`revocations.schema.json`](revocations.schema.json). Rows carry a `digest` **or** a
`version`, plus a reason an operator can act on, a severity, and optionally what to move to
instead. Published wholesale on every revocation by `vexa_channel.py revoke`; the list carries its
own `expires` so a stale answer to *"has anything been recalled?"* is visible as one.

- **An absent list is an EMPTY list, not an error.** Every channel published before this
  capability existed has none, and the fail-closed reading would refuse every install made before
  we thought of it. Publish an empty list to a channel to make the capability live before it is
  needed.
- **Kyverno cannot read it, and this is stated rather than papered over.** An admission controller
  verifies signatures on the images in front of it; it does not fetch a vendor document and reason
  about it. **The PreSync verifier is the enforcement point for revocation.** Admission remains
  the independent check on signatures and digest-pinning — different questions, different gates.

## The two-directional contract

The customer's contract file has always answered *"may this release run here?"*. It now answers
the two questions a regulated buyer asks first, in both directions:

| | Section | Enforced by |
|---|---|---|
| **out** | `delivery_scope` — namespaces · cluster-scoped objects yes/no · Pod Security Standards level · image-source allowlist · sum-of-requests ceiling | publisher station gate **S10–S14** on the rendered chart · PreSync re-checks the *claim* · the customer's own PSA + Kyverno check what runs |
| **in** | `report_scope` — [`report.v1`](report.v1.schema.json) · explicit trigger · single destination · enumerated file roles | `kit/validate --submit`, locally, before a byte moves |

Vocabulary is borrowed wherever one exists — **PSS/SCC**, the cluster-scoped/namespaced split OLM
install modes turn on, registry allowlisting — so a reviewer who recognises the standard can stop
evaluating and start checking. Only the inbound half has no standard; nobody has standardised what
telemetry may leave a perimeter, so that format is ours and says so.

**`report.v1`'s guarantee is structural, not promissory.** Every object sets
`additionalProperties: false`, so the permitted field set is the whole field set: there is nowhere
to put a transcript, a meeting title, a participant, a mail body or a log line, and the submit tool
validates before it sends. Not *"we would not send content"* — *"the document cannot carry it."*

## The return leg

```
<registry>/vexa/stations/<station>/bundles:<date>    station bundle, pushed by the SUBSCRIBER
```

`kit/validate/vexa_validate.py --submit` pushes the station bundle to the channel host the estate
already pulls from — no new firewall rule, no second vendor endpoint — using the subscriber's own
credential, and prints the pushed digest as the operator's receipt. `vexa_station.py ingest
--from-registry <registry> --station <name>` pulls it back.

**The account name IS the path segment.** The edge permits a subscriber to write to
`/v2/vexa/stations/<its own name>/**` and answers `403` anywhere else, `401` to an account with no
grant. One station cannot overwrite another's evidence and nobody has to trust it not to; a
subscriber minted under a name that does not match its station name simply cannot submit.

## Break-glass

An entry published with an incomplete chain MUST carry `break_glass` (named actor, reason,
approver, receipt). The publisher refuses to build an entry with evidence gaps unless
`--break-glass` is given with all fields — there is no silent path. This is ApprovedFor-shaped:
the override is data in the signed entry, visible to every verifier, never a bypass around the
channel.

## What a puller does (the customer side, for reference)

1. Resolve the channel tag → entry artifact digest; verify cosign signature.
2. Verify bundle digests; verify candidate-map pin; verify source provenance offline.
3. Check policy predicates (their own): required evidence kinds present, minimum soak, seq
   monotonic, maintenance window.
4. Sync: Argo CD renders the digest-pinned chart with the customer's local values; admission
   (Kyverno) independently re-verifies image signatures and digest-pinning before a byte runs.

Steps 1–3 are the conformance the kit's policy encodes; step 4 is stock Argo CD + Kyverno,
configured by files the customer can read.
