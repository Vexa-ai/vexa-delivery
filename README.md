# vexa-delivery — the enterprise BYOC delivery factory

**Apache-2.0, whole repository — see [LICENSE](LICENSE) and [NOTICE](NOTICE).** Factory and kit
alike: the moat is the attested release stream, the receipts, the reference customer and the
relationship, not ~2k lines of configuration around stock Argo CD, Kyverno and cosign. The product
itself ([Vexa-ai/vexa](https://github.com/Vexa-ai/vexa)) is Apache-2.0 and unchanged: **no feature
is gated and no source is held back** — what an enterprise subscribes to is the attested release
stream, support and co-design. Ruling: [ADR-0008](docs/adr/0008-repository-apache-2.md).

**The repository is public** ([ADR-0009](docs/adr/0009-public-visibility.md)); auditability of the
attestation pipeline is the point — a delivery machine whose claims rest on signatures and evidence
should itself be inspectable. Customer-identifying material does not live here at all, and never
did as policy (see [ADR-0008](docs/adr/0008-repository-apache-2.md) § Consequences and the
[`.gitignore`](.gitignore) rules for `stations/`, `station/profiles/` and `onboarding/`): a
customer's estate, channel, timeline and evaluation state are theirs, not ours to show.

**What this is, honestly:** the delivery machinery **for Vexa** — it exists to ship
[Vexa-ai/vexa](https://github.com/Vexa-ai/vexa) releases to enterprise subscribers, and its
defaults, examples and receipts reflect that one product. The *pattern* is general — signed
pull-only channels, attestation-gated promotion, evidence receipts — and a vendor-neutral
extraction is on the roadmap, but that extraction has not been done: expect Vexa-specific
assumptions throughout.

This repository is the **vendor-side delivery factory**: it turns validated Vexa releases into a
signed, evidence-carrying **enterprise channel** that a customer's own cluster pulls from, and it
ships the **customer kit** (Argo CD wiring, admission policy, conformance preflight) that consumes
that channel. It supersedes the promotion tooling in `vexa-platform` — one delivery machine serving
staging → prod → enterprise → OSS — per the supersede map in [SUPERSEDES.md](SUPERSEDES.md).

---

## Charter

The two sections below are carried verbatim from the founding handoff (an internal document, not
publicly accessible); they are founder rulings and are not relitigated here. Changes to them go
through the founder, not through a PR.

### The product, one paragraph

An Argo CD–based **pull conveyor running in the customer's own cloud** (BYOC). The customer's
cluster subscribes to an **enterprise channel**: a signed manifest naming an exact image-digest set
plus the **evidence bundle** proving that set earned promotion — staging validation receipts,
production soak receipts, SLSA provenance, readiness-leg receipts. Their Argo pulls a new set only
when its evidence chain is complete; nothing on our side can push into their cloud, and their
admission layer independently verifies our attestations before a byte runs. Promotion is **evidence
accumulation, not a sequence of pushes** (Attestation-Conveyor);
the one bypass is an **audited break-glass**, never an unaudited path.

### Decisions already made — founder rulings, do not relitigate

1. **EE software, NEW repository** — not in `Vexa-ai/vexa`, not in `vexa-platform`
   (PRD §0c). The new repo must **SUPERSEDE the current
   promotion tooling, not parallel it** — one delivery machine serving staging→prod→enterprise→OSS,
   with today's vexa-platform scripts retired into it, never two lanes maintained.
2. **The chain**: validate in staging → validate in production → deliver enterprise → OSS release
   follows ("as a matter of fact later, with lite and compose built and validated"). Safe to flow
   forward automatically; human gates are audited exceptions, not the transport.
3. **Grounded in industry practice, not reinvented** — the governance docs carry the source refs;
   canonical sources and
   nearest neighbours are the survey.
   Verdict already taken: **Argo CD is the base** (industry standard, not OpenShift-centric —
   plain k8s works, OpenShift GitOps IS Argo). **Kargo is the promotion object model to imitate**:
   its `Freight` / `Stage` / `Status.VerifiedIn` / `RequiredSoakTime` / `ApprovedFor` map
   one-to-one onto our design; evaluate adopting it before writing a controller.
4. **OpenShift compatible; fully modular; isolation of concerns; single source of truth;
   harnessed with tests at all levels** (founder's words). SCC `restricted-v2` behavior is
   documented in the openshift audit — it mutates before PodSecurity; the real blocker class is
   explicit UIDs outside the namespace range and missing `USER` directives (15 Dockerfiles have
   none — the hardening track, ~2–4 days).
5. Ground-truth voice everywhere: mechanism in names, contract in descriptions, claims only at the
   rung the evidence supports (founder ruling on the 0.12.23 release notes).

---

## Repository map

| Path | What it is |
|---|---|
| [`spec/`](spec/) | The channel contract: channel-entry schema (the evidence bundle format), channel layout, goldens. One definition per contract; goldens are the spec. |
| [`publisher/`](publisher/) | The publisher CLI: turns a released version (tag + candidate map + attestations + delivery receipt) into a signed channel entry. Consumes released artifacts and receipts — never clusters. |
| [`kit/`](kit/) | The customer kit: Argo CD ApplicationSet, admission verification policy, cluster conformance preflight, installer, provider profiles. This is what a subscriber installs; everything it does is inspectable by them. Carries its own [LICENSE](kit/LICENSE)/[NOTICE](kit/NOTICE) copy because it ships as a standalone signed tarball. |
| [`docs/customer/`](docs/customer/index.mdx) | Customer-facing product docs (MDX, DRAFT — publication founder-gated). Start at [index.mdx](docs/customer/index.mdx). |
| [`docs/adr/`](docs/adr/) | This repo's ADR series, from ADR-0001. Delivery-system decisions land here; product-level decisions stay in `Vexa-ai/vexa`. |
| [`RUNBOOK.md`](RUNBOOK.md) | The per-release channel crank (MVP0: manual by design), founder gates marked. |
| [`docs/receipts/`](docs/receipts/) | Live evidence, including the current [MVP0 implementation state](docs/receipts/2026-08-21-mvp0-implementation.md). |
| [`SUPERSEDES.md`](SUPERSEDES.md) | The map of vexa-platform promotion tooling this factory retires, by file, with disposition. |

## Hard boundaries

- **No production credentials in this repo or its CI, ever.** The publisher consumes released
  artifacts and receipts, not clusters. CI runs entirely on fixtures.
- **Never push into a customer cloud.** The customer pulls, verifies, applies. Support is advisory.
- **Evidence is verifiable offline in the customer's cloud** — signatures and receipts check out
  without calling us; no phone-home is required for the change board to read the bundle.
- **Founder gates**: anything customer-visible, and the first channel publication. Everything else
  runs autonomous with receipts.
