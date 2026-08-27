# SUPERSEDES — the vexa-platform promotion tooling this factory retires

**Founder ruling (PRD §0c):** this repo must supersede the current promotion tooling, not parallel
it. `vexa-platform` ends up smaller — it stops being a deploy system and becomes one consumer's
site configuration (customer #0 of the channel).

**This map is the retirement plan, not the retirement.** Nothing is deleted by this commit. Each
row is retired in vexa-platform when the conveyor demonstrably owns its function (a channel entry
or kit component doing the same job with evidence), never before. Rows cite files at
`Vexa-ai/vexa-platform` **main = `cee893f`** (2026-08-20, the `promote/0.12.23-rc.21-packet`
merge). Note the long-lived local checkout `~/dev/vexa-platform` is a month stale
(`v012-core-swap`, 2026-07-18) and misses most of this machinery; the map was surveyed against
current main.

Disposition legend — where the function moves in this repo:
**PUBLISHER** (channel publication), **SPEC** (evidence-bundle / predicate contracts),
**KIT** (customer-side verification), **CONTROLLER** (M3 promotion controller — Kargo evaluation
first), **DOCS** (content migrates), **DROP** (function abolished by the pull model).

## 1 · Promotion ceremony (deploy targets and their guards)

| vexa-platform file | Function today | Disposition |
|---|---|---|
| `Makefile` `deploy-prod` (L766–882) | The prod version-forward push transaction: guard chain + six-layer values `helm upgrade` | **CONTROLLER.** Under the conveyor our prod is customer #0: it pulls from the channel; there is no push transaction to run. Retires when prod syncs from the channel. |
| `Makefile` `reconcile-prod`, `rollback-prod`, `history-prod` | Helm-memory reconcile / rollback / history | **CONTROLLER / DROP.** Continuous reconciliation replaces reconcile (obsolete by construction — spike finding); rollback/history become Git/channel-revision operations with different semantics. |
| `Makefile` `deploy-staging`, `deploy-staging-witness` | Staging version-forward push | **CONTROLLER.** Staging becomes validation stage 1 pulling candidate channel entries. |
| `Makefile` `rehearse-prod-baseline`, `rehearse-prod-leg` | Stage rehearsal of the prod push | **DROP.** Rehearses the push mechanics the conveyor abolishes. Render-diff validation moves to SPEC (config-contract gate per release). |
| `operations/scripts/promotion_leg_guard.py` (106 KB) + `test_promotion_leg_guard.py` (69 KB) + `test_promotion_legs.py` | Fail-closed ordering gate, hard-coded to the v0.12.23 legs/revisions; re-baselined twice in three days | **SPEC + CONTROLLER — generalized, never copied.** Its job (evidence-bound authorization of exactly one declared delta) becomes the channel predicate over signed receipts. The revision-anchor half has no equivalent and is rebuilt on channel-entry history. |
| `operations/scripts/test_production_deploy_recipe.py` | Asserts the Makefile text of the push recipe | **DROP** with the recipe it asserts. |
| `operations/scripts/helm_with_bot_continuity.py` | Wraps `helm upgrade`, verifies live-bot identity across the roll | **KIT/CONTROLLER — generalized.** Bot-continuity becomes a sync-hook/health check in the conveyor (PreSync/PostSync), not a CLI wrapper. |
| `operations/scripts/live_bot_deploy_guard.py` | Refuse rollout when live bots could break | Same as above — sync-gate, not push-guard. |
| `operations/scripts/schema_backstop_deploy_guard.py` + test | Refuse candidate to a DB missing its UNIQUE backstop | **SPEC.** Becomes a named preflight/predicate the channel entry declares (state-rides-with-the-release invariant). |
| `operations/scripts/helm_secret_values.py` + test | Resolve live K8s secrets into a 0600 temp values file at deploy time | **DROP.** Pull model: the chart consumes pre-existing Secrets by name (spike-proven); no deploy-time secret injection exists. |
| `operations/scripts/pre-deploy-check.sh` | Pre-push validation (no `:latest`, secrets reachable, DB reachable) | **KIT.** Function moves into the conformance preflight, run in the target cluster before sync. |
| `operations/scripts/stage_rehearsal_live_guard.py` (49 KB) + its 3 test files + `Makefile` `bootstrap-stage-access` / `teardown-stage-rehearsal` | Isolated rehearsal namespace machinery | **DROP** with the rehearsal it guards. |
| `operations/scripts/instantiate-witness-overlay.py`, `check_script_seals.py`, `test_stage_witness_precedence.py` | Witness-overlay seals for the push pipeline | **SPEC — generalized.** Witness receipts become signed evidence attached to the digest set, not values-file seals. |
| `release/lib/stage.py` (46 KB) + `test_stage_gate.py` | The stage state machine (idle→…→release), access-gated transitions, 24 h approval freshness | **CONTROLLER.** Stages become validation environments that produce evidence; transitions become predicates. `ContractSingleSourceTest` (the SSOT precedent) carries over as a pattern for every contract in SPEC. |
| `release/lib/promote.py` | Vestigial blue/green cutover stub ("use make deploy-…") | **DROP** outright (its own docstring proposes deletion). |
| `release/releases/release-0NN-*/` packets (leg values, gate-approval, runbooks) | The per-release push packet | **SPEC.** The channel entry + evidence bundle is the packet's successor; historical packets stay in vexa-platform as record. |

## 2 · Identity, parity and lock machinery (split — the promotion half comes, the site half stays)

| File | Function | Disposition |
|---|---|---|
| `chart/vexa-platform/checks/registry.json` — `NO_MUTABLE_TAGS` | Every image reference digest-pinned | **SPEC + KIT.** Already law; the channel entry is digest-only by schema, and the kit's admission policy enforces pinning in the customer cluster. The lock itself stays in vexa-platform only as site hygiene until the chart is channel-delivered. |
| `registry.json` — `ENV_PARITY`, `NO_EMPTY_RENDERED_ENV`, `WORKLOAD_SET_PARITY` + `release/lib/render_parity.py` + `env-parity-exceptions.yaml` | Staging↔prod structural render parity | **SPEC — generalized** as the config-contract / one-render-one-declared-delta gate bound to a channel entry ("an environment MAY scale or sandbox a workload; it MUST NOT omit one"). Site-specific exception lists stay with the site. |
| `release/locks/run`, `core-run`, `locks/lib/*` | Vendored lock harness + strict current-release gate | **DROP** as promotion authority; vexa-platform may keep it for site checks. |
| `release/checks/chart-hygiene/image-exists-on-registry.sh`, `chart-version-drift.sh`, `image-tag-staging-prod-parity.sh`, `pending-cutover.yaml`, `deploy-correctness/running-images-match-declared.sh`, `deployed-content-assertions.sh` | Digest/tag/deploy-truth checks around the push | **PUBLISHER + KIT.** Publisher verifies every digest resolves before a channel entry exists; the kit verifies running == declared in the customer cluster. (Note `image-exists-on-registry.sh` hardcodes `/home/dima/dev/vexa-platform`.) |
| `release/checks/chart-hygiene/image-has-git-revision-label.sh` | Deliberate always-failing stub: every image must carry `org.opencontainers.image.revision` | **PUBLISHER — implemented for real.** The publisher refuses an image whose provenance does not bind digest→source; the stub's intent lands as code. |
| `release/registry.yaml` + `release/lib/run.py` + `aggregate.py` | 143-check evidence registry → reports | **SPEC** for promotion-lane checks (44 of 143 declared checks do not exist on main — each gets an explicit adopt/drop verdict as its function is absorbed); operations checks stay. |

## 3 · Build & publication

| File | Function | Disposition |
|---|---|---|
| `.github/workflows/release-images.yml` (platform) | CI publish of the two platform-baked images (webapp, transcription-gateway); merged-but-dormant pending CI credentials (#231) | **PUBLISHER** consumes its outputs (digests as receipts). Building stays where the source is; publication *authority* (what becomes a channel entry) moves here. |
| `Makefile` `build` / `push` | Hand build+push of the same two images | **DROP** (already superseded by the workflow; doubly superseded here). |
| `operations/scripts/hc-build.sh` | Hosted-compat fork build of 4 OSS-core images + chart vendoring | **UNRESOLVED — named open question.** Whether the fork disappears (OSS carries the hosted deltas) or the factory absorbs the fork build is a founder/architecture call recorded in ADR-0001 as open. Nothing here depends on it for M0–M2. |
| `docs/delivery-pipeline.md`, `docs/governance/delivery.md`, `operations.mdx` (O-book), `release-model.md`, `release-system.md`, `release-harness.md`, `tests3/promotion-validation.md` (+ siblings) | The written promotion contract; some of it describes retired targets (`make publish`, `make promote-latest`, `promote-preflight` do not exist) | **DOCS.** The accurate content migrates into this repo's spec/ADRs as functions move; stale mechanics are corrected here rather than ported. O-book stays authoritative for operating production. |

## 4 · `Vexa-ai/vexa` release machinery — consumed, not retired

The OSS repo's release machinery is upstream of this factory and stays where it is. The publisher
consumes its outputs as released artifacts:

| vexa file | Relationship |
|---|---|
| `releases/vX.Y.Z/candidate-images.json` (frozen digest map) + `release/candidate-image-map.mjs` | **Input.** The digest set of a channel entry is the tag's frozen map, verified by sha256. |
| `.github/workflows/release-images.yml`, `release-validate.yml` (incl. the `release-promote` Environment gate), `release-attest.yml`, `release-published-guard.yml`, `latest-drift.yml` | **Inputs/receipts.** Build, validation, witness/value gates, SLSA provenance, publish guard — their run URLs and artifacts are evidence-bundle members. The `promote` job's `:v012` alias move stays OSS-side. |
| `scripts/registry-manifest-alias.mjs`, `registry-candidate-validate.mjs` | **Pattern source.** Same-byte alias + descriptor readback is how the channel tag moves; the publisher implements the same discipline against the channel registry. |
| `scripts/release-witness-gate.mjs`, `release-value-gate.mjs`, `scripts/sbom.mjs` | **Inputs.** Witness/value receipts and the SPDX SBOM enter the evidence bundle. |

## 5 · Stays in vexa-platform (cluster-ops / site config — no change)

Infrastructure Terraform (`infra/`), cluster state (`cluster/`), DNS/ingress/certs, secrets
provisioning, backup/data-protection, observability/SLO/incident (`release/lib/monitor.py`,
`observe.py`, `incident.py`), chaos/load/resilience checks, the functional test harness
(`tests3/`), the chart and its site values (shrinking to site config), product source
(`services/`, `analytics/`), and PR-gate CI (`.github/workflows/gates.yml`).
