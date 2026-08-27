---
title: "M2 kit test — throwaway LKE"
description: "The customer kit proven end-to-end: install, pull, admit, deny, the prod gate, every preflight failure class."
---

**Cluster:** a throwaway LKE cluster, us-sea, k8s 1.36.3, 2× g6-standard-2, tagged
`throwaway`, created and destroyed the same day by this session (cluster id and name in the
session log, not here). **Registry:** in-cluster
`registry:3` with self-signed TLS (Service `registry.channel-registry.svc:5000`, NodePort for the
operator side). **Signing:** the ephemeral test key of the M1 worked example (schema-confined to
dry-run). No production credential of any kind was used on or near this cluster.

## What was proven, in order

1. **One-command install** — `kit/install.sh --provider lke …` ran preflight (PASS on the clean
   cluster), installed pinned Argo CD v3.5.1 + Kyverno v1.19.0, applied both admission policies,
   registered the channel registry, and created the ApplicationSet, which generated both
   Applications (`vexa-enterprise-staging`, `vexa-enterprise-prod`).
2. **The channel flows** — the v0.12.23 channel entry (entry.json + evidence bundle + a
   digest-pinned demo Deployment under `manifests/`) was pushed as an OCI artifact, tagged
   `v0.12.23` (immutable) and `current` (pointer, same-byte). The staging Application pulled
   `current`, rendered, synced: **Synced / Healthy**, pod `vexa-mcp-demo` Running in
   `vexa-staging` with image `docker.io/vexaai/v012-mcp@sha256:a5d45bd7…` (the exact digest the
   channel entry names).
3. **Admission verifies independently** — before the signature was correctly published, Kyverno
   REFUSED the sync twice (TLS-unverifiable signature repo; then no signature found) — the
   refusals are the mechanism working. After publication:
   - signed digest-pinned image → **admitted**;
   - `vexaai/v012-terminal@sha256:e98025e2…` (valid release digest, never signed) → **denied**:
     "no signatures found";
   - `vexaai/v012-mcp:v0.12.23` (mutable tag) → **denied by both policies** (digest-pinning +
     "missing digest").
4. **The customer gate** — `vexa-enterprise-prod` tracked position `UNPINNED` and synced nothing.
   One customer-side patch moved the pin to `v0.12.23`; prod synced: **Synced / Healthy**, pod
   Running in `vexa-prod`. Nothing on the vendor side moved that pin.
5. **The preflight catches every handoff-§6 failure class** — seeded deliberately, then caught
   (full outputs in the sibling `2026-08-21-preflight-*` files):

   | §6 class | Seeded as | Caught |
   |---|---|---|
   | taints/tolerations | `vexa-test/dedicated=true:NoSchedule` on every node | **P1 FAIL**, naming the taint, for the rendered workload and the dynamic bot profile |
   | LimitRanges vs declared resources | LimitRange default 64Mi + max 1Gi | **P2 FAIL** — undeclared container named with "the LimitRange would silently assign it 64Mi (the exact 64Mi-squeeze class)"; bot limit 2560Mi > max 1Gi named |
   | SCC/PodSecurity | ns label `pod-security.kubernetes.io/enforce: restricted` | **P4 FAIL** — runAsNonRoot / allowPrivilegeEscalation / drop-ALL / seccomp, per container, incl. the bot (which ships no securityContext today — the audit's finding). SCC uid-range logic is unit-tested against the OpenShift audit fixture |
   | netpol reachability | default-deny egress NetworkPolicy | **P5 FAIL** static (no DNS allowance) **and P5-live FAIL** — in-cluster probe: DNS resolution failed, registry unreachable (Cilium enforced the deny) |
   | shm | bot 2Gi Memory-medium /dev/shm + 2560Mi limit vs max 1Gi | **P6 FAIL** — refused at admission, remedy names the 2560Mi floor |
   | image pull (spike finding 8) | pull probe on a not-present digest | **P7 FAIL** — containerd NotFound surfaced in plain language |

6. **The preflight's own probes must be admissible** — first live run was refused by PSA
   restricted (the probe pods lacked hardened securityContexts). Fixed: probes now run fully
   restricted-compliant (runAsNonRoot 65532, drop ALL, seccomp RuntimeDefault), honoring the
   documented `--overrides` container-replacement trap.

## Deltas the live run forced into the kit (all committed)

- `install.sh` applies the upstream Argo/Kyverno manifests **server-side** (the ApplicationSet CRD
  bursts the 256KB client-side annotation limit — spike finding 6 reproduced) with
  `--force-conflicts` (the installer owns what it installs).
- Kyverno's `--allowInsecureRegistry` flag must be **rewritten, not appended** (upstream carries
  `=false`; a blind append leaves both).
- Kyverno needs the **registry CA as a trust bundle** for signature fetch —
  `--allowInsecureRegistry` does not cover that TLS path in v1.19; `--registry-ca` now does this
  properly (Mozilla roots + corporate CA, so public-registry digest resolution keeps working).
- **cosign v3 signs in the new bundle format by default; Kyverno 1.19 finds only legacy `.sig`
  tags.** Channel image signing uses `--new-bundle-format=false --use-signing-config=false
  --tlog-upload=false` until Kyverno reads bundle-format referrers.
- Argo's OCI client refuses plain-HTTP registries regardless of repo-secret `insecure`; test rigs
  need self-signed TLS rather than plain HTTP.

## What this test does NOT claim

No full Vexa stack was deployed (backing services, migrations, secrets are the platform chart's
own story; the spike measured that separately). No OpenShift cluster was touched — SCC logic is
audit-grounded and unit-tested, not cluster-proven. The signing chain used a test key; the
production signing model is ADR-0002's open decision. Argo does not cosign-verify the channel
*entry* artifact itself at pull time — entry verification runs operator-side (`vexa-channel
verify`) and per-image verification runs at admission; the gap and its closure options are
recorded in ADR-0003.

## Teardown

Namespaces deleted, node taints removed, cluster destroyed via `linode-cli lke cluster-delete
<id>` (receipt in the session log). No PVCs were created; no NodeBalancers were provisioned;
nothing survives the cluster.
