# Gate report — station `rehearsal` · 2026-08-25

**Verdict: PASS**

| | |
|---|---|
| Station | `rehearsal` |
| Chart | `vexa-0.12.40.tgz` |
| Chart sha256 | `0b055bcc43944e9dbdea914488279223a951ab0bb1086a53cee72c0f90942ce6` |
| Station values sha256 | `0e99ad5cec48ad0fa880bb11b5b4c545ffed0a13fd6ea0b70828e2669dcb4a54` |
| Contract | `rehearsal-2026-01` @ `f203751bc593f9e63ce19810d704c5903343815de76cfe4f03e870d414aec562` |
| Evidence | `/tmp/hardening-live/evidence.json` |
| Gated at | 2026-08-25T12:28:31Z |

## Environment checks

| Check | What it holds | Verdict |
|---|---|---|
| S5 | the chart renders with the station's values | PASS (26 objects) |
| S6 | every container declares cpu+memory requests and limits | PASS |
| S7 | no workload mounts a hostPath volume | PASS |
| S8 | every image reference is digest-pinned | PASS |
| S10 | objects stay inside ['vexa-staging', 'vexa-prod'] | PASS |
| S11 | cluster-scoped objects allowed: False | PASS |
| S12 | Pod Security Standards level `baseline` (PSS/SCC vocabulary) | PASS |
| S13 | images come from ['docker.io/vexaai/', 'harbor.example.invalid/vexa-mirror/'] | PASS |
| S14 | sum of requests within {'cpu': '16', 'memory': '32Gi'} | PASS |

## Delivery scope — what this release may DO here

Stated by the station, enforced above (S10-S14) in Pod Security Standards / SCC and OLM-shaped vocabulary. This gate sees the RENDERED chart; the customer's own Pod Security admission and Kyverno see what actually runs, and where the two disagree the cluster is right.

| Clause | Value |
|---|---|
| `allow_cluster_scoped` | `False` |
| `allowed_image_registries` | `['docker.io/vexaai/', 'harbor.example.invalid/vexa-mirror/']` |
| `allowed_namespaces` | `['vexa-staging', 'vexa-prod']` |
| `pod_security` | `baseline` |
| `resource_ceiling` | `{'cpu': '16', 'memory': '32Gi'}` |

## Contract items

| Item | Verdict | Detail |
|---|---|---|
| `german-teams-meeting-validated` | **MET** | matched by --evidence guarantees |
| `images-digest-pinned` | **MET** | matched by --evidence guarantees |
| `no-hostpath` | **MET** | matched by --evidence guarantees |

---

Produced by `publisher/vexa_station.py gate`. The station's contract gates our publish: this report is the per-release guarantees document for this station, and it is generated, not written.
