# Gate report — station `rehearsal` · 2026-08-24

**Verdict: PASS**

| | |
|---|---|
| Station | `rehearsal` |
| Chart | `vexa-0.12.26.tgz` |
| Chart sha256 | `6f526076c257380e2ad891fc25558725a514938ae0a78e75244b4d48bc65072c` |
| Station values sha256 | `0e99ad5cec48ad0fa880bb11b5b4c545ffed0a13fd6ea0b70828e2669dcb4a54` |
| Contract | `rehearsal-2026-01` @ `384cc8e3a7c95a2f2cdb92823e85932805210d64428982ba64bb59968931b59c` |
| Evidence | `work/evidence-v0.12.26.json` |
| Gated at | 2026-08-24T14:30:43Z |

## Environment checks

| Check | What it holds | Verdict |
|---|---|---|
| S5 | the chart renders with the station's values | PASS (26 objects) |
| S6 | every container declares cpu+memory requests and limits | PASS |
| S7 | no workload mounts a hostPath volume | PASS |
| S8 | every image reference is digest-pinned | PASS |

## Contract items

| Item | Verdict | Detail |
|---|---|---|
| `german-teams-meeting-validated` | **MET** | matched by --evidence guarantees |
| `images-digest-pinned` | **MET** | matched by --evidence guarantees |
| `no-hostpath` | **MET** | matched by --evidence guarantees |

---

Produced by `publisher/vexa_station.py gate`. The station's contract gates our publish: this report is the per-release guarantees document for this station, and it is generated, not written.
