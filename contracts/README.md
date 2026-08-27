# Internal station contracts

> **Moved (2026-08-25).** `internal-prod.json` now lives in
> the stations ledger (a private repository) at
> `channels/vexa-internal/contracts/internal-prod.json`. **This repository
> carries schemas and examples; contract instances are records and live with
> the records.** The copy under `station/chart/files/contracts/` is the
> *enforcement* copy, derived from the record — when they disagree, the record
> wins.

The machine-readable half of OUR OWN subscriptions to the `vexa-internal`
channel — the same file format a customer pins (see
`kit/verify/policy.example.yaml`). Staging accepts candidates; prod additionally
requires staging's signed `station-verdict` attestation. Installed on the
standing station as ConfigMaps `vexa-contract-staging` / `vexa-contract-prod`.
Changing a file changes its sha256 — every verdict and approval names the
contract id + hash it was rendered under, which is why an instance moves only
by pull request on `vexa-stations`.

| Contract | Where it lives now |
|---|---|
| `vexa-internal-prod-2026` | `vexa-stations` → `channels/vexa-internal/contracts/internal-prod.json` |
| `vexa-internal-estate-2026-08` | `vexa-stations` → `channels/vexa-internal/contracts/policy.internal-estate.yaml` |
| `vexa-internal-staging-…` (`internal-staging.json`) | **still here** — see below |

`internal-staging.json` has NOT been moved. It is an instance by the same test
as the other two and belongs in `vexa-stations` for the same reason; it was
outside the scope of the move that took the other two, and moving it is a
one-line follow-up rather than something to do silently. Until it moves, this
directory holds one record that should be elsewhere.

## Using a contract that lives in `vexa-stations`

Every consumer takes the contract as a **path argument** — nothing resolves
`contracts/` implicitly — so point them at the checkout:

```bash
STATIONS=<stations-ledger>
sh kit/verify/vexa-verify.sh ... \
  --policy "$STATIONS/channels/vexa-internal/contracts/internal-prod.json"
sh kit/install.sh ... \
  --contract-prod "$STATIONS/channels/vexa-internal/contracts/internal-prod.json"
```
