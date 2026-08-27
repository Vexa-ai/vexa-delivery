# publisher — vexa-channel

Turns a released Vexa version into a signed channel entry. Consumes released artifacts
and receipts only — no clusters, no production credentials, by charter.

```
python3 publisher/vexa_channel.py fetch  --release v0.12.23 --out work/inputs
python3 publisher/vexa_channel.py build  --release v0.12.23 --channel acme-stable \
    --entry-seq 1 --vexa-repo ~/dev/vexa \
    --delivery-receipt <internal delivery receipt> \
    --archive work/inputs/vexa-core-v0.12.23.tar.gz \
    --provenance-bundle work/inputs/source-provenance.sigstore.json \
    --trusted-root work/inputs/trusted-root.jsonl \
    --identity sha256:<pubkey fp> --signing-mode test_key --out work/entry
python3 publisher/vexa_channel.py verify --entry work/entry --archive ... --pubkey ...
python3 publisher/vexa_channel.py push   --entry work/entry --ref <host>/vexa/channel/acme-stable \
    --channel-tag <host>/vexa/channel/acme-stable:current --sign-key <key>
```

Named cross-checks C1–C9 (tag identity, map identity, map↔receipt pin, receipt identity,
image consistency, provenance verification, bundle digesting, completeness-or-break-glass,
schema): any failure refuses the entry with exit 3. `build` needs the `jsonschema` package and,
unless `--skip-cosign-verify`, the `cosign` binary; `push` needs `oras` + `cosign`.

## The signing toolchain is pinned — T1 and T2

The publisher signs with **cosign 2.6.5**, not with whatever cosign is on `PATH`:

```
./publisher/install-cosign.sh          # verified against the release's checksum file
export COSIGN_BIN=$HOME/.local/bin/cosign-2.6.5
```

**Why.** The signature *layout* is not stable across cosign's major versions.
Signing an image digest `sha256:<hex>` into a signature repository writes:

| cosign | flags | what lands in the signature repository | Kyverno 1.19 |
|---|---|---|---|
| 2.x | default | tag `sha256-<hex>.sig` — a cosign signature manifest | reads it |
| 3.x | default | tag `sha256-<hex>` — an OCI referrers index over a sigstore bundle v0.3 | `no signatures found` |
| 3.x | `--new-bundle-format=false` | the 2.x layout again | reads it |

Kyverno 1.19 is the version `kit/providers/*` pins and `kit/install.sh` installs, and it
requests exactly one of those. Given the 3.x default it denies a correctly signed image
with a message that says the image is unsigned. `--new-bundle-format` is already
deprecation-warned by 3.x, so the legacy layout is not something to leave resting on a
flag and an ambient binary.

- **T1** — `push`, `sign-images` and `attest` refuse to sign with a cosign outside the
  pinned series and say what would break. `VEXA_COSIGN_ALLOW_UNPINNED=1` overrides it
  loudly, and the signing-run record then says which tool actually signed.
- **T2** — after signing, the publisher asserts the signature is discoverable in the exact
  shape admission will ask for (`sha256-<digest>.sig`, holding a
  `application/vnd.dev.cosign.simplesigning.v1+json` layer) and that it verifies against
  the channel key. It runs inside the push path, so it cannot be skipped. A pin is a
  promise; T2 is the proof.

`--signing-receipt` / `--receipt` write the signing-run record (tool, version, flags, layout,
per-image signature tags) as JSON. **`VERIFY.md` is generated from that record at push time**,
never hand-maintained — the shipped verification instructions are a function of the run that
produced the entry.

## vexa-station — the customer side of the same question

`vexa_channel.py` answers *may this release exist?*. [`vexa_station.py`](vexa_station.py)
answers *may it be published at this customer's station?* — their contract gates our publish.

```
python3 publisher/vexa_station.py ingest --bundle station-report.yaml --station rehearsal
python3 publisher/vexa_station.py gate   --station rehearsal --chart work/chart/vexa-0.12.26.tgz \
    --evidence work/evidence/v0.12.26.json \
    [--waive <require-item> --reason "<why, loudly recorded>"]
```

Checks S1–S9 in the same refusal shape (exit 3): bundle shape · completeness · manifest
identity · **no plaintext secrets** (defense in depth over the customer's redaction) · render ·
resources requests+limits · no hostPath · digest-pinned images · every contract `require:` item
evidenced or explicitly waived. The gate writes `stations/<name>/gate-report-<date>.md` on pass
AND on refusal. Bundle anatomy and the worked SYNTHETIC example: [`stations/README.md`](../stations/README.md).

The committed worked example is [`spec/goldens/v0.12.23/`](../spec/goldens/v0.12.23/) — built
from the real tag (`e59874bc`), the real candidate map, the real compound delivery receipt, and
the real SLSA source-provenance bundle; `test_golden.py` holds it green. Its signature uses an
ephemeral TEST key (`test-cosign.pub`), which the schema confines to `dry_run` — the production
signing model is [ADR-0002](../docs/adr/0002-channel-format.md)'s open decision.
