# kit/validate — one command, from "is this ready" to "here is my evidence"

Preflight asks *will it run here*. Smoke asks *did it work here*. Validate runs
both in order and produces the thing neither does: a portable, secret-free record
of the station as it actually stands.

```
python3 kit/validate/vexa_validate.py \
    --namespace vexa-staging \
    --customer-values my-values.yaml \
    --flows [--meeting-url URL | --non-interactive]
```

Add `--install` (with `--provider --registry --channel --channel-pubkey`) to run
`kit/install.sh` between the two phases — preflight, subscribe, smoke, one command.

## What you get

`station.tar.gz`, containing:

| File | What it is |
|---|---|
| `profile.env` | the provider profile used (or an honest stub saying none was) |
| `values.redacted.yaml` | your values file, structure intact, secrets removed |
| `contract.yaml` | the contract this environment verifies against |
| `preflight-receipt.txt` | P1–P9 findings, verbatim |
| `smoke-receipt-<ts>.md` | S1–S4 verdict, chart revision, image digests, segment count |
| `smoke-console.txt` | the smoke run's console — the evidence that survives if smoke dies before writing a receipt |
| `install-log.txt` | only when `--install` ran |
| `station.json` | date, kit revision, Kubernetes server version, provider, namespaces, contract id + sha256, phase verdicts, redaction result |

Send it back to Vexa. It is a configuration contribution, not telemetry: nothing
is transmitted from your cluster, you look at the file first, and you send it (or
do not) by hand.

## Redaction

Every value whose key matches `password|token|secret|key|apikey` — and everything
nested beneath such a key — is replaced by `REDACTED`. So is the `value` of any
env-var entry whose `name` matches. Empty values stay empty, because "not set" is
configuration, not a secret. The rule is blunt on purpose: a false positive costs
one redacted line, a false negative costs a credential.

`--verify-redaction` (on by default) re-extracts the finished archive and refuses
to finish if any plaintext value that redaction removed still appears anywhere in
it — a bug between the staging directory and the tar would otherwise be invisible.
On a leak it exits 3, names the files, and withholds the values.

## Naming

The *station bundle* on the channel (ADR-0007) is the machinery chart Vexa
publishes into your cluster. `station.tar.gz` is the return leg: your station's
record travelling the other way.

## Exit codes

`0` all phases passed · `1` a phase FAILed · `2` usage · `3` redaction leak (the
bundle is kept for inspection; do not send it).

A FAIL is still evidence — often the most useful kind to send. `--continue-on-fail`
bundles it instead of stopping.
