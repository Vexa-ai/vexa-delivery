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

**`station-report.yaml` — one file.** Not a directory, not an archive, nothing to
extract. You are the person who has to approve this before it leaves your
perimeter, so it is written to be read: YAML because you read it all day, and
because it carries comments, so what each section is sits directly above it.

| Section | What it is |
|---|---|
| the head | station name, kit revision, Kubernetes server version, provider, namespaces, contract id + sha256, phase verdicts |
| `profile` | the provider profile used (or an honest stub saying none was) |
| `values` | your values file, structure intact, secrets removed |
| `contract_document` | the contract this run was judged against, verbatim |
| `preflight_receipt` | P1–P9 findings, verbatim |
| `install_log` | only when `--install` ran; a console, so its tail |
| `smoke_receipt` | S1–S4 verdict, chart revision, image digests, segment count |
| `smoke_console` | the smoke run's console — the evidence that survives if smoke dies before writing a receipt |
| `sections` | the sha256 of every section above, and its length |
| `absent` | what could not be produced, and why |
| `redaction` | values removed, and whether the finished file was checked for them |

Send it back to Vexa. It is a configuration contribution you make by hand:
nothing is transmitted from your cluster, you look at the file first, and you
decide whether it leaves.

**Consoles are trimmed to their tail**, with the count in `sections[]`: a console
has no natural length, a run that fails says why in its last lines, and a
document nobody finishes reading is not a document anybody approved. When a trim
happens the whole console is written beside the report, on your disk, and is not
part of what leaves.

## Redaction

Every value whose key matches `password|token|secret|key|apikey` — and everything
nested beneath such a key — is replaced by `REDACTED`. So is the `value` of any
env-var entry whose `name` matches. Empty values stay empty, because "not set" is
configuration, not a secret. The rule is blunt on purpose: a false positive costs
one redacted line, a false negative costs a credential.

`--verify-redaction` (on by default) scans the **rendered document** — the exact
bytes that would be sent, not the values the tool believes it assembled — and
refuses to finish if any plaintext value that redaction removed survived into it.
On a leak it exits 3, names the count, and never names the value. The file is
kept so you can inspect it; do not send it.

## Sending it

```
python3 kit/validate/vexa_validate.py --customer-values my-values.yaml --submit
```

`--submit` validates the document against `report.v1` and against your contract's
`report_scope`, then pushes that one file to the channel host you already pull
from, with your own credential. The thing validated and the thing sent are the
same object: there is no second payload assembled beside it.

`report_scope.allowed_sections` bounds which sections may leave. This clause was
`allowed_files` while the report was six files in a tarball; the old spelling is
**refused rather than ignored** — a bound the tool quietly stopped reading is
worse than one it cannot satisfy — and the refusal names the new spelling.

## Naming

The *station bundle* on the channel (ADR-0007) is the machinery chart Vexa
publishes **into** your cluster. `station-report.yaml` is the return leg: your
station's record travelling the other way. Different direction, different
artifact — and now different words for each, which is the collision this note
used to have to explain.

## Exit codes

`0` all phases passed · `1` a phase FAILed · `2` usage · `3` redaction leak (the
file is kept for inspection; do not send it).

A FAIL is still evidence — often the most useful kind to send. `--continue-on-fail`
writes the report instead of stopping.
