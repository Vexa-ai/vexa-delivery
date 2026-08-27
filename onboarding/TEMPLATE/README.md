# `<customer>` — private delivery channel `<channel-name>`

**Template. Copy this directory, fill it in, and keep your copy out of git.**
`onboarding/*/` is gitignored except this template — see the rule at the bottom
of [`.gitignore`](../../.gitignore) and [ADR-0008](../../docs/adr/0008-repository-apache-2.md).

Why: this repository is **public**. A pack names an estate, a channel, a
delivery date and things said on a call — none of which is ours to show anyone
but the customer it belongs to. The license does not restrain a reader;
absence from the tree does.

Where a filled pack lives: with the account, not with the factory — the
customer's dossier in the business workspace, or a per-customer private
location. Generate it, deliver it, do not commit it.

---

| | |
|---|---|
| Channel | `<channel-name>` |
| Registry | `<registry host / path>` — and whether they mirror into their own registry |
| Verification key | `channel.pub` in this directory — state its grade (pilot key vs. formal ceremony) and which gate moves it to production |
| Subscription | which tier follows `current`; who moves the production pin |
| Contract | starts from [`kit/verify/policy.example.yaml`](../../kit/verify/policy.example.yaml); record when it is hardened and with whom |

## Their first hour

    python3 kit/preflight/vexa_preflight.py --namespace <namespace>
    bash kit/install.sh --provider <provider> \
        --registry <registry> --channel <channel-name> \
        --channel-pubkey channel.pub --customer-values customer-values.yaml
    python3 kit/smoke/vexa_smoke.py --namespace <namespace> \
        --customer-values customer-values.yaml --flows

The smoke receipt from the third command is the acceptance record.

## Their estate, reflected in values (not defaults)

One line per fact that differs from our defaults, each traceable to something
they said or something their cluster reports:

- **Models** — theirs or ours, per tier and per pilot phase.
- **Mail** — which mail edge hosts the flows mailbox, and who provisions it.
- **Call-home** — what may leave their perimeter, off by default.
- **Dashboards / health surfaces** — what they asked to see.

## Contribution lane

The kit is Apache-2.0 ([ADR-0008](../../docs/adr/0008-repository-apache-2.md))
so operators can shape it. Name one scoped first contribution their engineer
can actually land — the operator-side smoke (`kit/smoke/`) is usually the right
size.
