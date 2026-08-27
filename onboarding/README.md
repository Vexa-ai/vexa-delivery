# Onboarding pack — Vexa Delivery subscriber (MVP0 template)

What a new subscriber receives (assembled per pilot, founder-gated since
customer-visible):

1. **Credential** — pull-only registry token scoped to your channel.
2. **`channel.pub`** — the verification key your admission policy pins.
3. **Docs** — the published customer docs (install → preflight → verify →
   operations → security → support → co-design).
4. **Customer values template** — `kit/profiles/vexa/customer-values.example.yaml`;
   your copy stays in your cluster.
5. **Support address** — tickets@vexa.ai (threads carry your ticket id).

First hour: run the preflight; run `install.sh` with your provider; watch your
staging pull the current release; move your production pin when your gate says so.

## Where a real pack lives

**Not here.** [`TEMPLATE/`](TEMPLATE/README.md) is the shape; a filled pack is
generated per subscriber and kept with the account. `onboarding/*/` is
gitignored except the template — this repository is public, so a customer's
estate details must not sit in the tree at all. See
[ADR-0008](../docs/adr/0008-repository-apache-2.md) and
[ADR-0009](../docs/adr/0009-public-visibility.md).
