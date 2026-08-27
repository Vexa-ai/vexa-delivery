---
title: "Ticketing — design draft"
description: "Evidence-bound support: the sink, the lanes, automated events, metering."
---

**Status: DRAFT for founder review** · 2026-08-21
**Origin:** founder direction (2026-08-21, this session): *"vexa api here has ticketing system
sink, and we need to design the ticketing system itself here"* · *"they use the ticketing system
for first class support"* (in the context of reproducible per-provider installs — bring your own
AWS, run this command).

## What it is

The support surface of the enterprise delivery product. A BYOC customer's platform team runs our
software inside their governance; when something needs us — an install refusal, an admission
refusal, a health rollback, a platform change breaking capture, a question — the path is a
**ticket bound to delivery evidence**, not a call and a pastebin. First-class support means the
ticket carries the machine state needed to act on it, and its resolution is itself a delivery:
most tickets close as `fixed_in_entry(N)` — a channel entry the customer's cluster pulls.

## Placement — what runs where

| Piece | Where | Why |
|---|---|---|
| **Ticket sink** (ingest API) | the vexa API plane, vendor side | founder: "vexa api here has ticketing system sink". Nothing of ours runs in their perimeter; tickets arrive over egress *they* allow (R5 allowlist — one named endpoint). |
| **Ticket store + lifecycle** | vendor side (our cloud) | support is our obligation; their change board reads state through the same API, pull-only. |
| **`vexa-support` packager** | customer kit (this repo), runs on the operator's workstation | packages a preflight report / admission refusal / rollback event into a ticket payload **locally**, shows the operator exactly what leaves before it leaves. Not a resident agent. |
| **Advisories** (us → fleet) | the channel registry, as signed advisory artifacts | no push into their cloud, ever: advisories are pulled exactly like entries. A sev-high advisory ("Teams changed X; entry N+1 carries the fix") reaches every subscriber on their next poll. |

Blocking egress entirely degrades nothing (R5): ticketing is advisory-lane; an air-gapped
customer files by any out-of-band means and the evidence bundle attaches as files.

## Ticket object — v1 draft

```jsonc
{
  "ticket_id": "…",                    // vendor-assigned
  "subscription": "…",                 // the channel-subscription identity (auth principal)
  "severity": "sev1|sev2|sev3",
  "kind": "install|upgrade|admission_refusal|health_rollback|platform_change|question|break_glass_request",
  "channel_ref": {                     // the delivery coordinates the ticket is about
    "channel": "enterprise-stable",
    "entry_seq": 7,
    "release": "v0.12.23",
    "entry_digest": "sha256:…"
  },
  "cluster": {                         // shape, never content
    "provider_profile": "aws-eks|gcp-gke|azure-aks|openshift|lke|generic",
    "kubernetes_version": "1.36",
    "fingerprint": "…"                 // stable anonymous id derived customer-side
  },
  "evidence": [                        // attached machine state, digest-listed like a bundle
    {"name": "preflight-report.json", "sha256": "…"},
    {"name": "kyverno-refusal.json",  "sha256": "…"}
  ],
  "state": "open|acknowledged|in_progress|advisory_published|fixed_in_entry|answered|closed",
  "fixed_in": {"release": "v0.12.24", "entry_seq": 8}   // when state = fixed_in_entry
}
```

**Data minimization is load-bearing:** payloads carry configuration *shapes* (taints, LimitRange
values, policy names, digests, error strings) and never meeting content, transcripts, names, or
identifiers — same posture as the R5 metrics allowlist, and the `vexa-support` packager shows the
operator the full payload before anything is sent.

## The loop that makes it first-class

1. Machine event in their cluster (preflight FAIL, Kyverno refusal, health-judge rollback,
   break-glass request) → operator runs `vexa-support package <event>` → reviews → sends to the
   sink. Severity and kind are pre-classified by the event type.
2. Our side triages with the evidence already attached — the preflight report names the failing
   check and the §6 failure class; the refusal names the policy and the digest.
3. Resolution rides the conveyor: a fix ships as a channel entry; the ticket flips to
   `fixed_in_entry(N)`; the customer's staging pulls it, their gate promotes it, the ticket
   closes on their confirmation (or their cluster's next successful sync of ≥ N, where they opt
   into reporting it).
4. Fleet-relevant causes (a platform changed under everyone) additionally publish a signed
   advisory on the channel — subscribers see it before they hit it.

`break_glass_request` is a first-class kind: the request for an incomplete-chain publication
arrives as a sev1 ticket, and the approval produces the `break_glass` record inside the signed
entry (ADR-0002 §5) — the audit trail is the ticket + the entry, never a side channel.

## SLA surface (commitment shape only — numbers are commercial)

Severity binds to **delivery latency**, because with a pull conveyor our release latency is the
customer's incident path (Attestation-Conveyor): sev1 = hotfix conveyor cadence (same stations,
shortened soak — never a bypass), sev2 = next scheduled entry, sev3 = advisory/answer. The actual
numbers are part of the subscription contract and the §9 Q3 pricing decision — not set here.

## Automated events — founder direction 2026-08-21 (same session)

The pipeline must also let the deployment **call the sink itself** for a set of predefined
events — entirely optional, off by default, every event class individually enabled by the
customer: vendor-bound bandwidth **fully under their control**.

- **Event classes (initial set):** `health_degraded` · `sync_failed` · `prod_promotion` (their
  pin moved and synced — the promotion notification) · `admission_refusal` · `incident_report`
  (composed bundle) · `usage_report` (metering, below).
- **Mechanism — no new resident software:** Argo CD's **stock notifications engine**
  (triggers + templates, configuration we ship) posts to the sink with the subscription
  credential; Kyverno policy reports feed refusal events. This preserves the kit's claim
  verbatim: we ship configuration, not an agent.
- **Contract:** same shapes-not-content payloads; every class off by default; blocking all of it
  degrades nothing (advisory lane, R5-consistent).

## Behind the sink — the vendor-side architecture (founder question 2026-08-21: "what's behind the sink?")

The sink itself is deliberately thin; the machinery behind it reuses what the company already
runs. Nothing here is a new helpdesk product.

```
customer egress (their switch)
   │ POST, subscription-credential auth
   ▼
SINK  (vexa API plane — thin ingest: authn → schema-validate → assign id → persist → ack)
   │
   ├─▶ EVENT LOG        every payload, verbatim, append-only
   │      ├─ usage_report events  ─▶ billing reconciliation (Q3 machinery, when decided)
   │      └─ promotion/health/sync events ─▶ per-subscription state (fleet picture)
   │
   ├─▶ PROMOTION RULES  events → tickets, by rule: severity classes and thresholds
   │      (an operator-filed ticket enters as a ticket directly; a health_degraded
   │       event becomes a ticket only when its rule says so — e.g. N in M minutes)
   │
   ├─▶ TICKET STORE     system of record for status (DB) + evidence blobs by digest
   │      │                (object storage; retention/residency = open founder question)
   │      └─▶ GITHUB ISSUE BRIDGE — every ticket materializes as an issue in a private
   │            support repo, labeled subscription/severity/kind. THIS is the human
   │            workflow: the same issue-driven machinery the whole company runs on.
   │            A fix rides the release train; the closing release ref flips the
   │            ticket to fixed_in_entry. No separate helpdesk UI to build or staff.
   │
   ├─▶ PAGING           sev1 → the existing out-of-band notify broker (Telegram),
   │                    same channel every other production alert uses
   │
   └─▶ STATUS API       pull-only: the customer polls ticket state with the same
                        subscription credential. Nothing calls back into their cloud;
                        fleet-wide notices go out as signed channel advisories.
```

Decisions this encodes (all reuse, no invention):

1. **Two lanes behind one sink.** Events (high-volume, no human) and tickets (action-needed)
   share ingest and schema but not workflow; promotion rules are the only bridge. This is what
   makes "tickets might be health callbacks built automatically" true without drowning support
   in telemetry.
2. **GitHub Issues are the workflow, not a copy of it.** The bridge means a sev1 platform_change
   ticket *is* a scope item the release train can pick up, and `fixed_in_entry(N)` closure falls
   out of the existing close-with-release discipline rather than being built.
3. **The store is boring**: the vendor-side DB + object storage that already exist; evidence
   blobs stored by digest exactly like bundle members.
4. **Which vexa API service hosts the thin ingest** remains the named open question below
   (admin-api is the natural candidate); everything behind it is service-agnostic.

## The customer-facing lane — email confirmation or private repo? (founder question 2026-08-21)

Both patterns exist in industry; they serve different organizations. The resolution is to keep
three surfaces distinct and make the human lane per-subscription configuration:

1. **The internal workflow repo is never customer-visible.** One private repo, internal-only,
   mirroring the ticket store — where the release train picks work up. Customers hold no access
   of any kind, which removes the cross-tenant-leak class by construction. (One shared repo
   *with* customer access is the one option that is simply wrong — never.)
2. **Default customer lane: email, bound to the ticket.** On ingest the customer contact gets a
   confirmation carrying the ticket id; every state change (acknowledged, `fixed_in_entry(N)`,
   closed) goes out on the same thread; replies to `tickets+<id>@` thread back into the ticket.
   Why default: **email is the universal ITSM adapter** — ServiceNow and Jira ingest it
   natively, so the customer's own ticket system stays in sync without any integration project;
   change boards and on-call rotations live there; zero identity or licensing friction; works
   for the most compliance-bound subscriber.
3. **Offered lane for engineer-led subscriptions: a per-customer private repo**
   (`support-<subscription>`), outside-collaborator access only, with the sync bot mirroring
   ticket state and conversation both ways. The reference enterprise engagement arrived through
   a GitHub issue — engineer-champions live there, and for them issues ARE the natural support
   object. Two disciplines make it safe: **evidence never leaves the store** (issues carry
   digests and pointers, not blobs — sensitive payloads stay off GitHub, which also keeps the
   data-residency question tractable), and access is per-repo outside collaborators, never org
   membership. Cost note: outside collaborators on private repos consume paid seats — a small
   per-customer line.
4. **The machine API stays canonical** regardless of lane: the sink ingests, the status API
   answers, and both human lanes are projections of the same ticket store.

**Build order:** internal repo bridge + outbound email first; inbound email (the ITSM bridge)
second; per-customer repos third — config-light once the sync exists.
**Prerequisite (founder):** a transactional sender (`tickets@vexa.ai`) set up properly; and the
residency decision may exclude the GitHub lane for some subscriptions — the lane being
per-subscription configuration is exactly the accommodation for that.

## Email lane — implementation sketch (and the ownership boundary)

**Ownership first (founder observation 2026-08-21: "that's largely outside the delivery
product" — correct).** This repo owns the *contract*: the ticket schema, the sink API shape, the
kit's emitter configuration, and the `fixed_in_entry` coupling to channel entries. The
implementation — sink service, event log, ticket store, promotion rules, email bridge, GitHub
bridge, status API — is **vendor API-plane machinery** and belongs with the vendor-side services
(vexa-platform's proprietary services are the precedent home), tracked as an issue there when the
founder says go. Nothing in M3 depends on it.

**Outbound (build first):**

- A dedicated **transactional email provider** (Postmark/SES-class), never Workspace Gmail —
  deliverability, suppression handling and volume are the provider's job. Sender
  `tickets@vexa.ai`; SPF/DKIM/DMARC on a dedicated return-path subdomain via our DNS. Provider
  signup + DNS changes are founder-gated ops (already flagged as the prerequisite).
- **Threading is the feature:** first mail sets a stable `Message-ID`; every state change replies
  with `In-Reply-To`/`References` plus a `[VEXA-<id>]` subject token. That is exactly what makes
  Gmail, Outlook, ServiceNow and Jira keep the whole ticket as one thread — the ITSM bridge is
  the threading discipline, not an integration.
- Plain-text templates: confirmation (ticket id + what was received), state changes
  (`acknowledged`, `fixed_in_entry(N)` with the release ref, `closed`).

**Inbound (build second):**

- `tickets+<id>@vexa.ai` plus-addressing; MX/inbound-parse at the provider posting a webhook to
  the support service. Acceptance requires **both** the plus-address ticket id and a
  DKIM/SPF-passing sender that matches the ticket's contacts — the id alone is a weak capability,
  the pair is sturdy. Attachments are stored as evidence blobs by digest with size caps; loop
  hygiene (`Auto-Submitted`, suppression, never reply to bounces).

**One writer per surface (the house invariant, applied):** the ticket store is the single system
of record; email and GitHub-issue comments are *projections* of it, and inbound from either lane
lands in the store first, then projects outward. The sync bot is one process owning both mirrors
— never two writers on one surface.

**Effort shape:** outbound ≈ provider account + DNS + a day of service code; inbound ≈ two to
three days including auth hygiene. Neither blocks anything in the delivery product.

## The two-way evidence channel — founder reframe 2026-08-21

*"Validation evidence channel. We send our validations, they send theirs back to us (support
API)."* This names what the event lanes above actually are: the upstream half of the channel.

- **Down:** our evidence — staging validation, prod soak, provenance, signatures.
- **Up (opt-in, per class, their switch):** their evidence — `validation_report` (their
  staging/gate verdicts; the kit's `approve.sh` already produces the payload: release, verdict,
  verdict hash, approver, entry digest), plus the existing classes (health, sync, promotion,
  refusals, usage).

**Why it compounds:** release N+1 can ship with evidence nobody else can mint OR aggregate —
"validated in Vexa's prod and in K subscriber stagings across their providers." Every subscriber
strengthens the promise for all; a later competitor starts with a fleet of zero. This is the
network effect on evidence — the moat is the loop, not the signature.

**Honesty rule:** fleet evidence enters entries as its own kind, signed by the reporting
environment's identity (ADR-0004's N-identities), never blended into our receipts. A customer
who sends nothing back still receives the full down-channel; they simply do not strengthen it.

## Metering — the founder's question: "is that the product we charge against?"

Assessment for the §9 Q3 pricing decision — the decision itself stays open:

- **Industry practice for BYOC/self-managed is self-reported usage under contract, with
  true-up/audit clauses** — GitLab self-managed usage ping plus an offline usage file for
  air-gapped renewals; Atlassian Data Center self-declared user tiers; Red Hat self-declared
  subscriptions; cloud-marketplace metered billing as the procurement-friendly variant later.
  Structurally, in BYOC the vendor cannot measure independently — the pipe is convenience and
  evidence; **the contract is the enforcement** (pipe off ⇒ manual report per contract; the
  product itself is never degraded).
- **The shape that fits us:** per-cluster channel subscription as the floor (the access
  product) **plus one agreed usage dimension as the scaler** (e.g., active accounts /
  activation events), reported through this pipe on an agreed cadence.
- **Two requirements before charging on it:**
  1. **A sealed definition of the metric** — one definition, one carrier, queryable by the
     customer themselves so both sides compute the same number from the same source. (House
     lesson: an ambiguously-defined metric poisons every conversation it enters; the metering
     dimension gets a sealed schema'd definition or it does not get billed on.)
  2. **Signed usage reports** — the report is a signed statement from the customer's side, using
     the same attestation machinery the delivery already carries. True-ups then compare
     receipts, not recollections. Nothing standard in the industry does this; for us it is a
     small extension and turns billing disputes into hash comparisons.
- **Open (founder, Q3):** the dimension itself, price levels, cadence, and whether the
  marketplace route (AWS/Azure/GCP metered private offers) is worth its integration cost.
  Nothing metering-related enters the customer docs until Q3 is decided — a documented metric
  is a published term.

## Open questions (founder)

1. **Which vexa API service hosts the sink** (and its auth = the subscription credential?). The
   sink contract will be filed as an issue on the owning repo once named — customer-visible, so
   founder-gated.
2. **Portal or API-only at v1?** API-only + email bridge is the cheapest honest start.
3. **Retention / data residency** for ticket evidence (regulated buyers will ask).
4. **Tier mapping** — which response/delivery SLAs at which subscription tier (couples to §9 Q3).

## What this is not

Not a general helpdesk product, not a status page, not telemetry (R5 metrics stay separate), and
not a resident agent in the customer's cluster. The kit ships a packager and configuration; the
system of record is vendor-side.
