# Sealed definition — security-hardening run, v1

Defines every term a Vexa security-hardening attestation may carry. Its sha256 is embedded in
each attestation and pinned by verifying contracts; the consumer verifies the numbers and their
meaning together. v1 is FROZEN.

## What an agent run is

One **independent adversarial review pass** over the defined scope, executed by one agent with
one named lens, producing findings. Passes are independent: no agent sees another's findings
before producing its own. `agents_run` counts completed passes, not agents configured.

**Lenses** name what the pass hunts: `injection`, `authn-authz`, `secrets-exposure`,
`supply-chain`, `container-escape`, `network-egress`, `data-at-rest`, `dependency-cve`, or
further named lenses; the attestation lists the lenses actually run.

**Scope** is stated per run: `release-diff` (changes since the previous release) or
`full-surface` (the entire codebase/images at the tag). A diff-scoped run claims nothing about
unchanged code.

## Findings and their states

| Term | Meaning |
|---|---|
| `confirmed` | reproduced, or independently verified by a second pass — never a single agent's raw claim |
| `fixed` | the remediation is **in the attested release** (merged before the tag) |
| `open` | confirmed and shipped anyway — a known, disclosed finding |

Severities: `critical`, `high`, `medium`, `low` — per the project's published severity ladder.
Raw (unconfirmed) findings are not attested; they are working material.

## The numbers

```
agents_run                      = completed independent passes
findings.confirmed.<severity>   = confirmed findings by severity
findings.fixed.<severity>       = confirmed findings remediated in this release
findings.open.<severity>        = confirmed − fixed, by severity
```

## What this attestation claims — and does not

It claims: **this process ran, with this many independent passes, over this scope, with these
results.** It does not claim the software is secure, that the lenses are exhaustive, or anything
about scope not named. `agents_run` measures review effort invested, not safety achieved; a
contract may set a floor on effort (`min_agents`) and a ceiling on shipped findings
(`max_open`), and must not read either as a guarantee of absence of vulnerabilities.
