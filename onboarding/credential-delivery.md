# Delivering a channel credential

A subscriber needs two things to consume a Vexa channel, and they travel by
different routes on purpose:

| Artefact | What it is | Route | Secret? |
|---|---|---|---|
| `channel.pub` | the channel's cosign public key | published in this repo (`onboarding/<sub>/channel.pub`) and read aloud on a call | no |
| registry credential | `<account>:<password>` for `channel.vexa.ai` | age-encrypted to a key they already control | **yes** |

The public key is not a secret and must not be treated as one — its whole job is
to be verifiable independently of us. The credential is a secret and never
travels in email, chat, a ticket, or a shared document.

## Mint

```bash
export KUBECONFIG=<production LKE admin kubeconfig>
python3 publisher/vexa_subscriber.py add <subscriber>
```

The password is printed **once**, to stdout, and is not recoverable afterwards.
Two things happen next, in this order, before the terminal is closed:

1. vault it — the operator's secrets vault (`$CHANNEL_CREDENTIAL_VAULT`, see `config/channel.example.env`), as
   `CHANNEL_SUB_PILOT_USER` / `CHANNEL_SUB_PILOT_PASS`;
2. encrypt it for the recipient.

If the value is lost, run `add` again — it rotates rather than duplicating.

## Encrypt for the recipient

Use [`age`](https://github.com/FiloSottile/age) against a key the recipient
already holds and has already proven control of. An SSH public key from their
GitHub account is the usual one — it means no new key ceremony and no key
exchange to get wrong:

```bash
curl -fsS https://github.com/<their-handle>.keys > /tmp/recipient.keys
age -R /tmp/recipient.keys -a -o channel-credential.age <<< '<subscriber>:<password>'
```

The armored output is safe to paste into email or a ticket; only the holder of
the matching private key can read it. They open it with:

```bash
age -d -i ~/.ssh/id_ed25519 channel-credential.age
```

Confirm the handle out of band — over a call, or against an address on their
corporate domain — before pulling keys from it. Pulling `.keys` from a handle
someone sent you in the same message as the request is how the credential ends
up encrypted to the wrong person.

This document is a reference, not a tool: there is deliberately no script that
automates the recipient-identity step, because that step is the one a human has
to be accountable for.

## What the subscriber does with it

```bash
oras login channel.vexa.ai -u <subscriber> --password-stdin
oras pull channel.vexa.ai/vexa/channel/<subscriber>-stable:current -o entry/
cosign verify-blob --key channel.pub \
  --bundle entry/entry.json.sigstore.json \
  --new-bundle-format=false --insecure-ignore-tlog=true entry/entry.json
```

The credential is **pull-only**. Writes are refused at the edge — see
`vexa-platform/cluster/channel-registry-ns/README.md` § security model for why
that gate lives in the proxy rather than in the registry.

## Rotation and revocation

```bash
python3 publisher/vexa_subscriber.py add <subscriber>      # rotate: new password, same account
python3 publisher/vexa_subscriber.py revoke <subscriber>   # revoke: effective within ~1 minute
```

Revocation takes effect when the registry Deployment finishes rolling, which the
CLI waits for. Rotate on any suspicion; there is no cost to it beyond one
delivery round trip, and nothing the subscriber already pulled is invalidated —
what they hold is signed and verifiable without us.
