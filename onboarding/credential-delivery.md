# Delivering a channel credential

A subscriber needs two things to consume a Vexa channel, and they travel by
different routes on purpose:

| Artefact | What it is | Route | Secret? |
|---|---|---|---|
| `channel.pub` | the channel's cosign public key | published in this repo (`onboarding/<sub>/channel.pub`) and read aloud on a call | no |
| registry credential | `<account>:<password>` for the channel registry | one of the four routes below, in this order | **yes** |

The public key is not a secret and must not be treated as one — its whole job is
to be verifiable independently of us.

## The order

Take the first route that applies. They are ordered by how few people end up able
to read the value, not by how convenient they are for us.

**1 · Their own intake, if they have one.** Ask first, before offering anything:
*"do you have a vendor-credential intake we should use?"* An enterprise with a
1Password or Vaultwarden share, a ServiceNow secret request, or a security-team
handoff has already decided how secrets reach their engineers, has already
audited that decision, and does not want ours. Using theirs costs us nothing and
skips every question below.

**2 · A claim code, on a call.** The default when they have no intake. We mint,
seal the value to the channel edge's key, and park it under a **six-digit code**
with a fifteen-minute life. We read the six digits aloud; their cluster exchanges
them for the credential and writes the Secret. **Nobody on their side ever sees
the value.**

**3 · Encrypted to a key they already hold — only if they ask.** Not offered
first: it puts the value in a file somebody keeps, and it needs a key-identity
step only a human can be accountable for.

**4 · Never in writing.** Not in mail, not in chat, not in a ticket, not in a
document, not in a meeting transcript, not in a screenshot. That is not a fourth
route — it is what the first three exist to avoid.

## Mint

```bash
# needs SSH to the standalone channel host: $CHANNEL_REGISTRY_SSH, $CHANNEL_ROOT
# and $CHANNEL_EDGE_URL from config/channel.env (RUNBOOK § 5.4)
python3 publisher/vexa_subscriber.py add <subscriber>
```

The tool rewrites the host's `htpasswd` and `env`, recreates the stack, and
proves the new credential against the live `/v2/` **before** printing it — a
credential that reaches your screen has already authenticated once.

The password is printed **once**, to stdout, and is not recoverable afterwards.
Vault it immediately in the operator's secrets vault
(`$CHANNEL_CREDENTIAL_VAULT`, see [`config/channel.example.env`](../config/channel.example.env)),
then deliver it by the route above. If the value is lost, run `add` again — it
rotates rather than duplicating.

## Route 2 — the claim code

Mechanics and the rotation gap: [RUNBOOK § 5.5](../RUNBOOK.md). Design, threat
model and deploy note: [`edge/claim/README.md`](../edge/claim/README.md).

On the call, with them at a terminal:

```bash
python3 publisher/vexa_subscriber.py add <subscriber> --park \
  --channel <channel> --station <station>
```

Two lines on stdout. Line 1 is `<account>:<password>` — vault it, as always.
Line 2 is the code, and it is the only thing you say out loud:

```
123 456
```

Six digits, grouped in threes for reading. They type them with the space or
without; both are the same code.

They run one of these — the first if they are installing now, the second if the
cluster is already installed or they are taking a rotation:

```bash
./kit/install.sh --provider <provider> --registry <registry> \
  --channel <channel> --channel-pubkey channel.pub \
  --claim-code 123456 --station <station>

./kit/claim.sh --code 123456 --edge https://<channel host>/claim \
  --station <station> --namespace <their prod namespace>
```

Nothing is printed but a receipt: the station, the Secret, the namespace. The
value is in the cluster and nowhere else.

**Read the code, do not send it.** A code in a chat message is a password in a
chat message, one step removed: short-lived, but for those fifteen minutes it
*is* the credential to anyone who can read that channel.

**Six digits is safe because it is counted, not because it is long.** Five wrong
attempts burn the park — 5 in 1,000,000, once — and the edge allows ten attempts
a minute from any one source before shutting that source out for fifteen
minutes, plus twenty a minute per station from everyone together. If a code is
burned or expires, you park again, which rotates. The arithmetic is in
[`edge/claim/README.md`](../edge/claim/README.md).

**Park during the call, not before it.** The clock starts at `--park`. A code
parked "to save time" while you wait for someone to join spends its life on the
waiting.

Afterwards, close the return leg so the record is complete:

```bash
scp $CHANNEL_REGISTRY_SSH:$CHANNEL_ROOT/claims/attempts.ndjson .
python3 publisher/vexa_stations.py record-credential \
  --channel <channel> --events attempts.ndjson
```

### The mirror path

A platform engineer mirroring the channel into Harbor, Artifactory or ECR has to
paste the credential into an endpoint form — a registry's own configuration
cannot read a Kubernetes Secret. `./kit/claim.sh --code <code> --edge <url>
--station <name> --print-once` prints it, once, after saying that the code is now
spent and the value exists only where they put it. It is the one path here that
puts a credential on a screen, and it is their screen, on their machine, at their
keyboard.

## Route 3 — encrypted to a key they already hold

Only when they ask for it. Use [`age`](https://github.com/FiloSottile/age)
against a key the recipient already holds and has already proven control of. An
SSH public key from their GitHub account is the usual one — no new key ceremony,
no key exchange to get wrong:

```bash
curl -fsS https://github.com/<their-handle>.keys > /tmp/recipient.keys
age -R /tmp/recipient.keys -a -o channel-credential.age <<< '<subscriber>:<password>'
```

The armored output is safe to paste into email or a ticket; only the holder of
the matching private key can read it. They open it with:

```bash
age -d -i ~/.ssh/id_ed25519 channel-credential.age
```

**Confirm the handle out of band** — over a call, or against an address on their
corporate domain — before pulling keys from it. Pulling `.keys` from a handle
someone sent you in the same message as the request is how the credential ends up
encrypted to the wrong person.

There is deliberately no script for the recipient-identity step, because that
step is the one a human has to be accountable for. Route 2 removes the need for
it rather than automating it: a claim code is bound to a station and a fifteen-
minute window, not to an identity somebody had to verify by reading a fingerprint
aloud.

## What the subscriber does with it

```bash
oras login <registry> -u <subscriber> --password-stdin
oras pull <registry>/vexa/channel/<subscriber>-stable:current -o entry/
cosign verify-blob --key channel.pub \
  --bundle entry/entry.json.sigstore.json \
  --new-bundle-format=false --insecure-ignore-tlog=true entry/entry.json
```

The credential is **pull-only**. Writes are refused at the edge — see
[RUNBOOK § 5.2](../RUNBOOK.md) for why that gate lives in the proxy rather than in
the registry.

## Rotation and revocation

```bash
python3 publisher/vexa_subscriber.py add <subscriber>            # rotate
python3 publisher/vexa_subscriber.py add <subscriber> --park …   # rotate + deliver
python3 publisher/vexa_subscriber.py revoke <subscriber>         # revoke
```

Rotating and onboarding are the same act against the registry; only the delivery
leg differs. Rotate on any suspicion — nothing the subscriber already pulled is
invalidated, because what they hold is signed and verifiable without us.

**A rotation has a gap, and it is not where you would expect.** The registry's
htpasswd holds one hash per account, so the old credential stops working the
moment `add` writes the new line — *before* the new one is claimed, not after. On
the happy path that is the length of one `claim.sh`, with them on the phone to
close it. Where a gap is unacceptable, park a second account (`<account>-next`),
let them claim it and prove a pull, then revoke the old one.
[RUNBOOK § 5.5](../RUNBOOK.md) carries both procedures and why there is no grace
timer.

## Later hardening: a PAKE

The claim code is a lookup key plus rate limiting over TLS, and the edge holds
the key that opens the parked value. A PAKE — SPAKE2, the shape magic-wormhole
uses — would make the code itself the shared secret both ends derive a session
key from, leaving the edge holding ciphertext it cannot open.

**Not built, and not needed for the first version.** The edge is already inside
the trust boundary: it is our host, beside the registry's own credentials, so
compromising it already yields the channel. And the cost is not the maths but the
shape — a PAKE is a rendezvous, needing both ends online at the same moment,
which is precisely what a claim code avoids. It becomes the right trade the day
the rendezvous stops being ours. Full argument:
[`edge/claim/README.md`](../edge/claim/README.md).
