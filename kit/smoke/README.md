# kit/smoke — human-in-the-loop acceptance test

The preflight asks "will this cluster run it"; smoke asks "did it actually work
here". One command after install or upgrade:

    python3 kit/smoke/vexa_smoke.py --namespace vexa-staging \
        --customer-values customer-values.yaml [--flows]

S1 delivered set healthy → S2 control plane answers over operator port-forwards
→ S3 THE HUMAN LOOP (open a real meeting, admit the bot, speak; the CLI streams
the transcript back and counts segments) → S4 flows tier vocabulary → a dated
markdown **receipt** with chart revision, image digests, meeting id and segment
count. The receipt is the acceptance evidence: it feeds pilot results papers and
security reviews. A delivery nobody has watched capture a real meeting is not
accepted — that is the point of S3, and why it cannot be fully automated.

`--non-interactive` (CI/rehearsal) skips or bounds the human phase but never
fakes it: no admitted bot → honest FAIL.

## S3 meeting links

Validation has to run on the platform the customer actually meets on, so S3
accepts both:

| paste | sent to `POST /bots` |
|---|---|
| `https://meet.google.com/abc-defg-hij` | `google_meet` · `abc-defg-hij` |
| `https://teams.live.com/meet/<numeric id>?p=<passcode>` | `teams` · `<numeric id>` · `passcode` |
| `https://teams.microsoft.com/meet/<numeric id>?p=<passcode>` | `teams` · `<numeric id>` · `passcode` |
| `https://teams.microsoft.com/l/meetup-join/19%3ameeting_…%40thread.v2/0?context=…` | `teams` · `19:meeting_…@thread.v2` |

Paste the **whole** Teams link. A Teams passcode travels in the `passcode`
field, never appended to the meeting id — the gateway refuses an id carrying
URL characters (`? # & = /`), which is exactly what a pasted `…602?p=X8hc…`
would be. The id forms above are the ones the gateway's own parser produces
(`meeting-api` `collector/meeting_link.py`) and the ones its join-URL template
re-expands (`bot_spawn/service.py`), so nothing here is invented client-side.

An unrecognized link fails immediately with the two shapes it expected, rather
than dispatching a bot that can never join.

Pure-function tests for the parser: `make test-smoke` (stdlib `unittest`, no
cluster needed).
