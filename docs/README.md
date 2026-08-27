# docs — one site, two tabs

Everything documented about Vexa Enterprise renders in one Mintlify site:

```bash
cd docs && npx -y mint@latest dev --port 3333
```

| Tab | Source | Audience |
|---|---|---|
| **Product** | `*.mdx` at this root | The subscriber. **DRAFT — publication is a founder gate.** |
| **Engineering** | `engineering/`, `receipts/`, `adr/`, `design/` | Us. Never published. |

The Product tab additionally carries a **"Not yet published"** group: customer-facing pages whose
subject is real work but has not shipped, so they are deliberately absent from `docs.public.json`.
A page sits there when the thing it documents is on an open PR or otherwise below the "merged"
rung; moving it into the main group is part of shipping the thing, not a separate chore.

**Publishing ships the Product tab only.** `docs.json` is the local, everything-visible config;
**`docs.public.json` is the publish config** and contains no Engineering pages. Publish with that
file (`mint deploy`-style tooling reads `docs.json`, so a publish step copies
`docs.public.json` → `docs.json` in a build directory rather than editing this tree).

Images live in `images/`, referenced as `/images/<name>`. The release-flow diagram is generated —
edit `images/generate-release-flow.py`, run it, commit the SVGs.

Product-page links are Mintlify-native (extensionless): they navigate in the rendered site and
404 in GitHub's raw file viewer. Review rendered.

Before committing a docs change, run:

```bash
python3 docs/check-docs.py
```

It parses both configs, checks every page they name exists and every page on disk is named by at
least one of them, and resolves every internal link **including its `#anchor`** against the target
page's headings. All four of those rot silently — Mintlify builds fine with a broken sidebar link.
