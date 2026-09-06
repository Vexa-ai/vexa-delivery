# gates

Repository-wide gates that guard properties of the tree itself, rather than of
a release. They run in `make test` and in CI.

## `private-tokens.sha256`

The list of names that may not appear anywhere in this public repository — a
subscriber's channel, that subscriber's name, its abbreviation and its mail
domain — held as **one lowercase sha256 per line and nothing else**. The tokens
themselves are never written here in plain text, in any file of this
repository, in a commit message, or in CI output: a gate that carries its own
secrets publishes them. Digests are all the check needs, and a digest cannot be
read backwards.

`check-private-tokens.py` hashes every word and every hyphenated, dotted or
underscored identifier in the tree — and each delimited part of one — and
compares digests. A finding prints **file:line only**; where a path segment
itself matches, that segment is redacted too.

It scans tracked files **and untracked ones git would let you add**, because a
leak arrives in a file nobody has staged yet. Ignored files are skipped: they
never reach the public tree.

```
python3 gates/check-private-tokens.py                       whole tracked tree
python3 gates/check-private-tokens.py --diff origin/main    changed files only
make check-private-tokens
```

Adding a token: hash the lowercased string with sha256 somewhere private and
append the digest. Never paste the string into this repository to compute it.
Add the spelling variants too — an abbreviation with and without its umlaut is
two tokens, and only the ones on the list are refused.

**What hashing cannot catch**, stated rather than left to be discovered: a token
that is percent-encoded, split across lines, or run together with its
neighbours produces different words and hashes to nothing on the list. This gate
refuses the spelling a human types, which is the one that reaches a page.

Public examples use neutral names — `pilot-stable` for a subscriber channel,
"the pilot subscriber" for the party.

## `check-secret-argv.py`

`/install` promises, of the channel password: **"read from the environment,
never from argv."** For three call sites in `kit/install.sh` that was false —
each ran `kubectl create secret docker-registry … --docker-password=…`, two of
them under `--dry-run`, inside the command hardened so a render would carry no
credential. Argv is world-readable in `/proc` and in `ps` output for the life of
the process. A promise a reviewer can grep for should be a promise a gate
enforces.

It refuses a credential-shaped **value on a command line** in any tracked
`*.sh`: `--docker-password=`, `--password=`/`--token=` (never
`--password-stdin`, which is the fix), and `--from-literal=` whose key looks
like a credential or whose value reads a credential-shaped variable. A finding
prints file:line and the flag, never the line — the line is where the
credential would be.

It does **not** refuse `--from-literal=verdict_sha256=…` or
`--from-literal=status=…`: those are argv and are not secrets, and a rule this
repository cannot keep is a rule somebody suppresses. `*/tests/*` is out of
scope — a stub kubectl *parses* the flag out of its own argv to assert on what
it was handed; it constructs nothing.

```
python3 gates/check-secret-argv.py
make check-secret-argv
```

When it fires, the fix is to render the object and apply it from stdin.
`kit/install.sh` § `render_registry_secret` and `kit/claim.sh` §
`vexa_claim_write_secret` are the two worked examples.
