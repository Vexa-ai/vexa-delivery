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
