# Contributing

Contributions are welcome. The whole ceremony is two things: the license and
the sign-off.

## License — Apache-2.0, inbound = outbound

The repository is Apache-2.0 ([LICENSE](LICENSE)). By contributing, you agree
your contribution is licensed under the same terms — Apache-2.0 in, Apache-2.0
out. There is no CLA.

## Sign your work — DCO

Every commit must carry a `Signed-off-by:` line certifying the
[Developer Certificate of Origin](https://developercertificate.org/) — that you
wrote the change or otherwise have the right to submit it under the project's
license. Sign with:

```bash
git commit -s
```

which appends:

```
Signed-off-by: Your Name <your@email.example>
```

The name and email must be yours (no anonymous or noreply sign-offs). A CI
check refuses pull requests whose commits lack the line; fix with
`git commit --amend -s` or `git rebase --signoff` and force-push your branch.

## Practicalities

- Run `make test` before opening a PR — it runs the unit tests, the spec
  goldens, and the CLI-reference coverage gate (regenerate reference pages on
  Python 3.12 with `make docs-reference` if you change a tool's `--help`).
- Never commit credentials, customer-identifying material, or operator
  infrastructure values — see `.gitignore`'s comments and
  [ADR-0009](docs/adr/0009-public-visibility.md) for what stays out and why.
  Site-specific values go through `config/channel.example.env`.
