# vexa-delivery — test and validation entry points, plus the one operational
# target. No TEST target here touches a cluster or a registry with credentials;
# everything runs on fixtures. `publish` is the exception and says so: it is the
# release crank, it reads the operator's own environment, and `DRY_RUN=1` is the
# form of it that touches nothing.

.PHONY: publish test test-publisher test-publish test-preflight test-smoke test-validate test-report test-kit test-platform test-verify test-edge test-gates validate-goldens docs-reference check-docs check-private-tokens check-secret-argv lint

# RUNBOOK § 1 as one command: fetch -> build -> sign-images -> push.
#
#   make publish RELEASE=v0.12.24 ENTRY_SEQ=5
#   make publish RELEASE=v0.12.24 ENTRY_SEQ=5 DRY_RUN=1     # prints, runs nothing
#
# Packaging, not weakening — every C1..C9 and T1/T2 check inside those verbs
# still runs, and there is no flag here that skips one. No credential moves: the
# signing key stays with the human runner (ADR-0001 § 6) and this target passes
# its PATH along out of the same environment the manual steps read. A missing
# variable refuses and names the variable. Full input list in
# publisher/publish.sh; RUNBOOK § 1 leads with this line.
publish:
	@RELEASE='$(RELEASE)' ENTRY_SEQ='$(ENTRY_SEQ)' CHANNEL='$(CHANNEL)' \
	 SUPERSEDES='$(SUPERSEDES)' PUBLICATION_MODE='$(PUBLICATION_MODE)' \
	 SIGNING_MODE='$(SIGNING_MODE)' DELIVERY_RECEIPT='$(DELIVERY_RECEIPT)' \
	 APPROVED_BY='$(APPROVED_BY)' APPROVAL_RECEIPT='$(APPROVAL_RECEIPT)' \
	 CHANNEL_TAG='$(CHANNEL_TAG)' EXTRA_EVIDENCE='$(EXTRA_EVIDENCE)' \
	 SIGNING_RECEIPT='$(SIGNING_RECEIPT)' WORK='$(WORK)' DRY_RUN='$(DRY_RUN)' \
	 sh publisher/publish.sh

test: test-publisher test-preflight test-smoke test-validate test-report test-kit test-platform test-verify test-edge test-gates validate-goldens check-docs check-private-tokens check-secret-argv

test-publisher:
	python3 -m unittest discover -s publisher/tests -v

# The `publish` target's own plumbing, on its own, for when that is what you are
# working on. Already inside `test-publisher` above — publisher/tests is one
# discovery root — so it is NOT a second dependency of `test`; a target listed
# twice would run the same four `make publish` subprocesses twice.
test-publish:
	python3 -m unittest discover -s publisher/tests -p 'test_publish_target.py' -v

test-preflight:
	@if [ -d kit/preflight/tests ]; then python3 -m unittest discover -s kit/preflight/tests -v; else echo "kit/preflight/tests not present yet; skipped"; fi

# The smoke CLI's pure functions (meeting-URL parsing) — no cluster, no network.
test-smoke:
	@if [ -d kit/smoke/tests ]; then python3 -m unittest discover -s kit/smoke/tests -v; else echo "kit/smoke/tests not present yet; skipped"; fi

test-validate:
	@if [ -d kit/validate/tests ]; then python3 -m unittest discover -s kit/validate/tests -v; else echo "kit/validate/tests not present yet; skipped"; fi

# The environment state reporter, end to end against a fake kubectl in
# kit/report/tests/bin. No cluster and no network — the fixture directory IS
# the estate — and the fake kubectl logs every invocation, so --dry-run is
# checked against what a real run actually executes.
test-report:
	@if [ -d kit/report/tests ]; then python3 -m unittest discover -s kit/report/tests -v; else echo "kit/report/tests not present yet; skipped"; fi

# install.sh's contracts, exercised against a stub kubectl. The dry-run one
# asserts on what is RENDERED; the adoption one asserts on what is EXECUTED —
# its stub LOGS every invocation, so "it did not apply that" is checkable
# rather than merely claimed. The claim one runs against a fixture edge and the
# same stub, where the assertion that matters is negative: the credential must
# never reach stdout. First, the cheapest gate of them all: every kit script is
# executable in the TREE, which is what a fresh clone gets and what
# `./kit/claim.sh` needs to be a command at all.
test-kit:
	bash kit/tests/test_script_modes.sh
	bash kit/tests/test_install_dry_run.sh
	bash kit/tests/test_install_adopt.sh
	bash kit/tests/test_install_manifests.sh
	bash kit/tests/test_install_dry_run_secrets.sh
	bash kit/tests/test_install_object_names.sh
	bash kit/tests/test_install_namespace_and_contract.sh
	bash kit/tests/test_claim.sh

# Every service under edge/, each against its own fixtures. One target rather
# than one per service: they are the same kind of thing — a small stdlib process
# behind the founder-owned Caddy — and a per-service target would be a line
# somebody has to remember to add. The loop refuses on the first failure; a
# bare `for` swallows exit status, which is the same defect the `lint` comment
# below records.
#
# edge/claim is the reason there is anything to discover: the park format, the
# claim state machine (park · claim · burn · expiry · attempt limit) and the
# service itself over a real loopback socket. No keypair — `decrypt` is injected
# — so the transitions that decide who gets a credential are proved in CI, where
# `age` is not installed. The one real age round trip skips without the binary,
# the way bcrypt hashing already does. edge/page joins it under the same rule.
test-edge:
	@found=0; for d in edge/*/tests; do [ -d "$$d" ] || continue; found=1; \
	  python3 -m unittest discover -s "$$d" -v || exit 1; done; \
	 [ "$$found" = 1 ] || echo "edge/*/tests not present yet; skipped"

# The platform pack, offline: render.sh against fixture manifests (determinism,
# the object set, the ceiling read from the chart, and the two ClusterPolicies
# diffed against what install.sh renders), then install.sh --cluster-scope
# platform-pack against a stub kubectl. The rendered pack is also linted when
# kubeconform is on the machine; a server-side apply on a real cluster is a
# receipt, not a unit test, so it is not here.
test-platform:
	bash kit/platform/tests/test_render.sh
	bash kit/platform/tests/test_install_cluster_scope.sh

# The in-cluster verifier's evidence model, against fixture entries with stub
# oras/cosign. Offline: no registry, no cluster, no signature.
test-verify:
	bash kit/verify/tests/test_estate_verify.sh
	bash kit/verify/tests/test_path_resolution.sh
	bash kit/verify/tests/test_verdict_out.sh
	bash kit/verify/tests/test_carriage_contract.sh
	bash kit/verify/tests/test_verdict_wiring.sh
	bash kit/verify/tests/test_values_proven.sh
	bash kit/verify/tests/test_station_verdict.sh

# The repository-wide gates' own tests: that the private-token gate catches a
# planted token, and that its refusal never reproduces the token text. Fixture
# tokens only — the real list is digests (gates/README.md).
test-gates:
	python3 -m unittest discover -s gates/tests -v

# Channel-entry goldens live one level down, per release: spec/goldens/<release>/entry.json.
# Find them; refuse to pass on an empty set (a bare glob silently matched nothing).
validate-goldens:
	@entries=$$(find spec/goldens -name entry.json | sort); \
	if [ -z "$$entries" ]; then echo "validate-goldens: no golden entry.json found under spec/goldens"; exit 1; fi; \
	python3 spec/validate.py $$entries

# `A && B || C` made a shellcheck FAILURE print "not installed; skipped" and exit
# 0 — the local lint disagreed with CI for as long as that line existed. Test for
# the tool, then run it as its own command so its exit status is the target's.
lint:
	python3 -m compileall -q publisher kit spec gates edge
	@if ! command -v shellcheck >/dev/null; then \
	  echo "lint: shellcheck is not installed (brew install shellcheck / apt-get install shellcheck)"; exit 1; \
	fi
	find . -name '*.sh' -not -path './.git/*' -print0 | xargs -0 -r shellcheck

# The CLI reference is generated from the tools' own --help. This target REWRITES
# docs/reference/*.mdx; `check-docs` below only reads. Run it after touching any
# CLI, then commit what it wrote.
docs-reference:
	python3 docs/gen-cli-reference.py

# Two read-only doc gates, inside `make test` so CI runs them:
#   gen-cli-reference --check  a verb exists in the code with no hand-written
#                              "when you use this" line, or the committed pages
#                              are stale against --help, or a publisher page
#                              leaked into the public nav  -> FAIL
#   check-docs                 a nav entry with no page, a page in no nav, a
#                              broken internal link                    -> FAIL
check-docs:
	python3 docs/gen-cli-reference.py --check
	python3 docs/check-docs.py

# Some names are private by contract and this repository is public. The gate
# hashes every word and identifier in the tracked tree against the digests in
# gates/private-tokens.sha256 and refuses a hit with file:line and nothing else
# — the token is never in the repository, never in a commit message, and never
# in CI output. `--diff origin/main` is the fast form; the default is the whole
# tree, which is the honest answer. See gates/README.md.
check-private-tokens:
	python3 gates/check-private-tokens.py

# `/install` promises the channel password is "read from the environment, never
# from argv", and for three call sites in kit/install.sh that was false — argv
# is world-readable in /proc and in `ps`. A promise a reviewer can grep for
# should be a promise a gate enforces. Stdlib, reads only *.sh in the tracked
# tree, prints file:line and the flag. See gates/README.md.
check-secret-argv:
	python3 gates/check-secret-argv.py
