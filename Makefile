# vexa-delivery — test and validation entry points. No target here touches a
# cluster or a registry with credentials; everything runs on fixtures.

.PHONY: test test-publisher test-preflight test-smoke test-validate test-report test-kit test-verify validate-goldens docs-reference check-docs lint

test: test-publisher test-preflight test-smoke test-validate test-report test-kit test-verify validate-goldens check-docs

test-publisher:
	python3 -m unittest discover -s publisher/tests -v

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

# install.sh's dry-run contract, exercised against a stub kubectl.
test-kit:
	bash kit/tests/test_install_dry_run.sh

# The in-cluster verifier's evidence model, against fixture entries with stub
# oras/cosign. Offline: no registry, no cluster, no signature.
test-verify:
	bash kit/verify/tests/test_estate_verify.sh
	bash kit/verify/tests/test_verdict_out.sh

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
	python3 -m compileall -q publisher kit spec
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
