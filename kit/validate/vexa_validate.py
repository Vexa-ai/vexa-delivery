#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-validate — one command that takes an operator from "is this cluster ready"
to "here is my signed-off evidence, and here is my contribution back".

It chains the two tools that already exist and adds the thing neither produces:
a portable, secret-free record of the station as it actually stands.

    preflight  (will it run here)      -> preflight-receipt.txt
    install    (optional, --install)   -> install-log.txt
    smoke      (did it work here)      -> smoke-receipt-<ts>.md
    bundle                             -> station.tar.gz

`station.tar.gz` is what the operator sends back to Vexa. It carries the
provider profile, their values file with every secret-looking value replaced by
REDACTED, the contract the environment verifies against, both receipts, and
station.json (date, kit revision, Kubernetes server version, provider,
namespaces, phase verdicts). It carries no credentials — and `--verify-redaction`
(on by default) refuses to finish if any plaintext value that redaction removed
still appears anywhere in the archive that was actually written.

Naming note: the *station bundle* on the channel (ADR-0007) is the machinery
chart Vexa publishes. This archive is the return leg — the operator's station
record travelling the other way. Different direction, different artifact.

Run on the operator's machine with kubectl access:

    python3 kit/validate/vexa_validate.py \
        --namespace vexa-staging \
        --customer-values my-values.yaml \
        --flows [--meeting-url URL | --non-interactive]

Exit codes: 0 all phases passed · 1 a phase failed · 2 usage · 3 redaction leak
(the bundle is kept for inspection but must not be sent).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
KIT = HERE.parent
REPO = KIT.parent

# Keys whose values never leave the customer's perimeter. Deliberately blunt:
# a false positive costs one redacted line of configuration, a false negative
# costs a credential.
SECRET_KEY_RE = re.compile(r"password|token|secret|key|apikey", re.IGNORECASE)
REDACTED = "REDACTED"
# Below this length a "secret" is more likely to collide with ordinary text than
# to be a credential; scanning for it would produce noise, not safety.
MIN_LEAK_SCAN_LEN = 6


# ── redaction ───────────────────────────────────────────────────────────────

def redact(node, key_matched: bool = False, removed: set | None = None):
    """Return a structural copy with secret-looking scalars replaced.

    Structure is preserved exactly — keys, nesting, list order and empty values
    all survive, because the shape of a customer's values file IS the
    contribution. Only non-empty scalars are replaced: an empty string says
    "not set", which is configuration information, not a secret.

    `key_matched` propagates down: everything nested under a `secrets:` block is
    secret, whether or not each leaf key says so itself.
    """
    if removed is None:
        removed = set()
    if isinstance(node, dict):
        out = {}
        # env-var idiom: [{name: FOO_TOKEN, value: ...}] — the secret is named
        # by a sibling key, not by the key holding it.
        env_named = isinstance(node.get("name"), str) and bool(SECRET_KEY_RE.search(node["name"]))
        for k, v in node.items():
            child_matched = key_matched or bool(SECRET_KEY_RE.search(str(k))) \
                or (env_named and k == "value")
            out[k] = redact(v, child_matched, removed)
        return out
    if isinstance(node, list):
        return [redact(v, key_matched, removed) for v in node]
    if key_matched and node is not None and str(node) != "":
        removed.add(str(node))
        return REDACTED
    return node


def scan_for_leaks(root: pathlib.Path, secrets: set) -> list:
    """Return [(relative path, index of the leaked secret)] — never the value."""
    hits = []
    candidates = sorted(s for s in secrets if len(s) >= MIN_LEAK_SCAN_LEN)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        blob = path.read_bytes()
        for i, secret in enumerate(candidates):
            if secret.encode() in blob:
                hits.append((str(path.relative_to(root)), i))
    return hits


# ── plumbing ────────────────────────────────────────────────────────────────

def run(cmd: list, log: pathlib.Path | None = None, cwd: pathlib.Path | None = None,
        tee: bool = True) -> tuple[int, str]:
    """Run a child process, capture combined output, optionally write it to a log."""
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if tee:
        sys.stdout.write(proc.stdout)
        sys.stdout.flush()
    if log:
        log.write_text(proc.stdout)
    return proc.returncode, proc.stdout


def verdict_of(output: str, default: str) -> str:
    m = re.findall(r"VERDICT:\s*\**\s*(PASS|FAIL)", output)
    return m[-1] if m else default


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def kube_server_version(kubeconfig: str | None) -> str | None:
    cmd = ["kubectl"]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    cmd += ["version", "-o", "json"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(r.stdout).get("serverVersion", {}).get("gitVersion")
    except Exception:
        return None


def git_revision() -> dict:
    """Which kit produced this receipt.

    Two sources, and the second exists because of the first's blind spot. On an
    operator's workstation the kit is a git checkout and `git` answers. Inside
    the kit RUNTIME IMAGE it is neither: there is no `.git` and no git binary,
    both left out on purpose — a VCS in a production pod holding a channel
    credential is not worth a provenance field. So the image stamps
    `KIT_REVISION` at build time and this reads it.

    Null is still a legitimate answer, and it stays legitimate: a kit unpacked
    from the tarball has neither source, and a receipt that says `null` is
    honest where an invented commit would not be.
    """
    out = {"commit": None, "describe": None}
    for field, args in (("commit", ["rev-parse", "--short", "HEAD"]),
                        ("describe", ["describe", "--tags", "--always", "--dirty"])):
        try:
            r = subprocess.run(["git", "-C", str(REPO), *args],
                               capture_output=True, text=True)
        except OSError:
            # No git binary at all — FileNotFoundError, not a non-zero exit.
            # The image is exactly this case, so the bare returncode check that
            # stood here would have crashed the sender rather than degraded.
            break
        if r.returncode == 0:
            out[field] = r.stdout.strip()
    if out["commit"] or out["describe"]:
        return out
    stamp = REPO / "KIT_REVISION"
    if stamp.is_file():
        for line in stamp.read_text().splitlines():
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key in out and value and value != "unknown":
                out[key] = value
    return out


def station_chart_version() -> str | None:
    chart = REPO / "station" / "chart" / "Chart.yaml"
    if not chart.exists():
        return None
    import yaml
    return (yaml.safe_load(chart.read_text()) or {}).get("version")


# ── phases ──────────────────────────────────────────────────────────────────

def phase_preflight(a, bundle: pathlib.Path) -> dict:
    print("\n== 1/3 preflight — will this cluster run what the channel delivers?")
    cmd = [sys.executable, str(KIT / "preflight" / "vexa_preflight.py"),
           "--namespace", a.namespace]
    if a.kubeconfig:
        cmd += ["--kubeconfig", a.kubeconfig]
    if a.manifests:
        cmd += ["--manifests", a.manifests]
    if a.live_probes:
        cmd += ["--live-probes"]
    if a.registry:
        cmd += ["--registry-host", a.registry]
    code, out = run(cmd, log=bundle / "preflight-receipt.txt")
    return {"verdict": verdict_of(out, "FAIL" if code else "PASS"), "exit_code": code,
            "receipt": "preflight-receipt.txt"}


def phase_install(a, bundle: pathlib.Path) -> dict:
    if not a.install:
        print("\n== 2/3 install — skipped (already installed; pass --install to run it)")
        return {"skipped": True, "reason": "not requested (--install)"}
    print("\n== 2/3 install — subscribing this cluster to the channel")
    cmd = [str(KIT / "install.sh"),
           "--provider", a.provider, "--registry", a.registry,
           "--channel", a.channel, "--channel-pubkey", a.channel_pubkey,
           "--customer-values", a.customer_values,
           "--staging-ns", a.namespace,
           # preflight already ran above; running it twice would only make the
           # log longer, and its findings are already in the bundle.
           "--skip-preflight"]
    if a.kubeconfig:
        cmd += ["--kubeconfig", a.kubeconfig]
    if a.contract:
        cmd += ["--contract", a.contract]
    cmd += a.install_arg
    code, _ = run(cmd, log=bundle / "install-log.txt")
    return {"skipped": False, "exit_code": code, "log": "install-log.txt",
            "channel": a.channel, "registry": a.registry}


def phase_smoke(a, bundle: pathlib.Path) -> dict:
    print("\n== 3/3 smoke — did what was delivered actually work here?")
    cmd = [sys.executable, str(KIT / "smoke" / "vexa_smoke.py"),
           "--namespace", a.namespace, "--customer-values", a.customer_values]
    if a.kubeconfig:
        cmd += ["--kubeconfig", a.kubeconfig]
    if a.release_prefix:
        cmd += ["--release-prefix", a.release_prefix]
    if a.flows:
        cmd += ["--flows"]
    if a.flows_key:
        cmd += ["--flows-key", a.flows_key]
    if a.admin_token:
        cmd += ["--admin-token", a.admin_token]
    if a.meeting_url:
        cmd += ["--meeting-url", a.meeting_url]
    if a.operator_email:
        cmd += ["--operator-email", a.operator_email]
    if a.non_interactive:
        cmd += ["--non-interactive"]
    cmd += ["--admit-timeout", str(a.admit_timeout), "--min-segments", str(a.min_segments)]
    # Run inside the bundle so the dated receipt lands where it belongs, and keep
    # the console too: if smoke dies before writing its receipt, the console is
    # the only evidence of why, and evidence of a crash is still evidence.
    code, out = run(cmd, cwd=bundle, log=bundle / "smoke-console.txt")
    receipts = sorted(p.name for p in bundle.glob("smoke-receipt-*.md"))
    return {"verdict": verdict_of(out, "FAIL" if code else "PASS"), "exit_code": code,
            "receipt": receipts[-1] if receipts else None}


# ── bundle ──────────────────────────────────────────────────────────────────

def write_profile(a, bundle: pathlib.Path) -> dict:
    """Copy the provider profile actually used, or say honestly that there was none."""
    dest = bundle / "profile.env"
    if a.provider:
        src = KIT / "providers" / a.provider / "profile.env"
        if src.exists():
            shutil.copyfile(src, dest)
            tested = None
            for line in src.read_text().splitlines():
                if line.startswith("PROFILE_TESTED="):
                    tested = line.split("=", 1)[1].strip().strip('"\'')
            return {"name": a.provider, "profile_env_present": True, "profile_tested": tested}
    dest.write_text(
        "# No provider profile was used for this run.\n"
        f"# provider requested: {a.provider or '(none)'}\n"
        f"# looked for: kit/providers/{a.provider or '<name>'}/profile.env\n"
        "# The cluster was validated against ambient kubectl credentials. If your\n"
        "# platform needs a profile (namespaces, pinned versions, node baseline),\n"
        "# this is the file to send back filled in — it is the highest-value part\n"
        "# of the contribution.\n"
        f"PROVIDER={a.provider or 'unspecified'}\n"
        "PROFILE_TESTED=no\n")
    return {"name": a.provider or "unspecified", "profile_env_present": False,
            "profile_tested": None}


def write_contract(a, bundle: pathlib.Path) -> dict:
    src = pathlib.Path(a.contract) if a.contract else KIT / "verify" / "policy.example.yaml"
    dest = bundle / "contract.yaml"
    shutil.copyfile(src, dest)
    contract_id = None
    try:
        import yaml
        contract_id = (yaml.safe_load(dest.read_text()) or {}).get("contract_id")
    except Exception:
        pass
    # the file's name and hash identify the contract; its path on the operator's
    # laptop is nobody's business and would only date the record
    return {"source": src.name, "kit_default": not bool(a.contract),
            "contract_id": contract_id, "sha256": sha256_of(dest)}


def write_values(a, bundle: pathlib.Path) -> set:
    import yaml
    removed: set = set()
    values = yaml.safe_load(pathlib.Path(a.customer_values).read_text()) or {}
    (bundle / "values.redacted.yaml").write_text(
        "# Your values file, structurally intact, with every secret-looking value\n"
        f"# replaced by {REDACTED} (keys matching: password|token|secret|key|apikey,\n"
        "# and everything nested beneath them). The SHAPE is the contribution.\n"
        + yaml.safe_dump(redact(values, removed=removed), sort_keys=False))
    return removed



# ── submit: the return leg, and the only thing that leaves ──────────────────
#
# Reporting rides the channel host the estate ALREADY PULLS FROM. That is the
# whole design: no new firewall rule, no second vendor endpoint, no change
# request. The credential is the subscriber's own — the same one that pulls —
# and the edge lets it write to exactly /v2/vexa/stations/<its-own-name>/**
# and refuses every other path, so a station cannot overwrite another station's
# evidence and nobody has to trust it not to.
#
# THE ACCOUNT NAME IS THE PATH SEGMENT. That convention is load-bearing in two
# places at once: the edge's rule matches the authenticated user against the
# path, and the publisher's `ingest --from-registry <station>` looks there. A
# subscriber minted with a name that does not match its station name cannot
# submit, and the 403 says so.
#
# Nothing here runs on a timer. There is no hook, no sidecar and no background
# process anywhere in the delivered software that originates a report: it
# happens when an operator types --submit, and the payload path is printed
# before anything is sent so they can open it first.

REPORT_SCHEMA_CANDIDATES = ("kit/validate/report.v1.schema.json", "spec/report.v1.schema.json")


def load_report_schema() -> dict:
    """The kit ships its own copy because the kit tarball carries kit/ and
    nothing else; `make test` proves the two files are byte-identical, so the
    copy cannot drift into a second, laxer contract."""
    for rel in (HERE / "report.v1.schema.json", REPO / "spec" / "report.v1.schema.json"):
        if rel.is_file():
            return json.loads(rel.read_text())
    raise SystemExit("--submit: report.v1 schema not found beside the tool "
                     f"(looked for {', '.join(REPORT_SCHEMA_CANDIDATES)})")


def validate_report(payload: dict) -> None:
    try:
        import jsonschema
    except ImportError:
        raise SystemExit(
            "--submit needs the jsonschema package (pip install jsonschema).\n"
            "It will NOT send a payload it could not validate — the guarantee that "
            "report.v1 cannot carry your content is the validation, not the intention.")
    schema = load_report_schema()
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(payload),
                    key=lambda e: list(e.absolute_path))
    if errors:
        print("\n!! the report does NOT satisfy report.v1 — nothing was sent:")
        for e in errors[:10]:
            loc = "/".join(str(x) for x in e.absolute_path) or "(root)"
            print(f"   at {loc}: {e.message}")
        raise SystemExit(2)


def read_report_scope(contract_path: pathlib.Path) -> dict:
    import yaml
    try:
        doc = yaml.safe_load(contract_path.read_text()) or {}
    except Exception:
        return {}
    scope = doc.get("report_scope")
    return scope if isinstance(scope, dict) else {}


ALLOWED_TRIGGERS = ("explicit-command-only", "scheduled")


def check_report_scope(scope: dict, bundle_names: list, destination: str,
                       station_doc: dict) -> None:
    """The contract's own limits, checked locally before a byte moves."""
    import fnmatch
    problems = []

    # THE TRIGGER IS THE CUSTOMER'S TO SET, AND THE DEFAULT DID NOT CHANGE.
    #
    # `explicit-command-only` means what it always meant, and it remains the
    # default and the T0/T1 posture: nothing in the delivered software
    # originates a report — it happens when an operator types --submit.
    #
    # `scheduled` exists because T2 and T3 are cadenced rungs (daily, weekly)
    # and a rung nobody can reach without a human typing a command every
    # morning is a rung nobody climbs. It is opt-in IN THEIR OWN FILE: the
    # station chart renders no CronJob unless the contract says `scheduled`,
    # so the timer is authorised by the same document that bounds what it may
    # send. What has NOT happened is a timer appearing in software somebody
    # already installed.
    trigger = scope.get("trigger", "explicit-command-only")
    if trigger not in ALLOWED_TRIGGERS:
        problems.append(f"report_scope.trigger is '{trigger}'; this tool implements "
                        f"{' and '.join(repr(t) for t in ALLOWED_TRIGGERS)} and refuses to "
                        f"pretend otherwise")

    # ---- the ladder rung, checked HERE as well as in the schema -------------
    #
    # The schema already refuses a payload whose blocks exceed its `tier`. It
    # does it with jsonschema's if/then, whose failure message is the whole
    # instance printed back at you — technically correct and useless to the
    # operator standing in front of it at 2am. This says the sentence.
    # A report_scope with no `tier` is tier 1 — see collectors.resolve_tier for
    # why that is compatibility rather than laxity: every pre-ladder contract
    # permits exactly the install bundle, which is what T1 is. Above T1 nothing
    # arrives by default, which is what the comparisons below are for.
    declared = scope.get("tier", 1) if scope else None
    carried = station_doc.get("tier")
    if declared is None:
        problems.append("your contract has no report_scope at all — refusing to send. "
                        "report_scope is the clause that bounds what may leave this "
                        "perimeter, and a submission with no bound is not one we will make "
                        "on your behalf.")
    elif carried is not None and carried > declared:
        problems.append(
            f"this payload is tier {carried} and your contract declares tier {declared} — "
            f"refusing to send it. Nothing above your declared rung leaves this perimeter.")
    if declared == 0:
        problems.append("report_scope.tier is 0 (silent): a T0 station submits nothing at "
                        "all. Nothing was sent.")
    for block, min_tier in (("release", 1), ("health", 2), ("usage", 3)):
        if block in station_doc and (declared or 0) < min_tier:
            problems.append(f"the payload carries a '{block}' block, which is tier {min_tier}, "
                            f"and your contract declares tier {declared}")

    want_dest = scope.get("destination")
    if want_dest and want_dest != destination:
        problems.append(f"report_scope.destination is '{want_dest}' but the submit target is "
                        f"'{destination}' — one destination, and it is the one you wrote down")

    allowed = scope.get("allowed_files")
    if allowed:
        for name in bundle_names:
            if not any(fnmatch.fnmatch(name, pat) for pat in allowed):
                problems.append(f"bundle member '{name}' is outside report_scope.allowed_files")

    if scope.get("require_redaction_verified") and not station_doc.get(
            "redaction", {}).get("verified"):
        problems.append("report_scope.require_redaction_verified is set and redaction was not "
                        "verified against the written archive")

    if problems:
        print("\n!! report_scope refuses this submission — nothing was sent:")
        for p_ in problems:
            print(f"   - {p_}")
        raise SystemExit(2)


def registry_env(host: str) -> dict:
    """A throwaway DOCKER_CONFIG carrying the subscriber credential.

    From the ENVIRONMENT, never argv: a password on a command line lands in
    shell history and in every process listing on the machine. Existing on-disk
    auths are carried across and only the credential HELPER keys are dropped —
    blanking auths outright is what broke pushing to an authenticated channel
    in the rehearsal."""
    import base64
    env = dict(os.environ)
    cfg = pathlib.Path(tempfile.mkdtemp(prefix="vexa-submit-cfg-"))
    auths = {}
    real = pathlib.Path(env.get("HOME", "")) / ".docker" / "config.json"
    try:
        auths = {k: v for k, v in (json.loads(real.read_text()).get("auths") or {}).items()
                 if isinstance(v, dict) and v.get("auth")}
    except (OSError, ValueError):
        auths = {}
    user, password = env.get("VEXA_CHANNEL_USER"), env.get("VEXA_CHANNEL_PASS")
    if user and password:
        auths[host] = {"auth": base64.b64encode(f"{user}:{password}".encode()).decode()}
    (cfg / "config.json").write_text(json.dumps({"auths": auths}))
    env["DOCKER_CONFIG"] = str(cfg)
    return env


def phase_submit(a, archive: pathlib.Path, station_doc: dict,
                 contract_path: pathlib.Path) -> int:
    scope = read_report_scope(contract_path)
    destination = a.submit_destination or scope.get("destination") or a.registry
    if not destination:
        raise SystemExit("--submit needs a destination: report_scope.destination in your "
                         "contract, or --submit-destination, or --registry")
    destination = destination.replace("https://", "").replace("http://", "").rstrip("/")

    station_name = station_doc["station"]
    print("\n== submit — validating what would leave this perimeter")

    payload = out_payload = None
    payload = dict(station_doc)
    validate_report(payload)
    check_report_scope(scope, [f["name"] for f in payload["files"]], destination, payload)

    out_payload = archive.parent / f"report-{station_name}-{a.submit_tag}.json"
    out_payload.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"   report.v1 OK — every field below is in the schema, and the schema has no "
          f"field that could hold your content")
    print(f"   payload:     {out_payload}")
    print(f"   open it. that is what it is for.")
    print(f"   destination: {destination}/vexa/stations/{station_name}/bundles:{a.submit_tag}")
    print(f"   carrying:    {archive.name} ({archive.stat().st_size} bytes), "
          f"{len(payload['files'])} member(s)")

    if a.submit_dry_run:
        print("   --submit-dry-run: nothing sent.")
        return 0

    ref = f"{destination}/vexa/stations/{station_name}/bundles:{a.submit_tag}"
    plain = (["--plain-http"] if a.submit_plain_http
             else (["--insecure"] if a.submit_insecure else []))
    cmd = ["oras", "push", *plain, "--artifact-type", BUNDLE_ARTIFACT_TYPE, ref,
           archive.name, out_payload.name]
    proc = subprocess.run(cmd, cwd=str(archive.parent), capture_output=True, text=True,
                          env=registry_env(destination))
    sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip()[-500:]
        print(f"\n!! submit FAILED: {tail}")
        if "401" in tail or "Unauthorized" in tail or "403" in tail:
            print("   The edge allows a subscriber to write to /v2/vexa/stations/<its own "
                  "name>/** and nothing else. Check that VEXA_CHANNEL_USER is the same "
                  f"string as the station name ('{station_name}').")
        return 1
    digest = next((ln.split()[-1] for ln in proc.stdout.splitlines()
                   if ln.startswith("Digest:")), None)
    print(f"\nsubmitted: {ref}")
    print(f"digest:    {digest}")
    print("this is your receipt — it names the exact bytes that left, and we can be held to it")
    return 0


BUNDLE_ARTIFACT_TYPE = "application/vnd.vexa.station-bundle.v1+gzip"


# ── the ladder: T1-T3 collection, and T4's deliberate absence from it ───────


def _collectors():
    sys.path.insert(0, str(HERE))
    import collectors
    return collectors


def collect_tier_blocks(a, scope: dict) -> dict:
    """Run exactly the collectors the contract's declared tier permits.

    The gating lives in collectors.collect(): the callable list is filtered by
    tier BEFORE anything runs, so a T2 station does not execute the usage
    collector and drop its output — the function is never referenced. Here we
    only supply the tier and the cluster handle.
    """
    c = _collectors()
    tier = c.resolve_tier(scope)          # raises TierRefusal; no default tier exists
    if tier == 0:
        return {}
    kube = c.Kube(a.namespace, kubeconfig=a.kubeconfig)
    cfg = {
        "app": a.app or "",
        "pin": a.pin or "",
        "entry_seq": a.entry_seq,
        "entry_digest": a.entry_digest,
        "chart_version": a.chart_version,
        "chart_digest": a.chart_digest,
        "windowHours": a.window_hours,
        "collectNodes": not a.namespace_scoped,
    }
    return c.collect(tier, kube, cfg)


def phase_report(a, contract_path: pathlib.Path) -> int:
    """A TELEMETRY submission: the ladder's cadenced return leg.

    Distinct from the install bundle above, and the distinction is carried in
    the payload as `bundle_kind` rather than inferred. No phase ran here — no
    preflight, no install, no smoke — so there is no receipt for any of them,
    and a bundle that carries none is complete rather than incomplete. The
    ingest side reads the same field and applies the matching role set.

    What travels: `station.json` (the report itself, with the tier blocks) and
    `contract.yaml` (so the bundle states the policy it was produced under,
    beside the data, in one signed archive). Nothing else — and `allowed_files`
    in the contract still has the final say on that.
    """
    scope = read_report_scope(contract_path)
    c = _collectors()
    try:
        tier = c.resolve_tier(scope)
        blocks = collect_tier_blocks(a, scope)
    except c.TierRefusal as e:
        print(f"\n!! refusing to collect: {e}")
        return 2
    if tier == 0:
        print("report_scope.tier is 0 (silent). Nothing collected, nothing sent.")
        return 0

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="vexa-report-"))
    try:
        bundle = tmp / "station"
        bundle.mkdir()
        shutil.copyfile(contract_path, bundle / "contract.yaml")
        contract_text = contract_path.read_text()

        station = {
            "schema_version": 1,
            "bundle_kind": "telemetry",
            "tier": tier,
            "station": a.station or a.namespace,
            "generated_at": datetime.datetime.now(datetime.timezone.utc)
                                    .isoformat(timespec="seconds"),
            "generator": "kit/validate/vexa_validate.py --report",
            "kit": {**git_revision(), "station_chart_version": station_chart_version()},
            "kubernetes": {"server_version": kube_server_version(a.kubeconfig)},
            "provider": {"name": a.provider or "unknown"},
            "namespaces": {"target": a.namespace,
                           "release_prefix": a.release_prefix or None},
            "contract": {
                "source": contract_path.name,
                "kit_default": False,
                "contract_id": _contract_id(contract_text),
                "sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
            },
            "phases": {},
            "tiers": {"flows": bool(a.flows)},
            # A telemetry bundle carries no customer values, so there is
            # nothing to redact. Said as a number rather than left null: a
            # null here would read as "not checked".
            "redaction": {"verified": True, "values_redacted": 0, "leaks": 0,
                          "note": "telemetry bundle: no values file travels, "
                                  "nothing to redact"},
            **blocks,
        }
        station["contents"] = sorted([p.name for p in bundle.iterdir()] + ["station.json"])
        station["files"] = sorted(
            ({"name": f.name, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
             for f in bundle.iterdir() if f.is_file()),
            key=lambda r: r["name"])
        (bundle / "station.json").write_text(json.dumps(station, indent=2) + "\n")

        out_dir = pathlib.Path(a.out).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        archive = out_dir / "station-report.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(bundle, arcname="station")
        print(f"\ntelemetry bundle (tier {tier} — {c.TIER_NAMES[tier]}): {archive}")
        for name in station["contents"]:
            print(f"  station/{name}")
        if not a.submit:
            print("\nnothing was sent. --submit sends it; --submit-dry-run shows the payload.")
            return 0
        return phase_submit(a, archive, station, contract_path)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _contract_id(text: str):
    import yaml
    try:
        return (yaml.safe_load(text) or {}).get("contract_id")
    except Exception:
        return None


def phase_export_diagnostics(a, contract_path: pathlib.Path) -> int:
    """T4 — AND IT DOES NOT SUBMIT. That is the whole feature.

    T4 is scrubbed logs and traces. It is the rung where the thing being
    collected could, by its nature, contain a workload's data, so it is the one
    rung with no automatic path: no CronJob emits it, no `--submit` accepts it,
    and there is deliberately no `tier: 4` value in report.v1 — a schema that
    could express T4 is a schema that could carry one automatically.

    What this command does is write a bundle to a LOCAL directory and stop. The
    customer's own admin reads it, decides, and hands it over per incident by
    whatever means their policy allows. The reason the command exists at all is
    that "send us your logs" otherwise means an engineer improvising `kubectl
    logs` under incident pressure, which is exactly when redaction gets skipped.
    """
    scope = read_report_scope(contract_path)
    declared = scope.get("tier")
    if declared is not None and declared < 4:
        print(f"\nnote your contract declares tier {declared}; diagnostics are tier 4.")
        print("     This still runs — the bundle is going to your own disk and nowhere else,")
        print("     and what you do with it afterwards is not ours to gate. The tier matters")
        print("     for what may be SENT, and nothing here sends.")

    out_dir = pathlib.Path(a.out).resolve() / f"vexa-diagnostics-{a.submit_tag}"
    out_dir.mkdir(parents=True, exist_ok=True)
    c = _collectors()
    kube = c.Kube(a.namespace, kubeconfig=a.kubeconfig)

    wrote, absent = [], []
    for label, resource, namespaced in (
        ("events", "events", True),
        ("pods", "pods", True),
        ("deployments", "deployments.apps", True),
        ("cronjobs", "cronjobs.batch", True),
        ("jobs", "jobs.batch", True),
    ):
        doc, err = kube.get(resource, namespace=namespaced)
        if doc is None:
            absent.append({"what": label, "reason": err or "not readable"})
            continue
        scrubbed = _scrub(doc)
        p = out_dir / f"{label}.json"
        p.write_text(json.dumps(scrubbed, indent=1) + "\n")
        wrote.append(p.name)

    (out_dir / "README.txt").write_text(
        "Vexa diagnostics export — tier 4.\n"
        "\n"
        "NOTHING HERE HAS BEEN SENT ANYWHERE. This directory was written to your\n"
        "disk by a command you typed, and no part of the delivered software will\n"
        "transmit it. There is no --submit for tier 4.\n"
        "\n"
        "What was removed before writing: every Secret and ConfigMap value, every\n"
        "container environment value, and every annotation whose key looks like a\n"
        "credential. Object names, namespaces, images, conditions and event\n"
        "messages are KEPT, because without them the bundle diagnoses nothing.\n"
        "\n"
        "READ IT BEFORE YOU SHARE IT. That is what it is for, and it is why it is\n"
        "plain JSON on your disk rather than an archive that leaves on a timer.\n"
        f"\nWritten: {', '.join(wrote) or '(nothing)'}\n"
        + ("".join(f"Absent: {r['what']} — {r['reason']}\n" for r in absent)))

    print(f"\ndiagnostics written to: {out_dir}")
    for n in sorted(wrote):
        print(f"  {n}")
    for r in absent:
        print(f"  ABSENT {r['what']}: {r['reason']}")
    print("\nNothing was sent. Read the files, then share them however your policy allows.")
    return 0


DIAG_DROP_KEYS = re.compile(
    r"(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|credential|"
    r"private[_-]?key|passphrase|client[_-]?secret|authorization|cookie)", re.I)


def _scrub(node):
    """Structural scrub for the diagnostics export.

    Drops the CARRIERS of secrets outright — a Secret's `data`, a ConfigMap's
    `data`, `env[].value`, `last-applied-configuration` — rather than trying to
    recognise secret-looking strings inside them. Recognition is a losing game
    on arbitrary cluster objects; removal of the whole field is not.
    """
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k in ("data", "stringData") and node.get("kind") in ("Secret", "ConfigMap"):
                out[k] = f"<removed: {len(v) if isinstance(v, dict) else 1} key(s)>"
                continue
            if k == "annotations" and isinstance(v, dict):
                out[k] = {ak: ("<removed>" if DIAG_DROP_KEYS.search(ak)
                               or ak.endswith("last-applied-configuration") else av)
                          for ak, av in v.items()}
                continue
            if k == "env" and isinstance(v, list):
                out[k] = [{**{ik: iv for ik, iv in (e or {}).items() if ik != "value"},
                           **({"value": "<removed>"} if isinstance(e, dict) and "value" in e
                              else {})}
                          for e in v]
                continue
            if isinstance(k, str) and DIAG_DROP_KEYS.search(k) and not isinstance(v, (dict, list)):
                out[k] = "<removed>"
                continue
            out[k] = _scrub(v)
        return out
    if isinstance(node, list):
        return [_scrub(v) for v in node]
    return node


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vexa-validate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--namespace", default="vexa-staging")
    ap.add_argument("--kubeconfig")
    ap.add_argument("--customer-values",
                    help="the values file you edit and keep; redacted into the bundle. "
                         "Required for a validation run; a --report or --export-diagnostics "
                         "run carries no values file and does not take one.")
    ap.add_argument("--contract", help="contract this environment verifies against "
                                       "(default kit/verify/policy.example.yaml)")
    ap.add_argument("--provider", help="provider profile name under kit/providers/")
    ap.add_argument("--out", default=".", help="where station.tar.gz is written")
    # preflight pass-through
    ap.add_argument("--manifests")
    ap.add_argument("--station", help="station name recorded in station.json; the publisher's "
                                      "ingest --station must match it (default: the namespace)")
    ap.add_argument("--live-probes", action="store_true")
    # install (optional)
    ap.add_argument("--install", action="store_true",
                    help="also run kit/install.sh between preflight and smoke")
    ap.add_argument("--registry")
    ap.add_argument("--channel")
    ap.add_argument("--channel-pubkey")
    ap.add_argument("--install-arg", action="append", default=[],
                    help="extra argument passed verbatim to install.sh (repeatable)")
    # smoke pass-through
    ap.add_argument("--release-prefix")
    ap.add_argument("--flows", action="store_true")
    ap.add_argument("--flows-key")
    ap.add_argument("--admin-token")
    ap.add_argument("--meeting-url")
    ap.add_argument("--operator-email")
    ap.add_argument("--admit-timeout", type=int, default=240)
    ap.add_argument("--min-segments", type=int, default=3)
    ap.add_argument("--non-interactive", action="store_true")
    # bundle
    ap.add_argument("--verify-redaction", dest="verify_redaction", action="store_true",
                    default=True, help="refuse to finish if a redacted value survives (default)")
    ap.add_argument("--no-verify-redaction", dest="verify_redaction", action="store_false")
    # submit — the return leg
    ap.add_argument("--submit", action="store_true",
                    help="after bundling, validate the report against report.v1 and your "
                         "contract's report_scope, then push it to the channel host you "
                         "already pull from. Explicit command only: nothing sends on its own.")
    ap.add_argument("--submit-destination",
                    help="registry host; default report_scope.destination, then --registry")
    ap.add_argument("--submit-tag", help="bundle tag; default today's UTC date")
    ap.add_argument("--submit-dry-run", action="store_true",
                    help="validate and print the payload; send nothing")
    ap.add_argument("--submit-plain-http", action="store_true")
    ap.add_argument("--submit-insecure", action="store_true")
    ap.add_argument("--continue-on-fail", action="store_true",
                    help="build the bundle even if a phase FAILs (a failing run is "
                         "still evidence — and often the most useful kind to send)")
    # ── the telemetry ladder ────────────────────────────────────────────────
    ap.add_argument("--report", action="store_true",
                    help="TELEMETRY MODE: skip the phases and emit a ladder submission at "
                         "the tier your contract's report_scope declares (T1 receipts / T2 "
                         "health / T3 usage). Collectors above the declared tier are never "
                         "called. Combine with --submit to send it.")
    ap.add_argument("--export-diagnostics", action="store_true",
                    help="TIER 4: write a scrubbed diagnostics bundle to a local directory "
                         "and stop. Nothing is sent — there is no --submit path for tier 4; "
                         "your admin reads the bundle and shares it per incident.")
    ap.add_argument("--app", help="the Argo CD Application name this station follows (T1)")
    ap.add_argument("--pin", help="the position that Application follows (T1); read from the "
                                  "Application when it can be, this is the fallback")
    ap.add_argument("--entry-seq", type=int, help="channel entry sequence the pin resolves to (T1)")
    ap.add_argument("--entry-digest", help="channel entry digest the pin resolves to (T1)")
    ap.add_argument("--chart-version", help="chart version running (T1)")
    ap.add_argument("--chart-digest", help="chart digest running (T1)")
    ap.add_argument("--window-hours", type=float, default=24.0,
                    help="how much time the T2/T3 counters cover (default 24)")
    ap.add_argument("--namespace-scoped", action="store_true",
                    help="this station has no cluster-scoped read; node counters are "
                         "reported absent rather than collected")
    a = ap.parse_args(argv)
    if not a.submit_tag:
        a.submit_tag = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    if a.install and not (a.provider and a.registry and a.channel and a.channel_pubkey):
        ap.error("--install needs --provider, --registry, --channel and --channel-pubkey")
    if not (a.report or a.export_diagnostics) and not a.customer_values:
        ap.error("--customer-values is required for a validation run")
    if a.report and a.export_diagnostics:
        ap.error("--report and --export-diagnostics are different acts: one submits at your "
                 "declared tier, the other writes to your disk and never sends. Run them "
                 "separately so nobody later reads a diagnostics run as a submission.")
    for attr in ("customer_values", "contract", "kubeconfig", "channel_pubkey", "manifests"):
        v = getattr(a, attr, None)
        if v:
            setattr(a, attr, str(pathlib.Path(v).resolve()))

    # The ladder modes run instead of the phases, not after them: a cadenced
    # T2 submission must not install anything or dispatch a smoke meeting.
    if a.report or a.export_diagnostics:
        contract_path = (pathlib.Path(a.contract) if a.contract
                         else KIT / "verify" / "policy.example.yaml")
        if a.export_diagnostics:
            return phase_export_diagnostics(a, contract_path)
        return phase_report(a, contract_path)
    out_dir = pathlib.Path(a.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="vexa-station-"))
    bundle = tmp / "station"
    bundle.mkdir()

    phases = {}
    phases["preflight"] = phase_preflight(a, bundle)
    hard_fail = phases["preflight"]["verdict"] == "FAIL"
    if hard_fail and not a.continue_on_fail:
        print("\npreflight FAILED — fix the findings above and rerun. "
              f"Findings: {bundle / 'preflight-receipt.txt'}\n"
              "(--continue-on-fail bundles the failure instead, which is a perfectly "
              "good thing to send us.)")
        shutil.copyfile(bundle / "preflight-receipt.txt", out_dir / "preflight-receipt.txt")
        shutil.rmtree(tmp, ignore_errors=True)
        return 1

    phases["install"] = phase_install(a, bundle)
    if phases["install"].get("exit_code"):
        hard_fail = True
        if not a.continue_on_fail:
            print("\ninstall FAILED — see install-log.txt")
            shutil.copyfile(bundle / "install-log.txt", out_dir / "install-log.txt")
            shutil.rmtree(tmp, ignore_errors=True)
            return 1

    phases["smoke"] = phase_smoke(a, bundle)
    hard_fail = hard_fail or phases["smoke"]["verdict"] == "FAIL"

    # ── the bundle ──────────────────────────────────────────────────────────
    print("\n== bundling the station record")
    provider_meta = write_profile(a, bundle)
    contract_meta = write_contract(a, bundle)
    secrets = write_values(a, bundle)

    station = {
        # report.v1 (spec/report.v1.schema.json). This document IS the report:
        # the manifest that travels is the manifest the operator can read, not
        # a second one assembled for us out of sight.
        "schema_version": 1,
        # Stated, not inferred. The ingest applies a different required-file
        # set to each kind, and a telemetry bundle carrying no smoke receipt is
        # complete rather than incomplete.
        "bundle_kind": "install",
        # The station's NAME is what the publisher's ingest checks its
        # --station argument against. Without it every real bundle was refused
        # at S3 (rehearsal 2026-08-24: the ingest had never seen one).
        "station": a.station or a.namespace,
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
                                .isoformat(timespec="seconds"),
        "generator": "kit/validate/vexa_validate.py",
        "kit": {**git_revision(), "station_chart_version": station_chart_version()},
        "kubernetes": {"server_version": kube_server_version(a.kubeconfig)},
        "provider": provider_meta,
        "namespaces": {"target": a.namespace,
                       "release_prefix": a.release_prefix or "vexa-vexa"},
        "contract": contract_meta,
        "phases": phases,
        "tiers": {"flows": bool(a.flows)},
        "redaction": {"verified": None, "values_redacted": len(secrets), "leaks": None},
    }

    if a.verify_redaction:
        leaks = scan_for_leaks(bundle, secrets)
        station["redaction"]["verified"] = not leaks
        station["redaction"]["leaks"] = len(leaks)
        if leaks:
            station["redaction"]["leaking_files"] = sorted({p for p, _ in leaks})
    else:
        station["redaction"]["verified"] = False
        station["redaction"]["note"] = "--no-verify-redaction: NOT checked"

    # A validation run is itself a T1 event — an install happened and a verdict
    # exists — so when the contract declares a rung, the install bundle carries
    # it too. Collected through the same gated path as the cadenced one: no
    # second implementation, and nothing above the declared tier is reachable.
    _scope = read_report_scope(pathlib.Path(a.contract) if a.contract
                              else KIT / "verify" / "policy.example.yaml")
    if _scope.get("tier") not in (None, 0):
        try:
            station["tier"] = _collectors().resolve_tier(_scope)
            station.update(collect_tier_blocks(a, _scope))
        except Exception as e:                                   # noqa: BLE001
            # A collector failing must never lose a validation run that already
            # happened. The bundle ships without the ladder blocks and says so.
            print(f"note ladder collection skipped: {e}")

    # station.json lists itself: the manifest a reader checks the archive against
    # is only useful if it is complete.
    station["contents"] = sorted([p.name for p in bundle.iterdir()] + ["station.json"])
    # ...and it lists them WITH their digests, under the key the publisher's
    # ingest actually reads. `contents` alone is a list of names a tampered
    # bundle satisfies trivially; `files` is what makes S3 a real check.
    station["files"] = sorted(
        ({"name": f.name, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
         for f in bundle.iterdir() if f.is_file()),
        key=lambda r: r["name"],
    )
    (bundle / "station.json").write_text(json.dumps(station, indent=2) + "\n")

    archive = out_dir / "station.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(bundle, arcname="station")

    # Check what was actually written, not what we think we wrote: re-extract
    # the archive and scan that. A bug between the staging directory and the tar
    # would otherwise be invisible.
    leak_exit = 0
    if a.verify_redaction:
        with tempfile.TemporaryDirectory() as verify_dir:
            with tarfile.open(archive) as tar:
                try:
                    tar.extractall(verify_dir, filter="data")
                except TypeError:          # python < 3.12 has no extraction filters
                    tar.extractall(verify_dir)
            leaks = scan_for_leaks(pathlib.Path(verify_dir), secrets)
        leak_exit = 3 if leaks else 0

    shutil.rmtree(tmp, ignore_errors=True)

    print(f"\nbundle: {archive}")
    for name in station["contents"]:
        print(f"  station/{name}")
    print(f"\nphases: preflight {phases['preflight']['verdict']}"
          f" · install {'skipped' if phases['install'].get('skipped') else 'ran'}"
          f" · smoke {phases['smoke']['verdict']}")
    if leak_exit:
        print(f"\n!! REDACTION FAILED — {len(leaks)} plaintext secret occurrence(s) "
              f"survived into {archive.name}")
        for path, idx in leaks:
            print(f"   {path}: secret #{idx} (value withheld)")
        print("   DO NOT SEND THIS FILE. Report the finding to Vexa without attaching it.")
        return 3
    if a.verify_redaction:
        print(f"redaction: {len(secrets)} value(s) removed, 0 found in the archive")
    if a.submit:
        rc = phase_submit(a, archive, station, pathlib.Path(a.contract) if a.contract
                          else KIT / "verify" / "policy.example.yaml")
        if rc:
            return rc
        return 1 if hard_fail else 0

    print("\nsend station.tar.gz back to Vexa — it is your configuration contribution;"
          " it contains NO secrets")
    print("or let the channel carry it: re-run with --submit (nothing sends on its own)")
    return 1 if hard_fail else 0


if __name__ == "__main__":
    sys.exit(main())
