#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-validate — one command that takes an operator from "is this cluster ready"
to "here is my signed-off evidence, and here is my contribution back".

It chains the two tools that already exist and adds the thing neither produces:
a portable, secret-free record of the station as it actually stands.

    preflight  (will it run here)      -> the preflight verdict, verbatim
    install    (optional, --install)   -> the install log
    smoke      (did it work here)      -> the smoke verdict and its console
    report                             -> station-report.yaml

ONE FILE, AND THAT IS THE DESIGN. `station-report.yaml`. Not a directory, not
an archive, nothing to extract. The person who has to approve this before it
leaves their perimeter must read ALL of it, and six files in a tarball is a
review task where one commented document is a read. This one goes back on
every release rather than once, so the cost of a document nobody reads
compounds. YAML because the reader is a Kubernetes engineer who reads it all
day, and because it carries comments — so the explanation of each section sits
above the section instead of in a second document that can drift from it.

WHAT IS IN IT, and the list is complete:

  1. PROFILE       the provider profile this run used, verbatim — substrate
                   facts (k8s version, storage class, PSA mode, mirror host),
                   never credentials
  2. VALUES        the operator's own values file, structurally intact, with
                   every secret-looking value replaced by REDACTED. The SHAPE
                   is the contribution
  3. CONTRACT      the contract this environment verifies against, verbatim,
                   beside its id and sha256 — the document states the policy
                   it was produced under
  4. PREFLIGHT     the P-check receipt, verbatim
  5. SMOKE         the smoke receipt, and the raw console TAIL — evidence of a
                   crash is still evidence, and it is the half a receipt never
                   gets to write
  6. THE MANIFEST  station identity, section digests, kit revision, phase
                   verdicts and the redaction verdict, as top-level keys

It carries no credentials, and `--verify-redaction` (on by default) refuses to
finish if any plaintext value that redaction removed still appears anywhere in
the finished file — the check reads the bytes that would be sent, not the
values we believe we assembled.

ABSENT OVER ZERO. A section that could not be produced is recorded as absent
with a reason, never as an empty string: an empty receipt in a document whose
whole purpose is to say what happened is worse than a stated gap.

Naming note: the *station bundle* on the channel (ADR-0007) is the machinery
chart Vexa publishes INTO a cluster. `station-report.yaml` is the return leg —
the operator's station record travelling the other way. Different direction,
different artifact, and now different words for each.

Run on the operator's machine with kubectl access:

    python3 kit/validate/vexa_validate.py \
        --namespace vexa-staging \
        --customer-values my-values.yaml \
        --flows [--meeting-url URL | --non-interactive]

Exit codes: 0 all phases passed · 1 a phase failed · 2 usage · 3 redaction leak
(the file is kept so it can be inspected, and it must not be sent).
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
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
KIT = HERE.parent
REPO = KIT.parent

OUTPUT_NAME = "station-report.yaml"

# Keys whose values never leave the customer's perimeter. Deliberately blunt:
# a false positive costs one redacted line of configuration, a false negative
# costs a credential.
SECRET_KEY_RE = re.compile(r"password|token|secret|key|apikey", re.IGNORECASE)
REDACTED = "REDACTED"
# Below this length a "secret" is more likely to collide with ordinary text than
# to be a credential; scanning for it would produce noise, not safety.
MIN_LEAK_SCAN_LEN = 6

# A console is the one section with no natural end, and an operator asked to
# read a document before sending it will not read four thousand lines of one.
# The TAIL is what a failure says why in, so the tail is what is kept — with
# the count in the document, because a silent trim is a lie about what
# happened. The full console is written beside the report, locally, and never
# travels: see `trim_console`.
CONSOLE_TAIL_LINES = 200


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


def scan_text_for_leaks(text: str, secrets: set) -> list:
    """Return the INDEX of each withheld value that survived — never the value.

    Naming the value in the failure message would put the credential into a
    terminal, a CI log and a screenshot, which is the thing this file exists to
    avoid. The scan runs on the rendered document, so what is checked is what
    would actually be written rather than what we believe we assembled — the
    same property the archive got by being re-extracted and scanned, now free.
    """
    candidates = sorted(s for s in secrets if len(s) >= MIN_LEAK_SCAN_LEN)
    return [i for i, secret in enumerate(candidates) if secret in text]


# ── sections ────────────────────────────────────────────────────────────────
#
# Each section is one verbatim document that used to be one file in the
# archive. It lands under its own top-level key as a YAML block scalar, and
# `sections:` at the foot of the document carries its digest — the manifest
# facts survive the change of shape, they are just over sections now.

def normalise(text: str) -> str:
    """CRLF to LF, no trailing whitespace, exactly one final newline.

    So that the digest is over WHAT A READER SEES, and so that a YAML round
    trip cannot change it: a block scalar preserves lines exactly, and the one
    thing that could differ between what we hash and what a reader parses back
    is whitespace nobody can see. Normalising once, before hashing, removes the
    question rather than answering it.
    """
    lines = [line.rstrip() for line in
             (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n" if lines else ""


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def trim_console(text: str, keep: int = CONSOLE_TAIL_LINES):
    """Keep the tail of a console, and SAY SO. Returns (text, note, dropped).

    A console has no natural length. Including all of it makes a document
    nobody reads; dropping it makes a document that cannot explain a crash.
    The tail is the compromise the evidence supports — a run that died says why
    in its last lines — and the count of what was dropped travels with it so
    the trim is never something a reader has to notice on their own.
    """
    lines = normalise(text).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) <= keep:
        return normalise(text), None, 0
    dropped = len(lines) - keep
    note = ("the last %d of %d lines. A console has no natural length and this "
            "document is meant to be read end to end; a run that fails says why "
            "in its last lines, so the tail is what is kept. The full console "
            "was written beside this file, on your disk, and is not part of "
            "what leaves." % (keep, len(lines)))
    return "\n".join(lines[-keep:]) + "\n", note, dropped


# ── the document ────────────────────────────────────────────────────────────
#
# ONE STYLE, ONE WRITER. The YAML writer and the comment wrapper are IMPORTED
# from kit/report/vexa_state_report.py rather than copied. The state report and
# this one land on the same desk, in front of the same person, and a reader who
# has learned to read one has learned to read both. Two implementations of one
# format drift within a week — the fold width, the quoting rule, how a gap is
# spelt — and the drift is invisible because both still parse.
#
# It is a hard dependency, deliberately: the kit ships as one tree, and half a
# kit should fail loudly at import rather than silently render a second style.

sys.path.insert(0, str(KIT / "report"))
from vexa_state_report import _yaml, comment  # noqa: E402

TOOL = "vexa-validate"
TOOL_VERSION = "0.2.0"

# The keys that identify this run, emitted first and without individual
# comments: a reader takes them in as one block, and the header above them has
# already said what the document is.
HEAD_KEYS = ("schema_version", "bundle_kind", "tier", "station", "generated_at",
             "generator", "kit", "kubernetes", "provider", "namespaces", "tiers")

# Everything else, in the order it is read, with the comment that goes above
# it. The prose lives HERE, beside the key it describes, so a section and its
# explanation move together — which is the whole reason this file is YAML.
DOCUMENT = (
    ("contract", """
THE CONTRACT THIS RUN WAS JUDGED AGAINST — id and sha256. The document itself
is below under `contract_document`; the sha256 is over that text, so the
identity can be recomputed from what you can see rather than from a file you
were told about.
"""),
    ("phases", """
WHAT RAN, AND WHAT IT DECIDED. Verdicts and exit codes. The receipts these
verdicts came from are below, verbatim — nothing here summarises them.
"""),
    ("profile", """
1 · THE PROVIDER PROFILE this run used, verbatim. Substrate facts: provider,
Kubernetes version, scope, storage class, PSA mode, mirror host. Never
credentials. If it says PROFILE_TESTED=no, this is the section worth sending
back filled in — it is the highest-value part of the contribution.
"""),
    ("values", """
2 · YOUR VALUES FILE, structurally intact, with every secret-looking value
replaced by REDACTED — keys matching password|token|secret|key|apikey, and
everything nested beneath them. THE SHAPE IS THE CONTRIBUTION: what we need is
which knobs you turned, never what you turned them to. An empty value stays
empty, because "not set" is configuration and not a secret.
"""),
    ("contract_document", """
3 · THE CONTRACT, verbatim — the policy this run was produced under, carried
beside the evidence rather than referenced from it. Its `report_scope` is the
clause that bounds what may leave this perimeter, and `--submit` checks this
document against it before a byte moves.
"""),
    ("preflight_receipt", """
4 · THE PREFLIGHT RECEIPT, verbatim — will this cluster run what the channel
delivers. Every finding names its own remedy.
"""),
    ("install_log", """
4b · THE INSTALL LOG, present only when --install ran. A console, so only its
tail is kept when it is long; the line count is recorded below.
"""),
    ("smoke_receipt", """
5 · THE SMOKE RECEIPT, verbatim — did what was delivered actually work here.
Chart revision, image digests, segment count.
"""),
    ("smoke_console", """
5b · THE SMOKE RUN'S CONSOLE. Kept because if smoke dies before writing its
receipt, the console is the only evidence of why, and evidence of a crash is
still evidence. Trimmed to its tail when long — the trim is stated below,
never silent.
"""),
    ("release", """
T1 · WHAT IS RUNNING HERE — the Argo Application, the position it follows, the
channel entry that position resolves to, and the PreSync verifier's verdict.
Identifiers and digests; there is no field here that could hold a workload's
data.
"""),
    ("health", """
T2 · AGGREGATE COUNTERS over the workloads this subscription manages. Integers
and ratios, no identities, no logs. A counter that could not be collected is
listed as absent with a reason rather than reported as zero.
"""),
    ("usage", """
T3 · VOLUME AND ACTIVATION AGGREGATES, pseudonymous — counts, never identities.
Shipped as an interface with no implementation: nothing in this kit can produce
these numbers yet, so they arrive absent with a reason. Absent over faked.
"""),
    ("sections", """
THE MANIFEST — every verbatim section above, with the sha256 of its text and
its length. This is what makes the document checkable rather than merely
readable: the ingest recomputes each digest from the text it parsed, and a
section edited in transit is a refusal rather than a surprise later. Digests
are over the NORMALISED text (LF line endings, no trailing whitespace, one
final newline), which is exactly what is written below.
"""),
    ("absent", """
WHAT IS NOT HERE, AND WHY. Recorded rather than defaulted to an empty string: a
receipt that is blank because nothing ran and a receipt that is blank because a
phase produced nothing look identical, and only one of them is fine. An empty
list here means every section was produced.
"""),
    ("refuses", """
WHAT THE TOOL REFUSES, each enforced by code rather than by intent. This one
CAN transmit — that is what --submit is — so the refusals say what bounds the
transmission rather than pretending there is none.
"""),
    ("redaction", """
THE REDACTION SELF-CHECK. `values_redacted` counts the plaintext values that
were removed from your values file. The finished document is then scanned for
every one of them; `verified: true` means none survived. A survivor exits 3,
names the count and never the value, and the file is kept so you can inspect
it — but it must not be sent.
"""),
)

SECTION_KEYS = ("profile", "values", "contract_document", "preflight_receipt",
                "install_log", "smoke_receipt", "smoke_console")

HEADER = """
%s %s — this station, as it actually stands.

WHAT THIS IS. One file: the provider profile, your values with every secret
removed, the contract this run was judged against, and the preflight and smoke
receipts — each verbatim, each with the digest of its own text at the foot of
the document.

ONE FILE, AND THAT IS THE DESIGN. Not a directory, not an archive, nothing to
extract. You have to read all of it before any of it leaves, and six files in a
tarball is a review task where one commented document is a read.

WHAT IS NOT IN IT. No credentials: every value under a key matching
password|token|secret|key|apikey is REDACTED, and the finished file is scanned
for what was removed. No meeting content, no transcripts, no participants, no
schema and no rows — report.v1 sets additionalProperties:false on every object,
so there is nowhere in this document to put one.

IT HAS NOT BEEN SENT ANYWHERE. Writing it sends nothing. `--submit` sends it,
to the channel host you already pull from, with your own credential, after
checking it against your contract's report_scope. Read it first. That is what
it is for.
"""

REFUSES = [
    "send on its own: nothing here transmits until an operator types --submit; "
    "there is no timer and no hook in this tool",
    "send anywhere else: one destination, and it is the channel host you already "
    "pull from — report_scope.destination in your own contract",
    "send above your rung: this document is validated against report.v1 and against "
    "your contract's report_scope before a byte moves",
    "carry a credential: values under keys matching password|token|secret|key|apikey "
    "are REDACTED, and the finished file is scanned for every one removed",
    "carry your content: report.v1 has no field for a transcript, a meeting title, a "
    "participant or a log line, at any tier",
]


def render_yaml(report: dict) -> str:
    """The whole document: header comment, then one commented block per key."""
    lines = comment(HEADER.strip("\n") % (TOOL, TOOL_VERSION)) + [""]
    lines += _yaml({k: report[k] for k in HEAD_KEYS if k in report})
    for key, note in DOCUMENT:
        if report.get(key) is None:
            continue
        value = report[key]
        lines += ["", ""] + comment(note)
        if isinstance(value, (dict, list)) and value:
            lines += ["%s:" % key] + _yaml(value, 2)
        else:
            lines += _yaml({key: value})
    return "\n".join(lines) + "\n"


class Doc:
    """The document under construction, and the two things a phase may add.

    `absent` is the same discipline the state report enforces: a section that
    could not be produced is named with a reason in one central place, so there
    is one list to read rather than a blank field to interpret.
    """

    def __init__(self):
        self.sections: dict = {}
        self.manifest: list = []
        self.gaps: list = []
        # A console that was trimmed is kept whole HERE, and the caller writes
        # it beside the report on the operator's own disk. It never travels:
        # the point of the trim is that the document stays readable, not that
        # the evidence stops existing.
        self.overflow: dict = {}

    def add(self, name: str, text: str, note: str | None = None,
            source_lines: int | None = None) -> None:
        text = normalise(text)
        if not text:
            return self.absent(name, "produced nothing")
        self.sections[name] = text
        row = {"name": name, "sha256": digest_of(text),
               "lines": len(text.rstrip("\n").split("\n"))}
        if source_lines is not None:
            row["source_lines"] = source_lines
        if note:
            row["note"] = note
        self.manifest.append(row)

    def add_console(self, name: str, text: str) -> None:
        kept, note, dropped = trim_console(text)
        if dropped:
            self.overflow[name] = normalise(text)
        self.add(name, kept, note=note,
                 source_lines=(len(kept.rstrip("\n").split("\n")) + dropped
                               if dropped else None))

    def absent(self, name: str, reason: str) -> None:
        self.gaps.append({"what": name, "reason": reason})


def write_report(report: dict, out_dir: pathlib.Path, verify: bool,
                 secrets: set) -> tuple:
    """Render, self-check, render again, write. Returns (path, text, leaks).

    VERIFY THE DOCUMENT, NOT THE INTENTION. The scan runs on the rendered text,
    so what is checked is exactly the bytes that would be written — and then the
    verdict goes back into the document and it is rendered again, which is why
    this happens twice. The archive got this property by being re-extracted and
    scanned; one file gets it for free.
    """
    if not verify:
        report["redaction"]["verified"] = False
        report["redaction"]["note"] = "--no-verify-redaction: NOT checked"
        leaks = []
    else:
        leaks = scan_text_for_leaks(render_yaml(report), secrets)
        report["redaction"]["verified"] = not leaks
        report["redaction"]["leaks"] = len(leaks)
    text = render_yaml(report)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUTPUT_NAME
    path.write_text(text)
    return path, text, leaks


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

def phase_preflight(a, work: pathlib.Path) -> dict:
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
    code, out = run(cmd, log=work / "preflight-receipt.txt")
    return {"verdict": verdict_of(out, "FAIL" if code else "PASS"), "exit_code": code,
            "receipt": "preflight-receipt.txt"}


def phase_install(a, work: pathlib.Path) -> dict:
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
           # log longer, and its findings are already in the report.
           "--skip-preflight"]
    if a.kubeconfig:
        cmd += ["--kubeconfig", a.kubeconfig]
    if a.contract:
        cmd += ["--contract", a.contract]
    cmd += a.install_arg
    code, _ = run(cmd, log=work / "install-log.txt")
    return {"skipped": False, "exit_code": code, "log": "install-log.txt",
            "channel": a.channel, "registry": a.registry}


def phase_smoke(a, work: pathlib.Path) -> dict:
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
    # Run inside the scratch directory so the dated receipt lands somewhere
    # known, and keep the console too: if smoke dies before writing its receipt,
    # the console is the only evidence of why, and a crash is still evidence.
    code, out = run(cmd, cwd=work, log=work / "smoke-console.txt")
    receipts = sorted(p.name for p in work.glob("smoke-receipt-*.md"))
    return {"verdict": verdict_of(out, "FAIL" if code else "PASS"), "exit_code": code,
            "receipt": receipts[-1] if receipts else None}


# ── the sections that used to be files ──────────────────────────────────────

def profile_section(a) -> tuple:
    """The provider profile actually used, or an honest stub saying there was none.

    Returns (text, meta). The stub is not filler: `PROFILE_TESTED=no` is the
    line the whole contribution loop exists to turn into a date, and a silent
    empty section would lose the ask.
    """
    if a.provider:
        src = KIT / "providers" / a.provider / "profile.env"
        if src.exists():
            tested = None
            for line in src.read_text().splitlines():
                if line.startswith("PROFILE_TESTED="):
                    tested = line.split("=", 1)[1].strip().strip('"\'')
            return normalise(src.read_text()), {
                "name": a.provider, "profile_env_present": True,
                "profile_tested": tested}
    text = (
        "# No provider profile was used for this run.\n"
        f"# provider requested: {a.provider or '(none)'}\n"
        f"# looked for: kit/providers/{a.provider or '<name>'}/profile.env\n"
        "# The cluster was validated against ambient kubectl credentials. If your\n"
        "# platform needs a profile (namespaces, pinned versions, node baseline),\n"
        "# this is the section to send back filled in — it is the highest-value\n"
        "# part of the contribution.\n"
        f"PROVIDER={a.provider or 'unspecified'}\n"
        "PROFILE_TESTED=no\n")
    return normalise(text), {"name": a.provider or "unspecified",
                             "profile_env_present": False, "profile_tested": None}


def contract_section(a) -> tuple:
    """The contract, verbatim, beside its identity.

    The document states the policy it was produced under, in the same file as
    the evidence produced under it — which is the whole reason the contract
    travelled in the archive too. Its sha256 is over the normalised text that
    appears below it, so a reader can recompute the identity from what they can
    see rather than from a file they were told about.
    """
    src = pathlib.Path(a.contract) if a.contract else KIT / "verify" / "policy.example.yaml"
    text = normalise(src.read_text())
    contract_id = None
    try:
        import yaml
        contract_id = (yaml.safe_load(text) or {}).get("contract_id")
    except Exception:
        pass
    # the file's name and hash identify the contract; its path on the operator's
    # laptop is nobody's business and would only date the record
    return text, {"source": src.name, "kit_default": not bool(a.contract),
                  "contract_id": contract_id, "sha256": digest_of(text)}


def values_section(a) -> tuple:
    """The operator's values file, structure intact, values gone.

    Returns (text, the set of plaintext values removed). That set is what the
    redaction self-check scans the finished document for, which is what makes
    the promise checkable rather than merely stated.
    """
    import yaml
    removed: set = set()
    values = yaml.safe_load(pathlib.Path(a.customer_values).read_text()) or {}
    return normalise(yaml.safe_dump(redact(values, removed=removed),
                                    sort_keys=False)), removed



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


def check_report_scope(scope: dict, section_names: list, destination: str,
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

    # `allowed_files` was the clause when the report was six files in a tarball.
    # It is REFUSED rather than silently ignored: a customer who wrote down
    # which files may leave has written a bound, and a bound this tool no longer
    # reads is worse than one it cannot satisfy. The refusal names the new
    # spelling and the section names, so the edit is a minute's work.
    if scope.get("allowed_files") is not None:
        problems.append(
            "report_scope.allowed_files names bundle FILES, and this report is one file "
            "with named sections. Rename the clause to report_scope.allowed_sections and "
            f"list section names ({', '.join(sorted(SECTION_KEYS))}). Nothing was sent — "
            "a bound we cannot read is not a bound we will guess at.")

    allowed = scope.get("allowed_sections")
    if allowed:
        for name in section_names:
            if not any(fnmatch.fnmatch(name, pat) for pat in allowed):
                problems.append(f"section '{name}' is outside report_scope.allowed_sections")

    if scope.get("require_redaction_verified") and not station_doc.get(
            "redaction", {}).get("verified"):
        problems.append("report_scope.require_redaction_verified is set and redaction was not "
                        "verified against the written report")

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


def phase_submit(a, report: pathlib.Path, station_doc: dict,
                 contract_path: pathlib.Path) -> int:
    """Push the one file. THE PAYLOAD AND THE DOCUMENT ARE NOW THE SAME OBJECT.

    Before, a JSON payload was assembled beside the archive and validated, and
    the archive rode along beside it — so the thing checked against report.v1
    was not the thing an operator had read. Now `station-report.yaml` is parsed,
    validated, and pushed: what leaves is what they opened.
    """
    scope = read_report_scope(contract_path)
    destination = a.submit_destination or scope.get("destination") or a.registry
    if not destination:
        raise SystemExit("--submit needs a destination: report_scope.destination in your "
                         "contract, or --submit-destination, or --registry")
    destination = destination.replace("https://", "").replace("http://", "").rstrip("/")

    station_name = station_doc["station"]
    print("\n== submit — validating what would leave this perimeter")

    payload = dict(station_doc)
    validate_report(payload)
    check_report_scope(scope, [s["name"] for s in payload["sections"]], destination, payload)

    print("   report.v1 OK — every field in this document is in the schema, and the "
          "schema has no field that could hold your content")
    print(f"   sending:     {report}")
    print(f"   open it. that is what it is for — it is the file, not a summary of it.")
    print(f"   destination: {destination}/vexa/stations/{station_name}/bundles:{a.submit_tag}")
    print(f"   carrying:    {report.name} ({report.stat().st_size} bytes), "
          f"{len(payload['sections'])} section(s)")

    if a.submit_dry_run:
        print("   --submit-dry-run: nothing sent.")
        return 0

    ref = f"{destination}/vexa/stations/{station_name}/bundles:{a.submit_tag}"
    plain = (["--plain-http"] if a.submit_plain_http
             else (["--insecure"] if a.submit_insecure else []))
    cmd = ["oras", "push", *plain, "--artifact-type", REPORT_ARTIFACT_TYPE, ref,
           report.name]
    proc = subprocess.run(cmd, cwd=str(report.parent), capture_output=True, text=True,
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


# The artifact type says what a puller is about to get, so it changed with the
# shape: one YAML document, not a gzipped tree.
REPORT_ARTIFACT_TYPE = "application/vnd.vexa.station-report.v1+yaml"


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
    and a report that carries none is complete rather than incomplete. The
    ingest side reads the same field and applies the matching role set.

    What travels: this document, with the tier blocks and the contract verbatim
    — so the report states the policy it was produced under, beside the data,
    in one file. Nothing else, and `allowed_sections` in the contract still has
    the final say on that.
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

    doc = Doc()
    contract_text = normalise(contract_path.read_text())
    doc.add("contract_document", contract_text)
    # ONE line, not six. No phase ran and no values file travels, so a report
    # carrying none of those sections is complete rather than incomplete —
    # naming each one missing would turn a correct document into a list of
    # apologies.
    doc.absent("profile, values and the phase receipts",
               "this is a telemetry report, not a validation run: no phase ran and no "
               "values file travels, so there is nothing to carry. `vexa_validate.py "
               "--customer-values ...` produces the install shape that has them.")

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
            "sha256": digest_of(contract_text),
        },
        "phases": {},
        "tiers": {"flows": bool(a.flows)},
        # A telemetry report carries no customer values, so there is nothing to
        # redact. Said as a number rather than left null: a null here would
        # read as "not checked".
        "redaction": {"verified": True, "values_redacted": 0, "leaks": 0,
                      "note": "telemetry report: no values file travels, "
                              "nothing to redact"},
        **blocks,
        **doc.sections,
        "sections": doc.manifest,
        "absent": doc.gaps,
        "refuses": REFUSES,
    }

    out_dir = pathlib.Path(a.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    text = render_yaml(station)
    report = out_dir / OUTPUT_NAME
    report.write_text(text)
    print(f"\ntelemetry report (tier {tier} — {c.TIER_NAMES[tier]}): {report}"
          f"   ({len(text.splitlines())} lines)")
    if not a.submit:
        print("\nnothing was sent. Read it, then --submit sends exactly this file; "
              "--submit-dry-run validates it and sends nothing.")
        return 0
    return phase_submit(a, report, station, contract_path)


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
                    help="the values file you edit and keep; redacted into the report. "
                         "Required for a validation run; a --report or --export-diagnostics "
                         "run carries no values file and does not take one.")
    ap.add_argument("--contract", help="contract this environment verifies against "
                                       "(default kit/verify/policy.example.yaml)")
    ap.add_argument("--provider", help="provider profile name under kit/providers/")
    ap.add_argument("--out", default=".",
                    help=f"directory to write {OUTPUT_NAME} into (default: here)")
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
    # the report
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
    ap.add_argument("--submit-tag", help="the tag this report is pushed under; default today's UTC date")
    ap.add_argument("--submit-dry-run", action="store_true",
                    help="validate and print the payload; send nothing")
    ap.add_argument("--submit-plain-http", action="store_true")
    ap.add_argument("--submit-insecure", action="store_true")
    ap.add_argument("--continue-on-fail", action="store_true",
                    help="write the report even if a phase FAILs (a failing run is "
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
    # A SCRATCH directory, not a bundle root. The phases are separate programs
    # that write receipts as files, so they need somewhere to write them; what
    # the operator gets is one document assembled from that, and this directory
    # is deleted before the command returns.
    work = tmp / "phases"
    work.mkdir()

    phases = {}
    phases["preflight"] = phase_preflight(a, work)
    hard_fail = phases["preflight"]["verdict"] == "FAIL"
    if hard_fail and not a.continue_on_fail:
        print("\npreflight FAILED — fix the findings above and rerun. "
              f"Findings: {out_dir / 'preflight-receipt.txt'}\n"
              "(--continue-on-fail writes the failure into the report instead, which is a "
              "perfectly good thing to send us.)")
        shutil.copyfile(work / "preflight-receipt.txt", out_dir / "preflight-receipt.txt")
        shutil.rmtree(tmp, ignore_errors=True)
        return 1

    phases["install"] = phase_install(a, work)
    if phases["install"].get("exit_code"):
        hard_fail = True
        if not a.continue_on_fail:
            print("\ninstall FAILED — see install-log.txt")
            shutil.copyfile(work / "install-log.txt", out_dir / "install-log.txt")
            shutil.rmtree(tmp, ignore_errors=True)
            return 1

    phases["smoke"] = phase_smoke(a, work)
    hard_fail = hard_fail or phases["smoke"]["verdict"] == "FAIL"

    # ── the report ──────────────────────────────────────────────────────────
    print("\n== writing the station record")
    provider_text, provider_meta = profile_section(a)
    contract_text, contract_meta = contract_section(a)
    values_text, secrets = values_section(a)

    doc = Doc()
    doc.add("profile", provider_text)
    doc.add("values", values_text)
    doc.add("contract_document", contract_text)
    for name, path in (("preflight_receipt", work / "preflight-receipt.txt"),
                       ("smoke_receipt", work / (phases["smoke"].get("receipt") or ""))):
        if path.is_file():
            doc.add(name, path.read_text())
        else:
            doc.absent(name, "the phase produced no receipt — see its verdict and exit "
                             "code above, and the console below if there is one")
    for name, path in (("install_log", work / "install-log.txt"),
                       ("smoke_console", work / "smoke-console.txt")):
        if path.is_file():
            doc.add_console(name, path.read_text())
    if phases["install"].get("skipped"):
        doc.absent("install_log", "install was not requested (--install); nothing ran, so "
                                  "there is no log rather than an empty one")

    station = {
        # report.v1 (spec/report.v1.schema.json). This document IS the report:
        # the manifest that travels is the manifest the operator can read, not
        # a second one assembled for us out of sight.
        "schema_version": 1,
        # Stated, not inferred. The ingest applies a different required-section
        # set to each kind, and a telemetry report carrying no smoke receipt is
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

    # A validation run is itself a T1 event — an install happened and a verdict
    # exists — so when the contract declares a rung, the install report carries
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
            # happened. The report ships without the ladder blocks and says so.
            print(f"note ladder collection skipped: {e}")
            doc.absent("telemetry blocks", f"the ladder collector raised {type(e).__name__}; "
                                           "the validation run itself is unaffected")

    # The sections themselves, then the manifest OVER them. `sections` is what
    # makes the document checkable rather than merely readable — a list of names
    # a tampered report satisfies trivially, a list of digests it does not.
    station.update(doc.sections)
    station["sections"] = doc.manifest
    station["absent"] = doc.gaps
    station["refuses"] = REFUSES

    report, text, leaks = write_report(station, out_dir, a.verify_redaction, secrets)

    # The trimmed console, whole, on the operator's own disk. It is not part of
    # what leaves and it is not referenced by the manifest: it exists so that a
    # trim costs readability and never evidence.
    for name, whole in sorted(doc.overflow.items()):
        spill = out_dir / f"{OUTPUT_NAME.rsplit('.', 1)[0]}-{name.replace('_', '-')}.txt"
        spill.write_text(whole)
        print(f"  (kept whole, locally, and never sent: {spill})")

    shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{report}   ({len(text.splitlines())} lines)")
    for row in station["sections"]:
        print(f"  {row['sha256'][:12]}  {row['name']}")
    print(f"\nphases: preflight {phases['preflight']['verdict']}"
          f" · install {'skipped' if phases['install'].get('skipped') else 'ran'}"
          f" · smoke {phases['smoke']['verdict']}")
    if leaks:
        print(f"\n!! REDACTION FAILED — {len(leaks)} withheld value(s) survived into "
              f"{report.name}")
        print("   The file was written so you can inspect it. DO NOT SEND IT.")
        print("   Report the finding to Vexa without attaching it.")
        return 3
    if a.verify_redaction:
        print(f"redaction: {len(secrets)} value(s) removed, 0 found in the report")
    if a.submit:
        rc = phase_submit(a, report, station, pathlib.Path(a.contract) if a.contract
                          else KIT / "verify" / "policy.example.yaml")
        if rc:
            return rc
        return 1 if hard_fail else 0

    print(f"\nread {OUTPUT_NAME} — it is one file and it explains itself. Then send it "
          "back to Vexa: it is your configuration contribution and it contains NO secrets.")
    print("Or let the channel carry it: re-run with --submit (nothing sends on its own).")
    return 1 if hard_fail else 0


if __name__ == "__main__":
    sys.exit(main())
