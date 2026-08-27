#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-station — ingest a customer's station report, then gate publishes on
the station's own contract.

The channel publisher (`vexa_channel.py`) answers "may this release exist?".
This tool answers the other half: "may this release be published AT this
customer's station, given what that station's contract requires?" — the
per-release guarantees document, made executable.

  ingest  read a station report (ONE commented YAML file: the provider
          profile, the redacted values, the contract, the phase receipts, and
          a manifest of section digests) into stations/<name>/ after checking
          it is complete, self-consistent and free of plaintext secrets
  gate    render a packaged chart with the station's values and refuse the
          publish unless the render survives the station's environment and
          every `require:` item in its contract is met by evidence or
          explicitly waived

Checks are named S1..S9 and a failure REFUSES with exit 3 — the same shape as
the channel publisher's C1..C9. There is no silent path: an unmet contract
item needs an explicit, loudly recorded waiver, which becomes visible data in
the gate report.

  S1 report shape        one YAML document, a mapping, report.v1, bounded size
  S2 completeness        the section roles this report KIND requires are present
  S3 manifest identity   the report names this station, its section digests
                         match the text, and nothing undeclared rides along
  S4 no plaintext secrets  defense in depth over the customer's redaction
  S5 render              helm template succeeds with the station's values
  S6 resources           every container declares cpu+memory requests+limits
  S7 no hostPath         no workload mounts a host path
  S8 digest-pinned       every image reference carries @sha256:
  S9 contract            every require: item is evidenced or waived
  S10 report scope       the report does not exceed the station's declared
                         telemetry tier — WE ENFORCE THEIR POLICY AGAINST
                         OURSELVES, which is the half of the promise worth
                         anything: a customer can read the packager and see
                         that it cannot collect above its rung, but only this
                         check proves we would not KEEP a report that did.

WHAT CHANGED WITH THE SINGLE FILE, since a check that quietly stopped checking
is the failure this file exists to prevent. S1 no longer walks archive members
for traversal, links and a single root, because there is no archive: it bounds
the file's size and refuses anything that is not exactly one YAML mapping. S2
and S3 hold unchanged in substance and are expressed against SECTIONS instead
of files — a declared section must be present, its sha256 must match the text
that is there to read, and a top-level key that is neither a manifest field nor
a declared section is a refusal. S4 gained reach rather than losing it: it
scans the whole document AND parses the values and profile sections back into
their own formats, so a credential inside a section is caught by the same two
scans that used to run over files.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vexa_channel import CheckFailure, sha256_file, utcnow  # noqa: E402

REPORT_NAME = "station-report.yaml"

# A station report is a document a person is expected to read before sending
# it. This is not a memory limit, it is that claim in bytes: anything larger
# than this was not read by anybody, whatever it says.
MAX_REPORT_BYTES = 4 * 1024 * 1024

# role -> the section key that fills it. The role is what the gate reasons
# about; the key is what the packager writes.
BUNDLE_ROLES = {
    "profile": "profile",
    "values": "values",
    "contract": "contract_document",
    "preflight_receipt": "preflight_receipt",
    "smoke_receipt": "smoke_receipt",
}

# Sections a report may carry beyond the required roles. Optional because a
# run that did not install has no install log and a smoke that wrote its
# receipt cleanly may carry no console.
OPTIONAL_SECTIONS = ("install_log", "smoke_console")

# Everything else a report may carry at the top level. A key outside this set
# and outside the declared sections is refused by S3 — the ingest is the second
# enforcer of report.v1's closed field set, on the side the customer cannot
# audit.
MANIFEST_KEYS = {
    "schema_version", "bundle_kind", "tier", "station", "generated_at", "generator",
    "kit", "kubernetes", "provider", "namespaces", "contract", "phases", "tiers",
    "redaction", "release", "health", "usage", "sections", "absent", "refuses",
}

WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet")

# ------------------------------------------------------------------ secrets
#
# Two independent scans. The key scan catches a credential the customer meant
# to redact and did not; the pattern scan catches a credential pasted into a
# file nobody thought of as a secrets file (a receipt, a profile comment).
# NEITHER EVER PRINTS THE VALUE — a refusal names the file, the line and the
# rule, so the refusal text itself is safe to paste into an issue.

SECRET_KEY_RE = re.compile(
    r"(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|"
    r"credential|private[_-]?key|passphrase|client[_-]?secret)", re.I)
# ...but these name or locate a credential rather than carrying one.
REFERENCE_KEY_RE = re.compile(r"(name|ref|path|file|enabled|repository|namespace|id)$", re.I)
PLACEHOLDER_RE = re.compile(
    r"^\s*(|~|-|null|none|redacted|<[^>]*>|\*{2,}|x{3,}|change[_-]?me.*|todo.*|"
    r"set[_-]?in[_-]?cluster|from[_-]?vault.*|sha256:[0-9a-f]{64})\s*$", re.I)

SECRET_PATTERNS = (
    ("PEM private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("kubeconfig client key", re.compile(r"client-key-data\s*:")),
)


def value_is_placeholder(value):
    return not isinstance(value, str) or bool(PLACEHOLDER_RE.match(value))


def scan_mapping(obj, findings, where, trail=()):
    """Walk parsed YAML/JSON for secret-looking keys carrying real values."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = trail + (str(k),)
            if isinstance(v, (dict, list)):
                scan_mapping(v, findings, where, path)
                continue
            if (SECRET_KEY_RE.search(str(k)) and not REFERENCE_KEY_RE.search(str(k))
                    and not value_is_placeholder(v) and len(str(v)) >= 6):
                findings.append(f"{where}: key '{'.'.join(path)}' carries a plaintext value "
                                f"(len {len(str(v))}) where a redaction placeholder was expected")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            scan_mapping(v, findings, where, trail + (str(i),))


def scan_env_text(text, findings, where):
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip("'\"")
        if (SECRET_KEY_RE.search(k) and not REFERENCE_KEY_RE.search(k)
                and not value_is_placeholder(v) and len(v) >= 6):
            findings.append(f"{where}:{n}: env key '{k}' carries a plaintext value "
                            f"(len {len(v)}) where a redaction placeholder was expected")


def scan_patterns(text, findings, where):
    for n, line in enumerate(text.splitlines(), 1):
        for label, pat in SECRET_PATTERNS:
            if pat.search(line):
                findings.append(f"{where}:{n}: looks like a {label} in plaintext")


def scan_report_for_secrets(report, sections):
    """S4 — refuse a report carrying anything credential-shaped. Defense in
    depth: the customer redacts, we refuse to hold what they missed.

    Three scans, and the second and third are why folding six files into one
    did not cost this check anything. The whole document is pattern-scanned
    line by line. Then each section is parsed back into ITS OWN format — the
    values section as YAML, the profile section as an env file — so a
    secret-shaped key carrying a real value is caught inside a block scalar
    exactly as it was caught inside a file. A scan of the outer document alone
    would see those sections as one long string and find nothing.
    """
    import yaml

    findings = []
    scan_mapping({k: v for k, v in report.items() if k not in sections},
                 findings, REPORT_NAME)
    for name, text in sorted(sections.items()):
        where = f"{REPORT_NAME}[{name}]"
        scan_patterns(text, findings, where)
        if name in ("values", "contract_document"):
            try:
                for doc in yaml.safe_load_all(text):
                    scan_mapping(doc, findings, where)
            except yaml.YAMLError as e:
                raise CheckFailure("S4", f"section '{name}' is not parseable YAML: {e}")
        elif name == "profile":
            scan_env_text(text, findings, where)
    return findings


# ------------------------------------------------------------------- report


def load_report(path):
    """S1 — one YAML document, a mapping, report.v1, and small enough to read.

    The old S1 walked a tar for absolute paths, `..` and links, and refused
    more than one top-level directory. None of those exist for a file that is
    never extracted, so the check is not weakened — its subject is gone. What
    remains is the same question in the new shape: is this one document of the
    kind we accept, and is it a size a human could have read before sending it?
    """
    if not path.is_file():
        raise CheckFailure("S1", f"station report {path} does not exist")
    size = path.stat().st_size
    if size > MAX_REPORT_BYTES:
        raise CheckFailure("S1", f"{path.name} is {size} bytes, above the {MAX_REPORT_BYTES} "
                                 "byte ceiling. A station report is a document somebody read "
                                 "before sending it; this one was not.")
    try:
        text = path.read_text()
    except UnicodeDecodeError as e:
        raise CheckFailure("S1", f"{path.name} is not text: {e}")
    import yaml
    try:
        docs = [d for d in yaml.safe_load_all(text)]
    except yaml.YAMLError as e:
        raise CheckFailure("S1", f"{path.name} is not parseable YAML: {e}")
    if len(docs) != 1:
        raise CheckFailure("S1", f"{path.name} carries {len(docs)} YAML documents; "
                                 "a station report is exactly one")
    report = docs[0]
    if not isinstance(report, dict):
        raise CheckFailure("S1", f"{path.name} is not a mapping")
    if report.get("schema_version") != 1:
        raise CheckFailure("S1", f"{path.name} declares schema_version "
                                 f"{report.get('schema_version')!r}; this ingest reads "
                                 "report.v1")
    return report, text


# Which roles each report KIND must carry. An install report is an operator's
# validation run and carries all five. A TELEMETRY report is a ladder
# submission from the station itself: no phase ran, so there is no preflight
# receipt and no smoke receipt to carry, and requiring one would mean either
# refusing every T2 submission or having the sender manufacture an empty
# receipt — a fabricated section in a signed report, which is the worse of
# the two by a distance.
KIND_ROLES = {
    "install": tuple(BUNDLE_ROLES),
    "telemetry": ("contract",),
}


def sections_of(report):
    """Every top-level key that carries a section body, by name."""
    known = set(BUNDLE_ROLES.values()) | set(OPTIONAL_SECTIONS)
    return {k: v for k, v in report.items() if k in known and isinstance(v, str)}


def locate_roles(report, kind="install"):
    """S2 — every role this report kind requires, present and non-empty."""
    found, missing = {}, []
    sections = sections_of(report)
    for role in KIND_ROLES.get(kind, KIND_ROLES["install"]):
        key = BUNDLE_ROLES[role]
        text = sections.get(key)
        if not text or not text.strip():
            missing.append(f"{role} (section '{key}')")
        else:
            found[role] = key
    if missing:
        raise CheckFailure("S2", "report is incomplete; missing " + "; ".join(missing))
    return found


def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def check_manifest(report, station, roles):
    """S3 — the report names this station, and its digests match the text.

    Same three claims as the file version, over sections: every declared
    section is present and hashes to what was declared, nothing undeclared
    rides along, and every required role is declared rather than merely
    present. The third is what stops a section being smuggled in below a
    manifest that does not mention it.
    """
    if report.get("station") != station:
        raise CheckFailure("S3", f"the report declares station "
                                 f"'{report.get('station')}' but --station is '{station}'")
    declared = report.get("sections")
    if not isinstance(declared, list) or not declared:
        raise CheckFailure("S3", "the report declares no sections[]")
    present = sections_of(report)
    for row in declared:
        if not isinstance(row, dict):
            raise CheckFailure("S3", f"sections[] carries {row!r}, which is not a mapping")
        name, want = row.get("name"), row.get("sha256")
        text = present.get(name)
        if not name or text is None:
            raise CheckFailure("S3", f"the report declares section '{name}', which is not in "
                                     "the document")
        got = sha256_text(text)
        if want != got:
            raise CheckFailure("S3", f"section '{name}' digest mismatch — the manifest says "
                                     f"{want}, the text is {got}")
        present.pop(name)
    if present:
        raise CheckFailure("S3", f"the report carries sections its manifest does not declare: "
                                 f"{sorted(present)}")
    names = {row["name"] for row in declared}
    for role, key in roles.items():
        if key not in names:
            raise CheckFailure("S3", f"required section '{key}' ({role}) is undeclared in "
                                     "sections[]")
    stray = set(report) - MANIFEST_KEYS - names
    if stray:
        raise CheckFailure("S3", f"the report carries top-level keys that are neither manifest "
                                 f"fields nor declared sections: {sorted(stray)} — report.v1 is "
                                 "a closed schema and this is where we hold ourselves to it")


# ------------------------------------------------------------------ S10 · scope
#
# The tier -> block table is IMPORTED from the station-side packager rather
# than restated here. Two copies of one rule is how a refusal quietly stops
# matching what it is refusing: the packager tightens, the ingest does not, and
# the gap is invisible because nothing errors — a bundle simply passes. One
# table, two readers, and a test that pins it against the schema's own rules.

def _tier_blocks():
    kit_validate = pathlib.Path(__file__).resolve().parent.parent / "kit/validate"
    sys.path.insert(0, str(kit_validate))
    import collectors
    return collectors.TIER_BLOCKS, collectors.MAX_SUBMITTABLE_TIER


def contract_tier(contract_text):
    """The tier the STATION's own contract declares. Their document, our limit."""
    import yaml
    try:
        doc = yaml.safe_load(contract_text) or {}
    except yaml.YAMLError:
        return None
    scope = doc.get("report_scope")
    if not isinstance(scope, dict) or not scope:
        return None
    # A report_scope with no `tier` is tier 1 — the pre-ladder shape, which
    # permits exactly the operator's install bundle, which is what T1 is. The
    # refusal below is for a contract with NO report_scope: no bound at all.
    tier = scope.get("tier", 1)
    return tier if isinstance(tier, int) and not isinstance(tier, bool) else None


def check_report_scope_tier(manifest, contract_text):
    """S10 — refuse a bundle that exceeds the station's declared report scope.

    Three ways a bundle can exceed it, and each gets its own sentence, because
    "refused" with no reason turns a policy into an outage:

      1. it declares a higher tier than the contract does;
      2. it carries a BLOCK belonging to a higher tier, whatever it declares —
         the block is the payload, the number is only a label;
      3. it declares a tier the contract does not permit at all (T0 silent
         stations submit nothing; T4 never travels this path).

    Note the asymmetry that makes this worth writing: a station could send us
    anything it liked. This check is not defence against a hostile station —
    it is us, holding ourselves to their declaration, on the one side of the
    exchange they cannot audit.
    """
    blocks, max_submittable = _tier_blocks()
    declared = contract_tier(contract_text)
    if declared is None:
        raise CheckFailure(
            "S10", "the contract section of this report carries no "
                   "report_scope — refusing to ingest a report under a policy nobody wrote "
                   "down. report_scope is the clause that bounds what may leave their "
                   "perimeter; without it there is no bound to enforce, and we do not get "
                   "to pick one on their behalf. (A report_scope with no `tier` is fine — "
                   "that is the pre-ladder shape and reads as tier 1.)")

    carried = manifest.get("tier")
    if carried is None:
        # Pre-ladder bundles are T1 receipts by construction: an install run
        # with phase verdicts and nothing else. Reading them as anything else
        # would either invent data or refuse evidence already in the ledger.
        carried = 1
    if not isinstance(carried, int) or isinstance(carried, bool):
        raise CheckFailure("S10", f"station.json declares tier {carried!r}, which is not an integer")

    if declared == 0:
        raise CheckFailure(
            "S10", "this station's contract declares tier 0 (silent) — it submits nothing at "
                   "all, and a bundle arriving from it is a contract violation on our side of "
                   "the exchange, not theirs. Nothing was ingested.")
    if carried > max_submittable:
        raise CheckFailure(
            "S10", f"station.json declares tier {carried}. Tier 4 (diagnostics) never travels "
                   "this path: it is exported locally by the customer's admin and handed over "
                   "per incident. A bundle claiming it is malformed.")
    if carried > declared:
        raise CheckFailure(
            "S10", f"bundle is tier {carried} and this station's contract declares tier "
                   f"{declared} — REFUSED. Nothing above their declared rung is kept, "
                   "regardless of what they sent us.")

    for tier, block in sorted(blocks.items()):
        if block and block in manifest and tier > declared:
            raise CheckFailure(
                "S10", f"bundle carries a '{block}' block, which is tier {tier}, and this "
                       f"station's contract declares tier {declared} — REFUSED. The block is "
                       "the payload; the tier field is only a label, and a label cannot "
                       "authorise its own contents.")
    return {"declared_tier": declared, "bundle_tier": carried,
            "blocks": sorted(b for t, b in blocks.items() if b and b in manifest)}


def cmd_ingest(args):
    bundle = pathlib.Path(args.bundle)
    manifest, _text = load_report(bundle)
    # The KIND is read before the roles are located, because it decides which
    # roles are required. Locating first and then asking would refuse every
    # telemetry report at S2 for the absence of a receipt no telemetry run
    # produces.
    kind = manifest.get("bundle_kind", "install")
    if kind not in KIND_ROLES:
        raise CheckFailure("S2", f"the report declares bundle_kind '{kind}'; "
                                 f"known kinds are {sorted(KIND_ROLES)}")
    roles = locate_roles(manifest, kind)
    check_manifest(manifest, args.station, roles)
    sections = sections_of(manifest)
    findings = scan_report_for_secrets(manifest, sections)
    if findings:
        raise CheckFailure("S4", "the report carries plaintext credential material — "
                                 "refusing to ingest:\n  - " + "\n  - ".join(findings))
    # S10 — the station's OWN contract, as carried in this report, decides what
    # we are allowed to keep. Read from the report rather than from our copy on
    # disk: our copy is what we last ingested, and a station that has TIGHTENED
    # its scope must have that take effect on the very report that tells us so.
    scope = check_report_scope_tier(manifest, sections[roles["contract"]])

    dest = pathlib.Path(args.stations_dir) / args.station
    if dest.exists() and not args.force:
        raise CheckFailure("S2", f"{dest} already exists; pass --force to re-ingest")
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    # The report VERBATIM, and nothing extracted out of it. The sections are
    # not written back out as files: what the customer sent is one document,
    # and a directory of derived copies is a second version of it that can
    # disagree with the first.
    shutil.copyfile(bundle, dest / REPORT_NAME)
    receipt = {
        "station": args.station,
        "ingested_at": utcnow(),
        "bundle": bundle.name,
        "bundle_sha256": sha256_file(bundle),
        # The identity fields, and only the ones this report actually carried —
        # a row of nulls for the M1 shape's keys reads as "we looked and there
        # was nothing there", which is not what an absent key means.
        "manifest": {k: manifest[k] for k in
                     ("schema_version", "bundle_kind", "tier", "generated_at", "generator",
                      "customer", "environment", "kit_version", "created_at")
                     if manifest.get(k) is not None},
        "sections": [{"name": r["name"], "sha256": r["sha256"]}
                     for r in manifest["sections"]],
        "bundle_kind": kind,
        "report_scope": scope,
        "checks_passed": ["S1", "S2", "S3", "S4", "S10"],
    }
    (dest / "ingest-receipt.json").write_text(json.dumps(receipt, indent=1) + "\n")
    print(f"ingested station '{args.station}' -> {dest} at {receipt['ingested_at']}")
    for row in receipt["sections"]:
        print(f"  {row['sha256'][:12]}  {row['name']}")

    # The durable half. `stations/<name>/` is a working directory on one
    # laptop and gitignored by design; the ledger is where a station's
    # receipts and derived state survive the laptop. `ingest` is the sole
    # writer of stations/* there — see publisher/vexa_stations.py.
    import os

    if getattr(args, "ledger", None) or os.environ.get("VEXA_STATIONS_DIR"):
        if not args.channel:
            raise CheckFailure("S2", "--ledger needs --channel: a station's state is "
                                     "recorded under the channel it subscribes to")
        import vexa_stations

        # The manifest WITHOUT the section bodies. The report itself is stored
        # verbatim beside the receipt, so writing the bodies a second time into
        # the reduced manifest would be two copies that can disagree — and the
        # ledger's job is the reduction, not the archive.
        out = vexa_stations.record_ingest(
            vexa_stations.resolve_root(getattr(args, "ledger", None)),
            channel=args.channel, station=args.station, receipt=receipt,
            manifest={k: v for k, v in manifest.items() if k not in sections},
            bundle=bundle, values_text=sections.get("values", ""),
        )
        print(f"ledger: {out['channel']}/{out['station']} recorded; flags: "
              f"{', '.join(out['flags']) or 'none'} "
              f"({out['commit'][:12] if out['commit'] else 'no change'})")
    return 0


# ------------------------------------------------- pulling a bundle back down
#
# The return leg. `kit/validate --submit` pushes the station bundle to
# <registry>/vexa/stations/<station>/bundles:<date> using the SUBSCRIBER's own
# credential, on the host their firewall already permits. This pulls it.
#
# The path segment IS the account name: the edge lets a subscriber write to
# /v2/vexa/stations/<their-name>/** and refuses every other path, so a station
# cannot overwrite another station's evidence and we do not have to trust it
# not to. That convention is load-bearing in two places at once and is
# documented in both.

def stations_ref(registry, station):
    return f"{registry.rstrip('/')}/vexa/stations/{station}/bundles"


def newest_bundle_tag(ref, plain):
    r = subprocess.run(["oras", "repo", "tags", *plain, ref],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise CheckFailure("S1", f"cannot list bundles at {ref}: "
                                 f"{(r.stderr or '').strip()[-300:]}")
    tags = [t.strip() for t in r.stdout.splitlines() if t.strip()]
    if not tags:
        raise CheckFailure("S1", f"{ref} holds no bundles — the station has not submitted one")
    # Tags are dates (YYYY-MM-DD[-HHMMSS]); lexical order is chronological order
    # for that shape, which is why the shape was chosen.
    return sorted(tags)[-1]


def cmd_ingest_from_registry(args):
    plain = ["--plain-http"] if args.plain_http else (["--insecure"] if args.insecure else [])
    ref = stations_ref(args.from_registry, args.station)
    tag = args.bundle_tag or newest_bundle_tag(ref, plain)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="vexa-station-pull-"))
    try:
        r = subprocess.run(["oras", "pull", *plain, f"{ref}:{tag}", "-o", str(tmp)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise CheckFailure("S1", f"cannot pull {ref}:{tag}: "
                                     f"{(r.stderr or '').strip()[-300:]}")
        reports = sorted(tmp.glob("*.yaml")) + sorted(tmp.glob("*.yml"))
        if len(reports) != 1:
            raise CheckFailure("S1", f"{ref}:{tag} carries {len(reports)} YAML members; "
                                     f"a station report is exactly one")
        print(f"pulled {ref}:{tag} -> {reports[0].name} "
              f"(sha256 {sha256_file(reports[0])[:12]}…)")
        args.bundle = str(reports[0])
        return cmd_ingest(args)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------- gate checks


def pod_spec(doc):
    if not isinstance(doc, dict) or doc.get("kind") not in WORKLOAD_KINDS:
        return None
    if doc["kind"] == "Pod":
        return doc.get("spec")
    spec = doc.get("spec") or {}
    if doc["kind"] == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    tpl = spec.get("template") or {}
    return tpl.get("spec")


def workload_id(doc):
    return f"{doc.get('kind')}/{(doc.get('metadata') or {}).get('name', '<unnamed>')}"


def containers_of(spec):
    for key in ("initContainers", "containers"):
        for c in (spec.get(key) or []):
            yield key, c


def check_resources(docs):
    """S6 — every container declares cpu+memory requests AND limits. A
    container that declares nothing is the 64Mi-LimitRange-squeeze class
    (vexa#1005): admission does not refuse it, it silently shrinks it."""
    bad = []
    for doc in docs:
        spec = pod_spec(doc)
        if not spec:
            continue
        for key, c in containers_of(spec):
            res = c.get("resources") or {}
            for section in ("requests", "limits"):
                for unit in ("cpu", "memory"):
                    if (res.get(section) or {}).get(unit) in (None, ""):
                        bad.append(f"{workload_id(doc)} {key}/{c.get('name')} "
                                   f"does not declare resources.{section}.{unit}")
    return bad


def check_no_hostpath(docs):
    """S7 — a hostPath mount reaches out of the tenancy the station promised."""
    bad = []
    for doc in docs:
        spec = pod_spec(doc)
        if not spec:
            continue
        for v in (spec.get("volumes") or []):
            if isinstance(v, dict) and "hostPath" in v:
                bad.append(f"{workload_id(doc)} mounts hostPath volume '{v.get('name')}' "
                           f"({(v.get('hostPath') or {}).get('path')})")
    return bad


DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


def check_digest_pinned(docs):
    """S8 — a mutable tag means the bytes that pass the gate are not the bytes
    that run. Every reference carries its digest."""
    bad = []
    for doc in docs:
        spec = pod_spec(doc)
        if not spec:
            continue
        for key, c in containers_of(spec):
            image = c.get("image") or ""
            if not DIGEST_RE.search(image):
                bad.append(f"{workload_id(doc)} {key}/{c.get('name')} image "
                           f"'{image}' is not digest-pinned")
    return bad



# ------------------------------------------------- delivery_scope (blast radius)
#
# The OUTBOUND half of the two-directional contract: what a release may DO
# inside the customer's cluster. Its sibling, report_scope, says what may leave
# — the two are one document because a subscription is a pair of bounded
# promises, and a customer who can only read one of them is being asked to
# trust the other.
#
# Every clause is expressed in a vocabulary a reviewer already has:
# Pod Security Standards (and therefore OpenShift SCC), the cluster-scoped/
# namespaced split that OLM install modes turn on, and registry allowlisting.
# Nothing here is a Vexa invention, deliberately: a reviewer who recognises
# the standard stops evaluating and starts checking.
#
# WHERE IT IS ENFORCED, honestly, and it is not one place:
#   * HERE, publisher-side, on the rendered chart — the only point that sees
#     every object the release would create.
#   * The PreSync verifier re-checks what a shell in a Job can re-check: that
#     the scope the gate ENFORCED is the scope the customer's own contract
#     asks for. It cannot render the chart, so it says so rather than implying
#     a check it did not run.
#   * Kubernetes itself — Pod Security admission and Kyverno — is the only
#     party that sees what actually runs. The clauses are written in PSS
#     vocabulary precisely so the customer can switch that on and get the same
#     answer from a party that is not us.

CLUSTER_SCOPED_KINDS = {
    "CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding", "Namespace",
    "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration",
    "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
    "APIService", "PriorityClass", "StorageClass", "CSIDriver", "IngressClass",
    "RuntimeClass", "PersistentVolume", "ClusterIssuer", "ClusterPolicy",
}

# Volume types Pod Security Standards `restricted` permits. Anything else is
# host-reaching or driver-specific and is refused at that level.
PSS_RESTRICTED_VOLUMES = {
    "configMap", "csi", "downwardAPI", "emptyDir", "ephemeral",
    "persistentVolumeClaim", "projected", "secret",
}
PSS_BASELINE_CAPABILITIES = {
    "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
    "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
}


def parse_quantity(value):
    """Kubernetes resource quantity -> float. CPU in cores, memory in bytes."""
    text = str(value).strip()
    suffixes = [("Ki", 1024), ("Mi", 1024 ** 2), ("Gi", 1024 ** 3), ("Ti", 1024 ** 4),
                ("k", 1000), ("M", 1000 ** 2), ("G", 1000 ** 3), ("T", 1000 ** 4),
                ("m", 0.001)]
    for suf, mult in suffixes:
        if text.endswith(suf):
            return float(text[: -len(suf)]) * mult
    return float(text)


def check_namespaces(docs, allowed):
    """S10 — a release may only create objects in namespaces the customer named."""
    bad = []
    for doc in docs:
        ns = (doc.get("metadata") or {}).get("namespace")
        if ns and ns not in allowed:
            bad.append(f"{workload_id(doc)} targets namespace '{ns}', which is not in "
                       f"delivery_scope.allowed_namespaces {sorted(allowed)}")
    return bad


def check_cluster_scoped(docs, allowed):
    """S11 — CRDs, ClusterRoles and webhooks are the objects that reach outside
    the tenancy. OLM makes this a declared install mode; here it is a yes/no the
    customer holds."""
    if allowed:
        return []
    return [f"{workload_id(doc)} is a cluster-scoped object and "
            f"delivery_scope.allow_cluster_scoped is false"
            for doc in docs if doc.get("kind") in CLUSTER_SCOPED_KINDS]


def check_pod_security(docs, level):
    """S12 — Pod Security Standards, applied to the rendered objects.

    Not a reimplementation of PSA: it is the same rule set checked one step
    earlier, so a violation is a REFUSED PUBLISH rather than a pod the
    customer's cluster rejects at 3am. Where the two disagree, the cluster
    wins and that is the correct order."""
    if level not in ("baseline", "restricted"):
        raise CheckFailure("S12", f"delivery_scope.pod_security must be 'baseline' or "
                                  f"'restricted', not '{level}'")
    bad = []
    for doc in docs:
        spec = pod_spec(doc)
        if not spec:
            continue
        wid = workload_id(doc)
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(field):
                bad.append(f"{wid} sets {field}: true (PSS {level} forbids it)")
        for v in (spec.get("volumes") or []):
            types = [k for k in v if k != "name"]
            if "hostPath" in types:
                bad.append(f"{wid} mounts a hostPath volume (PSS {level} forbids it)")
            if level == "restricted":
                for t in types:
                    if t not in PSS_RESTRICTED_VOLUMES:
                        bad.append(f"{wid} uses volume type '{t}', outside the PSS "
                                   f"restricted set {sorted(PSS_RESTRICTED_VOLUMES)}")
        pod_sc = spec.get("securityContext") or {}
        for key, c in containers_of(spec):
            sc = c.get("securityContext") or {}
            name = f"{wid} {key}/{c.get('name')}"
            if sc.get("privileged"):
                bad.append(f"{name} is privileged (PSS {level} forbids it)")
            for port in (c.get("ports") or []):
                if port.get("hostPort"):
                    bad.append(f"{name} binds hostPort {port['hostPort']} "
                               f"(PSS {level} forbids it)")
            adds = {str(x).upper() for x in ((sc.get("capabilities") or {}).get("add") or [])}
            illegal = adds - PSS_BASELINE_CAPABILITIES
            if illegal:
                bad.append(f"{name} adds capabilities {sorted(illegal)} beyond the PSS "
                           f"baseline set")
            if level != "restricted":
                continue
            if sc.get("allowPrivilegeEscalation") is not False:
                bad.append(f"{name} does not set allowPrivilegeEscalation: false "
                           f"(PSS restricted)")
            drops = {str(x).upper() for x in ((sc.get("capabilities") or {}).get("drop") or [])}
            if "ALL" not in drops:
                bad.append(f"{name} does not drop ALL capabilities (PSS restricted)")
            if sc.get("runAsNonRoot") is None and pod_sc.get("runAsNonRoot") is None:
                bad.append(f"{name} does not set runAsNonRoot (PSS restricted)")
            elif sc.get("runAsNonRoot") is False or (
                    sc.get("runAsNonRoot") is None and pod_sc.get("runAsNonRoot") is False):
                bad.append(f"{name} sets runAsNonRoot: false (PSS restricted)")
            profile = ((sc.get("seccompProfile") or {}).get("type")
                       or (pod_sc.get("seccompProfile") or {}).get("type"))
            if profile not in ("RuntimeDefault", "Localhost"):
                bad.append(f"{name} has no RuntimeDefault/Localhost seccompProfile "
                           f"(PSS restricted)")
    return bad


def normalize_image_ref(image):
    """Expand an image reference the way a container runtime does.

    `vexaai/v012-gateway` IS `docker.io/vexaai/v012-gateway` and `postgres` IS
    `docker.io/library/postgres` — the registry is implicit, and a chart writes
    the short form because that is what everyone writes. A prefix allowlist
    compared against the raw string therefore refuses every Docker Hub image on
    a chart that is doing nothing wrong (observed 2026-08-25 on the real
    v0.12.23 render: eight refusals, all spurious). Normalise first, then match
    — and match the raw form too, so a customer who wrote the short prefix in
    their contract also gets what they meant."""
    first = image.split("/")[0]
    if "/" not in image:
        return f"docker.io/library/{image}"
    if "." not in first and ":" not in first and first != "localhost":
        return f"docker.io/{image}"
    return image


def check_image_sources(docs, allowed_prefixes):
    """S13 — every image comes from a registry the customer allowlisted. Their
    egress rules and their mirror policy are stated in the same file that gates
    our publish, so a release that would need a new firewall hole is refused
    here instead of failing in their cluster."""
    bad = []
    for doc in docs:
        spec = pod_spec(doc)
        if not spec:
            continue
        for key, c in containers_of(spec):
            image = c.get("image") or ""
            forms = (image, normalize_image_ref(image))
            if not any(f.startswith(pfx) for pfx in allowed_prefixes for f in forms):
                bad.append(f"{workload_id(doc)} {key}/{c.get('name')} pulls '{image}' "
                           f"({normalize_image_ref(image)}), "
                           f"outside delivery_scope.allowed_image_registries "
                           f"{sorted(allowed_prefixes)}")
    return bad


def sum_requests(docs):
    cpu = mem = 0.0
    for doc in docs:
        spec = pod_spec(doc)
        if not spec:
            continue
        replicas = (doc.get("spec") or {}).get("replicas")
        n = replicas if isinstance(replicas, int) and replicas > 0 else 1
        for _key, c in containers_of(spec):
            req = ((c.get("resources") or {}).get("requests") or {})
            if req.get("cpu"):
                cpu += parse_quantity(req["cpu"]) * n
            if req.get("memory"):
                mem += parse_quantity(req["memory"]) * n
    return cpu, mem


def check_resource_ceiling(docs, ceiling):
    """S14 — the sum of requests a release may claim. Requests, not limits:
    requests are what the scheduler actually reserves, so they are what a
    release costs the estate whether or not it uses them."""
    bad = []
    cpu, mem = sum_requests(docs)
    if ceiling.get("cpu") is not None:
        cap = parse_quantity(ceiling["cpu"])
        if cpu > cap:
            bad.append(f"sum of container cpu requests is {cpu:.3f} cores, above the "
                       f"delivery_scope ceiling of {ceiling['cpu']}")
    if ceiling.get("memory") is not None:
        cap = parse_quantity(ceiling["memory"])
        if mem > cap:
            bad.append(f"sum of container memory requests is {mem / 1024 ** 3:.2f}Gi, above "
                       f"the delivery_scope ceiling of {ceiling['memory']}")
    return bad


def delivery_scope_of(contract):
    scope = contract.get("delivery_scope")
    if scope is None:
        return None
    if not isinstance(scope, dict):
        raise CheckFailure("S10", "contract 'delivery_scope:' must be a mapping")
    # A clause of the wrong SHAPE is as dangerous as one nobody implements: a
    # YAML list whose last item lost its quotes parses as a mapping, and the
    # check that reads it either crashes (found 2026-08-25, writing this
    # fixture) or — worse — quietly matches nothing. Type it here, once.
    for key in ("allowed_namespaces", "allowed_image_registries"):
        v = scope.get(key)
        if v is not None and (not isinstance(v, list)
                              or any(not isinstance(x, str) for x in v)):
            raise CheckFailure("S10", f"delivery_scope.{key} must be a list of strings; got "
                                      f"{v!r} — quote any value ending in ':' ")
    if scope.get("allow_cluster_scoped") is not None and not isinstance(
            scope["allow_cluster_scoped"], bool):
        raise CheckFailure("S10", "delivery_scope.allow_cluster_scoped must be true or false")
    if scope.get("resource_ceiling") is not None:
        rc = scope["resource_ceiling"]
        if not isinstance(rc, dict) or set(rc) - {"cpu", "memory"}:
            raise CheckFailure("S10", "delivery_scope.resource_ceiling takes cpu and/or memory")
        for k, v in rc.items():
            try:
                parse_quantity(v)
            except (TypeError, ValueError):
                raise CheckFailure("S10", f"delivery_scope.resource_ceiling.{k}={v!r} is not a "
                                          f"Kubernetes quantity")

    unknown = set(scope) - {"allowed_namespaces", "allow_cluster_scoped", "pod_security",
                            "allowed_image_registries", "resource_ceiling"}
    if unknown:
        # An unrecognised clause is a clause NOBODY ENFORCES, and the customer
        # who wrote it believes otherwise. Refuse the contract, not the release.
        raise CheckFailure("S10", f"delivery_scope has clauses this gate does not implement: "
                                  f"{sorted(unknown)} — the gate refuses a contract it would "
                                  f"silently under-enforce")
    return scope


def delivery_scope_checks(scope, docs):
    """Return [(check-id, what-it-holds, findings)] for the clauses present."""
    rows = []
    if scope.get("allowed_namespaces") is not None:
        rows.append(("S10", f"objects stay inside {scope['allowed_namespaces']}",
                     check_namespaces(docs, set(scope["allowed_namespaces"]))))
    if scope.get("allow_cluster_scoped") is not None:
        rows.append(("S11", f"cluster-scoped objects allowed: "
                            f"{bool(scope['allow_cluster_scoped'])}",
                     check_cluster_scoped(docs, bool(scope["allow_cluster_scoped"]))))
    if scope.get("pod_security") is not None:
        rows.append(("S12", f"Pod Security Standards level `{scope['pod_security']}` "
                            f"(PSS/SCC vocabulary)",
                     check_pod_security(docs, scope["pod_security"])))
    if scope.get("allowed_image_registries") is not None:
        rows.append(("S13", f"images come from {scope['allowed_image_registries']}",
                     check_image_sources(docs, list(scope["allowed_image_registries"]))))
    if scope.get("resource_ceiling") is not None:
        rows.append(("S14", f"sum of requests within {scope['resource_ceiling']}",
                     check_resource_ceiling(docs, scope["resource_ceiling"])))
    return rows


def load_contract(text):
    """The contract, parsed from the report's own contract section."""
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise CheckFailure("S9", f"the contract section is not parseable YAML: {e}")
    if not isinstance(data, dict):
        raise CheckFailure("S9", "the contract section is not a contract mapping")
    return data


def contract_requirements(contract):
    req = contract.get("require") or []
    if isinstance(req, str):
        req = [req]
    if not isinstance(req, list) or any(not isinstance(r, str) for r in req):
        raise CheckFailure("S9", "contract 'require:' must be a list of item names")
    return req


def load_guarantees(path):
    if not path:
        return []
    data = json.loads(pathlib.Path(path).read_text())
    if isinstance(data, list):
        return [str(x) for x in data]
    g = data.get("guarantees")
    if not isinstance(g, list):
        raise CheckFailure("S9", f"{path} has no 'guarantees' list")
    return [str(x) for x in g]


def check_contract(requirements, guarantees, waivers):
    """S9 — every require: item is met by evidence or explicitly waived.
    Returns (rows, unmet). A waiver is never silent: it is printed loudly and
    written into the gate report as the record of who accepted what."""
    rows, unmet = [], []
    for item in requirements:
        if item in guarantees:
            rows.append((item, "MET", "matched by --evidence guarantees"))
        elif item in waivers:
            rows.append((item, "WAIVED", waivers[item]))
        else:
            rows.append((item, "UNMET", "no guarantee, no waiver"))
            unmet.append(item)
    for item in waivers:
        if item not in requirements:
            rows.append((item, "WAIVER-UNUSED", waivers[item]))
    return rows, unmet


def parse_waivers(args):
    items = args.waive or []
    reasons = args.reason or []
    if len(items) != len(reasons):
        raise CheckFailure("S9", f"{len(items)} --waive but {len(reasons)} --reason; "
                                 f"every waiver states its reason, paired in order")
    for r in reasons:
        if len(r.strip()) < 8:
            raise CheckFailure("S9", "a waiver reason must actually say something")
    return dict(zip(items, reasons))


def render_chart(chart, values, release="station"):
    """S5 — helm template with the station's values over the chart defaults.
    Redacted placeholders are fine: the gate reads shapes, not credentials."""
    import yaml

    cmd = ["helm", "template", release, str(chart), "--values", str(values)]
    try:
        r = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        raise CheckFailure("S5", "helm is not on PATH")
    except subprocess.CalledProcessError as e:
        raise CheckFailure("S5", f"chart does not render with the station's values:\n"
                                 f"{(e.stderr or '')[-1200:]}")
    try:
        return [d for d in yaml.safe_load_all(r.stdout) if isinstance(d, dict)]
    except yaml.YAMLError as e:
        raise CheckFailure("S5", f"rendered output is not parseable YAML: {e}")


def write_gate_report(path, ctx):
    lines = [
        f"# Gate report — station `{ctx['station']}` · {ctx['date']}",
        "",
        f"**Verdict: {ctx['verdict']}**",
        "",
        "| | |",
        "|---|---|",
        f"| Station | `{ctx['station']}` |",
        f"| Chart | `{ctx['chart_name']}` |",
        f"| Chart sha256 | `{ctx['chart_sha256']}` |",
        f"| Station values sha256 | `{ctx['values_sha256']}` |",
        f"| Contract | `{ctx['contract_id']}` @ `{ctx['contract_sha256']}` |",
        f"| Evidence | {ctx['evidence']} |",
        f"| Gated at | {ctx['at']} |",
        "",
        "## Environment checks",
        "",
        "| Check | What it holds | Verdict |",
        "|---|---|---|",
    ]
    for cid, what, verdict in ctx["env_rows"]:
        lines.append(f"| {cid} | {what} | {verdict} |")
    if ctx.get("delivery_scope"):
        lines += ["", "## Delivery scope — what this release may DO here", "",
                  "Stated by the station, enforced above (S10-S14) in Pod Security Standards / "
                  "SCC and OLM-shaped vocabulary. This gate sees the RENDERED chart; the "
                  "customer's own Pod Security admission and Kyverno see what actually runs, "
                  "and where the two disagree the cluster is right.", "",
                  "| Clause | Value |", "|---|---|"]
        for k, v in sorted(ctx["delivery_scope"].items()):
            lines.append(f"| `{k}` | `{v}` |")
    lines += ["", "## Contract items", "", "| Item | Verdict | Detail |", "|---|---|---|"]
    for item, verdict, detail in ctx["contract_rows"]:
        lines.append(f"| `{item}` | **{verdict}** | {detail} |")
    if ctx["waivers"]:
        lines += ["", "## ⚠️ WAIVERS — a human accepted these unproven", ""]
        for item, reason in ctx["waivers"].items():
            lines.append(f"- **`{item}`** — {reason}")
        lines += ["", "A waiver is a promise nobody checked. It is recorded here so the next "
                      "release can be asked whether it is still needed."]
    if ctx["failures"]:
        lines += ["", "## Refusals", ""]
        for cid, detail in ctx["failures"]:
            lines.append(f"- **{cid}** — {detail}")
    lines += ["", "---", "", "Produced by `publisher/vexa_station.py gate`. The station's contract "
                            "gates our publish: this report is the per-release guarantees document "
                            "for this station, and it is generated, not written."]
    pathlib.Path(path).write_text("\n".join(lines) + "\n")


def cmd_gate(args):
    station_dir = pathlib.Path(args.stations_dir) / args.station
    if not station_dir.is_dir():
        raise CheckFailure("S2", f"station '{args.station}' is not ingested ({station_dir} missing)")
    station_report, _ = load_report(station_dir / REPORT_NAME)
    sections = sections_of(station_report)
    values_text = sections.get(BUNDLE_ROLES["values"])
    contract_text = sections.get(BUNDLE_ROLES["contract"])
    if not values_text or not contract_text:
        raise CheckFailure("S2", f"station '{args.station}' has no values/contract section — "
                                 "re-ingest it")

    waivers = parse_waivers(args)
    contract = load_contract(contract_text)
    requirements = contract_requirements(contract)
    guarantees = load_guarantees(args.evidence)

    chart = pathlib.Path(args.chart)
    if not chart.exists():
        raise CheckFailure("S5", f"chart {chart} does not exist")
    # `helm template` takes a FILE, so the values section becomes one for the
    # length of the render and no longer. The station directory keeps one
    # artifact — the report the customer sent — and this temporary copy cannot
    # drift from it because it does not outlive the command.
    with tempfile.TemporaryDirectory(prefix="vexa-gate-") as scratch:
        values = pathlib.Path(scratch) / "values.redacted.yaml"
        values.write_text(values_text)
        docs = render_chart(chart, values, args.release_name)

    env_checks = [
        ("S6", "every container declares cpu+memory requests and limits", check_resources(docs)),
        ("S7", "no workload mounts a hostPath volume", check_no_hostpath(docs)),
        ("S8", "every image reference is digest-pinned", check_digest_pinned(docs)),
    ]
    # The outbound half of the contract, when the station states one.
    scope = delivery_scope_of(contract)
    if scope:
        env_checks += delivery_scope_checks(scope, docs)
    failures = []
    env_rows = [("S5", "the chart renders with the station's values",
                 f"PASS ({len(docs)} objects)")]
    for cid, what, bad in env_checks:
        env_rows.append((cid, what, "PASS" if not bad else f"**REFUSED** ({len(bad)})"))
        for detail in bad:
            failures.append((cid, detail))

    contract_rows, unmet = check_contract(requirements, guarantees, waivers)
    for item in unmet:
        failures.append(("S9", f"contract requires '{item}' — no guarantee in evidence and "
                               f"no waiver"))

    verdict = "REFUSED" if failures else "PASS"
    date = utcnow()[:10]
    report = station_dir / f"gate-report-{date}.md"
    if report.exists():
        # a second gate run on the same day never destroys the first report —
        # a refusal that vanishes when someone re-runs with a waiver is
        # exactly the evidence an audit wants
        k = 1
        while (station_dir / f"gate-report-{date}.{k}.md").exists():
            k += 1
        report.rename(station_dir / f"gate-report-{date}.{k}.md")
    ctx = {
        "station": args.station, "date": date, "at": utcnow(), "verdict": verdict,
        "chart_name": chart.name, "chart_sha256": sha256_file(chart),
        # The digests are over the section TEXT — the same bytes the ingest
        # hashed and the same bytes a reader sees in the report — so a gate
        # report and a station report name the same object.
        "values_sha256": sha256_text(values_text),
        "contract_id": contract.get("contract_id", "<unnamed>"),
        "contract_sha256": sha256_text(contract_text),
        "evidence": f"`{args.evidence}`" if args.evidence else "none supplied",
        "env_rows": env_rows, "contract_rows": contract_rows,
        "waivers": waivers, "failures": failures, "delivery_scope": scope,
    }
    write_gate_report(report, ctx)
    # The markdown report is for a person; this one is for the PreSync verifier,
    # which cannot render a chart and therefore cannot re-run S5-S14. It reads
    # this instead and checks that the scope we ENFORCED is the scope the
    # customer's own contract asks for — a weaker claim than re-checking, and
    # it is labelled as one rather than dressed up as verification.
    report_json = report.with_suffix(".json")
    report_json.write_text(json.dumps({
        "schema_version": 1,
        "station": args.station,
        "gated_at": ctx["at"],
        "verdict": verdict,
        "chart": {"name": chart.name, "sha256": ctx["chart_sha256"]},
        "contract": {"id": ctx["contract_id"], "sha256": ctx["contract_sha256"]},
        "delivery_scope_enforced": scope,
        "checks": [{"id": cid, "holds": what, "verdict": v}
                   for cid, what, v in env_rows],
        "contract_items": [{"item": i, "verdict": v, "detail": d}
                           for i, v, d in contract_rows],
        "waivers": waivers,
        "enforced_by": "publisher/vexa_station.py gate (publisher-side, on the rendered chart)",
        "not_enforced_here": [
            "what actually runs — only the cluster's Pod Security admission and Kyverno see that",
            "anything the chart creates at runtime rather than at render time",
        ],
    }, indent=1) + "\n")

    for item, v, detail in contract_rows:
        print(f"  {v:<14} {item}  — {detail}")
    if waivers:
        print("\n!!! WAIVED, UNPROVEN — recorded in the gate report:")
        for item, reason in waivers.items():
            print(f"  !!! {item}: {reason}")
    print(f"\ngate report written to {report}")
    if failures:
        raise CheckFailure(failures[0][0],
                           f"station '{args.station}' refuses this publish — "
                           f"{len(failures)} finding(s), see {report}\n  - "
                           + "\n  - ".join(f"{c}: {d}" for c, d in failures))
    print(f"PASS — station '{args.station}' admits {chart.name}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="vexa-station", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--stations-dir", default=str(pathlib.Path(__file__).resolve().parent.parent / "stations"))
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("ingest", help="validate and record a customer station report")
    i.add_argument("--bundle", metavar="STATION_REPORT_YAML",
                   help="the station report (station-report.yaml) produced by kit validate "
                        "(or use --from-registry)")
    i.add_argument("--station", required=True, help="station name; must match the report")
    i.add_argument("--force", action="store_true", help="replace an already-ingested station")
    i.add_argument("--from-registry", metavar="REGISTRY",
                   help="pull the report from <REGISTRY>/vexa/stations/<station>/bundles "
                        "instead of reading --bundle from disk (the submit path's return leg)")
    i.add_argument("--bundle-tag", help="which submitted report; default the newest")
    i.add_argument("--channel", help="the channel this station subscribes to; required with --ledger")
    i.add_argument("--ledger", help="checkout of the vexa-stations ledger; on a successful ingest "
                   "the report and its receipt are stored verbatim under "
                   "channels/<channel>/stations/<station>/receipts/ and state.yaml is "
                   "recomputed. Defaults to $VEXA_STATIONS_DIR.")
    i.add_argument("--plain-http", action="store_true")
    i.add_argument("--insecure", action="store_true")

    g = sub.add_parser("gate", help="gate a packaged chart on the station's contract")
    g.add_argument("--station", required=True)
    g.add_argument("--chart", required=True, help="packaged chart .tgz (publisher chart output)")
    g.add_argument("--evidence", help="JSON with a 'guarantees' list — what this release proved")
    g.add_argument("--waive", action="append", help="contract item to waive (repeatable)")
    g.add_argument("--reason", action="append", help="reason for the waiver, paired in order")
    g.add_argument("--release-name", default="station", help="helm release name used for rendering")

    args = p.parse_args(argv)
    try:
        if args.cmd == "ingest":
            if bool(args.bundle) == bool(args.from_registry):
                raise CheckFailure("S1", "ingest takes exactly one of --bundle or --from-registry")
            return (cmd_ingest_from_registry if args.from_registry else cmd_ingest)(args)
        return {"gate": cmd_gate}[args.cmd](args)
    except CheckFailure as e:
        print(f"REFUSED {e}", file=sys.stderr)
        return 3
    except subprocess.CalledProcessError as e:
        print(f"command failed: {e.cmd}\n{(e.stderr or '')[-800:]}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
