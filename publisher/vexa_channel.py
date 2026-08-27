#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-channel — turn a released Vexa version into a channel entry.

The publisher consumes released artifacts and receipts, never clusters, and
holds no production credentials. Subcommands:

  fetch   gather the network-fetched inputs (release archive, provenance
          bundle, trusted root) via the gh CLI into a directory
  build   assemble and cross-check a channel entry from a release tag, the
          candidate map at that tag, the internal delivery receipt, and the
          fetched inputs; write entry.json + evidence/ + VERIFY.md
  verify  re-run every offline check against a built entry directory
  push    push a built entry to an OCI registry (or layout) via oras, sign it
          and its image digests with cosign, and move the channel tag

Every cross-check is named C1..C9; a failed check refuses the entry (there is
no silent path — an incomplete chain needs an explicit --break-glass record,
which becomes visible data in the signed entry).

Two further checks guard the signing toolchain itself, and they run inside the
push path so they cannot be skipped:

  T1  the cosign that signs is inside the pinned series. The signature LAYOUT is
      not stable across cosign majors, and the customer's admission controller
      reads exactly one layout.
  T2  after signing, the signature is discoverable in the shape Kyverno 1.19
      will ask for — sha256-<digest>.sig in the signature repository — and
      verifies against the channel key. A pin is a promise; T2 is the proof.
"""
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

SCHEMA_ID = "https://vexa.ai/schemas/ee/channel-entry.v1.json"
ENTRY_MEDIA_TYPE = "application/vnd.vexa.channel-entry.v1+json"
REQUIRED_EVIDENCE_KINDS = ("candidate_map", "delivery_receipt", "source_provenance", "trusted_root")
SOURCE_IDENTITY_PATTERN = "^https://github.com/Vexa-ai/vexa/"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://slsa.dev/provenance/v1"


class CheckFailure(Exception):
    """A named cross-check refused the entry."""

    def __init__(self, check, message):
        self.check = check
        super().__init__(f"{check}: {message}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------- the signing toolchain (T1)
#
# WHY THIS EXISTS. Everything this product sells is deterministic verification,
# and until 2026-08-25 it signed with "whatever cosign is on PATH". The layout
# cosign writes into a signature repository is NOT stable across the tool's own
# major versions:
#
#   cosign 2.x, default                  -> tag  sha256-<digest>.sig  holding a
#                                           cosign signature manifest (a layer of
#                                           application/vnd.dev.cosign.simplesigning.v1+json)
#   cosign 3.x, default                  -> tag  sha256-<digest>      holding an
#                                           OCI referrers index over a sigstore
#                                           bundle v0.3
#   cosign 3.x, --new-bundle-format=false-> the 2.x layout again
#
# Kyverno 1.19 — the version kit/providers pins and kit/install.sh installs —
# asks for exactly `sha256-<digest>.sig` and nothing else. Given the 3.x default
# it reports `no signatures found`: a correctly signed release denied at
# admission with a message that says it is unsigned. Measured against live
# Kyverno 1.19.0, both directions, on 2026-08-25.
#
# `--new-bundle-format` is already deprecation-warned by 3.x ("this will be the
# only supported format in future versions"), so the correctness of every
# signature we ship rested on a deprecated flag of an unpinned binary. It had
# already drifted in production: 14 of the 15 tags in the live pilot-stable
# signature repository carried the referrers layout.
#
# So: pin the series, refuse to sign with anything else, and — because a pin is
# a promise and not a proof — verify the RESULT the way Kyverno will (T2 below).

COSIGN_PINNED_SERIES = 2
COSIGN_RECOMMENDED_VERSION = "2.6.5"
COSIGN_LEGACY_SIGNATURE_LAYER = "application/vnd.dev.cosign.simplesigning.v1+json"
_COSIGN_CACHE = {}


def cosign_bin():
    """The cosign to sign with. COSIGN_BIN overrides PATH so an operator can
    point at a pinned download without touching the rest of their machine."""
    import os

    return os.environ.get("COSIGN_BIN") or "cosign"


def cosign_version(binary=None):
    """(major, full_version_string) of the resolved cosign, or CheckFailure."""
    binary = binary or cosign_bin()
    if binary in _COSIGN_CACHE:
        return _COSIGN_CACHE[binary]
    try:
        out = subprocess.run([binary, "version"], capture_output=True, text=True)
    except FileNotFoundError:
        raise CheckFailure("T1", f"cosign not found at {binary!r}; install cosign {COSIGN_RECOMMENDED_VERSION} or set COSIGN_BIN")
    text = (out.stdout or "") + (out.stderr or "")
    m = re.search(r"GitVersion:\s*v?(\d+)\.(\d+)\.(\S+)", text)
    if not m:
        raise CheckFailure("T1", f"could not read a version out of `{binary} version`; refusing to sign with an unidentified toolchain")
    full = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
    _COSIGN_CACHE[binary] = (int(m.group(1)), full)
    return _COSIGN_CACHE[binary]


def require_pinned_cosign():
    """Refuse to sign with a cosign outside the pinned series, and say why.

    The escape hatch is deliberate and loud: VEXA_COSIGN_ALLOW_UNPINNED=1 lets an
    operator sign with another series, and the signing-run record then says so, so
    the entry's own VERIFY.md documents what actually produced it."""
    import os

    major, full = cosign_version()
    if major == COSIGN_PINNED_SERIES:
        return major, full
    detail = (
        f"cosign {full} is outside the pinned {COSIGN_PINNED_SERIES}.x series "
        f"(recommended: {COSIGN_RECOMMENDED_VERSION}). The signature LAYOUT depends on "
        f"the tool's major version: {COSIGN_PINNED_SERIES}.x writes the legacy "
        f"sha256-<digest>.sig tag that Kyverno 1.19 reads; 3.x writes an OCI referrers "
        f"index that Kyverno 1.19 reports as 'no signatures found' — a correctly signed "
        f"image denied at admission as unsigned. "
        f"Install cosign {COSIGN_RECOMMENDED_VERSION} and point COSIGN_BIN at it, or set "
        f"VEXA_COSIGN_ALLOW_UNPINNED=1 if you have verified the layout yourself."
    )
    if os.environ.get("VEXA_COSIGN_ALLOW_UNPINNED") == "1":
        print(f"WARNING T1: {detail}", file=sys.stderr)
        return major, full
    raise CheckFailure("T1", detail)


def cosign_supported_flags(binary=None):
    """Flags `cosign sign` actually accepts, so the offline posture can be stated
    without guessing at a version's flag surface."""
    binary = binary or cosign_bin()
    key = ("flags", binary)
    if key in _COSIGN_CACHE:
        return _COSIGN_CACHE[key]
    out = subprocess.run([binary, "sign", "--help"], capture_output=True, text=True)
    text = (out.stdout or "") + (out.stderr or "")
    _COSIGN_CACHE[key] = set(re.findall(r"--([a-z0-9-]+)", text))
    return _COSIGN_CACHE[key]



def cosign_registry_auth():
    """Registry credentials for cosign, passed EXPLICITLY.

    WHY NOT THE DOCKER CONFIG (learned 2026-08-25, publishing vexa-internal).
    `cosign login` writes the credential and then `cosign sign` fails the very
    next second with `UNAUTHORIZED: authentication required` on a repository
    that `curl -u`, `oras` and `helm push` all read and write happily. The
    cause is the ambient docker config: a `credsStore` entry sends the lookup
    to a platform keychain that the signing path does not resolve, and cosign
    reports the miss as an authorization failure by the REGISTRY rather than
    as a credential it could not find locally. The error names the wrong
    party, which is why this costs half an hour every time.

    Passing --registry-username/--registry-password removes the ambient
    dependency entirely. VEXA_REGISTRY_USER / VEXA_REGISTRY_PASS, or the
    channel-registry variables an operator already has exported.
    """
    import os

    user = os.environ.get("VEXA_REGISTRY_USER") or os.environ.get("CHANNEL_PUBLISHER_USER")
    pw = os.environ.get("VEXA_REGISTRY_PASS") or os.environ.get("CHANNEL_PUBLISHER_PASS")
    if user and pw:
        return ["--registry-username", user, "--registry-password", pw]
    return []


def cosign_offline_flags():
    """The flags that make a signature offline AND legacy-layout, for whichever
    cosign is resolved. 2.x needs only --tlog-upload=false (legacy is its
    default); 3.x additionally needs --new-bundle-format=false to get the layout
    at all, and refuses --tlog-upload=false unless --use-signing-config=false
    rides with it."""
    have = cosign_supported_flags()
    flags = []
    if "tlog-upload" in have:
        flags.append("--tlog-upload=false")
    if "new-bundle-format" in have:
        flags.append("--new-bundle-format=false")
    if "use-signing-config" in have:
        flags.append("--use-signing-config=false")
    return flags


# --------------------------------------- verify the way Kyverno verifies (T2)
#
# A pin is a promise. This is the proof, and it runs in the same code path as
# the push so it cannot be skipped: after signing, assert the signature is
# discoverable in the EXACT shape the customer's admission controller will look
# for — the `sha256-<digest>.sig` tag in the signature repository, holding a
# cosign signature manifest — and that it verifies against the channel key.
#
# Had this existed, the live channel could not have shipped 14 referrers-layout
# signatures that Kyverno reports as "no signatures found".


def signature_tag(digest):
    """The tag Kyverno 1.19 requests for an image digest. Not a convention we
    chose — it is what the admission controller GETs, observed on the wire:
    GET /v2/<sigrepo>/manifests/sha256-<hex>.sig"""
    hexdigest = digest.split(":", 1)[-1]
    return f"sha256-{hexdigest}.sig"


def derive_public_key(private_key_path, env):
    """The pinned key's public half, written to a temp file, so the push-time
    check verifies with the same material the customer pins."""
    import tempfile

    out = run([cosign_bin(), "public-key", "--key", str(private_key_path)], env=env)
    fd = tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False)
    fd.write(out.stdout)
    fd.close()
    return fd.name


def check_kyverno_readable(subject_ref, digest, signature_repository, pubkey, env, insecure=False):
    """Refuse the push unless the signature is there in the admission
    controller's shape. Returns the resolved signature manifest descriptor."""
    repo = signature_repository or subject_ref.split("@", 1)[0]
    tag = signature_tag(digest)
    ref = f"{repo}:{tag}"

    plain = ["--insecure"] if insecure else []
    try:
        manifest = run(["oras", "manifest", "fetch", *plain, ref]).stdout
    except subprocess.CalledProcessError as e:
        raise CheckFailure(
            "T2",
            f"the tag Kyverno 1.19 will ask for does not exist: {ref}. "
            f"This is the cosign 3.x referrers layout; admission would report the image "
            f"as UNSIGNED. Sign with cosign {COSIGN_RECOMMENDED_VERSION} "
            f"(registry said: {e.stderr.strip()[-160:]})",
        )

    doc = json.loads(manifest)
    layers = doc.get("layers") or []
    kinds = {ly.get("mediaType") for ly in layers}
    if COSIGN_LEGACY_SIGNATURE_LAYER not in kinds:
        raise CheckFailure(
            "T2",
            f"{ref} exists but is not a cosign signature manifest — it holds "
            f"{sorted(k for k in kinds if k) or [doc.get('mediaType')]}, not "
            f"{COSIGN_LEGACY_SIGNATURE_LAYER}. Kyverno 1.19 cannot read it.",
        )

    venv = dict(env)
    if signature_repository:
        venv["COSIGN_REPOSITORY"] = signature_repository
    # Same explicit-credential reasoning as cosign_registry_auth(): a verify
    # that cannot AUTHENTICATE reports the signature as not verifying, which
    # reads as a signature mismatch and is not one.
    cmd = [cosign_bin(), "verify", "--key", str(pubkey), "--insecure-ignore-tlog=true", *cosign_registry_auth()]
    if insecure:
        cmd.append("--allow-insecure-registry")
    cmd.append(subject_ref)
    r = subprocess.run(cmd, capture_output=True, text=True, env=venv)
    if r.returncode != 0:
        raise CheckFailure(
            "T2",
            f"{ref} exists but does not verify against the channel key: "
            f"{(r.stderr or r.stdout).strip()[-200:]}",
        )
    return {"ref": ref, "tag": tag, "manifest_media_type": doc.get("mediaType"),
            "signature_layer": COSIGN_LEGACY_SIGNATURE_LAYER}

DEFAULT_EXPIRES_DAYS = 30


def utcplus(days):
    return (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc)


def is_expired(stamp, now=None):
    """True when `stamp` is in the past. The boundary is EXCLUSIVE: an entry is
    live up to and including its expiry instant, so a verifier and a publisher
    that disagree by a second do not disagree about the verdict."""
    return parse_ts(stamp) < (now or datetime.datetime.now(datetime.timezone.utc))


# ---------------------------------------------------------------- git inputs


def read_tag(vexa_repo, version):
    """Return (tag_object_sha, source_sha, candidate_map_bytes) for a release tag."""
    tag_object = run(["git", "-C", vexa_repo, "rev-parse", version]).stdout.strip()
    source_sha = run(["git", "-C", vexa_repo, "rev-parse", f"{version}^{{}}"]).stdout.strip()
    map_path = f"releases/{version}/candidate-images.json"
    map_bytes = subprocess.run(
        ["git", "-C", vexa_repo, "show", f"{version}:{map_path}"],
        check=True, capture_output=True,
    ).stdout
    return tag_object, source_sha, map_bytes


# ------------------------------------------------------------- cross-checks


def check_map_identity(version, candidate_map):
    if candidate_map.get("release") != version or candidate_map.get("stable_tag") != version:
        raise CheckFailure(
            "C2",
            f"candidate map identity mismatch: release={candidate_map.get('release')} "
            f"stable_tag={candidate_map.get('stable_tag')} expected {version}",
        )


def check_map_pin(map_bytes, receipt):
    """C3 — one carrier per fact: the receipt's packet pin must equal the map bytes."""
    pin = receipt.get("packet", {}).get("sha256", "")
    actual = "sha256:" + sha256_bytes(map_bytes)
    if pin != actual:
        raise CheckFailure("C3", f"candidate map sha256 {actual} != receipt packet pin {pin}")


def check_receipt_identity(version, source_sha, receipt):
    r = receipt.get("release")
    if r not in (version, version.lstrip("v")):
        raise CheckFailure("C4", f"receipt release {r} != {version}")
    oss = receipt.get("oss", {})
    if oss.get("tag") != version:
        raise CheckFailure("C4", f"receipt oss.tag {oss.get('tag')} != {version}")
    if oss.get("source_sha") != source_sha:
        raise CheckFailure("C4", f"receipt oss.source_sha {oss.get('source_sha')} != tag target {source_sha}")


def check_image_consistency(candidate_map, receipt):
    """C5 — the map is the identity carrier; the receipt must corroborate it."""
    receipt_images = {i["name"]: i for i in receipt.get("oss", {}).get("images", [])}
    map_images = candidate_map.get("images", {})
    missing = sorted(set(map_images) - set(receipt_images))
    if missing:
        raise CheckFailure("C5", f"images in map but not in receipt: {missing}")
    extra = sorted(set(receipt_images) - set(map_images))
    if extra:
        raise CheckFailure("C5", f"images in receipt but not in map: {extra}")
    for name, m in map_images.items():
        r = receipt_images[name]
        if r.get("index_digest") != m.get("digest"):
            raise CheckFailure(
                "C5",
                f"{name}: receipt index_digest {r.get('index_digest')} != map digest {m.get('digest')}",
            )
        if r.get("class") != m.get("class"):
            raise CheckFailure("C5", f"{name}: class disagrees (receipt {r.get('class')}, map {m.get('class')})")
        r_pm = r.get("platform_manifests") or {}
        m_pm = m.get("platform_manifests") or {}
        for platform, ident in r_pm.items():
            m_ident = m_pm.get(platform)
            if not m_ident:
                raise CheckFailure("C5", f"{name}: receipt has platform {platform} the map lacks")
            if ident.get("manifest_digest") != m_ident.get("manifest_digest"):
                raise CheckFailure(
                    "C5",
                    f"{name}/{platform}: manifest_digest disagrees "
                    f"(receipt {ident.get('manifest_digest')}, map {m_ident.get('manifest_digest')})",
                )


def build_images(candidate_map, receipt):
    """Entry images: identity from the map; validation receipts from the
    delivery receipt — or, on a candidate (no receipt exists yet), from the
    map's own build/validation evidence as lite-leg receipts."""
    if receipt is None:
        out = []
        for name in sorted(candidate_map.get("images", {})):
            m = candidate_map["images"][name]
            out.append({
                "name": name,
                "class": m["class"],
                "index_digest": m["digest"],
                "platforms": list(m.get("platforms", [])),
                "platform_manifests": m.get("platform_manifests"),
                "source_sha": m.get("build_source") or candidate_map["build_source"],
                "validation_receipts": [{
                    "kind": "lite",
                    "receipt": m.get("evidence")
                    or f"candidate build {candidate_map.get('build_run')} validation {candidate_map.get('validation_run')}",
                }],
            })
        return out
    receipt_images = {i["name"]: i for i in receipt.get("oss", {}).get("images", [])}
    out = []
    for name in sorted(candidate_map.get("images", {})):
        m = candidate_map["images"][name]
        r = receipt_images[name]
        receipts = [
            {"kind": v["kind"], "receipt": v["receipt"]}
            for v in r.get("validation_receipts", [])
        ]
        if not receipts:
            raise CheckFailure("C5", f"{name}: no validation receipts in delivery receipt")
        out.append(
            {
                "name": name,
                "class": m["class"],
                "index_digest": m["digest"],
                "platforms": list(m.get("platforms", [])),
                "platform_manifests": m.get("platform_manifests"),
                "source_sha": r["source_sha"],
                "validation_receipts": receipts,
            }
        )
    return out


def verify_archive(archive, provenance_bundle, skip_cosign=False):
    """C6 — the provenance bundle verifies against the archive (cosign, offline)."""
    if skip_cosign:
        return "skipped (--skip-cosign-verify)"
    cmd = [
        cosign_bin(), "verify-blob-attestation",
        "--bundle", str(provenance_bundle),
        "--new-bundle-format",
        "--type", "slsaprovenance1",
        f"--certificate-oidc-issuer={OIDC_ISSUER}",
        f"--certificate-identity-regexp={SOURCE_IDENTITY_PATTERN}",
        str(archive),
    ]
    try:
        run(cmd)
    except FileNotFoundError:
        raise CheckFailure("C6", "cosign not found; install cosign or pass --skip-cosign-verify (build then refuses published mode)")
    except subprocess.CalledProcessError as e:
        raise CheckFailure("C6", f"provenance bundle does not verify against archive: {e.stderr.strip()[-400:]}")
    return "cosign verify-blob-attestation: Verified OK"


# -------------------------------------------------------------------- build


def assemble_entry(args, tag_object, source_sha, candidate_map, receipt, evidence_rows, absent):
    entry = {
        "schema_version": 1,
        "channel": {
            "name": args.channel,
            "entry_seq": args.entry_seq,
            "supersedes": None if args.supersedes in (None, "none") else args.supersedes,
        },
        "release": {
            "version": args.release,
            "source_sha": source_sha,
            "tag_object_sha": tag_object,
            "release_url": (receipt or {}).get("oss", {}).get("release_url")
            or f"https://github.com/Vexa-ai/vexa/releases/tag/{args.release}",
        },
        "source": {
            "archive_name": pathlib.Path(args.archive).name,
            "archive_sha256": sha256_file(args.archive),
            "provenance_predicate": PREDICATE,
            "certificate_oidc_issuer": OIDC_ISSUER,
            "certificate_identity_pattern": SOURCE_IDENTITY_PATTERN,
        },
        "images": build_images(candidate_map, receipt),
        "evidence": evidence_rows,
        "evidence_absent": absent,
        "prod_soak": None if receipt is None else {
            "receipt": receipt["prod"]["hold_receipt"],
            "carrier": "delivery_receipt:prod.hold_receipt",
        },
        "chart": None,
        "break_glass": None,
        "signing": {
            "mode": args.signing_mode,
            "identity": args.identity,
            "note": args.signing_note,
        },
        "publication": {
            "mode": args.publication_mode,
            "published_at": utcnow(),
            "publisher": args.publisher,
        },
        # Freshness. Nothing else in the chain stops a `current` tag nobody has
        # moved for six months from looking exactly like a healthy channel: the
        # signature still verifies, the digests still resolve, the evidence is
        # still intact. Only a stated horizon turns "we stopped publishing" into
        # a refusal the customer can see, and it has to live INSIDE the signed
        # subject or it is advisory.
        "expires": utcplus(getattr(args, "expires_days", None) or DEFAULT_EXPIRES_DAYS),
    }
    # The founder gate, recorded in the signed entry. The schema requires both
    # fields for publication.mode=published, so a real publication cannot be
    # produced without naming the approver and the receipt.
    if args.approved_by:
        entry["publication"]["approved_by"] = args.approved_by
    if args.approval_receipt:
        entry["publication"]["approval_receipt"] = args.approval_receipt

    if args.chart_ref:
        entry["chart"] = {
            "oci_ref": args.chart_ref,
            "digest": args.chart_digest,
            "version": args.chart_version,
        }
    else:
        absent.append(
            {
                "kind": "chart",
                "reason": "OCI chart publishing pending (vexa PRD §12 C1); the OSS chart ships in the Vexa-ai/vexa tree",
            }
        )
    return entry


def default_absent_rows(candidate=False):
    rows = [] if not candidate else [
        {"kind": "soak",
         "reason": "pending: candidate entry — the prod station signs its soak attestation after it runs; downstream contracts require that attestation, not this entry alone"},
        {"kind": "other",
         "reason": "pending: delivery receipt — produced at prod publication; candidates carry the map's build/validation evidence"},
    ]
    return rows + [
        {
            "kind": "image_provenance",
            "reason": "per-image SLSA attestations not produced by the OSS pipeline yet (vexa PRD §12 C1); "
            "images bind to source via the sha-pinned candidate map",
        }
    ]


def evidence_row(name, kind, path, media_type, description):
    return {
        "name": name,
        "kind": kind,
        "sha256": sha256_file(path),
        "media_type": media_type,
        "description": description,
    }


def schema_validate(entry):
    """C9 — the assembled entry validates against the sealed schema."""
    spec_dir = pathlib.Path(__file__).resolve().parent.parent / "spec"
    sys.path.insert(0, str(spec_dir))
    try:
        import validate as v  # spec/validate.py
        import jsonschema

        schema = v.load_schema()
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(entry), key=lambda e: list(e.absolute_path))
        if errors:
            locs = "; ".join(
                f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}" for e in errors[:5]
            )
            raise CheckFailure("C9", f"entry does not validate: {locs}")
    except ImportError:
        raise CheckFailure("C9", "jsonschema package required to build (pip install jsonschema)")
    finally:
        sys.path.remove(str(spec_dir))


def write_verify_md(out, entry, signing_run=None):
    """Generated, never hand-maintained. At build time there is no signing run
    yet, so the page says so; `push` regenerates it from the run that actually
    signed the entry, and only that version is ever published."""
    if signing_run:
        c = signing_run["cosign"]
        provenance = f"""> Generated from the signing run that produced this entry on
> **{signing_run['signed_at']}**: cosign **{c['version']}**, bundle format
> **{signing_run['bundle_format']}**, transparency log **{signing_run['transparency_log']}**,
> signing flags `{' '.join(c['flags'])}`. The commands below are the ones that
> verify what that run wrote — they are not maintained by hand.
"""
    else:
        provenance = """> **PROVISIONAL.** This entry has not been signed yet, so these instructions
> describe the intended posture rather than an observed one. `vexa-channel push`
> regenerates this file from the actual signing run before publishing it.
"""
    text = provenance + f"""
# VERIFY — offline verification of this channel entry

No network access and no call to Vexa is required; the bundle carries the
Sigstore trusted root. Run from this directory.

## 1 · Entry signature

```
cosign verify-blob --key <channel.pub> --bundle entry.json.sigstore.json \\
  --insecure-ignore-tlog=true entry.json
```

`--insecure-ignore-tlog=true` is REQUIRED and is not a weakening here: this
channel signs offline against a pinned key and deliberately uploads nothing to
a public transparency log (`--tlog-upload=false` at signing time), so there is
no Rekor entry to find. Without the flag cosign refuses with "signature not
found in transparency log". Do NOT pass `--new-bundle-format`: these bundles
are written in the legacy format, and the flag makes cosign parse them as v0.3
bundles and fail.

The signing identity this entry declares: `{entry['signing']['identity']}`
— that string is the SHA-256 of the channel public key's PEM bytes. Check the
key you are pinning is the one this entry names:

```
shasum -a 256 <channel.pub>     # must equal {entry['signing']['identity'].removeprefix('sha256:')}
```

(signing mode `{entry['signing']['mode']}`).

## 1b · Signature on the channel artifact itself

The OCI artifact carrying this entry is signed with the same key. Same two
flags, same reason:

```
cosign verify --key <channel.pub> --insecure-ignore-tlog=true \\
  <registry>/vexa/channel/<channel>@<digest>
```

## 2 · Evidence file integrity

```
python3 - <<'EOF'
import hashlib, json, sys
entry = json.load(open("entry.json"))
bad = 0
for row in entry["evidence"]:
    h = hashlib.sha256(open("evidence/" + row["name"], "rb").read()).hexdigest()
    ok = h == row["sha256"]
    bad += 0 if ok else 1
    print(("OK  " if ok else "BAD ") + row["name"])
sys.exit(1 if bad else 0)
EOF
```

## 3 · Source provenance (SLSA v1, Sigstore keyless)

```
cosign verify-blob-attestation \\
  --bundle evidence/source-provenance.sigstore.json --new-bundle-format \\
  --type slsaprovenance1 \\
  --certificate-oidc-issuer={entry['source']['certificate_oidc_issuer']} \\
  --certificate-identity-regexp='{entry['source']['certificate_identity_pattern']}' \\
  <path-to>/{entry['source']['archive_name']}
```

The archive's sha256 must equal `{entry['source']['archive_sha256']}`.

## 4 · Candidate-map pin (one carrier per fact)

```
python3 - <<'EOF'
import hashlib, json, sys
entry = json.load(open("entry.json"))
receipt = json.load(open("evidence/delivery-receipt.json"))
h = "sha256:" + hashlib.sha256(open("evidence/candidate-images.json","rb").read()).hexdigest()
pin = receipt["packet"]["sha256"]
print("map", h)
print("pin", pin)
sys.exit(0 if h == pin else 1)
EOF
```

## 5 · Image signatures, and what your admission controller will look for

Every image digest this entry names is cosign-signed with the same channel key.
The signatures live in the channel's signature repository, so verification needs
no reachability to Docker Hub and no call to Vexa.

They are written in the **legacy cosign layout**: for an image digest
`sha256:<hex>`, the signature is the tag `sha256-<hex>.sig` in the signature
repository, holding a cosign signature manifest (a layer of media type
`{COSIGN_LEGACY_SIGNATURE_LAYER}`).

That is the only layout **Kyverno 1.19** reads. Newer cosign releases default to
writing an OCI referrers index instead, which Kyverno 1.19 reports as
`no signatures found` — indistinguishable from an unsigned image. The publisher
pins cosign {COSIGN_PINNED_SERIES}.x ({COSIGN_RECOMMENDED_VERSION}) and refuses
to publish a signature it cannot find at that tag, so what you receive is what
your admission layer can read.

Check it by hand for any image in this entry:

```
oras manifest fetch <signature-repository>:sha256-<hex-of-image-digest>.sig
COSIGN_REPOSITORY=<signature-repository> cosign verify --key <channel.pub> \\
  --insecure-ignore-tlog=true <image>@sha256:<hex>
```

## What this entry does NOT claim

{chr(10).join('- **' + a['kind'] + '**: ' + a['reason'] for a in entry['evidence_absent']) or '- (nothing absent)'}
"""
    (out / "VERIFY.md").write_text(text)


def cmd_build(args):
    out = pathlib.Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"refusing to build into non-empty {out}")
    (out / "evidence").mkdir(parents=True, exist_ok=True)

    tag_object, source_sha, map_bytes = read_tag(args.vexa_repo, args.release)  # C1
    candidate_map = json.loads(map_bytes)
    check_map_identity(args.release, candidate_map)          # C2

    candidate = args.publication_mode == "candidate"
    if candidate:
        # Internal channel, before prod has run: the delivery receipt does not
        # exist yet. Per-image receipts come from the map's own build/validate
        # evidence; the prod claim is honestly pending, not smoothed.
        if args.delivery_receipt:
            raise SystemExit("candidate mode takes no --delivery-receipt: it does not exist yet by definition")
        receipt = None
    else:
        receipt = json.loads(pathlib.Path(args.delivery_receipt).read_text())
        check_map_pin(map_bytes, receipt)                        # C3
        check_receipt_identity(args.release, source_sha, receipt)  # C4
        check_image_consistency(candidate_map, receipt)          # C5
    c6 = verify_archive(args.archive, args.provenance_bundle, args.skip_cosign_verify)  # C6

    # C7 — materialize the bundle and digest-list it
    ev = out / "evidence"
    (ev / "candidate-images.json").write_bytes(map_bytes)
    if not candidate:
        shutil.copy(args.delivery_receipt, ev / "delivery-receipt.json")
    shutil.copy(args.provenance_bundle, ev / "source-provenance.sigstore.json")
    shutil.copy(args.trusted_root, ev / "trusted-root.jsonl")
    evidence_rows = [
        evidence_row(
            "candidate-images.json", "candidate_map", ev / "candidate-images.json",
            "application/json",
            f"frozen digest map at tag {args.release} ({source_sha[:8]}); the identity carrier every other document pins",
        ),
    ]
    if not candidate:
        evidence_rows.append(evidence_row(
            "delivery-receipt.json", "delivery_receipt", ev / "delivery-receipt.json",
            "application/json",
            "internal compound prod+OSS delivery receipt (prod-delivery-receipt.v1): custody, per-image prod/stage/lite receipts, prod hold, publication readbacks",
        ))
    evidence_rows += [
        evidence_row(
            "source-provenance.sigstore.json", "source_provenance", ev / "source-provenance.sigstore.json",
            "application/vnd.dev.sigstore.bundle.v0.3+json",
            "SLSA Provenance v1 bundle (GitHub Artifact Attestations, Sigstore keyless) for the release source archive",
        ),
        evidence_row(
            "trusted-root.jsonl", "trusted_root", ev / "trusted-root.jsonl",
            "application/jsonl",
            "Sigstore trusted-root snapshot enabling fully offline verification",
        ),
    ]

    for spec3 in (args.extra_evidence or []):
        e_kind, e_name, e_path = spec3.split("=", 2)
        shutil.copy(e_path, ev / e_name)
        evidence_rows.append(evidence_row(
            e_name, e_kind if e_kind in (
                "candidate_map", "delivery_receipt", "source_provenance", "trusted_root",
                "readiness", "storm", "witness", "soak", "security_hardening", "sbom",
            ) else "other",
            ev / e_name,
            # The media type must describe the bytes. Stamping a station's
            # gate report (markdown) as application/json made the entry lie
            # about its own evidence (rehearsal 2026-08-24).
            {"json": "application/json", "md": "text/markdown",
             "txt": "text/plain", "yaml": "application/yaml",
             "yml": "application/yaml", "jsonl": "application/jsonl",
            }.get(e_name.rsplit(".", 1)[-1].lower(), "application/octet-stream"),
            f"attached evidence ({e_kind})",
        ))

    absent = default_absent_rows(candidate)
    entry = assemble_entry(args, tag_object, source_sha, candidate_map, receipt, evidence_rows, absent)

    # C8 — completeness or explicit break-glass (candidates honestly need less:
    # the receipt and the soak arrive later as the stations run)
    required = tuple(k for k in REQUIRED_EVIDENCE_KINDS if not (candidate and k == "delivery_receipt"))
    kinds = {r["kind"] for r in evidence_rows}
    missing = [k for k in required if k not in kinds]
    if missing and not args.break_glass:
        raise CheckFailure("C8", f"evidence kinds missing with no --break-glass: {missing}")
    if args.break_glass:
        entry["break_glass"] = parse_break_glass(args.break_glass)

    schema_validate(entry)  # C9

    (out / "entry.json").write_text(json.dumps(entry, indent=1, sort_keys=False) + "\n")
    write_verify_md(out, entry)
    print(f"built channel entry: {out}/entry.json")
    print(f"  C1 tag {args.release} -> {source_sha}")
    print(f"  C3 map pin OK; C5 {len(entry['images'])} images consistent; C6 {c6}")
    print(f"  evidence: {', '.join(r['name'] for r in evidence_rows)}")
    print(f"  absent (declared): {', '.join(a['kind'] for a in entry['evidence_absent'])}")
    return 0


def parse_break_glass(spec):
    fields = dict(kv.split("=", 1) for kv in spec.split(","))
    required = {"actor", "reason", "approved_by", "receipt"}
    missing = required - set(fields)
    if missing:
        raise SystemExit(f"--break-glass missing fields: {sorted(missing)}")
    fields["at"] = utcnow()
    return fields


# -------------------------------------------------------------------- fetch


def cmd_fetch(args):
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    archive = f"vexa-core-{args.release}.tar.gz"
    run(["gh", "release", "download", args.release, "--repo", args.repo,
         "-p", archive, "--clobber", "-D", str(out)])
    digest = sha256_file(out / archive)
    run(["gh", "attestation", "download", str(out / archive), "--repo", args.repo],
        cwd=str(out))
    bundle = out / f"sha256:{digest}.jsonl"
    (out / "source-provenance.sigstore.json").write_bytes(bundle.read_bytes())
    with open(out / "trusted-root.jsonl", "w") as f:
        subprocess.run(["gh", "attestation", "trusted-root"], check=True, stdout=f)
    print(f"fetched: {archive} (sha256 {digest}), provenance bundle, trusted root -> {out}")
    return 0


# -------------------------------------------------------------------- verify


def cmd_verify(args):
    entry_dir = pathlib.Path(args.entry)
    entry = json.loads((entry_dir / "entry.json").read_text())
    failures = []

    def check(name, ok, detail=""):
        print(("OK   " if ok else "FAIL ") + f"{name} {detail}")
        if not ok:
            failures.append(name)

    try:
        schema_validate(entry)
        check("schema", True)
    except CheckFailure as e:
        check("schema", False, str(e))

    # Freshness, and it is reported as its OWN failure. An expired entry and a
    # forged entry are different events with different remedies, and the
    # rehearsal's worst defect was a good release reported as forged — so the
    # two never share a message.
    expires = entry.get("expires")
    if not expires:
        check("freshness", False, "entry declares no expires (pre-expiry entry; rebuild it)")
    elif is_expired(expires):
        check("freshness", False,
              f"STALE CHANNEL — this entry expired at {expires}. It is not invalid and it is "
              f"not forged: nobody has published to this channel since. Contact Vexa.")
    else:
        check("freshness", True, f"expires {expires}")

    for row in entry["evidence"]:
        p = entry_dir / "evidence" / row["name"]
        check(f"digest {row['name']}", p.exists() and sha256_file(p) == row["sha256"])

    # DECLARED-ABSENT IS NOT MISSING (estate-verify gap, filed 2026-08-25).
    #
    # These two lines used to run unconditionally, so `verify` on a PLATFORM
    # ESTATE entry did not report a failure — it CRASHED, with
    # `FileNotFoundError: evidence/delivery-receipt.json`, before printing a
    # single verdict. An estate has no candidate map and no delivery receipt
    # because no release train produced it; the entry says so in
    # `evidence_absent`, and the tool that reads entries did not read that
    # field. The result was a whole class of entry that our own verifier could
    # not verify, discovered only because someone published one.
    #
    # The absence is TOLERATED HERE and ADJUDICATED IN THE CONTRACT: the
    # in-cluster verifier's `forbid_absent_evidence` is what refuses an entry
    # that declared away something the subscriber requires. This function has
    # no contract, so it states what it did not check rather than passing it.
    absent_kinds = {row.get("kind") for row in entry.get("evidence_absent", [])}
    if {"candidate_map", "delivery_receipt"} & absent_kinds:
        reasons = "; ".join(
            f"{row['kind']}: {row['reason']}" for row in entry.get("evidence_absent", [])
            if row.get("kind") in ("candidate_map", "delivery_receipt"))
        print(f"note map pin / image consistency NOT CHECKED — declared absent ({reasons})")
        print("note  an estate's identity is carried by its captured digest set and its "
              "validation contract; whether that is acceptable is the SUBSCRIBER's contract "
              "to answer (forbid_absent_evidence), not this tool's.")
        # What CAN be checked without the map: that every image the entry ships
        # is digest-pinned. An entry naming a floating tag is refusable here
        # with no contract at all, and an estate is exactly where that could
        # slip in, because the digests were read off a cluster by hand.
        bad = [i.get("name") for i in entry.get("images", [])
               if not str(i.get("index_digest", "")).startswith("sha256:")
               or len(str(i.get("index_digest", ""))) != 71]
        check("image pins well-formed", not bad,
              f"{len(entry.get('images', []))} images" if not bad else f"unpinned: {bad}")
    else:
        receipt = json.loads((entry_dir / "evidence" / "delivery-receipt.json").read_text())
        map_bytes = (entry_dir / "evidence" / "candidate-images.json").read_bytes()
        try:
            check_map_pin(map_bytes, receipt)
            check("map pin", True)
        except CheckFailure as e:
            check("map pin", False, str(e))
        try:
            check_image_consistency(json.loads(map_bytes), receipt)
            check("image consistency", True)
        except CheckFailure as e:
            check("image consistency", False, str(e))

    if args.archive:
        arch_ok = sha256_file(args.archive) == entry["source"]["archive_sha256"]
        check("archive sha256", arch_ok)
        if arch_ok:
            try:
                verify_archive(args.archive, entry_dir / "evidence" / "source-provenance.sigstore.json")
                check("source provenance", True)
            except CheckFailure as e:
                check("source provenance", False, str(e))
    else:
        print("note archive not supplied; source-provenance verification against bytes skipped")

    sig = entry_dir / "entry.json.sigstore.json"
    if sig.exists() and args.pubkey:
        try:
            # Legacy bundle, no tlog: the channel signs offline against a pinned
            # key. --new-bundle-format made this check fail on every genuine
            # entry (rehearsal 2026-08-24); the flags below are what verifies.
            run([cosign_bin(), "verify-blob", "--key", args.pubkey,
                 "--bundle", str(sig), "--insecure-ignore-tlog=true",
                 str(entry_dir / "entry.json")], env=cosign_env())
            check("entry signature", True)
        except subprocess.CalledProcessError as e:
            check("entry signature", False, e.stderr.strip()[-200:])
    elif sig.exists():
        print("note entry.json.sigstore.json present; pass --pubkey to verify")

    if failures:
        print(f"VERIFY FAILED: {failures}")
        return 1
    print("VERIFY OK")
    return 0


# ---------------------------------------------------------------------- push


def cmd_push(args):
    entry_dir = pathlib.Path(args.entry)
    entry = json.loads((entry_dir / "entry.json").read_text())
    version = entry["release"]["version"]
    env = cosign_env()
    run_record = None

    if args.sign_key:
        major, full = require_pinned_cosign()                              # T1
        flags = cosign_offline_flags()
        print(f"signing with cosign {full} ({cosign_bin()}); offline flags: {' '.join(flags)}")
        # Explicitly offline: no transparency-log upload, legacy bundle — the
        # same posture as the artifact signature below, so VERIFY.md can state
        # one flag set that works for both. The flags are derived from the
        # resolved binary rather than hardcoded: 2.x has no --use-signing-config.
        run([cosign_bin(), "sign-blob", "--yes", "--key", args.sign_key, *flags,
             "--bundle", str(entry_dir / "entry.json.sigstore.json"),
             str(entry_dir / "entry.json")],
            env=env)
        print("signed entry.json -> entry.json.sigstore.json")
        run_record = signing_run_record(full, flags)

        # VERIFY.md is REGENERATED here, from what just happened, and only then
        # pushed. It used to be hand-maintained prose written at build time, and
        # it printed a cosign invocation that failed on every genuine entry while
        # onboarding/credential-delivery.md printed different flags again. The
        # instructions the customer receives are now a function of the signing
        # run that produced the thing they are verifying.
        write_verify_md(entry_dir, entry, run_record)
        print("VERIFY.md regenerated from this signing run")

    files = ["entry.json"] + (
        ["entry.json.sigstore.json"] if (entry_dir / "entry.json.sigstore.json").exists() else []
    ) + ["VERIFY.md"] + [f"evidence/{r['name']}" for r in entry["evidence"]]

    plain = ["--plain-http"] if args.plain_http else (["--insecure"] if args.insecure else [])
    ref = f"{args.ref}:{version}"
    out = run(
        ["oras", "push", *plain, "--artifact-type", ENTRY_MEDIA_TYPE, ref, *files],
        cwd=str(entry_dir),
    )
    digest = next((ln.split()[-1] for ln in out.stdout.splitlines() if ln.startswith("Digest:")), None)
    print(f"pushed {ref} digest {digest}")

    if args.sign_key and digest and not args.skip_sign_artifact:
        insecure = bool(args.plain_http or args.insecure)
        run([cosign_bin(), "sign", "--yes", "--key", args.sign_key, *cosign_offline_flags(), *cosign_registry_auth(),
             *(["--allow-insecure-registry"] if insecure else []),
             f"{args.ref}@{digest}"], env=env)
        print(f"cosign signed {args.ref}@{digest}")
        # T2 on the entry artifact too: the same `sha256-<digest>.sig` shape, in
        # the entry's own repository. The PreSync verifier reads this, and a
        # future cosign that drops the legacy layout would silently break it.
        pubkey = derive_public_key(args.sign_key, env)
        found = check_kyverno_readable(f"{args.ref}@{digest}", digest, None, pubkey, env,
                                       insecure=insecure)
        print(f"  entry signature discoverable at {found['ref']} and verifies")
        if run_record is not None:
            run_record["entry_artifact"] = found

    # The release tag names the CURRENT entry for that release, and a refreshed
    # entry moves it — otherwise re-stamping `expires` would need a version bump
    # for a release whose bytes did not change, and the PreSync hook (which asks
    # for the entry at the release tag) would keep pulling the stale one. The
    # superseded entry does not vanish: every entry also gets a permanent
    # <version>-seq<N> tag here, and its digest was never mutable. Rollback
    # protection is entry_seq monotonicity, which is inside the signature; tag
    # immutability never was.
    if digest:
        seq_tag = f"{version}-seq{entry['channel']['entry_seq']}"
        run(["oras", "tag", *plain, f"{args.ref}@{digest}", seq_tag])
        print(f"permanent tag {args.ref}:{seq_tag} -> {digest}")

    if args.channel_tag:
        # `oras tag` takes a bare tag name; the help string here showed a full
        # reference. Both now work — the ref form is normalised to its tag —
        # because the two spellings are indistinguishable to a reader and only
        # one of them was ever going to be typed.
        tag = args.channel_tag.rsplit(":", 1)[-1] if "/" in args.channel_tag else args.channel_tag
        run(["oras", "tag", *plain, f"{args.ref}@{digest}", tag])
        print(f"channel tag {args.ref}:{tag} -> {digest} (same-byte descriptor)")

    if run_record is not None and args.signing_receipt:
        pathlib.Path(args.signing_receipt).write_text(json.dumps(run_record, indent=1) + "\n")
        print(f"signing-run receipt -> {args.signing_receipt}")

    # The ledger write is LAST, and deliberately so: it records what was
    # published, so it must not run before the push that published it. `push`
    # is the sole writer of channel.yaml — see publisher/vexa_stations.py.
    if getattr(args, "ledger", None) or os.environ.get("VEXA_STATIONS_DIR"):
        import vexa_stations

        out = vexa_stations.record_publish(
            vexa_stations.resolve_root(getattr(args, "ledger", None)),
            entry, entry_digest=digest, registry_ref=args.ref,
            channel_tag=(args.channel_tag.rsplit(":", 1)[-1]
                         if args.channel_tag and "/" in args.channel_tag else args.channel_tag),
        )
        print(f"ledger: {out['channel']} entry_seq {out['entry_seq']} recorded "
              f"({out['commit'][:12] if out['commit'] else 'no change'})")
    return 0


def signing_run_record(cosign_full_version, flags, signature_repository=None, images=None):
    """What actually signed, with what, in which layout. VERIFY.md is written
    from this; nothing about the verification instructions is hand-maintained."""
    return {
        "signed_at": utcnow(),
        "cosign": {
            "binary": cosign_bin(),
            "version": cosign_full_version,
            "pinned_series": f"{COSIGN_PINNED_SERIES}.x",
            "recommended": COSIGN_RECOMMENDED_VERSION,
            "flags": list(flags),
        },
        "bundle_format": "legacy",
        "transparency_log": "none (offline, key-pinned)",
        "signature_layout": "legacy cosign tag sha256-<digest>.sig",
        "signature_repository": signature_repository,
        "images": images or [],
    }


# ------------------------------------------------------ refresh (freshness)


def cmd_refresh(args):
    """Re-stamp an existing entry's expiry without touching the release.

    Republishing the same release with a fresh horizon must be ordinary — an
    expiry that can only be extended by cutting a new version would make
    freshness cost a release, and nobody would set it short. So: same bytes,
    same digests, same evidence; new `expires`, new `published_at`, next
    `entry_seq`, re-signed. Push it and the release tag moves to the new entry
    while the superseded one keeps its permanent <version>-seq<N> tag.
    """
    src = pathlib.Path(args.entry)
    entry = json.loads((src / "entry.json").read_text())
    out = pathlib.Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"refusing to refresh into non-empty {out}")
    shutil.copytree(src, out, dirs_exist_ok=True)
    # the old signature covers the old bytes and must not survive beside new ones
    (out / "entry.json.sigstore.json").unlink(missing_ok=True)

    was_seq, was_exp = entry["channel"]["entry_seq"], entry.get("expires")
    entry["channel"]["entry_seq"] = args.entry_seq or (was_seq + 1)
    if entry["channel"]["entry_seq"] <= was_seq:
        raise CheckFailure("C10", f"--entry-seq {entry['channel']['entry_seq']} does not exceed "
                                  f"the entry it refreshes ({was_seq}) — a puller would refuse it")
    entry["expires"] = utcplus(args.expires_days)
    entry["publication"]["published_at"] = utcnow()
    if args.publisher:
        entry["publication"]["publisher"] = args.publisher

    schema_validate(entry)  # C9, again — a refresh is a publication
    (out / "entry.json").write_text(json.dumps(entry, indent=1, sort_keys=False) + "\n")
    write_verify_md(out, entry)
    print(f"refreshed {entry['release']['version']} on channel {entry['channel']['name']}")
    print(f"  entry_seq {was_seq} -> {entry['channel']['entry_seq']}")
    print(f"  expires   {was_exp} -> {entry['expires']}")
    print(f"  now sign and push it: vexa_channel.py push --entry {out} --ref <ref> "
          f"--sign-key <key> --channel-tag <ref>:current")
    return 0


# ----------------------------------------------------------- revocation list
#
# We can publish and we cannot un-publish. Deleting a tag does not reach a
# cluster that already resolved it, and an immutable tag is the whole point of
# the layout — so withdrawal has to be a positive, signed statement that the
# verifier goes and reads. One list per channel, replaced wholesale, cosign-
# signed with the channel key.
#
# WHAT THIS IS NOT: Kyverno cannot read it. An admission controller verifies
# signatures on the images in front of it; it does not fetch a vendor document
# and reason about it, and no amount of policy YAML makes it do so. The
# enforcement point for revocation is the PreSync verifier, which runs before
# the sync and refuses it. Admission remains the independent check on
# signatures and digest-pinning, and those are different questions.

REVOCATIONS_MEDIA_TYPE = "application/vnd.vexa.channel-revocations.v1+json"
REVOCATIONS_TAG = "latest"
DEFAULT_REVOCATIONS_EXPIRES_DAYS = 30


def revocations_schema_validate(doc):
    import jsonschema
    schema = json.loads((pathlib.Path(__file__).resolve().parent.parent
                         / "spec" / "revocations.schema.json").read_text())
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(doc),
                    key=lambda e: list(e.absolute_path))
    if errors:
        locs = "; ".join(f"{'/'.join(str(x) for x in e.absolute_path) or '(root)'}: {e.message}"
                         for e in errors[:5])
        raise CheckFailure("R1", f"revocation list does not validate: {locs}")


def revocations_ref(base):
    return f"{base}/revocations:{REVOCATIONS_TAG}"


def pull_revocations(base, workdir, plain):
    """Return the published list, or None when the channel has none.

    ABSENT IS NOT AN ERROR and this is the only place that decision is made.
    Every channel published before this capability existed has no list, and a
    fail-closed reading would refuse every one of those installs the moment
    the verifier learned to look."""
    try:
        run(["oras", "pull", *plain, revocations_ref(base), "-o", str(workdir)])
    except subprocess.CalledProcessError:
        return None
    f = pathlib.Path(workdir) / "revocations.json"
    return json.loads(f.read_text()) if f.is_file() else None


def cmd_revoke(args):
    plain = ["--plain-http"] if args.plain_http else (["--insecure"] if args.insecure else [])
    work = pathlib.Path(tempfile.mkdtemp(prefix="vexa-revoke-"))
    try:
        doc = pull_revocations(args.ref, work, plain)
        if doc is None:
            print(f"no revocation list on {args.ref} yet — starting one")
            doc = {"schema_version": 1, "channel": args.channel, "updated_at": utcnow(),
                   "expires": utcplus(args.expires_days), "entries": []}
        elif doc.get("channel") != args.channel:
            raise CheckFailure("R2", f"the list on {args.ref} governs channel "
                                     f"'{doc.get('channel')}', not '{args.channel}'")

        if args.version or args.digest:
            if not args.reason:
                raise SystemExit("--reason is required to revoke something")
            row = {"reason": args.reason, "severity": args.severity, "date": utcnow()}
            if args.version:
                row["version"] = args.version
            if args.digest:
                row["digest"] = args.digest
            if args.supersedes:
                row["supersedes"] = args.supersedes
            if args.advisory:
                row["advisory"] = args.advisory
            doc["entries"].append(row)
            print(f"revoking {args.version or args.digest} ({args.severity}): {args.reason}")
        else:
            print("no --version/--digest given: publishing the list as it stands "
                  "(this is how an EMPTY list goes live before it is needed)")

        doc["updated_at"] = utcnow()
        doc["expires"] = utcplus(args.expires_days)
        revocations_schema_validate(doc)  # R1

        out = work / "out"
        out.mkdir()
        (out / "revocations.json").write_text(json.dumps(doc, indent=1) + "\n")
        if args.key:
            run(["cosign", "sign-blob", "--yes", "--key", args.key,
                 "--tlog-upload=false", "--new-bundle-format=false", "--use-signing-config=false",
                 "--bundle", str(out / "revocations.json.sigstore.json"),
                 str(out / "revocations.json")], env=cosign_env())
            print("signed revocations.json")
        elif not args.unsigned:
            raise SystemExit("--key is required (an unsigned revocation list is a document "
                             "anyone can write; pass --unsigned only for local fixtures)")

        if args.dry_run:
            dest = pathlib.Path(args.out or ".").resolve()
            dest.mkdir(parents=True, exist_ok=True)
            for f in out.iterdir():
                shutil.copy(f, dest / f.name)
            print(f"dry run: wrote {dest}/revocations.json ({len(doc['entries'])} entr"
                  f"{'y' if len(doc['entries']) == 1 else 'ies'})")
            return 0

        files = ["revocations.json"] + (
            ["revocations.json.sigstore.json"]
            if (out / "revocations.json.sigstore.json").exists() else [])
        r = run(["oras", "push", *plain, "--artifact-type", REVOCATIONS_MEDIA_TYPE,
                 revocations_ref(args.ref), *files], cwd=str(out))
        digest = next((ln.split()[-1] for ln in r.stdout.splitlines()
                       if ln.startswith("Digest:")), None)
        print(f"published {revocations_ref(args.ref)} digest {digest} — "
              f"{len(doc['entries'])} entr{'y' if len(doc['entries']) == 1 else 'ies'}, "
              f"list expires {doc['expires']}")
        print("NOTE Kyverno cannot read this list. The PreSync verifier is the "
              "enforcement point; admission still only checks signatures and pinning.")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def cosign_env():
    import os
    import tempfile

    env = dict(os.environ)
    env.setdefault("COSIGN_PASSWORD", "")
    # Neutralize docker credential helpers: with Docker Desktop absent, the
    # configured credsStore helper hangs forever inside cosign's keychain
    # lookup (observed: cosign blocked in wait4 on docker-credential-desktop).
    # Anonymous auth is correct here - public pulls, unauthenticated test
    # registries; real registry auth is passed explicitly when needed.
    iso = pathlib.Path(tempfile.gettempdir()) / "vexa-channel-dockercfg"
    iso.mkdir(exist_ok=True)

    # The hazard is the credential HELPER, not the credentials. Blanking auths
    # outright meant cosign could not sign into an authenticated channel
    # registry at all: `cosign sign` on the pushed entry failed UNAUTHORIZED
    # while the oras push beside it succeeded (rehearsal 2026-08-24). So carry
    # the already-logged-in `auths` across and drop only the helper keys.
    real = pathlib.Path(env.get("HOME", "")) / ".docker" / "config.json"
    auths = {}
    try:
        auths = json.loads(real.read_text()).get("auths", {}) or {}
    except (OSError, ValueError):
        auths = {}
    auths = {k: v for k, v in auths.items() if isinstance(v, dict) and v.get("auth")}

    # An authenticated channel registry logged in through `oras login` leaves
    # nothing usable here on a macOS host: credsStore=desktop puts the secret in
    # the keychain behind the helper we must not call. Take the credential from
    # the environment instead — never from argv, where it would land in shell
    # history and process listings.
    import base64
    host = env.get("VEXA_CHANNEL_REGISTRY")
    user = env.get("VEXA_CHANNEL_USER")
    password = env.get("VEXA_CHANNEL_PASS")
    if host and user and password:
        auths[host] = {"auth": base64.b64encode(f"{user}:{password}".encode()).decode()}

    (iso / "config.json").write_text(json.dumps({"auths": auths}))
    env["DOCKER_CONFIG"] = str(iso)
    return env




# ----------------------------------------------------- chart + pins (MVP0)

CHART_COMPONENT_IMAGES = {
    "gateway": "vexaai/v012-gateway",
    "adminApi": "vexaai/v012-admin-api",
    "meetingApi": "vexaai/v012-meeting-api",
    "runtime": "vexaai/v012-runtime",
    "agentApi": "vexaai/v012-agent-api",
    "terminal": "vexaai/v012-terminal",
}
SPAWNED_IMAGES = {
    "browserImage": "vexaai/vexa-bot",
    "agentImage": "vexaai/v012-agent-api",
    "agentWorkerImage": "vexaai/v012-agent-worker",
}


def build_pins(version, candidate_map):
    """Digest pins for every image the chart runs or spawns — identity only,
    toggles live in the node baseline."""
    images = candidate_map.get("images", {})

    def ref_tag(repo):
        m = images.get(repo)
        if not m:
            raise CheckFailure("C5", f"chart needs {repo} but the candidate map lacks it")
        return f"{version}@{m['digest']}"

    pins = {c: {"image": {"tag": ref_tag(repo)}} for c, repo in CHART_COMPONENT_IMAGES.items()}
    pins.setdefault("runtime", {}).update(
        {k: f"{repo}:{ref_tag(repo)}" for k, repo in SPAWNED_IMAGES.items()}
    )
    return pins


def deep_merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v
    return base


ARGO_HOOK_STAMP = (
    '"helm.sh/hook-delete-policy": before-hook-creation\n'
    '    # Stamped by the channel publisher: under Argo CD the helm pre-upgrade hook\n'
    '    # collapses to PreSync and deadlocks on first sync (DB and secret are main\n'
    '    # resources). Argo prefers its own annotations: run as a Sync-phase hook in\n'
    '    # a late wave, after postgres and secrets are healthy.\n'
    '    "argocd.argoproj.io/hook": Sync\n'
    '    "argocd.argoproj.io/sync-wave": "5"\n'
    '    "argocd.argoproj.io/hook-delete-policy": BeforeHookCreation'
)


# ---------------------------------------------- the PreSync gate rides the chart
#
# EVERY chart this publisher ships carries it — the OSS chart and the platform
# ESTATE charts alike. Until 2026-08-25 only `chart` (the OSS path) injected it,
# so an estate published through `platform-chart` reached a subscriber's Argo CD
# with **no PreSync verification at all**: the signature, the contract, the
# revocation list and the human approval were all checked by nothing, because
# the object that checks them was never in the chart. Nothing failed — an
# estate simply synced, which is the failure shape this whole repository exists
# to make impossible. The injection is therefore one function called from all
# three packaging paths, not a line copied into each.
#
# It is INERT by default: `verify.enabled: false` renders zero objects, so
# adding it to an existing estate chart is a no-op in the render diff until a
# subscription turns it on per environment.

VERIFY_DEFAULTS = {
    "enabled": False,
    "registry": "",
    "channel": "",
    "image": "",
    "contractConfigMap": "vexa-contract",
    "registrySecret": "",
    "deadlineSeconds": 300,
    "requireApproval": "",
    "approvalNamespace": "argocd",
    "insecure": False,
    # ESTATE ESCAPE HATCH, and it is not cosmetic. The template derives the
    # entry ref as `<registry>/vexa/channel/<channel>:v<Chart.AppVersion>`,
    # which is right for an OSS release (appVersion IS the entry tag, and the
    # tags carry a `v`). An estate entry is tagged `0.12.23-estate-20260825`
    # while its chart's appVersion is `0.12.23-estate` — so the derived ref
    # asks for `v0.12.23-estate`, a tag that does not exist, and every sync
    # fails on a 404 that says nothing about the evidence. Setting entryTag
    # names the entry outright and skips the derivation.
    "entryTag": "",
    # The verifier's own two inputs, chart-managed when supplied. Empty means
    # "an object by that name is managed outside this chart" — a real and
    # supported choice. What is NOT supported is the accidental version of it,
    # where both were kubectl-created during a ceremony and owned by nobody
    # (prod orphan audit, 2026-08-25). contractPolicy is JSON TEXT: the
    # verifier reads the contract with jq.
    "contractPolicy": "",
    "channelPublicKey": "",
    # POD PLACEMENT, and it is the third "the gate failed for a reason that is
    # not the evidence" defect in this template (prod, 2026-08-25). The Job
    # rendered with neither, so on a cluster whose only node pool is tainted
    # — ours: `vexa.ai/pool=main:NoSchedule` — the pod sat Pending until
    # activeDeadlineSeconds fired and the Job went DeadlineExceeded. The sync
    # failed closed and prod was untouched, so nothing was damaged; nothing
    # was verified either.
    #
    # EMPTY BY DEFAULT, which is the whole point: a subscriber who did not ask
    # for placement gets a render that is byte-identical to before. An estate
    # that taints its nodes declares its own placement in the values it
    # publishes with, next to its pull secret and its entry tag.
    "tolerations": [],
    "nodeSelector": {},
    # EGRESS, and it is the FOURTH "the gate failed for a reason that is not the
    # evidence" defect (prod, 2026-08-25, seq 4). With the pod finally
    # schedulable, the verifier started and immediately could not pull the
    # entry: `vexa-production` runs a default-deny NetworkPolicy plus one
    # enumerated egress policy per workload, and the verify Job — being a hook,
    # not a workload — was in nobody's enumeration. The container image pulled
    # fine, because the kubelet pulls from the node's network namespace; the
    # ENTRY pull is oras inside the pod and is ordinary pod egress.
    #
    # ON BY DEFAULT, unlike tolerations. A deny-by-default namespace is the norm
    # on the estates this gate exists for, the failure it prevents is silent
    # until a sync fails closed, and the failure it can CAUSE — a registry that
    # is not on 443 — is one the subscriber knows about and can turn off here.
    "networkPolicy": True,
    # The registry is one host behind one address, and hard-coding it in the
    # template would put a subscriber's registry inside OUR chart, exactly like
    # a hard-coded toleration would. An estate narrows this in its own values.
    "egressCIDR": "0.0.0.0/0",
}


def inject_channel_verify(chart_dir, values):
    """Write the PreSync verify template into a chart and default its values.

    PER-KEY, not `setdefault("verify", ...)`. The estate publishes with a
    `verify:` block of its own (entry tag, pull secret, placement), and a
    whole-key setdefault means the block the operator wrote REPLACES the
    defaults rather than overriding them — so every default added after that
    file was written silently never reaches the estate that most needs it.
    Caught adding verify.networkPolicy, 2026-08-25: the egress fix would have
    rendered nothing on the one cluster it was written for, and rendered
    nothing SILENTLY, which is this template's whole failure history.
    """
    gate_src = (pathlib.Path(__file__).resolve().parent.parent
                / "kit/verify/chart-template/channel-verify.yaml")
    (chart_dir / "templates/channel-verify.yaml").write_text(gate_src.read_text())
    verify = dict(VERIFY_DEFAULTS)
    deep_merge(verify, values.get("verify") or {})   # the operator still wins
    values["verify"] = verify
    return values


def cmd_chart(args):
    import tempfile
    import yaml

    version = args.release
    tag_object, source_sha, map_bytes = read_tag(args.vexa_repo, version)
    candidate_map = json.loads(map_bytes)
    check_map_identity(version, candidate_map)
    pins = build_pins(version, candidate_map)

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="vexa-chart-"))
    subprocess.run(
        f"git -C {args.vexa_repo} archive {version} deploy/helm/charts/vexa | tar -x -C {workdir}",
        shell=True, check=True,
    )
    chart_dir = workdir / "deploy/helm/charts/vexa"

    values_path = chart_dir / "values.yaml"
    values = yaml.safe_load(values_path.read_text())
    deep_merge(values, pins)
    if args.baseline:
        deep_merge(values, yaml.safe_load(pathlib.Path(args.baseline).read_text()) or {})
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))

    cy = chart_dir / "Chart.yaml"
    cyd = yaml.safe_load(cy.read_text())
    # Helm keeps two version lines and they are not the same fact: `version` is
    # the CHART revision (what a subscriber's `targetRevision: "*"` ranks), and
    # `appVersion` is the release the chart deploys. Collapsing them meant a
    # release could never ship a second chart revision — the packaging fix,
    # values change or hook stamp had nowhere to go — and it put chart revisions
    # into the same number space as release versions. --chart-version separates
    # them; without it the old behaviour (both = the release) is unchanged.
    cyd["version"] = (args.chart_version or version).lstrip("v")
    cyd["appVersion"] = version.lstrip("v")
    cy.write_text(yaml.safe_dump(cyd, sort_keys=False))

    inject_channel_verify(chart_dir, values)
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))

    mig = chart_dir / "templates/job-migrations.yaml"
    mt = mig.read_text()
    needle = '"helm.sh/hook-delete-policy": before-hook-creation'
    if needle not in mt:
        raise CheckFailure("C10", "job-migrations hook shape changed; refusing to stamp blind")
    mt = mt.replace(needle, ARGO_HOOK_STAMP.replace("\\n", "\n"))
    mig.write_text(mt)

    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    run(["helm", "package", str(chart_dir), "-d", str(out)])
    tgz = out / f"vexa-{cyd['version']}.tgz"
    print(f"packaged {tgz}")
    (out / f"pins-{version}.yaml").write_text(yaml.safe_dump(pins, sort_keys=False))

    if args.push:
        cmd = ["helm", "push", str(tgz), args.push]
        if args.insecure:
            cmd.insert(2, "--insecure-skip-tls-verify")
        r = run(cmd)
        line = next((ln for ln in (r.stdout + r.stderr).splitlines() if "Digest:" in ln), "")
        digest = line.split("Digest:")[-1].strip() if line else None
        print(f"pushed chart to {args.push} digest {digest}")
        (out / "chart-info.json").write_text(json.dumps(
            {"oci_ref": f"{args.push.removeprefix('oci://')}/vexa", "digest": digest,
             "version": cyd["version"], "app_version": version.lstrip("v")}, indent=1))
    return 0



# ------------------------------------- platform chart + cluster pins (MVP0.5)
#
# WHY THIS IS A SEPARATE COMMAND. `chart` above packages the OPEN-SOURCE vexa
# chart, and it gets its digests from a release artifact: the candidate map
# committed at a git tag. The PROPRIETARY platform chart has no such artifact.
# Its values reference images by TAG (`vexaai/vexa-transcription-gateway:
# 0.10.6.3-260713-keepalive`, `caddy:2-alpine`); the tags were resolved to
# digests at deploy time, so the only place the digest set has ever existed is
# the live cluster's workload manifests. `release/registry.yaml` in
# vexa-platform is an evidence-CHECK registry (check -> script/modes/proves) and
# holds no pins at all.
#
# So the pin source is an EXPLICIT INPUT FILE (--pin-set), captured from a
# cluster by whoever is publishing, and the whole point of this command is to
# turn that cluster-only state into a signed artifact.
#
# HOW THE CHART EXPRESSES AN IMAGE. Two shapes, and they need different writes:
#
#   "whole"  the value is the entire reference string
#            templates/statefulset-postgres.yaml: image: {{ .Values.postgres.image }}
#   "split"  repository and tag are joined with a literal colon
#            templates/deployment-caddy.yaml:
#              image: "{{ .Values.caddy.image.repository }}:{{ .Values.caddy.image.tag }}"
#
# NEITHER shape can express a bare `repo@sha256:...` — the split templates would
# render `repo@sha256:xxx:tag`. Both CAN express `repo:tag@sha256:...`, which is
# a valid OCI reference (name[:tag][@digest]) where the digest is authoritative
# and the tag is decoration. That is what this command writes, so no template in
# either chart has to change.
#
# Every row below was read out of the template that consumes it. Do not add a
# row without opening that template.

PLATFORM_IMAGE_PATHS = [
    # (values path, shape, docker repo, template that consumes it)
    ("caddy.image",                        "split", "caddy",                             "templates/deployment-caddy.yaml"),
    ("webapp.image",                       "split", "vexaai/vexa-webapp",                "templates/deployment-webapp.yaml"),
    ("dashboard.image",                    "split", "vexaai/dashboard",                  "templates/deployment-dashboard.yaml"),
    ("transcriptionGateway.image",         "split", "vexaai/vexa-transcription-gateway", "templates/deployment-transcription-gateway.yaml"),
    ("analytics.refresh.image",            "split", "vexaai/analytics-refresh",          "templates/cronjob-analytics-refresh.yaml"),
    ("analytics.meterSync.image",          "split", "vexaai/analytics-refresh",          "templates/cronjob-meter-sync.yaml"),
    ("analytics.customerMetricsSync.image","split", "vexaai/analytics-refresh",          "templates/cronjob-customer-metrics-sync.yaml"),
    ("postgres.image",                     "whole", "postgres",                          "templates/statefulset-postgres.yaml"),
    ("backups.database.image",             "whole", "postgres",                          "templates/cronjob-db-backup.yaml + cronjob-postgres-hydrate.yaml"),
    ("backups.recordings.image",           "whole", "amazon/aws-cli",                    "templates/cronjob-s3-backup.yaml"),
    ("driftDetector.image",                "whole", "alpine/helm",                       "templates/cronjob-drift-detector.yaml"),
    ("capacityReserve.image",              "whole", "registry.k8s.io/pause",             "templates/deployment-capacity-reserve.yaml"),
    ("recordingReconciler.image",          "whole", "vexaai/v012-meeting-api",           "templates/cronjob-recording-reconciler.yaml"),
    # vendored OSS subchart (charts/vexa-*.tgz), reached under the `vexa:` key
    ("vexa.gateway.image",                 "split", "vexaai/v012-gateway",               "charts/vexa: templates/deployment-gateway.yaml"),
    ("vexa.adminApi.image",                "split", "vexaai/v012-admin-api",             "charts/vexa: templates/deployment-admin-api.yaml"),
    ("vexa.meetingApi.image",              "split", "vexaai/v012-meeting-api",           "charts/vexa: templates/deployment-meeting-api.yaml"),
    ("vexa.runtime.image",                 "split", "vexaai/v012-runtime",               "charts/vexa: templates/deployment-runtime.yaml"),
    ("vexa.agentApi.image",                "split", "vexaai/v012-agent-api",             "charts/vexa: templates/deployment-agent-api.yaml"),
    ("vexa.terminal.image",                "split", "vexaai/v012-terminal",              "charts/vexa: templates/deployment-terminal.yaml"),
    ("vexa.minio.image",                   "split", "minio/minio",                       "charts/vexa: templates/deployment-minio.yaml"),
    ("vexa.redis.image",                   "whole", "redis",                             "charts/vexa: templates/deployment-redis.yaml"),
    ("vexa.postgres.image",                "whole", "postgres",                          "charts/vexa: templates/statefulset-postgres.yaml"),
    ("vexa.pgbouncer.image",               "whole", "docker.io/bitnami/pgbouncer",       "charts/vexa: templates/deployment-pgbouncer.yaml"),
    # not an `image:` field — the reference the runtime hands to the k8s spawner
    ("vexa.runtime.browserImage",          "whole", "vexaai/vexa-bot",                   "charts/vexa: templates/deployment-runtime.yaml (env VEXA_BOT_IMAGE)"),
]

# `vexa.global.imageTag`, when set, WINS over every per-component tag in the
# vendored subchart ({{ .Values.global.imageTag | default .Values.gateway.image.tag }}).
# The generated overlay blanks it, or the one-tag-for-all pin would silently
# un-pin every OSS core image the moment values-base.yaml is applied.
SUBCHART_TAG_OVERRIDE = "vexa.global.imageTag"

DIGEST_RE = re.compile(r"^(?P<repo>[^\s@]+)@(?P<digest>sha256:[0-9a-f]{64})$")


def _dig(tree, path):
    cur = tree
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set(tree, path, value):
    parts = path.split(".")
    cur = tree
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def parse_pin_set(text):
    """Parse a --pin-set file into (auto, explicit).

    One reference per line, `#` comments and blank lines ignored:

        vexaai/v012-gateway@sha256:<64 hex>        auto-mapped by repo
        backups.database.image=postgres@sha256:..  assigned to one values path

    The explicit form exists because a repo can serve more than one values path
    with DIFFERENT digests (a re-pushed `postgres:17-alpine` is exactly this).
    The command never picks between them; a human declares the assignment.
    """
    auto, explicit = {}, {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        path = None
        if "=" in line:
            path, line = (s.strip() for s in line.split("=", 1))
        m = DIGEST_RE.match(line)
        if not m:
            raise CheckFailure("P1", f"pin-set line {lineno} is not repo@sha256:<64 hex>: {raw.strip()!r}")
        repo, digest = m.group("repo"), m.group("digest")
        if path:
            if path in explicit:
                raise CheckFailure("P1", f"pin-set assigns {path} twice")
            explicit[path] = (repo, digest)
        elif repo in auto:
            raise CheckFailure(
                "P1",
                f"{repo} appears twice with different digests ({auto[repo]} and {digest}); "
                f"assign each with an explicit <values.path>={repo}@<digest> line — refusing to guess",
            )
        else:
            auto[repo] = digest
    return auto, explicit


def parse_unpinnable(specs):
    """--unpinnable repo=reason. A declared, recorded hole; never a silent one."""
    out = {}
    for spec in specs or []:
        if "=" not in spec:
            raise CheckFailure("P2", f"--unpinnable needs repo=reason, got {spec!r}")
        repo, reason = (s.strip() for s in spec.split("=", 1))
        if not reason:
            raise CheckFailure("P2", f"--unpinnable {repo} needs a reason")
        out[repo] = reason
    return out


def resolve_platform_pins(auto, explicit, merged_values, unpinnable):
    """Turn a pin set into the values overlay the chart actually reads.

    Refuses on both directions of mismatch (check P2): a pin with no values path
    to land in, and a values path the chart configures with no pin to land there.
    Silent partial pinning is the failure mode this command exists to prevent.
    """
    rows = {p: (shape, repo, tmpl) for p, shape, repo, tmpl in PLATFORM_IMAGE_PATHS}
    by_repo = {}
    for path, shape, repo, _ in PLATFORM_IMAGE_PATHS:
        by_repo.setdefault(repo, []).append(path)

    for path in explicit:
        if path not in rows:
            raise CheckFailure("P2", f"pin-set assigns unknown values path {path}; not in PLATFORM_IMAGE_PATHS")

    assignments = dict(explicit)                                     # path -> (repo, digest)
    for repo, digest in auto.items():
        paths = [p for p in by_repo.get(repo, []) if p not in explicit]
        if not by_repo.get(repo):
            if repo in unpinnable:
                continue
            raise CheckFailure(
                "P2",
                f"{repo}@{digest} has no values path in this chart — either the image is "
                f"hardcoded in a template or it is not part of this chart at all; "
                f"declare it with --unpinnable '{repo}=<reason>' or add a row",
            )
        for p in paths:
            assignments[p] = (repo, digest)

    # The reverse direction is checked against what the chart RENDERS, not
    # against what its values happen to define: the vendored subchart ships
    # defaults for components this deployment disables (minio, pgbouncer,
    # agentApi), and demanding pins for images nobody runs is noise. See
    # check_render_coverage.

    overlay = {}
    mapping = []
    for path, (repo, digest) in sorted(assignments.items()):
        shape = rows[path][0]
        tag = _effective_tag(merged_values, path, shape)
        ref = f"{repo}:{tag}@{digest}" if tag else f"{repo}@{digest}"
        if shape == "whole":
            _set(overlay, path, ref)
        else:
            _set(overlay, path + ".repository", repo)
            _set(overlay, path + ".tag", f"{tag}@{digest}" if tag else f"pinned@{digest}")
        mapping.append({"values_path": path, "shape": shape, "image": ref, "template": rows[path][2]})
    _set(overlay, SUBCHART_TAG_OVERRIDE, "")
    return overlay, mapping


def _effective_tag(merged_values, path, shape):
    """The tag the chart would render today, kept as decoration in front of the
    digest so the artifact still says which build the digest belongs to."""
    if shape == "whole":
        cur = _dig(merged_values, path)
        if isinstance(cur, str) and ":" in cur and "@" not in cur:
            return cur.rsplit(":", 1)[1]
        return None
    if path.startswith("vexa."):
        override = _dig(merged_values, SUBCHART_TAG_OVERRIDE)
        if override:
            return str(override)
    cur = _dig(merged_values, path + ".tag")
    return str(cur) if cur else None


def ref_repo(ref):
    """The repository half of an image reference. Handles a registry:port host
    (`registry.k8s.io/pause:3.9`, `host:5000/x:1`) and a digest suffix."""
    ref = ref.split("@", 1)[0]
    head, sep, tail = ref.rpartition(":")
    return head if sep and "/" not in tail else ref


def check_render_coverage(images, assignments_by_repo, unpinnable):
    """P2, reverse direction: every image this chart actually renders must have
    somewhere for a pin to land. Names the exact image, like C5 does."""
    orphans = []
    for ref in images:
        repo = ref_repo(ref)
        if repo in assignments_by_repo or repo in unpinnable:
            continue
        orphans.append(ref)
    if orphans:
        raise CheckFailure(
            "P2",
            "the chart renders these images but the pin set does not cover them: "
            + ", ".join(sorted(orphans))
            + " — add the digest to --pin-set, or declare --unpinnable '<repo>=<reason>' "
              "(an image hardcoded in a template has no values path a pin can reach)",
        )


def rendered_images(chart, values_files):
    """Every `image:` a `helm template` of this chart emits. Local, no cluster."""
    cmd = ["helm", "template", "vexa-platform", str(chart)]
    for f in values_files:
        cmd += ["-f", str(f)]
    out = run(cmd).stdout
    return sorted({
        m.group(1).strip().strip('"').strip("'")
        for m in re.finditer(r"^\s*image:\s*(.+?)\s*$", out, re.M)
    })


def prune_stale_subcharts(chart_dir):
    """Keep only the subchart archive Chart.yaml's dependency pins.

    WHY. vexa-platform vendors THREE archives of the same subchart name —
    charts/vexa-0.12.4.tgz, -0.12.12.tgz, -0.12.15.tgz — while the dependency
    pins 0.12.4. `helm package` expands all three into ONE charts/vexa/
    directory: the Chart.yaml is 0.12.4's, the templates/ is the UNION of all
    three (89 files where each archive has ~30), and the result fails to render
    with a nil-pointer on a template that only exists in 0.12.15. Rendering the
    chart DIRECTORY hides this completely, because helm picks one archive there.

    That is silent version-mixing in the artifact a customer installs, so it is
    pruned here and the removal is recorded in the report.
    """
    import yaml

    cy = yaml.safe_load((chart_dir / "Chart.yaml").read_text()) or {}
    charts = chart_dir / "charts"
    if not charts.is_dir():
        return []
    removed = []
    for dep in cy.get("dependencies") or []:
        keep = charts / f"{dep['name']}-{dep['version']}.tgz"
        if not keep.is_file():
            raise CheckFailure("P4", f"dependency {dep['name']} {dep['version']} is not vendored at {keep}")
        for other in sorted(charts.glob(f"{dep['name']}-*.tgz")):
            if other != keep:
                other.unlink()
                removed.append(other.name)
    return removed



def _platform_chart_from_overlay(args, src_chart, unpinnable):
    """Package the chart with an operator-supplied values overlay baked in.

    Same output contract as the pin-set path: a packaged .tgz whose bare
    `helm install` is pinned, a values-pins.yaml that survives a later -f, and
    a report. The difference is only where the pins come from.
    """
    import tempfile
    import yaml

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="vexa-platform-chart-"))
    chart_dir = workdir / src_chart.name
    shutil.copytree(src_chart, chart_dir)
    pruned = prune_stale_subcharts(chart_dir)

    overlay = {}
    for f in args.pins_values:
        deep_merge(overlay, yaml.safe_load(pathlib.Path(f).read_text()) or {})

    values_path = chart_dir / "values.yaml"
    values = yaml.safe_load(values_path.read_text()) or {}
    deep_merge(values, overlay)
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))
    pins_file = chart_dir / "values-pins.yaml"
    pins_file.write_text(
        "# Generated by vexa-channel platform-chart (overlay mode). APPLY LAST:\n"
        "#   helm upgrade ... -f values-base.yaml -f values-<env>.yaml -f values-pins.yaml\n"
        "# Composed from: " + ", ".join(pathlib.Path(f).name for f in args.pins_values) + "\n"
        + yaml.safe_dump(overlay, sort_keys=False)
    )

    if not args.no_verify_gate:
        inject_channel_verify(chart_dir, values)
        values_path.write_text(yaml.safe_dump(values, sort_keys=False))

    cy = chart_dir / "Chart.yaml"
    cyd = yaml.safe_load(cy.read_text())
    cyd["version"] = (args.chart_version or args.release).lstrip("v")
    cyd["appVersion"] = args.release.lstrip("v")
    cy.write_text(yaml.safe_dump(cyd, sort_keys=False))

    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    run(["helm", "package", str(chart_dir), "-d", str(out)])
    tgz = out / f"{cyd['name']}-{cyd['version']}.tgz"
    print(f"packaged {tgz}")

    # P3 — THE guarantee in this mode. Render the PACKAGED ARTIFACT (helm
    # package rewrites charts/, so the tree and the tgz are not the same
    # chart) and refuse if any rendered image lacks a digest.
    images = rendered_images(tgz, [pins_file])
    unpinned = [i for i in images if "@sha256:" not in i and ref_repo(i) not in unpinnable]
    if unpinned:
        raise CheckFailure("P3", "rendered chart still has un-pinned images: " + ", ".join(unpinned))

    report = {
        "chart": cyd["name"], "version": cyd["version"], "app_version": cyd["appVersion"],
        "pin_mode": "overlay",
        "pin_source": [str(pathlib.Path(f).resolve()) for f in args.pins_values],
        "mapping": None,
        "mapping_absent_reason":
            "overlay mode does not map digest->values-path; PLATFORM_IMAGE_PATHS does not "
            "model this chart's operationalImages/billingWitness/.image.digest shapes. "
            "P3 (every rendered image carries a digest) is the guarantee instead.",
        "unpinnable": unpinnable,
        "pruned_subchart_archives": pruned,
        "rendered_images": images,
    }
    (out / f"platform-pins-{cyd['version']}.json").write_text(json.dumps(report, indent=1))
    (out / f"platform-pins-{cyd['version']}.yaml").write_text(pins_file.read_text())
    print(f"  P3 OK: {len(images)} rendered images, all digest-pinned")
    if pruned:
        print(f"  pruned stale subchart archives: {', '.join(pruned)}")

    if args.push:
        cmd = ["helm", "push", str(tgz), args.push]
        if args.insecure:
            cmd.insert(2, "--insecure-skip-tls-verify")
        r = run(cmd)
        line = next((ln for ln in (r.stdout + r.stderr).splitlines() if "Digest:" in ln), "")
        digest = line.split("Digest:")[-1].strip() if line else None
        print(f"pushed chart to {args.push} digest {digest}")
        (out / "chart-info.json").write_text(json.dumps(
            {"oci_ref": f"{args.push.removeprefix('oci://')}/{cyd['name']}", "digest": digest,
             "version": cyd["version"], "app_version": cyd["appVersion"]}, indent=1))
    return 0


def cmd_platform_chart(args):
    import tempfile
    import yaml

    src_chart = pathlib.Path(args.chart_dir).expanduser().resolve()
    if not (src_chart / "Chart.yaml").is_file():
        raise CheckFailure("P0", f"{src_chart} is not a chart directory")

    unpinnable = parse_unpinnable(args.unpinnable)

    # ---------------------------------------------------------------- OVERLAY MODE
    #
    # WHY THIS MODE EXISTS (added 2026-08-25, while publishing the real estate).
    #
    # The --pin-set path above maps digests onto values paths using
    # PLATFORM_IMAGE_PATHS, a hand-maintained table with one row per image and
    # a comment requiring that you open the consuming template before adding a
    # row. That discipline is right, and the table is nonetheless WRONG for the
    # chart as it stands today: the live chart reaches images through
    # `operationalImages.*`, `billingWitness.operationalImages.*`,
    # `corednsToleration.image`, `capacityReserve.resizeImage` and a
    # `.image.digest` sub-key shape that the table does not model at all. The
    # table describes an earlier chart.
    #
    # A hand-maintained mirror of someone else's structure goes stale silently,
    # and it goes stale in the direction of UNDER-pinning — a missing row is a
    # missing pin, and P3 is the only thing that catches it.
    #
    # So: --pins-values takes the values overlay the operator ALREADY has (the
    # one the deploy path uses), applies it as helm would, and relies on P3 —
    # render the packaged artifact, require a digest on every image — as the
    # actual guarantee. P3 is positive evidence over the rendered output; the
    # table is a promise about the input. When they disagree, trust P3.
    #
    # The table mode is kept, not deleted: it is the only mode that can tell
    # you WHICH values path a given digest landed in, which the report needs
    # when a human is reconciling a pin by hand.
    if args.pins_values:
        return _platform_chart_from_overlay(args, src_chart, unpinnable)

    auto, explicit = parse_pin_set(pathlib.Path(args.pin_set).read_text())

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="vexa-platform-chart-"))
    chart_dir = workdir / src_chart.name
    shutil.copytree(src_chart, chart_dir)                     # source chart stays read-only
    pruned = prune_stale_subcharts(chart_dir)

    # merged view used ONLY to learn existing tags and to run the coverage
    # check: the chart's own defaults, the vendored subchart's defaults under
    # `vexa:`, then every deploy-time overlay the operator named.
    merged = yaml.safe_load((chart_dir / "values.yaml").read_text()) or {}
    sub_defaults = _subchart_defaults(chart_dir)
    if sub_defaults:
        merged = deep_merge({"vexa": sub_defaults}, merged)
    for f in args.values or []:
        deep_merge(merged, yaml.safe_load(pathlib.Path(f).read_text()) or {})

    overlay, mapping = resolve_platform_pins(auto, explicit, merged, unpinnable)

    # what this chart renders BEFORE any pin is applied — the ground truth for
    # the reverse-coverage check (P2) below.
    overlay_files = [pathlib.Path(f).resolve() for f in (args.values or [])]
    check_render_coverage(
        rendered_images(chart_dir, overlay_files),
        {repo for repo, _ in ([v for v in explicit.values()] + list(auto.items()))},
        unpinnable,
    )

    # The pins go in TWICE and that is deliberate: merged into values.yaml so a
    # bare `helm install <chart>` is pinned, and shipped as values-pins.yaml so
    # an operator who applies values-base.yaml (which sets vexa.global.imageTag)
    # has a LAST overlay that restores them. Helm's precedence is positional;
    # values.yaml alone cannot defend against a later -f.
    values_path = chart_dir / "values.yaml"
    values = yaml.safe_load(values_path.read_text()) or {}
    deep_merge(values, overlay)
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))
    pins_file = chart_dir / "values-pins.yaml"
    pins_file.write_text(
        "# Generated by vexa-channel platform-chart. APPLY LAST:\n"
        "#   helm upgrade ... -f values-base.yaml -f values-<env>.yaml -f values-pins.yaml\n"
        + yaml.safe_dump(overlay, sort_keys=False)
    )

    if not args.no_verify_gate:
        inject_channel_verify(chart_dir, values)
        values_path.write_text(yaml.safe_dump(values, sort_keys=False))

    cy = chart_dir / "Chart.yaml"
    cyd = yaml.safe_load(cy.read_text())
    # Same two-facts reasoning as cmd_chart: `version` is the CHART revision a
    # subscriber's targetRevision ranks, `appVersion` is the release it deploys.
    cyd["version"] = (args.chart_version or args.release).lstrip("v")
    cyd["appVersion"] = args.release.lstrip("v")
    cy.write_text(yaml.safe_dump(cyd, sort_keys=False))

    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    run(["helm", "package", str(chart_dir), "-d", str(out)])
    tgz = out / f"{cyd['name']}-{cyd['version']}.tgz"
    print(f"packaged {tgz}")

    # P3 — positive evidence, not a promise: render the packaged chart and
    # require every image it emits to carry a digest.
    # P3 renders the PACKAGED ARTIFACT, not the source tree: `helm package`
    # rewrites charts/, so the tree and the tgz are not the same chart.
    images = rendered_images(tgz, overlay_files + [pins_file])
    unpinned = [i for i in images if "@sha256:" not in i and ref_repo(i) not in unpinnable]
    if unpinned:
        raise CheckFailure("P3", "rendered chart still has un-pinned images: " + ", ".join(unpinned))

    report = {
        "chart": cyd["name"],
        "version": cyd["version"],
        "app_version": cyd["appVersion"],
        "pin_source": str(pathlib.Path(args.pin_set).resolve()),
        "mapping": mapping,
        "unpinnable": unpinnable,
        "pruned_subchart_archives": pruned,
        "rendered_images": images,
    }
    (out / f"platform-pins-{cyd['version']}.json").write_text(json.dumps(report, indent=1))
    (out / f"platform-pins-{cyd['version']}.yaml").write_text(pins_file.read_text())
    for line in images:
        print(f"  rendered {line}")

    if args.push:
        cmd = ["helm", "push", str(tgz), args.push]
        if args.insecure:
            cmd.insert(2, "--insecure-skip-tls-verify")
        r = run(cmd)
        line = next((ln for ln in (r.stdout + r.stderr).splitlines() if "Digest:" in ln), "")
        digest = line.split("Digest:")[-1].strip() if line else None
        print(f"pushed chart to {args.push} digest {digest}")
        (out / "chart-info.json").write_text(json.dumps(
            {"oci_ref": f"{args.push.removeprefix('oci://')}/{cyd['name']}", "digest": digest,
             "version": cyd["version"], "app_version": cyd["appVersion"]}, indent=1))
    return 0


def _subchart_defaults(chart_dir):
    """Defaults of the vendored `vexa` subchart, so tag lookup under `vexa.*`
    sees what helm will see. Read from charts/vexa-<version>.tgz."""
    import tarfile
    import tempfile
    import yaml

    cy = yaml.safe_load((chart_dir / "Chart.yaml").read_text()) or {}
    want = next((d.get("version") for d in (cy.get("dependencies") or []) if d.get("name") == "vexa"), None)
    tgz = chart_dir / "charts" / f"vexa-{want}.tgz"
    if not tgz.is_file():
        return None
    with tempfile.TemporaryDirectory() as td:
        with tarfile.open(tgz) as tf:
            member = next((m for m in tf.getmembers() if m.name.endswith("vexa/values.yaml")), None)
            if not member:
                return None
            tf.extract(member, td, filter="data")
            return yaml.safe_load(pathlib.Path(td, member.name).read_text()) or {}



# ---------------------------------------- platform ESTATE entry (vexa-internal)
#
# WHY cmd_build CANNOT DO THIS. `build` takes its identity from a Vexa-ai/vexa
# release tag: it reads the tag object, the frozen candidate map committed at
# that tag, the GitHub release source archive and its SLSA provenance bundle.
# Every check C1-C6 is a statement about that release.
#
# The vexa-internal channel does not carry a Vexa OSS release. It carries the
# PRODUCTION ESTATE: a proprietary chart in a different repository, two charts
# that until 2026-08-25 existed only inside live Helm release payloads, a
# third-party monitoring chart pinned by values, and a set of additional
# manifests. There is no tag, no archive, no provenance bundle — and there is
# no honest way to synthesize one. Passing `build` a fabricated archive to get
# past C6 would make the entry assert a provenance claim that is false.
#
# So this verb builds the same SCHEMA from a different, declared identity: a
# commit in the platform repository plus the live cluster revision the pins
# were captured from. What it gives up relative to `build` it says out loud in
# `evidence_absent`, rather than leaving the reader to infer it.
#
# THE ONE RULE THIS VERB ENFORCES THAT `build` DOES NOT: an estate entry must
# name a VALIDATION CONTRACT. A platform estate is validated against
# dependencies it does not own — a database, a payment processor, a
# transcription tier. "It came up green" is meaningless without saying what it
# came up against. See spec/validation-contract.schema.json.


def _estate_images(spec):
    """Images, from the estate spec. Each row carries its own provenance: the
    values path that pins it and the live evidence it was read from."""
    rows = []
    for i in spec["images"]:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", i["digest"]):
            raise CheckFailure("E2", f"{i['name']}: digest is not sha256:<64 hex>: {i['digest']!r}")
        row = {
            "name": i["name"],
            "class": i.get("class", "prod_deployed"),
            "index_digest": i["digest"],
            "platforms": i.get("platforms") or ["linux/amd64"],
            "source_sha": spec["source"]["commit"],
            "validation_receipts": [{"kind": "prod", "receipt": i["receipt"]}],
        }
        if i.get("values_path"):
            row["values_path"] = i["values_path"]
        if i.get("mirrored_to"):
            row["mirrored_to"] = i["mirrored_to"]
        rows.append(row)
    return rows


def cmd_platform_entry(args):
    import yaml

    spec = yaml.safe_load(pathlib.Path(args.spec).read_text())
    out = pathlib.Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"refusing to build into non-empty {out}")
    ev = out / "evidence"
    ev.mkdir(parents=True, exist_ok=True)

    # E1 — the validation contract is mandatory and must be a real file whose
    # hash goes into the signed entry. A contract referenced by name only is a
    # promise; a contract referenced by hash is a claim you can check.
    contract_path = pathlib.Path(args.validation_contract)
    if not contract_path.is_file():
        raise CheckFailure("E1", f"validation contract not found: {contract_path}")
    contract = yaml.safe_load(contract_path.read_text())
    for dep in contract.get("dependencies") or []:
        if not dep.get("fidelity", "").startswith("real") and not dep.get("justification"):
            raise CheckFailure(
                "E1",
                f"dependency {dep.get('id')!r} has fidelity {dep.get('fidelity')!r} and no justification. "
                "The rule is REAL BY DEFAULT: a double is permitted only where real is "
                "impossible or harmful, and it must say which. An unjustifiable double "
                "is a contract violation.",
            )
    shutil.copy(contract_path, ev / contract_path.name)
    contract_row = evidence_row(
        contract_path.name, "validation_contract", ev / contract_path.name, "application/yaml",
        f"validation contract {contract.get('id')} — declares, per external dependency, "
        f"what stood in during validation and what that fidelity does and does not prove",
    )

    evidence_rows = [contract_row]
    for spec3 in (args.extra_evidence or []):
        e_kind, e_name, e_path = spec3.split("=", 2)
        shutil.copy(e_path, ev / e_name)
        evidence_rows.append(evidence_row(
            e_name, e_kind if e_kind in (
                "candidate_map", "delivery_receipt", "source_provenance", "trusted_root",
                "readiness", "storm", "witness", "soak", "security_hardening", "sbom",
            ) else "other",
            ev / e_name,
            {"json": "application/json", "md": "text/markdown", "txt": "text/plain",
             "yaml": "application/yaml", "yml": "application/yaml",
             "jsonl": "application/jsonl"}.get(e_name.rsplit(".", 1)[-1].lower(),
                                               "application/octet-stream"),
            f"attached evidence ({e_kind})",
        ))

    src = spec["source"]
    entry = {
        "schema_version": 1,
        "channel": {
            "name": args.channel,
            "entry_seq": args.entry_seq,
            "supersedes": None if args.supersedes in (None, "none") else args.supersedes,
        },
        "release": {
            "version": args.release,
            "source_sha": src["commit"],
            "tag_object_sha": src["commit"],
            "release_url": src["repo_url"],
        },
        # The schema's `source` block was written for a GitHub release archive.
        # An estate has no archive. Rather than leave the required fields empty
        # or invent a tarball, this states what the estate IS: a repository
        # commit, identified by that commit, with the provenance predicate
        # NAMED AS ABSENT. The evidence_absent rows below carry the same fact
        # in the place a reader looks for it.
        "source": {
            "archive_name": src["archive_name"],
            "archive_sha256": src["archive_sha256"],
            "provenance_predicate": src.get("provenance_predicate") or "none",
            "certificate_oidc_issuer": src.get("certificate_oidc_issuer") or "none",
            "certificate_identity_pattern": src.get("certificate_identity_pattern") or "none",
        },
        "images": _estate_images(spec),
        "evidence": evidence_rows,
        "evidence_absent": spec["evidence_absent"],
        "prod_soak": spec.get("prod_soak"),
        "chart": None,
        "break_glass": None,
        "signing": {"mode": args.signing_mode, "identity": args.identity,
                    "note": args.signing_note},
        "publication": {"mode": args.publication_mode, "published_at": utcnow(),
                        "publisher": args.publisher},
        "expires": utcplus(args.expires_days or DEFAULT_EXPIRES_DAYS),
    }
    if args.approved_by:
        entry["publication"]["approved_by"] = args.approved_by
    if args.approval_receipt:
        entry["publication"]["approval_receipt"] = args.approval_receipt

    # An estate is MORE THAN ONE CHART, which the schema's singular `chart`
    # cannot express. The primary chart goes in `chart` so existing consumers
    # (kit, Argo bootstrap) keep working unchanged; the full set goes in
    # `estate`, which is additive. A consumer that does not know about
    # `estate` installs the platform chart and nothing else — degraded, but
    # not wrong. That is the intended failure mode.
    charts = spec["charts"]
    primary = next(c for c in charts if c.get("primary"))
    entry["chart"] = {"oci_ref": primary["oci_ref"], "digest": primary["digest"],
                      "version": primary["version"]}
    entry["estate"] = {
        "kind": "platform_estate",
        "release_name": spec["release_name"],
        "charts": charts,
        "additional_manifests": spec.get("additional_manifests") or [],
        "validation_contract": {
            "id": contract["id"],
            "sha256": sha256_file(contract_path),
            "file": contract_path.name,
        },
        "secrets_required": spec.get("secrets_required") or [],
        # Holes the publisher KNOWS about, carried in the signed entry rather
        # than in a wiki nobody reads. A subscriber pulling this entry gets the
        # list of things we already know do not work, before they find out.
        # An entry with no known_holes is claiming there are none.
        "known_holes": spec.get("known_holes") or [],
        "captured_from": spec["captured_from"],
    }

    schema_validate(entry)  # E3

    (out / "entry.json").write_text(json.dumps(entry, indent=1, sort_keys=False) + "\n")
    write_verify_md(out, entry)
    print(f"built platform-estate entry: {out}/entry.json")
    print(f"  E1 validation contract {contract['id']} sha256 {sha256_file(contract_path)[:16]}…")
    print(f"  E2 {len(entry['images'])} images, all digest-pinned")
    print(f"  charts: {', '.join(c['name'] for c in charts)}")
    print(f"  absent (declared): {', '.join(a['kind'] for a in entry['evidence_absent'])}")
    return 0


def cmd_sign_images(args):
    candidate_map = json.loads(pathlib.Path(args.candidate_map).read_text())
    major, full = require_pinned_cosign()                                  # T1
    flags = cosign_offline_flags()
    print(f"signing with cosign {full} ({cosign_bin()}); offline flags: {' '.join(flags)}")

    env = cosign_env()
    signing_env = dict(env)
    if args.signature_repository:
        signing_env["COSIGN_REPOSITORY"] = args.signature_repository
    pubkey = derive_public_key(args.key, env)

    images = sorted(candidate_map.get("images", {}).items())
    failures, unreadable, signed = [], [], []
    for name, m in images:
        ref = f"docker.io/{name}@{m['digest']}"
        cmd = [cosign_bin(), "sign", "--yes", "--key", args.key, *flags, *cosign_registry_auth()]
        if args.insecure:
            cmd.append("--allow-insecure-registry")
        cmd.append(ref)
        r = subprocess.run(cmd, capture_output=True, text=True, env=signing_env)
        if r.returncode != 0:
            failures.append(name)
            print(f"FAILED {name}: {r.stderr.strip()[-200:]}", file=sys.stderr)
            continue
        # T2 — assert it landed in the shape admission will look for, now,
        # beside the push, where it cannot be skipped or forgotten.
        try:
            found = check_kyverno_readable(ref, m["digest"], args.signature_repository,
                                           pubkey, env, insecure=args.insecure)
        except CheckFailure as e:
            unreadable.append(name)
            print(f"REFUSED {name}: {e}", file=sys.stderr)
            continue
        signed.append({"name": name, "digest": m["digest"], **found})
        print(f"signed {name}@{m['digest'][:19]}… -> {found['tag']} (Kyverno-readable)")

    if failures or unreadable:
        if failures:
            print(f"sign-images failed for: {failures}", file=sys.stderr)
        if unreadable:
            print(f"signatures NOT discoverable the way Kyverno 1.19 looks: {unreadable}", file=sys.stderr)
        return 5

    record = signing_run_record(full, flags, signature_repository=args.signature_repository,
                                images=signed)
    if args.receipt:
        pathlib.Path(args.receipt).write_text(json.dumps(record, indent=1) + "\n")
        print(f"signing-run receipt -> {args.receipt}")
    print(f"all {len(images)} image digests signed and verified Kyverno-style")
    return 0




# ------------------------------------------------------------- attestations

ATTEST_KINDS = {
    "prod-soak": {
        "predicate_type": "https://vexa.ai/attestations/prod-soak/v1",
        "schema": "prod-soak-attestation.schema.json",
        "definitions_doc": "prod-soak-metrics.v1",
        "definitions_file": "definitions/prod-soak-metrics.v1.md",
        "evidence_kind": "soak",
    },
    "security-hardening": {
        "predicate_type": "https://vexa.ai/attestations/security-hardening/v1",
        "schema": "security-hardening-attestation.schema.json",
        "definitions_doc": "security-hardening.v1",
        "definitions_file": "definitions/security-hardening.v1.md",
        "evidence_kind": "security_hardening",
    },
    "station-verdict": {
        "predicate_type": "https://vexa.ai/attestations/station-verdict/v1",
        "schema": "station-verdict-attestation.schema.json",
        "definitions_doc": None,
        "definitions_file": None,
        "evidence_kind": "other",
    },
}


def check_soak_consistency(predicate):
    """A10 — the derived numbers must equal what the sealed definition computes
    from the raw counts; an attestation carrying an inconsistent rate is
    refused, never repaired."""
    for platform, m in predicate.get("platforms", {}).items():
        n = m["meetings_dispatched"]
        want_rate = round(1 - m["software_failures"] / n, 6)
        if abs(m["software_success_rate"] - want_rate) > 1e-6:
            raise CheckFailure(
                "A10",
                f"{platform}: software_success_rate {m['software_success_rate']} != computed {want_rate}",
            )
        want_cr = round(m["completed"] / n, 6)
        if abs(m["completion_rate"] - want_cr) > 1e-6:
            raise CheckFailure("A10", f"{platform}: completion_rate {m['completion_rate']} != computed {want_cr}")
        er = m.get("exit_reasons")
        if er is not None:
            if sum(er.values()) != n:
                raise CheckFailure("A10", f"{platform}: exit_reasons sum {sum(er.values())} != dispatched {n}")
            sw = er.get("JOIN_FAILURE", 0) + er.get("AUTH_SESSION_MISSING", 0)
            if sw != m["software_failures"]:
                raise CheckFailure("A10", f"{platform}: software_failures {m['software_failures']} != taxonomy count {sw}")


def check_hardening_consistency(predicate):
    f = predicate["findings"]
    for sev in ("critical", "high", "medium", "low"):
        if f["fixed"][sev] > f["confirmed"][sev]:
            raise CheckFailure("A10", f"findings.fixed.{sev} exceeds confirmed")
        if f["open"][sev] != f["confirmed"][sev] - f["fixed"][sev]:
            raise CheckFailure("A10", f"findings.open.{sev} != confirmed - fixed")


def cmd_attest(args):
    import jsonschema

    kind = ATTEST_KINDS[args.kind]
    spec_dir = pathlib.Path(__file__).resolve().parent.parent / "spec"

    tag_object, source_sha, map_bytes = read_tag(args.vexa_repo, args.release)
    candidate_map = json.loads(map_bytes)
    check_map_identity(args.release, candidate_map)
    subjects = [
        {"name": name, "digest": {"sha256": m["digest"].removeprefix("sha256:")}}
        for name, m in sorted(candidate_map["images"].items())
    ]

    predicate = json.loads(pathlib.Path(args.metrics).read_text())
    predicate["release"] = args.release
    if kind["definitions_file"]:
        defs_path = spec_dir / kind["definitions_file"]
        predicate["definitions"] = {
            "document": kind["definitions_doc"],
            "sha256": sha256_file(defs_path),
        }

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": kind["predicate_type"],
        "predicate": predicate,
    }

    schema = json.loads((spec_dir / kind["schema"]).read_text())
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(statement),
        key=lambda e: list(e.absolute_path),
    )
    if errors:
        locs = "; ".join(
            f"{'/'.join(str(x) for x in e.absolute_path) or '(root)'}: {e.message}" for e in errors[:4]
        )
        raise CheckFailure("A9", f"attestation does not validate: {locs}")

    if args.kind == "prod-soak":
        check_soak_consistency(predicate)
    elif args.kind == "security-hardening":
        check_hardening_consistency(predicate)

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    name = f"{args.kind}.{args.release}.intoto.json"
    stmt_path = out / name
    stmt_path.write_text(json.dumps(statement, indent=1, sort_keys=False) + "\n")

    # Same unpinned-toolchain class as the image/entry signatures, and worse:
    # this path passed NO offline flags at all, so an attestation's bundle format
    # and transparency-log posture were whatever the ambient cosign happened to
    # default to that day.
    _, full = require_pinned_cosign()                                      # T1
    flags = cosign_offline_flags()
    print(f"signing attestation with cosign {full}; offline flags: {' '.join(flags)}")
    run([cosign_bin(), "sign-blob", "--yes", "--key", args.key, *flags,
         "--bundle", str(out / f"{name}.sigstore.json"), str(stmt_path)],
        env=cosign_env())
    if args.push:
        plain = ["--insecure"] if args.insecure else []
        tag = f"{args.kind}.{args.release}"
        run(["oras", "push", *plain, "--artifact-type",
             "application/vnd.vexa.attestation.v1+json",
             f"{args.push}/attestations:{tag}",
             stmt_path.name, f"{stmt_path.name}.sigstore.json"], cwd=str(out))
        print(f"pushed attestation {args.push}/attestations:{tag}")

    print(f"attested {args.kind} for {args.release}: {stmt_path}")
    if kind["definitions_file"]:
        print(f"  definitions {kind['definitions_doc']} sha256:{predicate['definitions']['sha256'][:12]}…")
    print(f"  add to an entry with: --extra-evidence {kind['evidence_kind']}={name}={stmt_path} "
          f"--extra-evidence {kind['evidence_kind']}_signature={name}.sigstore.json={out / (name + '.sigstore.json')}")
    return 0


# ----------------------------------------------------------------------- cli


def main(argv=None):
    p = argparse.ArgumentParser(prog="vexa-channel", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="fetch archive + provenance + trusted root via gh")
    f.add_argument("--release", required=True)
    f.add_argument("--repo", default="Vexa-ai/vexa")
    f.add_argument("--out", required=True)

    b = sub.add_parser("build", help="assemble and cross-check a channel entry")
    b.add_argument("--release", required=True)
    b.add_argument("--channel", required=True)
    b.add_argument("--entry-seq", type=int, required=True)
    b.add_argument("--supersedes", default="none")
    b.add_argument("--vexa-repo", required=True)
    b.add_argument("--delivery-receipt")
    b.add_argument("--archive", required=True)
    b.add_argument("--provenance-bundle", required=True)
    b.add_argument("--trusted-root", required=True)
    b.add_argument("--chart-ref")
    b.add_argument("--chart-digest")
    b.add_argument("--chart-version")
    b.add_argument("--identity", required=True, help="signing identity the entry declares")
    b.add_argument("--signing-mode", choices=["test_key", "cosign_key", "cosign_keyless"], required=True)
    b.add_argument("--signing-note", default="see docs/adr/0002-channel-format.md")
    b.add_argument("--publication-mode", choices=["dry_run", "candidate", "published"], default="dry_run")
    b.add_argument("--publisher", default="vexa-delivery publisher CLI")
    b.add_argument("--approved-by", help="the named human approving publication (required for --publication-mode published)")
    b.add_argument("--approval-receipt", help="where that approval is recorded")
    b.add_argument("--break-glass", help="actor=..,reason=..,approved_by=..,receipt=..")
    b.add_argument("--extra-evidence", action="append",
                   help="kind=filename=path, repeatable — e.g. soak=prod-soak.v0.12.24.intoto.json=/path")
    b.add_argument("--skip-cosign-verify", action="store_true")
    b.add_argument("--expires-days", type=int, default=DEFAULT_EXPIRES_DAYS,
                   help=f"freshness horizon in days (default {DEFAULT_EXPIRES_DAYS}). The entry "
                        f"declares it, every verifier refuses it afterwards, and `refresh` "
                        f"extends it without a version bump.")
    b.add_argument("--out", required=True)

    v = sub.add_parser("verify", help="offline verification of a built entry")
    v.add_argument("--entry", required=True)
    v.add_argument("--archive")
    v.add_argument("--pubkey")

    u = sub.add_parser("push", help="push entry to OCI registry, sign, move channel tag")
    u.add_argument("--entry", required=True)
    u.add_argument("--ref", required=True, help="repository ref without tag, e.g. host/base/channel/enterprise-stable")
    u.add_argument("--channel-tag", help="floating tag to move, e.g. `current`. A full ref "
                   "(host/base/channel/x:current) is accepted and normalised to its tag.")
    u.add_argument("--sign-key")
    u.add_argument("--skip-sign-artifact", action="store_true")
    u.add_argument("--plain-http", action="store_true")
    u.add_argument("--insecure", action="store_true", help="registry TLS is self-signed (test rigs)")
    u.add_argument("--signing-receipt", help="write the signing-run record (cosign version, flags, layout) as JSON")
    u.add_argument("--ledger", help="checkout of the vexa-stations ledger; on a successful push "
                   "the entry is reduced into channels/<channel>/channel.yaml, which is the "
                   "AUTHORITY for entry_seq (the copy in the bucket is derived). "
                   "Defaults to $VEXA_STATIONS_DIR.")


    ch = sub.add_parser("chart", help="package the OSS chart with digest pins baked; optionally push OCI")
    ch.add_argument("--release", required=True)
    ch.add_argument("--vexa-repo", required=True)
    ch.add_argument("--baseline", help="node-baseline values merged after the pins")
    ch.add_argument("--chart-version", help="chart revision (Chart.yaml version); appVersion stays the release. Default: the release version, the pre-2026-08-24 behaviour")
    ch.add_argument("--out-dir", required=True)
    ch.add_argument("--push", help="oci://host/path/charts destination")
    ch.add_argument("--insecure", action="store_true")

    rf = sub.add_parser("refresh", help="re-stamp an entry's expiry: same release, next seq, new horizon")
    rf.add_argument("--entry", required=True, help="a built entry directory")
    rf.add_argument("--out", required=True)
    rf.add_argument("--expires-days", type=int, default=DEFAULT_EXPIRES_DAYS)
    rf.add_argument("--entry-seq", type=int, help="default: the refreshed entry's seq + 1")
    rf.add_argument("--publisher")

    rv = sub.add_parser("revoke", help="append to (or start, or re-publish) the channel's signed revocation list")
    rv.add_argument("--ref", required=True, help="channel base ref, e.g. host/vexa/channel/pilot-stable")
    rv.add_argument("--channel", required=True, help="channel name the list governs")
    rv.add_argument("--version", help="release to withdraw, e.g. v0.12.23")
    rv.add_argument("--digest", help="exact artifact/image digest to withdraw")
    rv.add_argument("--reason", help="what an operator reads when their sync stops")
    rv.add_argument("--severity", choices=["low", "medium", "high", "critical"], default="high")
    rv.add_argument("--supersedes", help="the release to move to instead, if one exists")
    rv.add_argument("--advisory", help="link to the fuller writeup")
    rv.add_argument("--expires-days", type=int, default=DEFAULT_REVOCATIONS_EXPIRES_DAYS)
    rv.add_argument("--key", help="cosign key; the list is signed with the channel key")
    rv.add_argument("--unsigned", action="store_true", help="local fixtures only")
    rv.add_argument("--dry-run", action="store_true", help="write the list, publish nothing")
    rv.add_argument("--out", help="where --dry-run writes")
    rv.add_argument("--plain-http", action="store_true")
    rv.add_argument("--insecure", action="store_true")
    pc = sub.add_parser("platform-chart", help="package the proprietary vexa-platform chart with cluster-captured digest pins baked; optionally push OCI")
    pc.add_argument("--release", required=True, help="the platform release this chart deploys (Chart.yaml appVersion)")
    pc.add_argument("--chart-dir", required=True, help="path to chart/vexa-platform (read-only; copied before edit)")
    pc.add_argument("--pin-set", help="newline-delimited repo@sha256:... refs (or <values.path>=repo@sha256:...)")
    pc.add_argument("--values", action="append", help="deploy-time overlay this chart is rendered with (repeatable, in order)")
    pc.add_argument("--pins-values", action="append", help="OVERLAY MODE: bake these values files in as the pins and rely on P3, instead of mapping a --pin-set through PLATFORM_IMAGE_PATHS (repeatable, in order)")
    pc.add_argument("--unpinnable", action="append", metavar="REPO=REASON", help="declare an image that cannot be pinned through values, with the reason; recorded in the report")
    pc.add_argument("--chart-version", help="chart revision (Chart.yaml version); appVersion stays the release")
    pc.add_argument("--out-dir", required=True)
    pc.add_argument("--push", help="oci://host/path/charts destination")
    pc.add_argument("--insecure", action="store_true")
    pc.add_argument("--no-verify-gate", action="store_true",
                    help="do NOT inject the PreSync verify template. An estate packaged this "
                         "way reaches Argo CD with no signature, contract, revocation or "
                         "approval check at sync time — it exists for reproducing a chart "
                         "published before 2026-08-25, and for nothing else.")

    pe = sub.add_parser("platform-entry", help="build a channel entry for a PLATFORM ESTATE (multi-chart, no OSS release tag); requires a validation contract")
    pe.add_argument("--spec", required=True, help="YAML describing the estate: source commit, charts, images, absences")
    pe.add_argument("--validation-contract", required=True, help="the validation contract this estate was proven against; hashed into the entry")
    pe.add_argument("--release", required=True)
    pe.add_argument("--channel", required=True)
    pe.add_argument("--entry-seq", type=int, required=True)
    pe.add_argument("--supersedes")
    pe.add_argument("--identity", required=True)
    pe.add_argument("--signing-mode", choices=["test_key", "cosign_key", "cosign_keyless"], required=True)
    pe.add_argument("--signing-note", default="")
    pe.add_argument("--publication-mode", choices=["dry_run", "candidate", "published"], default="candidate")
    pe.add_argument("--publisher")
    pe.add_argument("--approved-by")
    pe.add_argument("--approval-receipt")
    pe.add_argument("--extra-evidence", action="append")
    pe.add_argument("--expires-days", type=int, default=DEFAULT_EXPIRES_DAYS)
    pe.add_argument("--out", required=True)

    si = sub.add_parser("sign-images", help="cosign-sign every candidate-map digest into the channel signature repo")
    si.add_argument("--candidate-map", required=True)
    si.add_argument("--key", required=True)
    si.add_argument("--signature-repository", help="flat COSIGN_REPOSITORY for all signatures")
    si.add_argument("--receipt", help="write the signing-run record (cosign version, flags, per-image signature tags) as JSON")
    si.add_argument("--insecure", action="store_true")


    at = sub.add_parser("attest", help="build + sign a structured attestation (in-toto statement) over the release digests")
    at.add_argument("--kind", choices=list(ATTEST_KINDS), required=True)
    at.add_argument("--release", required=True)
    at.add_argument("--vexa-repo", required=True)
    at.add_argument("--metrics", required=True, help="JSON file with the predicate's measured fields")
    at.add_argument("--key", required=True)
    at.add_argument("--out", required=True)
    at.add_argument("--push", help="channel base ref; attestation lands at <ref>/attestations:<kind>.<release>")
    at.add_argument("--insecure", action="store_true")

    args = p.parse_args(argv)
    try:
        return {"fetch": cmd_fetch, "build": cmd_build, "verify": cmd_verify, "push": cmd_push,
                "chart": cmd_chart, "platform-chart": cmd_platform_chart, "platform-entry": cmd_platform_entry,
                "sign-images": cmd_sign_images, "attest": cmd_attest,
                "refresh": cmd_refresh, "revoke": cmd_revoke}[args.cmd](args)
    except CheckFailure as e:
        print(f"REFUSED {e}", file=sys.stderr)
        return 3
    except subprocess.CalledProcessError as e:
        print(f"command failed: {e.cmd}\n{(e.stderr or '')[-800:]}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
