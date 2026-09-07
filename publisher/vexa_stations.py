#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-stations — the reducer that writes the channel/station ledger.

The bucket behind `channel.vexa.ai` is a DISTRIBUTION copy. This module writes
the thing it is a copy of: a git repository (a private repository) that
holds, per channel, what has been published and where every station stands.

    channels/<channel>/channel.yaml                 last entry_seq, current
                                                    position, pin map, expiry
    channels/<channel>/stations/<station>/state.yaml   subscribed position,
                                                    last receipt, flags
    channels/<channel>/stations/<station>/receipts/     ingested bundles verbatim

**Git history IS the audit trail.** Every reducer call is one commit, made BY
PATHSPEC, naming what moved. There is no separate log to keep in sync, and
nothing here is a cache of the bucket: after this, `entry_seq` authority lives
in `channel.yaml` and the copy inside the published entry is derived.

**One writer per surface**, which is the whole design and the only rule that
matters when two operators run at once:

  - `vexa_channel.py push`  is the sole writer of `channel.yaml`
  - `vexa_station.py ingest` is the sole writer of `stations/<station>/*`

A surface with two writers does not error. It produces a plausible result and
loses one writer's intent, which is why the split is enforced here rather than
left to convention: `record_publish` refuses to touch a station directory and
`record_ingest` refuses to touch `channel.yaml`.

The one fact that legitimately appears on both sides is a station's position,
and it appears as TWO DIFFERENT FACTS. `channel.yaml`'s `pins:` is the
publisher's intent — what we promoted this station to, moved by a human's pin
commit. `state.yaml`'s `subscribed_position` is the observation — what the
station's own bundle said it was following when it last reported. A divergence
between them is a finding, not a bug: it means a promotion did not land, or a
station moved itself.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not logic
    print("vexa-stations needs PyYAML (pip install pyyaml)", file=sys.stderr)
    raise

SCHEMA_VERSION = 1
# A station is considered stale when it has not reported against the newest
# entry on its channel, or has not reported at all in this many days. Both are
# "we do not know that this customer is on a release we would stand behind".
STALE_AFTER_DAYS = 30

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


class LedgerError(Exception):
    pass


# ------------------------------------------------------------------ helpers


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_name(kind: str, value: str) -> str:
    """Path components come from entries and bundles — data, not our own
    constants. A channel called `../../etc` would otherwise write there."""
    if not value or not NAME_RE.match(value):
        raise LedgerError(f"unsafe {kind} name {value!r}: expected [a-z0-9][a-z0-9._-]*")
    return value


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_yaml(path: pathlib.Path) -> dict:
    if not path.is_file():
        return {}
    return yaml.safe_load(path.read_text()) or {}


class _NoAliasDumper(yaml.SafeDumper):
    """The same row legitimately appears twice — as `current` and as the last
    of `entries`. PyYAML would emit the second as an `*id001` alias, which is
    valid YAML and unreadable state: a reviewer cannot see what changed, and a
    later hand-edit of one silently edits the other."""

    def ignore_aliases(self, data):  # noqa: D102 - PyYAML hook
        return True


def write_yaml(path: pathlib.Path, header: str, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = yaml.dump(data, Dumper=_NoAliasDumper, sort_keys=False,
                     default_flow_style=False, width=88)
    path.write_text(header.rstrip("\n") + "\n\n" + body)


def git(root: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args],
                          capture_output=True, text=True, check=True)


def commit_paths(root: pathlib.Path, message: str, paths: list[pathlib.Path]) -> "str | None":
    """Commit exactly these paths and nothing else.

    `git add` then `git commit` commits THE INDEX, not what you just added. On
    2026-08-21 that swept 180 unrelated files from a concurrent agent into one
    commit in another repository. `git commit -- <paths>` is the one flag that
    makes the commit mean what its message says, and the ledger is written by
    tooling that may well be running twice at once.

    Returns the new commit sha, or None when the reducer was a no-op.
    """
    rel = [str(p.relative_to(root)) for p in paths]
    git(root, "add", "--", *rel)
    staged = git(root, "diff", "--cached", "--name-only", "--", *rel).stdout.strip()
    if not staged:
        return None
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", message, "--", *rel],
                   capture_output=True, text=True, check=True)
    # Read the result from the DIFF's own commit, never from a message match:
    # deciding "did my change land" by grepping log output reads a surface this
    # process does not own.
    return git(root, "rev-parse", "HEAD").stdout.strip()


def resolve_root(ledger: "str | pathlib.Path | None") -> pathlib.Path:
    import os

    raw = ledger or os.environ.get("VEXA_STATIONS_DIR")
    if not raw:
        raise LedgerError("no ledger checkout given: pass --ledger or set VEXA_STATIONS_DIR")
    root = pathlib.Path(raw).expanduser().resolve()
    if not (root / ".git").exists():
        raise LedgerError(f"{root} is not a git checkout — the ledger's history IS the audit trail")
    return root


def channel_file(root: pathlib.Path, channel: str) -> pathlib.Path:
    return root / "channels" / safe_name("channel", channel) / "channel.yaml"


def station_dir(root: pathlib.Path, channel: str, station: str) -> pathlib.Path:
    return (root / "channels" / safe_name("channel", channel)
            / "stations" / safe_name("station", station))


CHANNEL_HEADER = """\
# channel.yaml — WRITTEN ONLY BY `publisher/vexa_channel.py push`.
#
# This file is the AUTHORITY for this channel's entry sequence. The copy of
# `entry_seq` inside a published entry in the bucket is derived from it: lose
# the bucket and this file still says what was published, at which sequence,
# and where every station was pointed.
#
# `pins:` is the publisher's INTENT — what we promoted a station to. What the
# station is observed to be following lives in its own state.yaml and is
# written by ingest. A divergence between the two is a finding.
#
# Hand-edit only to move a pin (a promotion is a human act, justified by the
# dev station's receipt in its own commit message). Everything else is reduced."""

STATE_HEADER = """\
# state.yaml — WRITTEN ONLY BY `publisher/vexa_station.py ingest`.
#
# What this station last told us, reduced. `subscribed_position` is an
# OBSERVATION from the station's own bundle, not our intent — the intent is
# `pins:` in the channel's channel.yaml.
#
# flags: derived on every ingest, except `revoked`, which is a human's word
# and is preserved across reductions."""

CREDENTIAL_HEADER = """\
# credential-events.yaml — WRITTEN ONLY BY `record_credential_events`.
#
# Who parked a credential for this station, when, under which code hash, with
# what expiry — and every attempt the edge saw against it. NEVER the credential,
# never the code, never the ciphertext: the reducer refuses the whole batch if
# an event carries one, because it is the last thing standing between an
# internet-facing service's log and a git repository.
#
# A THIRD SURFACE IN THE STATION DIRECTORY, deliberately, and not an exception
# to the one-writer rule. `state.yaml` and `receipts/` are written only by
# ingest; this file is written only by the credential path. One file, one
# writer — the rule is about the surface, and the surface is the file.
#
# The two halves arrive by different routes and merge here by content: `park`
# from the publisher at mint time, `claim` from the edge's attempts log when an
# operator copies it back. Re-ingesting the same log is a no-op."""


# ---------------------------------------------------------- publish reducer


def entry_facts(entry: dict) -> dict:
    """The subset of a channel entry the ledger keeps. Everything here is read
    from the entry the publisher just pushed; nothing is inferred."""
    ch = entry.get("channel") or {}
    rel = entry.get("release") or {}
    chart = entry.get("chart") or {}
    pub = entry.get("publication") or {}
    seq = ch.get("entry_seq")
    if not isinstance(seq, int):
        raise LedgerError("entry has no integer channel.entry_seq — refusing to reduce it")
    return {
        "entry_seq": seq,
        "release": rel.get("version"),
        "source_sha": rel.get("source_sha"),
        "chart": ({"version": chart.get("version"), "digest": chart.get("digest")}
                  if chart else None),
        "publication_mode": pub.get("mode"),
        "published_at": pub.get("published_at"),
        "supersedes": ch.get("supersedes"),
        # Channel hardening (vexa-delivery-internal#37) gives entries an expiry. Entries predating it
        # carry none, and `null` here means "no expiry declared", never "fresh".
        "expires": entry.get("expires"),
    }


def record_publish(root: pathlib.Path, entry: dict, *, entry_digest: "str | None" = None,
                   registry_ref: "str | None" = None, channel_tag: "str | None" = None,
                   commit: bool = True, note: "str | None" = None) -> dict:
    """Reduce one published entry into channels/<channel>/channel.yaml."""
    channel = safe_name("channel", ((entry.get("channel") or {}).get("name") or ""))
    path = channel_file(root, channel)
    doc = load_yaml(path)
    facts = entry_facts(entry)
    seq = facts["entry_seq"]

    last = doc.get("last_entry_seq")
    if isinstance(last, int) and seq < last:
        raise LedgerError(
            f"entry_seq {seq} is below the ledger's {last} for channel '{channel}'. "
            "A puller refuses a sequence that does not advance; so does the ledger. "
            "Rebuild the entry at the right sequence rather than rewriting history."
        )

    row = dict(facts)
    row["entry_digest"] = entry_digest
    row["recorded_at"] = utcnow()
    if note:
        row["note"] = note

    entries = [e for e in (doc.get("entries") or []) if e.get("entry_seq") != seq]
    entries.append(row)
    entries.sort(key=lambda e: e.get("entry_seq") or 0)

    doc.update({
        "schema_version": SCHEMA_VERSION,
        "channel": channel,
        "registry_ref": registry_ref or doc.get("registry_ref"),
        "channel_tag": channel_tag or doc.get("channel_tag") or "current",
        "last_entry_seq": max(seq, last if isinstance(last, int) else seq),
        # `current` MIRRORS THE CHANNEL TAG, AND IS NOT A SYNONYM FOR "NEWEST".
        #
        # This used to be `"current": row` unconditionally, so publishing a
        # CANDIDATE — which by definition does not move the channel tag —
        # rewrote the ledger to claim the tag had moved. Caught publishing the
        # seq-3 estate candidate on 2026-08-25: the registry's `current` tag
        # pointed at seq 1 while this file said seq 3, and nothing errored.
        #
        # That is the worst shape a durability store can fail in. `channel.yaml`
        # exists so that losing the bucket does not lose the answer to "what
        # was published, and where was every station pointed"; a `current` that
        # silently means something other than the tag makes it answer that
        # question wrongly, confidently, and only for the case that matters —
        # recovery, when the registry is not there to check against.
        #
        # A push that moves the tag passes `channel_tag`. One that does not,
        # does not, and `current` stays where it is.
        "current": row if channel_tag else doc.get("current"),
        "entries": entries,
        # Pin map per station: the publisher's intent. Never invented here —
        # a station appears once someone promotes it, and `record_ingest`
        # seeds an entry as `unknown` rather than guessing.
        "pins": doc.get("pins") or {},
        # Expiry index: one row per entry that declared an expiry, so "what is
        # about to go stale on this channel" is a read, not a crawl.
        "expiry": [{"entry_seq": e["entry_seq"], "release": e.get("release"),
                    "expires": e.get("expires")}
                   for e in entries if e.get("expires")],
        "updated_at": utcnow(),
    })
    write_yaml(path, CHANNEL_HEADER, doc)

    sha = None
    if commit:
        sha = commit_paths(
            root,
            f"{channel}: publish entry seq {seq} ({facts['release']})\n\n"
            f"Reduced by publisher/vexa_channel.py push. entry digest "
            f"{entry_digest or 'unrecorded'}.\n\n<!-- vexa-agent -->",
            [path],
        )
    return {"channel": channel, "entry_seq": seq, "path": str(path), "commit": sha}


# ----------------------------------------------------------- ingest reducer


def _manifest_identity(manifest: dict) -> dict:
    """Bundle manifests exist in two shapes: the M1 one (customer/environment/
    kit_version/created_at) and the one kit/validate emits today (generated_at,
    kit{}, kubernetes{}, provider{}, namespaces{}). Read whichever is present
    instead of recording a row of nulls for the other."""
    kit = manifest.get("kit") or {}
    return {k: v for k, v in {
        "customer": manifest.get("customer"),
        "environment": manifest.get("environment"),
        "namespace": (manifest.get("namespaces") or {}).get("target"),
        "kubernetes": (manifest.get("kubernetes") or {}).get("server_version"),
        "provider": (manifest.get("provider") or {}).get("name"),
        "kit_version": manifest.get("kit_version") or kit.get("describe") or kit.get("commit"),
        "created_at": manifest.get("created_at") or manifest.get("generated_at"),
    }.items() if v is not None}


def _verdict_of(manifest: dict) -> str:
    """A bundle carries its own phase verdicts. Any non-PASS phase is the
    station's verdict — we report what it reported, and never upgrade it."""
    phases = manifest.get("phases") or {}
    seen = [p.get("verdict") for p in phases.values()
            if isinstance(p, dict) and p.get("verdict")]
    if not seen:
        return "UNKNOWN"
    return "PASS" if all(v == "PASS" for v in seen) else "REFUSED"


def _release_of(manifest: dict) -> dict:
    """The station report's own `release` block, reduced to the identity fields.

    The report ALREADY carries what it is running — `entry_seq`, `entry_digest`,
    `chart_version`, `chart_digest`, and `pin` where Argo was readable. Until
    2026-09-07 the reducer read none of it: a bundle whose report said
    `entry_seq: 5, chart_version: 0.12.36` was reduced to
    `subscribed_position: unknown` and `entry_seq: null`, so `stale` could not
    fire for it and the ledger held less than the bundle it had just stored.
    """
    rel = manifest.get("release") or {}
    return {k: v for k, v in {
        "entry_seq": rel.get("entry_seq"),
        "entry_digest": rel.get("entry_digest"),
        "chart_version": rel.get("chart_version"),
        "chart_digest": rel.get("chart_digest"),
        "pin": rel.get("pin"),
    }.items() if v is not None}


def _position_of(manifest: dict, values_text: str) -> str:
    """What the station says it is following, read from what it actually sent.

    Four sources, most specific first, and each one is something the station
    ASSERTED rather than something we assumed:

      1. `release.pin` — the Application's own position, read off the cluster by
         the report generator. This is the answer when there is one.
      2. `targetRevision` in the values the operator handed us with the bundle.
      3. `release.chart_version` — the chart revision the subscription actually
         resolved to. A station following `*` has no pin to state, and this is
         the number `channel.yaml`'s `pins:` are written in, so it is directly
         comparable with our intent.
      4. `release.entry_seq`, spelled `seq N` so nobody reads a sequence as a
         chart version.

    Only when the report asserts none of those is it `unknown` — which stays the
    honest value, never an assumed `*`.
    """
    rel = manifest.get("release") or {}
    if rel.get("pin"):
        return str(rel["pin"])
    m = re.search(r"targetRevision:\s*[\"']?([^\s\"']+)", values_text or "")
    if m:
        return m.group(1)
    if rel.get("chart_version"):
        return str(rel["chart_version"])
    if isinstance(rel.get("entry_seq"), int):
        return f"seq {rel['entry_seq']}"
    return manifest.get("position") or "unknown"


def derive_flags(state: dict, channel_doc: dict, *, now: "datetime.datetime | None" = None) -> list:
    """stale and contract-breach are DERIVED on every ingest. `revoked` is a
    human's word about a credential and is preserved, never recomputed."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    flags = []
    receipt = state.get("last_receipt") or {}
    latest = channel_doc.get("last_entry_seq")
    seq = receipt.get("entry_seq")
    if isinstance(latest, int) and isinstance(seq, int) and seq < latest:
        flags.append("stale")
    elif receipt.get("ts"):
        try:
            ts = datetime.datetime.fromisoformat(receipt["ts"].replace("Z", "+00:00"))
            if (now - ts).days > STALE_AFTER_DAYS:
                flags.append("stale")
        except ValueError:
            pass
    if receipt.get("verdict") not in (None, "PASS"):
        flags.append("contract-breach")
    if "revoked" in (state.get("flags") or []):
        flags.append("revoked")
    return flags


def record_ingest(root: pathlib.Path, *, channel: str, station: str, receipt: dict,
                  manifest: dict, bundle: "pathlib.Path | None" = None,
                  values_text: str = "", commit: bool = True) -> dict:
    """Reduce one ingested station bundle into stations/<station>/."""
    channel = safe_name("channel", channel)
    station = safe_name("station", station)
    sdir = station_dir(root, channel, station)
    channel_doc = load_yaml(channel_file(root, channel))

    stamp = (receipt.get("ingested_at") or utcnow()).replace(":", "").replace("-", "")
    rdir = sdir / "receipts" / stamp
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "ingest-receipt.json").write_text(json.dumps(receipt, indent=1) + "\n")
    (rdir / "station.json").write_text(json.dumps(manifest, indent=1) + "\n")
    if bundle is not None and bundle.is_file():
        # The bundle verbatim. It is the only thing here we did not write, so
        # it is the only thing that can settle an argument about what the
        # customer actually sent. S4 has already refused it if it carried a
        # plaintext credential.
        shutil.copy2(bundle, rdir / bundle.name)

    state = load_yaml(sdir / "state.yaml")
    # NOT defaulted to the channel's newest sequence. A bundle that does not say
    # which entry it is running is telling us we do not know, and writing the
    # newest in its place would make `stale` unable to fire for exactly the
    # stations we are least sure about. `null` is the honest value.
    #
    # But the REPORT is the station saying it, not us assuming it: when the
    # ingest receipt carries no sequence and `release.entry_seq` does, that is
    # the station's own claim about which entry it is running and it belongs in
    # the ledger. Reading neither is how a report asserting seq 5 was reduced to
    # `entry_seq: null` on 2026-09-07.
    release = _release_of(manifest)
    entry_seq = receipt.get("entry_seq")
    if entry_seq is None:
        entry_seq = release.get("entry_seq")
    # THE CROSS-CHECK (vexa-delivery#47 item 2, the reducer's half). Two sources
    # for one fact must be compared, not silently ranked. A disagreement means
    # the bundle and the gate that accepted it describe different releases, and
    # that is a finding about the submission rather than a number to pick from.
    mismatch = []
    for field in ("entry_seq", "entry_digest"):
        theirs, ours = release.get(field), receipt.get(field)
        if theirs is not None and ours is not None and theirs != ours:
            mismatch.append(f"{field}: report says {theirs}, ingest receipt says {ours}")
    state.update({
        "schema_version": SCHEMA_VERSION,
        "station": station,
        "channel": channel,
        "identity": _manifest_identity(manifest),
        "contract": manifest.get("contract") or state.get("contract"),
        "subscribed_position": _position_of(manifest, values_text),
        # What the report says is RUNNING, kept beside what it says it FOLLOWS.
        # They are different facts and the ledger held neither.
        "release": release or state.get("release"),
        "last_receipt": {
            "entry_seq": entry_seq,
            "ts": receipt.get("ingested_at") or utcnow(),
            "verdict": receipt.get("verdict") or _verdict_of(manifest),
            "bundle": receipt.get("bundle"),
            "bundle_sha256": receipt.get("bundle_sha256"),
            "path": str((rdir / "ingest-receipt.json").relative_to(sdir)),
        },
    })
    if mismatch:
        state["last_receipt"]["entry_mismatch"] = mismatch
    state["flags"] = derive_flags(state, channel_doc)
    if mismatch and "entry-mismatch" not in state["flags"]:
        state["flags"].append("entry-mismatch")
    write_yaml(sdir / "state.yaml", STATE_HEADER, state)

    sha = None
    if commit:
        verdict = state["last_receipt"]["verdict"]
        flags = ", ".join(state["flags"]) or "none"
        sha = commit_paths(
            root,
            f"{channel}/{station}: ingest {state['last_receipt']['ts']} — {verdict}\n\n"
            f"Reduced by publisher/vexa_station.py ingest. entry_seq "
            f"{entry_seq}; flags: {flags}.\n\n<!-- vexa-agent -->",
            [sdir],
        )
    return {"channel": channel, "station": station, "path": str(sdir / "state.yaml"),
            "receipts": str(rdir), "flags": state["flags"], "commit": sha}


def record_pin(root: pathlib.Path, *, channel: str, station: str, position: str,
               justification: str, commit: bool = True) -> dict:
    """Move a station's pin — a promotion. This is the ONE hand-driven write to
    channel.yaml, and it takes a justification because a promotion with no
    stated reason is indistinguishable in history from a slip."""
    channel = safe_name("channel", channel)
    station = safe_name("station", station)
    path = channel_file(root, channel)
    doc = load_yaml(path)
    if not doc:
        raise LedgerError(f"channel '{channel}' has no channel.yaml — publish an entry first")
    if not justification.strip():
        raise LedgerError("a pin move needs a justification (the dev station's receipt)")
    pins = doc.setdefault("pins", {})
    before = pins.get(station, "unset")
    pins[station] = position
    doc["updated_at"] = utcnow()
    write_yaml(path, CHANNEL_HEADER, doc)
    sha = None
    if commit:
        sha = commit_paths(
            root,
            f"{channel}: pin {station} {before} -> {position}\n\n{justification}\n\n"
            "<!-- vexa-agent -->",
            [path],
        )
    return {"channel": channel, "station": station, "from": before, "to": position,
            "commit": sha}


# ------------------------------------------------------- credential reducer

# Key names that must never reach this file. Checked by NAME, not by shape:
# a heuristic that tried to recognise a credential by looking at values would
# pass the first password that happened to look like a hostname, and the cost
# of being wrong here is a secret in git history, which is not removable.
# `code_salt` is on the list for the same reason as `password`, one step
# removed: `code_sha256` is a digest of that salt and a six-digit code, so a row
# carrying both is a code anyone can recover in milliseconds. The salt belongs
# to the park file on the edge and dies with it.
FORBIDDEN_EVENT_KEYS = {"password", "pass", "secret", "credential", "ciphertext",
                        "code", "claim_code", "code_salt", "token", "htpasswd"}

CREDENTIAL_EVENT_KINDS = {"park", "claim"}


def park_event(record: dict) -> dict:
    """The park, as the ledger keeps it: everything except the value.

    Built from the park record the publisher just wrote, field by field rather
    than by copying-and-deleting. A denylist over a record that carries the
    ciphertext is one forgotten key away from committing it; an allowlist that
    names each field cannot be.
    """
    return {
        "event": "park",
        "ts": record["parked_at"],
        "park_id": record["park_id"],
        "account": record["account"],
        "code_sha256": record["code_sha256"],
        "expires_at": record["expires_at"],
        "ttl_seconds": record["ttl_seconds"],
        "max_attempts": record["max_attempts"],
        "parked_by": record["parked_by"],
        "edge": record["edge"],
        "rotation": record["rotation"],
    }


def check_event(event: dict) -> dict:
    """Refuse an event that carries a value, or that is not one of ours."""
    if not isinstance(event, dict):
        raise LedgerError(f"credential event is not a mapping: {event!r}")
    kind = event.get("event")
    if kind not in CREDENTIAL_EVENT_KINDS:
        raise LedgerError(
            f"credential event {kind!r} is not one of {sorted(CREDENTIAL_EVENT_KINDS)}"
        )
    if not event.get("ts"):
        raise LedgerError("credential event has no `ts`")
    leaked = sorted(set(event) & FORBIDDEN_EVENT_KEYS)
    if leaked:
        raise LedgerError(
            f"credential event carries {leaked} — the ledger records that a "
            "credential moved, never the credential. Refusing the batch."
        )
    return event


def record_credential_events(root: pathlib.Path, *, channel: str, station: str,
                             events: list, commit: bool = True) -> dict:
    """Merge credential events into stations/<station>/credential-events.yaml.

    Idempotent by content: the edge's attempts log is a file an operator copies
    back, possibly twice, possibly overlapping with the last copy. Deduplicating
    on the whole event means a re-ingest is a no-op and nobody has to track a
    cursor for it.

    WHICH IS WHY THE EDGE STAMPS A `seq` ON EVERY ATTEMPT. Dedup-by-content and
    a second-resolution `ts` together collapsed a burst into one row: ten
    identical `no-park` attempts inside one second were ten identical events,
    and this kept one — in the record whose reason for existing is to show that
    somebody hammered a station (2026-09-07 rehearsal, finding 3). The sequence
    makes each attempt its own row while re-ingest still adds nothing, because
    the number is written into the log once and travels with it. Nothing here
    trusts the number: the comparison is still the whole row, and the sort uses
    it only to order attempts that share a second.
    """
    channel = safe_name("channel", channel)
    station = safe_name("station", station)
    path = station_dir(root, channel, station) / "credential-events.yaml"
    doc = load_yaml(path)
    known = list(doc.get("events") or [])
    seen = {json.dumps(e, sort_keys=True) for e in known}

    added = 0
    for event in events:
        row = {k: v for k, v in check_event(event).items() if v is not None}
        key = json.dumps(row, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        known.append(row)
        added += 1

    known.sort(key=lambda e: (e.get("ts") or "", e.get("event") or "",
                              e.get("seq") or 0))
    doc.update({
        "schema_version": SCHEMA_VERSION,
        "channel": channel,
        "station": station,
        "events": known,
        "updated_at": utcnow(),
    })
    if added:
        write_yaml(path, CREDENTIAL_HEADER, doc)

    sha = None
    if commit and added:
        kinds = ", ".join(sorted({e.get("event") for e in events})) or "none"
        sha = commit_paths(
            root,
            f"{channel}/{station}: credential events +{added} ({kinds})\n\n"
            "Reduced by publisher/vexa_stations.py. The ledger records that a "
            "credential moved and under which code hash; the value is sealed to "
            "the edge's key and never passes through here.\n\n<!-- vexa-agent -->",
            [path],
        )
    return {"channel": channel, "station": station, "path": str(path),
            "added": added, "total": len(known), "commit": sha}


# ------------------------------------------------------------------ reading


def cmd_show(args) -> int:
    root = resolve_root(args.ledger)
    for cpath in sorted((root / "channels").glob("*/channel.yaml")):
        doc = load_yaml(cpath)
        cur = doc.get("current") or {}
        print(f"\n{doc.get('channel')}  seq {doc.get('last_entry_seq')}  "
              f"current {cur.get('release')} ({cur.get('publication_mode')})")
        pins = doc.get("pins") or {}
        seen = set()
        for spath in sorted(cpath.parent.glob("stations/*/state.yaml")):
            st = load_yaml(spath)
            r = st.get("last_receipt") or {}
            name = st.get("station")
            seen.add(name)
            flags = ",".join(st.get("flags") or []) or "-"
            print(f"  {name:<16} pin={pins.get(name, 'unset'):<10} "
                  f"seen={str(st.get('subscribed_position')):<10} "
                  f"seq={r.get('entry_seq')} {r.get('verdict')} flags={flags}")
        # A station we have PINNED but never heard back from has no state.yaml.
        # Printing nothing for it would hide the one thing worth knowing about
        # it, so it is listed with what is missing said out loud.
        for name in sorted(set(pins) - seen):
            print(f"  {name:<16} pin={pins[name]:<10} seen=-          "
                  f"no station bundle ingested")
    return 0


def cmd_record_publish(args) -> int:
    root = resolve_root(args.ledger)
    p = pathlib.Path(args.entry)
    entry = json.loads((p / "entry.json" if p.is_dir() else p).read_text())
    out = record_publish(root, entry, entry_digest=args.entry_digest,
                         registry_ref=args.ref, channel_tag=args.channel_tag,
                         note=args.note)
    print(f"ledger: {out['channel']} seq {out['entry_seq']} -> {out['path']} "
          f"({out['commit'] or 'no change'})")
    return 0


def cmd_record_ingest(args) -> int:
    root = resolve_root(args.ledger)
    sdir = pathlib.Path(args.station_dir)
    receipt = json.loads((sdir / "ingest-receipt.json").read_text())
    # The ingested station report — one file, sections included. The reduction
    # takes the identity and the verdicts; the section bodies stay in the report
    # itself, which is stored verbatim beside the receipt.
    import yaml

    report = yaml.safe_load((sdir / "station-report.yaml").read_text()) or {}
    values_text = report.get("values") or ""
    manifest = {k: v for k, v in report.items()
                if not isinstance(v, str) or k not in
                ("profile", "values", "contract_document", "preflight_receipt",
                 "install_log", "smoke_receipt", "smoke_console")}
    out = record_ingest(root, channel=args.channel, station=args.station, receipt=receipt,
                        manifest=manifest,
                        bundle=pathlib.Path(args.bundle) if args.bundle else None,
                        values_text=values_text)
    print(f"ledger: {out['channel']}/{out['station']} -> {out['path']}; flags: "
          f"{', '.join(out['flags']) or 'none'} ({out['commit'] or 'no change'})")
    return 0


def cmd_pin(args) -> int:
    root = resolve_root(args.ledger)
    out = record_pin(root, channel=args.channel, station=args.station,
                     position=args.position, justification=args.justification)
    print(f"ledger: pin {out['channel']}/{out['station']} {out['from']} -> {out['to']} "
          f"({out['commit'] or 'no change'})")
    return 0


def cmd_record_credential(args) -> int:
    """Ingest the claim edge's attempts log — the credential path's return leg.

    The log is one NDJSON file covering every station the edge served, so it is
    grouped here and reduced per station: one commit each, naming the station,
    because 'which customer's code was guessed at' is the question this file
    exists to answer and a single mixed commit hides it.
    """
    root = resolve_root(args.ledger)
    by_station: "dict[str, list]" = {}
    unattributed = 0
    for lineno, raw in enumerate(pathlib.Path(args.events).read_text().splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"{args.events} line {lineno}: {exc}") from None
        name = event.get("station")
        # THE STATION FIELD IS ATTACKER-CONTROLLED — it comes off a public
        # endpoint's request body. Two guards, and both are needed:
        #
        #   the regex     an attempt whose body never parsed names no station
        #                 at all. Refusing the batch over it let one junk POST
        #                 block the return leg for every real event, which is a
        #                 denial of the record by anyone with curl.
        #   the directory a well-formed name for a station that does not exist
        #                 would CREATE its directory here. A caller posting a
        #                 thousand plausible names would grow a thousand
        #                 directories in the operator's ledger, one commit each.
        #
        # A real station always has a directory before its attempts arrive:
        # `add --park` writes its park row at mint time, which is necessarily
        # before anyone can claim against it.
        if not name or not NAME_RE.match(str(name)) or not (
            station_dir(root, args.channel, str(name)).is_dir()
        ):
            unattributed += 1
            continue
        by_station.setdefault(name, []).append(
            {k: v for k, v in event.items() if k != "station"}
        )
    if not by_station:
        print(f"ledger: {args.events} holds no attributable events "
              f"({unattributed} unattributed)")
        return 0
    for station, events in sorted(by_station.items()):
        out = record_credential_events(root, channel=args.channel, station=station,
                                       events=events)
        print(f"ledger: {out['channel']}/{station} credential events +{out['added']} "
              f"of {len(events)} -> {out['path']} ({out['commit'] or 'no change'})")
    if unattributed:
        print(f"ledger: {unattributed} attempt(s) named no station this channel "
              f"knows — probes at the endpoint; they stay in {args.events} and "
              f"enter no station's record")
    return 0


def add_ledger_flag(parser: argparse.ArgumentParser) -> None:
    """Shared by vexa_channel.py push and vexa_station.py ingest."""
    parser.add_argument("--ledger", help="checkout of the vexa-stations ledger "
                                         "(default: $VEXA_STATIONS_DIR)")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vexa-stations", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    add_ledger_flag(p)
    sub = p.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("record-publish", help="reduce a published entry into channel.yaml")
    rp.add_argument("--entry", required=True, help="built entry directory or entry.json")
    rp.add_argument("--entry-digest", help="digest the entry was pushed at")
    rp.add_argument("--ref", help="registry ref the entry lives at")
    rp.add_argument("--channel-tag", help="moving tag (default current)")
    rp.add_argument("--note", help="one line about why this entry exists")

    ri = sub.add_parser("record-ingest", help="reduce an ingested station into state.yaml")
    ri.add_argument("--channel", required=True)
    ri.add_argument("--station", required=True)
    ri.add_argument("--station-dir", required=True,
                    help="stations/<name>/ as written by vexa_station.py ingest")
    ri.add_argument("--bundle", help="the station report, stored verbatim in receipts/")

    pin = sub.add_parser("pin", help="move a station's pin (a promotion)")
    pin.add_argument("--channel", required=True)
    pin.add_argument("--station", required=True)
    pin.add_argument("--position", required=True, help="chart version, or * to follow")
    pin.add_argument("--justification", required=True,
                     help="the dev station's receipt that justifies the promotion")

    rc = sub.add_parser("record-credential",
                        help="reduce the claim edge's attempts log into "
                             "credential-events.yaml")
    rc.add_argument("--channel", required=True)
    rc.add_argument("--events", required=True,
                    help="the edge's attempts.ndjson, copied back from the spool")

    sub.add_parser("show", help="render the ledger")

    args = p.parse_args(argv)
    try:
        return {"record-publish": cmd_record_publish, "record-ingest": cmd_record_ingest,
                "record-credential": cmd_record_credential,
                "pin": cmd_pin, "show": cmd_show}[args.cmd](args)
    except LedgerError as e:
        print(f"REFUSED {e}", file=sys.stderr)
        return 3
    except subprocess.CalledProcessError as e:
        print(f"git failed: {e.cmd}\n{(e.stderr or '')[-800:]}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
