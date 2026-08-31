#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# vexa-verify — deterministic validation of a channel entry.
#
# Same bundle in, same verdict out. No judgment, no network beyond the channel
# registry: the entry carries the Sigstore trusted root, so provenance is
# checked offline. Non-zero exit means the release is NOT eligible.
#
# Runs anywhere: an operator's workstation, your CI, or as the Argo PreSync
# hook in presync-job.yaml. Apache-2.0, like the rest of the kit — read it.
#
# usage: vexa-verify.sh --entry-ref <registry/path:tag> --pubkey <file>
#                       [--policy <file>] [--workdir <dir>] [--insecure] [--plain-http]
#                       [--station <name> --verdict-out <file> [--verdict-log <file>]]
#
# --verdict-out writes the station-verdict PREDICATE this run just proved, ready
# for `vexa_channel.py attest --kind station-verdict --metrics <file>`. Until
# this existed the predicate was transcribed by a person from the line below,
# and nothing bound the signed claim to the run that produced it.
set -eu

ENTRY_REF=""; PUBKEY=""; POLICY=""; WORKDIR="/tmp/vexa-verify"; INSECURE=""; PLAIN_HTTP=""
REQUIRE_APPROVAL=""; APPROVAL_NS="argocd"
STATION=""; VERDICT_OUT=""; VERDICT_LOG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --entry-ref) ENTRY_REF=$2; shift 2;;
    --pubkey) PUBKEY=$2; shift 2;;
    --policy) POLICY=$2; shift 2;;
    --workdir) WORKDIR=$2; shift 2;;
    --require-approval) REQUIRE_APPROVAL=$2; shift 2;;
    --station) STATION=$2; shift 2;;
    --verdict-out) VERDICT_OUT=$2; shift 2;;
    --verdict-log) VERDICT_LOG=$2; shift 2;;
    --approval-namespace) APPROVAL_NS=$2; shift 2;;
    --insecure) INSECURE=1; shift;;
    --plain-http) PLAIN_HTTP=1; shift;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
if [ -z "$ENTRY_REF" ] || [ -z "$PUBKEY" ]; then
  echo "usage: --entry-ref REF --pubkey FILE [--policy FILE]" >&2; exit 2
fi
# A verdict is a claim about a contract, made by a named station. Refuse to emit
# one that cannot say who made it or what it was rendered against - an
# unattributable verdict is worse than none, because it looks signed.
if [ -n "$VERDICT_OUT" ]; then
  if [ -z "$STATION" ]; then
    echo "--verdict-out requires --station: the predicate names which station made the claim" >&2; exit 2
  fi
  if [ -z "$POLICY" ]; then
    echo "--verdict-out requires --policy: a verdict is rendered AGAINST a contract, and carries its id and sha256" >&2; exit 2
  fi
fi

FAILED=0
ok()   { echo "OK    $1"; }
fail() { echo "FAIL  $1" >&2; FAILED=$((FAILED+1)); }

# ISO-8601 Z timestamp -> unix epoch seconds, in awk.
#
# Not `date -d`: this script runs in the Alpine verifier image, in CI, and on
# an operator's macOS laptop, and BSD date's -d means something else entirely.
# A portability bug in the freshness check would express itself as a refusal
# of a perfectly good release — the exact failure shape the rehearsal spent a
# day on. So the arithmetic is done here, the same way everywhere.
iso_epoch() {
  echo "$1" | awk '{
    y=substr($0,1,4)+0; mo=substr($0,6,2)+0; d=substr($0,9,2)+0;
    h=substr($0,12,2)+0; mi=substr($0,15,2)+0; s=substr($0,18,2)+0;
    # days-from-civil (Howard Hinnant): exact, no leap-second pretence
    if (mo <= 2) { y-- ; era_m = mo + 9 } else { era_m = mo - 3 }
    era = (y >= 0 ? y : y - 399) ; era = int(era / 400)
    yoe = y - era * 400
    doy = int((153 * era_m + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe/4) - int(yoe/100) + doy
    days = era * 146097 + doe - 719468
    print days * 86400 + h * 3600 + mi * 60 + s
  }'
}
NOW_EPOCH=$(iso_epoch "$(date -u +%Y-%m-%dT%H:%M:%SZ)")

rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"; cd "$WORKDIR"

# ---------------------------------------------------------------- 1 · fetch
# --insecure applies to the registry pull only. cosign's verify-blob commands
# read local files and reject registry flags outright.
# --insecure is TLS-skip only; a registry speaking plain HTTP needs --plain-http
# (oras dials https otherwise and reports connection refused).
ORAS_FLAGS=""
[ -n "$INSECURE" ] && ORAS_FLAGS="--insecure"
[ -n "$PLAIN_HTTP" ] && ORAS_FLAGS="$ORAS_FLAGS --plain-http"
# shellcheck disable=SC2086
oras pull $ORAS_FLAGS "$ENTRY_REF" -o . >/dev/null 2>&1 || { echo "FAIL  cannot pull entry $ENTRY_REF" >&2; exit 1; }
[ -f entry.json ] || { echo "FAIL  entry.json missing from $ENTRY_REF" >&2; exit 1; }
ok "entry pulled: $ENTRY_REF"

# ------------------------------------------------------- 2 · entry signature
if [ -f entry.json.sigstore.json ]; then
  # shellcheck disable=SC2086
  # Legacy bundle, no Rekor: the channel signs offline against the key you
  # pinned. --new-bundle-format made this FAIL on a correctly signed entry and
  # block the sync (rehearsal 2026-08-24) — the one wrong flag in the whole
  # chain, and it read as a forged entry.
  if cosign verify-blob --key "$PUBKEY" --bundle entry.json.sigstore.json \
       --insecure-ignore-tlog=true entry.json >/dev/null 2>&1; then
    ok "entry signature verifies against the pinned channel key"
  else
    fail "entry signature does NOT verify against the pinned channel key"
  fi
else
  fail "entry carries no signature"
fi

# ------------------------------------------------------------ 2b · freshness
# An expired entry and a forged entry are DIFFERENT EVENTS with different
# remedies, and this check exists so they never share a message. A signature
# failure says someone may be attacking you. This says nobody has published to
# your channel — your supply chain has stopped, and from the inside that looks
# exactly like a healthy one. The first needs your security team; the second
# needs an email to us.
EXPIRES=$(jq -r '.expires // ""' entry.json)
if [ -z "$EXPIRES" ]; then
  fail "entry declares no expiry — it predates channel freshness; ask Vexa to republish it"
else
  exp_epoch=$(iso_epoch "$EXPIRES")
  if [ "$NOW_EPOCH" -gt "$exp_epoch" ]; then
    age_d=$(( (NOW_EPOCH - exp_epoch) / 86400 ))
    fail "STALE CHANNEL — this entry expired at $EXPIRES, ${age_d} day(s) ago. The signature is
      not in question and nothing has been tampered with: nobody has published to this channel
      since. Do not work around this by widening the contract. Contact Vexa."
  else
    left_d=$(( (exp_epoch - NOW_EPOCH) / 86400 ))
    ok "freshness: entry expires $EXPIRES (${left_d} day(s) left)"
  fi
fi

# ------------------------------------------------ 3 · evidence file integrity
jq -r '.evidence[] | "\(.sha256)  evidence/\(.name)"' entry.json > .sums
while read -r want path; do
  [ -f "$path" ] || { fail "evidence file missing: $path"; continue; }
  got=$(sha256sum "$path" | cut -d' ' -f1)
  if [ "$got" = "$want" ]; then ok "digest $path"; else fail "digest mismatch $path"; fi
done < .sums

# ----------------------------------------------- 4 · map pin (one carrier per fact)
#
# DECLARED-ABSENT IS NOT MISSING, and the difference decides whether an ESTATE
# can be verified at all (filed as the estate-verify gap, 2026-08-25).
#
# The candidate map and the delivery receipt are artifacts of the OSS RELEASE
# TRAIN: a tag was cut, a packet was built, a delivery happened. A platform
# estate has none of them and never will — it was captured from a running
# cluster, not cut from a tag — so an estate entry names them in
# `evidence_absent` with a reason, which is the honest form of saying so.
#
# Before this, the branch below read the absence as a defect and failed the
# entry with "candidate map absent from the bundle". In-cluster that is a
# FAILED PRESYNC HOOK: the sync stops, and the message blames a missing file
# rather than saying the verifier does not model this kind of entry. The
# control test is that the already-published seq-1 estate entry fails exactly
# the same way, so it is the verifier's model that is wrong, not the entry.
#
# The fix is NOT to tolerate absence generally — it is to let the ENTRY declare
# an absence and let the CONTRACT decide whether that absence is acceptable.
# §6's `forbid_absent_evidence` is where that decision lives and it is
# unchanged: an estate contract lists `validation_contract` there, so an entry
# that declared THAT absent is still refused. One authority, and it is the
# customer's file.
declared_absent() {
  jq -e --arg k "$1" '.evidence_absent[]? | select(.kind == $k)' entry.json >/dev/null 2>&1
}
absent_reason() {
  jq -r --arg k "$1" '.evidence_absent[]? | select(.kind == $k) | .reason' entry.json | head -1
}

PUB_MODE=$(jq -r '.publication.mode // "published"' entry.json)
if declared_absent candidate_map && declared_absent delivery_receipt; then
  ok "entry declares the OSS release-train evidence absent by design: $(absent_reason candidate_map)"
  echo "note  the map/receipt cross-check does not apply to this entry. What replaces it is the"
  echo "note  contract's own required evidence (§6) — for an estate, the validation contract."
elif [ "$PUB_MODE" = "candidate" ] && [ ! -f evidence/delivery-receipt.json ]; then
  # A candidate is published BEFORE any delivery happens — the receipt cannot
  # exist yet by definition. The map alone carries identity; the pin
  # cross-check runs when the published entry appears.
  if [ -f evidence/candidate-images.json ]; then
    ok "candidate entry: map present; delivery receipt deferred by definition"
  else
    fail "candidate map absent from the bundle"
  fi
elif [ -f evidence/candidate-images.json ] && [ -f evidence/delivery-receipt.json ]; then
  map_hash="sha256:$(sha256sum evidence/candidate-images.json | cut -d' ' -f1)"
  pin=$(jq -r '.packet.sha256' evidence/delivery-receipt.json)
  if [ "$map_hash" = "$pin" ]; then
    ok "candidate map matches the delivery receipt's packet pin"
  else
    fail "candidate map $map_hash != receipt pin $pin"
  fi
else
  fail "candidate map or delivery receipt absent from the bundle"
fi

# ------------------------------------------------- 5 · source provenance, offline
ARCHIVE=$(find . -maxdepth 1 -name 'vexa-core-*.tar.gz' 2>/dev/null | sed 's|^\./||' | sort | head -1)
if [ -n "$ARCHIVE" ] && [ -f evidence/source-provenance.sigstore.json ]; then
  issuer=$(jq -r '.source.certificate_oidc_issuer' entry.json)
  identity=$(jq -r '.source.certificate_identity_pattern' entry.json)
  # shellcheck disable=SC2086
  if cosign verify-blob-attestation --bundle evidence/source-provenance.sigstore.json \
       --new-bundle-format --type slsaprovenance1 \
       --certificate-oidc-issuer="$issuer" --certificate-identity-regexp="$identity" \
       "$ARCHIVE" >/dev/null 2>&1; then
    ok "source provenance verifies (offline, against the bundled trusted root)"
  else
    fail "source provenance does NOT verify"
  fi
elif declared_absent source_provenance; then
  # Same reasoning as §4, and said out loud so a reader of the log does not
  # take silence for a passed check: an estate was not cut from a tag, so
  # there is no archive to attest and no SLSA bundle to verify. The entry's
  # source block carries the `none` sentinels the schema permits ONLY for an
  # estate, and the zero digest that goes with them.
  ok "entry declares source provenance absent by design: $(absent_reason source_provenance)"
  echo "note  what binds an estate to reality is not a build attestation: it is the digest set"
  echo "note  captured from the running cluster, plus the validation contract the entry carries."
else
  echo "note  source archive not in the bundle; provenance checked by hash only"
  want=$(jq -r '.source.archive_sha256' entry.json)
  [ -n "$want" ] && ok "source archive sha256 recorded: ${want%"${want#??????????}"}…"
fi

# ----------------------------------------------------------- 5b · revocation
# We can publish and we cannot un-publish. An immutable tag stays resolvable
# and a cached chart stays installable, so withdrawing a bad release has to be
# a POSITIVE, signed statement that this verifier goes and reads.
#
# ABSENT IS NOT AN ERROR. Every channel published before this capability
# existed has no list, and the fail-closed reading would refuse every install
# made before we thought of it. A missing list is an EMPTY list, said out loud
# here so nobody later mistakes that for an oversight.
#
# AND KYVERNO CANNOT DO THIS. An admission controller verifies signatures on
# the images in front of it; it does not fetch a vendor document and reason
# about it, and no policy YAML makes it. This gate — PreSync, before the sync
# — is the enforcement point for revocation. Admission remains the independent
# check on signatures and digest-pinning, which are different questions.
ENTRY_BASE=${ENTRY_REF%:*}
REVDIR=".revocations"; mkdir -p "$REVDIR"
# shellcheck disable=SC2086
if oras pull $ORAS_FLAGS "$ENTRY_BASE/revocations:latest" -o "$REVDIR" >/dev/null 2>&1 \
   && [ -f "$REVDIR/revocations.json" ]; then
  if [ -f "$REVDIR/revocations.json.sigstore.json" ] \
     && cosign verify-blob --key "$PUBKEY" --bundle "$REVDIR/revocations.json.sigstore.json" \
          --insecure-ignore-tlog=true "$REVDIR/revocations.json" >/dev/null 2>&1; then
    ok "revocation list signature verifies against the pinned channel key"
  else
    fail "revocation list is present but does NOT verify against the pinned channel key — refusing to act on an unsigned recall notice, and refusing to ignore it"
  fi

  rev_exp=$(jq -r '.expires // ""' "$REVDIR/revocations.json")
  if [ -n "$rev_exp" ] && [ "$NOW_EPOCH" -gt "$(iso_epoch "$rev_exp")" ]; then
    fail "revocation list expired at $rev_exp — you are being served a stale answer to 'has anything been recalled?'"
  else
    ok "revocation list is current (expires $rev_exp)"
  fi

  REL_V=$(jq -r '.release.version' entry.json)
  hits=$(jq -r --arg v "$REL_V" '[.entries[]? | select(.version == $v)] | length' "$REVDIR/revocations.json")
  if [ "$hits" -gt 0 ]; then
    jq -r --arg v "$REL_V" '.entries[]? | select(.version == $v)
        | "  \(.severity | ascii_upcase): \(.reason)\(if .supersedes then "  -> move to \(.supersedes)" else "" end)"' \
      "$REVDIR/revocations.json" >&2
    fail "release $REL_V is REVOKED by the channel ($hits notice(s), printed above)"
  else
    ok "release $REL_V is not revoked"
  fi

  # Digest revocation is the precise form: it survives re-tagging and names one
  # immutable set of bytes. Checked against every image this entry ships.
  jq -r '.entries[]? | select(.digest) | .digest' "$REVDIR/revocations.json" | sort -u > .revoked-digests
  jq -r '.images[].index_digest' entry.json | sort -u > .entry-image-digests
  revoked_imgs=$(comm -12 .revoked-digests .entry-image-digests)
  if [ -n "$revoked_imgs" ]; then
    echo "$revoked_imgs" | sed 's/^/  revoked image: /' >&2
    fail "this entry ships image digests the channel has revoked (listed above)"
  else
    ok "no image digest in this entry is revoked"
  fi
else
  echo "note  no revocation list published on this channel — treated as EMPTY, which is correct for a channel that predates the capability, NOT an error"
fi

# ------------------------------------------- 6 · your contract (the policy)
# The policy file IS the machine-readable half of the subscription contract.
# Its digest is the contract's identity: every verdict below is rendered
# "against contract <id> @ <hash>", and the approval record stores both — so
# an audit can answer WHICH promise a deployment was admitted under.
CONTRACT_ID=""; CONTRACT_SHA=""
if [ -n "$POLICY" ] && [ -f "$POLICY" ]; then
  CONTRACT_ID=$(jq -r '.contract_id // "unnamed"' "$POLICY")
  CONTRACT_SHA=$(sha256sum "$POLICY" | cut -d' ' -f1)
  echo "--- contract: $CONTRACT_ID @ sha256:$(printf %.12s "$CONTRACT_SHA")…"

  # CARRIAGE. The 2026-09 contract shape splits one document in two:
  # `required_values[]` — what the release must be PROVEN to do — and
  # `carriage{}` — what the entry that carries it must look like. Every check
  # below is a carriage check and was written against the flat spelling, so a
  # contract that nests them would have every one of them read a missing key
  # and quietly take its default. `require_publication_mode` defaulting to
  # "published" against a candidate channel is the loud version of that; the
  # silent version is `allow_break_glass` defaulting to false and looking like
  # enforcement. Flatten into a WORKING COPY so the checks read one shape.
  #
  # THE ID AND HASH ABOVE ARE THE RECORD'S, computed before this and never
  # recomputed: a verdict names the contract a human can open in the ledger,
  # not a derived file that exists for four seconds inside a pod.
  #
  # `required_values[]` IS evaluated here as of 2026-08-31 — see §6b, which
  # reverses the earlier decision to leave it alone. The flatten keeps
  # `required_values[]` intact (only `carriage` is dissolved), so §6b reads it
  # off the working copy exactly as it stands in the record.
  if jq -e 'has("carriage")' "$POLICY" >/dev/null 2>&1; then
    # Written into the working directory, which is already the cwd — a
    # "$WORKDIR/…" path would be wrong for a relative --workdir.
    jq '.carriage as $c | del(.carriage) | . + $c' "$POLICY" > ".policy-flat.json"
    POLICY="$PWD/.policy-flat.json"
    echo "note  contract carries a carriage{} block; its keys are read as the entry checks below"
  fi

  # ------------------------------------- 6b · required_values[], adjudicated
  #
  # THE CLAUSE NOTHING READ. `carriage.require_entry_values_proven` has been
  # true on the live `vexa-internal` record since the 2026-09 shape landed, and
  # until 2026-08-31 it was VOID in both directions: the publisher wrote no
  # values_proven block and this verifier said, in its own transcript, that
  # `required_values[]` was not evaluated. A contract demanding proof of seven
  # values admitted an entry that proved none of them, and every run printed a
  # roster of green ticks for the carriage half while the proof half was not a
  # check at all. That is the worst failure shape this codebase names elsewhere:
  # a clause that reads as enforcement while enforcing nothing.
  #
  # WHAT THIS CAN AND CANNOT DO, said out loud so the OK lines are not read as
  # more than they are. This is a shell in a Job. It cannot deploy a platform,
  # join a meeting, or witness a transcript, so it CANNOT re-prove a value. What
  # it checks is that the signed entry CLAIMS each required value, that the
  # claim names a station, that a `proven` claim carries evidence, that a
  # `waived` claim names the human who granted it, and that evidence citing an
  # image digest cites one this entry actually ships. A weaker claim than
  # "these values hold" — and labelled as one — but it is the difference
  # between an unevidenced entry being refused and being admitted in silence.
  #
  # FAIL-CLOSED BY DESIGN, INCLUDING AGAINST WHAT IS ALREADY PUBLISHED. Every
  # entry through seq-11 predates the block and carries none, so this check
  # refuses all of them against the live contract. That is the correct reading
  # of a contract that has demanded this since 2026-09: the remedy is to
  # publish an entry that carries the proof, not to widen the contract.
  if [ "$(jq -r '.require_entry_values_proven // false' "$POLICY")" = "true" ]; then
    n_vals=$(jq -r '[.required_values[]? | select(.enforcement == "required")] | length' "$POLICY")
    if [ "$n_vals" -eq 0 ]; then
      echo "note  contract requires entry values_proven but names no required_values[] row with enforcement 'required' — nothing to adjudicate"
    fi
    if ! jq -e 'has("values_proven")' entry.json >/dev/null 2>&1; then
      echo "note  this entry carries NO values_proven block. Entries published before 2026-08-31"
      echo "note  predate it; the refusal below is the contract being read, not a new demand."
    fi
    jq -r '.images[].index_digest' entry.json | sort -u > .vp-entry-digests
    # The id list goes through a FILE, not a pipe. `jq | while read` runs the
    # loop body in a subshell, where every fail() increments a copy of FAILED
    # that dies with the subshell — the verdict would print NOT ELIGIBLE's
    # reasons and then exit ELIGIBLE. Redirecting from a file keeps the loop in
    # this shell, so the counter the verdict reads is the one the checks wrote.
    jq -r '.required_values[]? | select(.enforcement == "required") | .id' "$POLICY" > .vp-required-ids
    while IFS= read -r vid; do
      [ -n "$vid" ] || continue
      row=$(jq -c --arg id "$vid" '[.values_proven[]? | select(.id == $id)] | .[0] // empty' entry.json)
      if [ -z "$row" ]; then
        fail "values: $vid is REQUIRED by contract $CONTRACT_ID and this entry proves nothing about it"
        continue
      fi
      vv=$(printf '%s' "$row" | jq -r '.verdict // ""')
      vst=$(printf '%s' "$row" | jq -r '.station // ""')
      if [ -z "$vst" ]; then
        fail "values: $vid names no station — an unattributable proof is not a proof"
        continue
      fi
      case "$vv" in
        proven)
          n_ev=$(printf '%s' "$row" | jq -r '.evidence // [] | length')
          if [ "$n_ev" -eq 0 ]; then
            fail "values: $vid claims 'proven' with no evidence row — an assertion, not a proof"
            continue
          fi
          miss=""
          for sd in $(printf '%s' "$row" | jq -r '.evidence[]? | .subject_digest // empty'); do
            grep -qxF "$sd" .vp-entry-digests || miss="$miss $sd"
          done
          if [ -n "$miss" ]; then
            fail "values: $vid cites evidence against image digest(s)$miss, which this entry does not ship — evidence about another release"
            continue
          fi
          ok "values: $vid proven by station '$vst' ($n_ev evidence row(s))"
          ;;
        waived)
          wby=$(printf '%s' "$row" | jq -r '.waived_by // ""')
          if [ -z "$wby" ]; then
            fail "values: $vid is waived by nobody — an anonymous waiver is an omission with a label"
          else
            ok "values: $vid WAIVED by $wby (station '$vst') — accepted unproven, on the record"
          fi
          ;;
        *)
          fail "values: $vid carries verdict '$vv'; only 'proven' or 'waived' answers a required value"
          ;;
      esac
    done < .vp-required-ids
    for adv in $(jq -r '.required_values[]? | select(.enforcement != "required") | .id' "$POLICY"); do
      st=$(jq -r --arg id "$adv" '[.values_proven[]? | select(.id == $id)] | .[0].verdict // "unclaimed"' entry.json)
      echo "note  values: $adv is advisory in this contract — entry says '$st'; not gating"
    done
  else
    echo "note  contract does not set require_entry_values_proven; required_values[] is NOT adjudicated by this run"
  fi

  for kind in $(jq -r '.require_evidence_kinds[]? // empty' "$POLICY"); do
    if jq -e --arg k "$kind" '.evidence[] | select(.kind == $k)' entry.json >/dev/null; then
      ok "policy: evidence '$kind' present"
    else
      fail "policy: required evidence '$kind' absent"
    fi
  done

  allow_bg=$(jq -r '.allow_break_glass // false' "$POLICY")
  if jq -e '.break_glass != null' entry.json >/dev/null; then
    actor=$(jq -r '.break_glass.actor' entry.json)
    if [ "$allow_bg" = "true" ]; then
      ok "policy: break-glass entry accepted (actor: $actor)"
    else
      fail "policy: entry carries a break-glass record (actor: $actor) and your policy forbids it"
    fi
  else
    ok "policy: no break-glass on this entry"
  fi

  min_seq=$(jq -r '.min_entry_seq // 0' "$POLICY")
  seq=$(jq -r '.channel.entry_seq' entry.json)
  if [ "$seq" -ge "$min_seq" ]; then
    ok "policy: entry_seq $seq >= your floor $min_seq"
  else
    fail "policy: entry_seq $seq is below your floor $min_seq (no silent downgrade)"
  fi

  want_mode=$(jq -r '.require_publication_mode // "published"' "$POLICY")
  mode=$(jq -r '.publication.mode' entry.json)
  if [ "$mode" = "$want_mode" ]; then
    ok "policy: publication mode '$mode'"
  else
    fail "policy: publication mode '$mode', your policy requires '$want_mode'"
  fi

  # Vexa's own human gate, carried INSIDE the signed entry: a release reaches
  # the channel only when a named person at Vexa approved its publication.
  # This is the first of the two human approvals in the chain; the second is
  # yours (§7) and applies to your production.
  if [ "$(jq -r '.require_vendor_approval // false' "$POLICY")" = "true" ]; then
    vby=$(jq -r '.publication.approved_by // ""' entry.json)
    vrc=$(jq -r '.publication.approval_receipt // ""' entry.json)
    if [ -n "$vby" ] && [ -n "$vrc" ]; then
      ok "vendor approval: published by $vby"
    else
      fail "entry carries no Vexa approval (publication.approved_by/approval_receipt) — not a human-approved publication"
    fi
  fi

  # ---- structured attestations: parameters checked against the contract ----
  find_evidence() { jq -r --arg k "$1" '.evidence[] | select(.kind == $k) | .name' entry.json | head -1; }

  verify_att_sig() { # $1 = evidence file name
    if [ -f "evidence/$1.sigstore.json" ]; then
      if cosign verify-blob --key "$PUBKEY" --bundle "evidence/$1.sigstore.json" \
           --insecure-ignore-tlog=true "evidence/$1" >/dev/null 2>&1; then
        ok "attestation signature: $1"
      else
        fail "attestation signature does NOT verify: $1"
      fi
    fi
  }

  if jq -e '.soak' "$POLICY" >/dev/null; then
    if jq -e '.soak | .. | objects | select(has("min_completion_rate"))' "$POLICY" >/dev/null 2>&1; then
      fail "contract sets a floor on completion_rate — a definition error per prod-soak-metrics.v1 (completion mixes user/host/world with software); refuse the contract, not the release"
    fi
    sname=$(find_evidence "soak")
    if [ -z "$sname" ]; then
      fail "contract requires a prod-soak attestation and the entry carries none"
    else
      verify_att_sig "$sname"
      want_defs=$(jq -r '.soak.definitions_sha256' "$POLICY")
      got_defs=$(jq -r '.predicate.definitions.sha256' "evidence/$sname")
      if [ "$want_defs" = "$got_defs" ]; then
        ok "soak: definitions pin matches (prod-soak-metrics.v1 @ $(printf %.12s "$got_defs")…)"
      else
        fail "soak: attestation uses definitions $got_defs, your contract pins $want_defs — the numbers may not mean what you agreed"
      fi
      for plat in $(jq -r '.soak.platforms | keys[]' "$POLICY"); do
        if ! jq -e --arg p "$plat" '.predicate.platforms[$p]' "evidence/$sname" >/dev/null; then
          fail "soak: contract requires platform '$plat', attestation does not cover it"
          continue
        fi
        n=$(jq -r --arg p "$plat" '.predicate.platforms[$p].meetings_dispatched' "evidence/$sname")
        r=$(jq -r --arg p "$plat" '.predicate.platforms[$p].software_success_rate' "evidence/$sname")
        min_n=$(jq -r --arg p "$plat" '.soak.platforms[$p].min_meetings // 0' "$POLICY")
        min_r=$(jq -r --arg p "$plat" '.soak.platforms[$p].min_software_success_rate // 0' "$POLICY")
        if [ "$n" -ge "$min_n" ]; then
          ok "soak/$plat: $n meetings >= your floor $min_n"
        else
          fail "soak/$plat: $n meetings, your contract requires >= $min_n"
        fi
        if awk -v a="$r" -v b="$min_r" 'BEGIN{exit !(a>=b)}'; then
          ok "soak/$plat: software_success_rate $r >= your floor $min_r"
        else
          fail "soak/$plat: software_success_rate $r below your floor $min_r"
        fi
      done
    fi
  fi

  if jq -e '.security_hardening' "$POLICY" >/dev/null; then
    hname=$(find_evidence "security_hardening")
    if [ -z "$hname" ]; then
      fail "contract requires a security-hardening attestation and the entry carries none"
    else
      verify_att_sig "$hname"
      want_defs=$(jq -r '.security_hardening.definitions_sha256' "$POLICY")
      got_defs=$(jq -r '.predicate.definitions.sha256' "evidence/$hname")
      if [ "$want_defs" = "$got_defs" ]; then
        ok "hardening: definitions pin matches (security-hardening.v1 @ $(printf %.12s "$got_defs")…)"
      else
        fail "hardening: attestation uses definitions $got_defs, your contract pins $want_defs"
      fi
      agents=$(jq -r '.predicate.agents_run' "evidence/$hname")
      min_agents=$(jq -r '.security_hardening.min_agents // 1' "$POLICY")
      if [ "$agents" -ge "$min_agents" ]; then
        ok "hardening: $agents independent passes >= your floor $min_agents"
      else
        fail "hardening: $agents independent passes, your contract requires >= $min_agents"
      fi
      for sev in $(jq -r '.security_hardening.max_open // {} | keys[]' "$POLICY"); do
        open=$(jq -r --arg s "$sev" '.predicate.findings.open[$s]' "evidence/$hname")
        cap=$(jq -r --arg s "$sev" '.security_hardening.max_open[$s]' "$POLICY")
        if [ "$open" -le "$cap" ]; then
          ok "hardening: open $sev findings $open <= your cap $cap"
        else
          fail "hardening: $open open $sev findings shipped, your contract caps at $cap"
        fi
      done
    fi
  fi

  # ---- accumulated attestations: signatures that arrived AFTER the entry ----
  # The chain's core motion: a candidate entry is published once; stations sign
  # verdicts beside it. A downstream contract names the attestations it
  # requires; each is pulled from the channel, its signature verified, and its
  # subjects matched digest-for-digest against this entry's images.
  n_req=$(jq -r '.require_attestations // [] | length' "$POLICY")
  if [ "$n_req" -gt 0 ]; then
    REL=$(jq -r '.release.version' entry.json)
    jq -r '.images[].index_digest | sub("^sha256:"; "")' entry.json | sort > .entry-digests
    i=0
    while [ "$i" -lt "$n_req" ]; do
      akind=$(jq -r --argjson i "$i" '.require_attestations[$i].kind' "$POLICY")
      astation=$(jq -r --argjson i "$i" '.require_attestations[$i].station // empty' "$POLICY")
      atag="$akind.$REL"
      adir=".att-$i"; mkdir -p "$adir"
      # shellcheck disable=SC2086
      if ! oras pull $ORAS_FLAGS "$ENTRY_BASE/attestations:$atag" -o "$adir" >/dev/null 2>&1; then
        fail "required attestation '$atag' not found on the channel${astation:+ (station $astation)} — the upstream station has not signed this release"
        i=$((i+1)); continue
      fi
      astmt="$adir/$akind.$REL.intoto.json"
      if [ ! -f "$astmt" ] || [ ! -f "$astmt.sigstore.json" ]; then
        fail "attestation '$atag' is missing its statement or signature"
        i=$((i+1)); continue
      fi
      if cosign verify-blob --key "$PUBKEY" --bundle "$astmt.sigstore.json" \
           --insecure-ignore-tlog=true "$astmt" >/dev/null 2>&1; then
        ok "attestation signature: $atag"
      else
        fail "attestation '$atag' signature does NOT verify against the pinned key"
        i=$((i+1)); continue
      fi
      jq -r '.subject[].digest.sha256' "$astmt" | sort > "$adir/.subjects"
      if [ -n "$(comm -23 "$adir/.subjects" .entry-digests)" ]; then
        fail "attestation '$atag' covers digests that are NOT this entry's images — wrong release or tampering"
      else
        ok "attestation '$atag': every subject digest is in this entry's image set"
      fi
      arel=$(jq -r '.predicate.release' "$astmt")
      if [ "$arel" = "$REL" ]; then
        ok "attestation '$atag': release $arel matches"
      else
        fail "attestation '$atag' names release '$arel', entry is $REL"
      fi
      if [ -n "$astation" ]; then
        got_station=$(jq -r '.predicate.station // empty' "$astmt")
        if [ "$got_station" = "$astation" ]; then
          ok "attestation '$atag': signed by station '$got_station'"
        else
          fail "attestation '$atag': station '$got_station', your contract requires '$astation'"
        fi
      fi
      if [ "$akind" = "station-verdict" ]; then
        v=$(jq -r '.predicate.verdict' "$astmt")
        if [ "$v" = "ELIGIBLE" ]; then
          ok "attestation '$atag': verdict ELIGIBLE"
        else
          fail "attestation '$atag': verdict '$v'"
        fi
      fi
      i=$((i+1))
    done
  fi

  # ---- your own, tighter freshness floor ----------------------------------
  # §2b already refused an entry past the horizon Vexa stamped. This is the
  # knob for a change board that does not accept our horizon: refuse anything
  # published more than N days ago, whatever its expiry says.
  max_age=$(jq -r '.max_entry_age_days // ""' "$POLICY")
  if [ -n "$max_age" ]; then
    pub=$(jq -r '.publication.published_at' entry.json)
    age_d=$(( (NOW_EPOCH - $(iso_epoch "$pub")) / 86400 ))
    if [ "$age_d" -le "$max_age" ]; then
      ok "policy: entry is ${age_d}d old, within your max_entry_age_days of $max_age"
    else
      fail "policy: entry was published $pub (${age_d}d ago), past your max_entry_age_days of $max_age — ask Vexa to republish, do not raise the number"
    fi
  fi

  # ---- delivery_scope: what a release may DO here -------------------------
  # HONESTY, NOT THEATRE. This script is a shell in a Job. It has no chart, no
  # helm and no rendered manifests, so it CANNOT re-run the object-level checks
  # the publisher's station gate ran. What it can do is check that the gate ran
  # against THIS contract at THIS revision and enforced THESE clauses — a
  # weaker claim, labelled as one. The check that sees what actually runs is
  # Pod Security admission and Kyverno, in your cluster, answering to you.
  if jq -e '.delivery_scope' "$POLICY" >/dev/null 2>&1; then
    gname=$(jq -r '.evidence[] | select(.kind == "station_gate") | .name' entry.json | head -1)
    if [ -z "$gname" ]; then
      fail "your contract states a delivery_scope and this entry carries no station_gate evidence — nothing proves the scope was enforced before publication"
    else
      echo "note  delivery_scope is enforced PUBLISHER-SIDE on the rendered chart (S10-S14)."
      echo "note  this verifier re-checks the CLAIM, not the objects: it has no chart to render."
      echo "note  the object-level check that binds is your own Pod Security admission + Kyverno."
      gv=$(jq -r '.verdict // "?"' "evidence/$gname")
      if [ "$gv" = "PASS" ]; then
        ok "station gate verdict: PASS"
      else
        fail "station gate verdict is '$gv' — the publisher's own scope gate did not pass for this release"
      fi
      want_c=$(jq -r '.contract_id // ""' "$POLICY")
      got_c=$(jq -r '.contract.sha256 // ""' "evidence/$gname")
      if [ "$got_c" = "$CONTRACT_SHA" ]; then
        ok "station gate ran against THIS contract revision (sha256:$(printf %.12s "$CONTRACT_SHA")…)"
      else
        fail "station gate ran against contract sha256:$(printf %.12s "$got_c")… but yours is sha256:$(printf %.12s "$CONTRACT_SHA")… ($want_c) — the scope that was enforced is not the scope you are asking for"
      fi
      for clause in allowed_namespaces allow_cluster_scoped pod_security \
                    allowed_image_registries resource_ceiling; do
        wv=$(jq -Sc --arg k "$clause" '.delivery_scope[$k] // null' "$POLICY")
        [ "$wv" = "null" ] && continue
        gvv=$(jq -Sc --arg k "$clause" '.delivery_scope_enforced[$k] // null' "evidence/$gname")
        if [ "$wv" = "$gvv" ]; then
          ok "delivery_scope.$clause enforced as $wv"
        else
          fail "delivery_scope.$clause: your contract says $wv, the gate enforced $gvv"
        fi
      done
    fi
  fi

  for kind in $(jq -r '.forbid_absent_evidence[]? // empty' "$POLICY"); do
    if jq -e --arg k "$kind" '.evidence_absent[] | select(.kind == $k)' entry.json >/dev/null; then
      reason=$(jq -r --arg k "$kind" '.evidence_absent[] | select(.kind == $k) | .reason' entry.json)
      fail "policy: '$kind' is declared ABSENT ($reason) and your policy requires it"
    else
      ok "policy: '$kind' not declared absent"
    fi
  done
fi

# --------------------------------------------- 7 · YOUR human gate (prod)
# The second human approval in the chain. Vexa's approval (§6) let the release
# onto the channel and into your staging; this one is yours and it governs
# your production. A machine cannot supply it: the check asks whether a NAMED
# PERSON in YOUR organisation approved this exact release, and refuses the
# sync if nobody did.
if [ -n "$REQUIRE_APPROVAL" ]; then
  echo "--- human approval required for $REQUIRE_APPROVAL"
  cm="vexa-approval-$REQUIRE_APPROVAL"
  if ! kubectl -n "$APPROVAL_NS" get configmap "$cm" >/dev/null 2>&1; then
    fail "no approval record for $REQUIRE_APPROVAL — a named person must approve it (kit/verify/approve.sh)"
  else
    by=$(kubectl -n "$APPROVAL_NS" get configmap "$cm" -o jsonpath='{.data.approved_by}' 2>/dev/null || echo "")
    at=$(kubectl -n "$APPROVAL_NS" get configmap "$cm" -o jsonpath='{.data.approved_at}' 2>/dev/null || echo "")
    vd=$(kubectl -n "$APPROVAL_NS" get configmap "$cm" -o jsonpath='{.data.verdict}' 2>/dev/null || echo "")
    rel=$(kubectl -n "$APPROVAL_NS" get configmap "$cm" -o jsonpath='{.data.release}' 2>/dev/null || echo "")
    if [ -z "$by" ]; then
      fail "approval record for $REQUIRE_APPROVAL names no approver"
    elif [ "$vd" != "ELIGIBLE" ]; then
      fail "approval record for $REQUIRE_APPROVAL carries verdict '$vd', not ELIGIBLE"
    elif [ "$rel" != "$REQUIRE_APPROVAL" ]; then
      fail "approval record names release '$rel', not '$REQUIRE_APPROVAL'"
    else
      ok "approved by $by at $at"
    fi
  fi
fi

# ----------------------------------------------------------------- verdict
echo "---"
if [ "$FAILED" -gt 0 ]; then
  echo "VERDICT: NOT ELIGIBLE — $FAILED check(s) failed" >&2
  exit 1
fi
release=$(jq -r '.release.version' entry.json)
if [ -n "$CONTRACT_ID" ]; then
  echo "VERDICT: ELIGIBLE — $release verified against contract $CONTRACT_ID @ sha256:$CONTRACT_SHA"
else
  echo "VERDICT: ELIGIBLE — $release satisfies every check (no contract file supplied)"
fi

# ------------------------------------------------- the verdict, as a FILE
#
# Only ELIGIBLE verdicts are ever written: a failed verification exits above and
# produces nothing, which is what the schema means by "a failed verification
# simply produces no attestation".
#
# The subject is the entry's image digest set, verbatim — the same set the
# consuming verifier matches against, so a verdict cannot be transplanted onto a
# different release. Predicate shape and required fields:
# spec/station-verdict-attestation.schema.json (additionalProperties: false).
if [ -n "$VERDICT_OUT" ]; then
  vlog_sha=""
  if [ -n "$VERDICT_LOG" ] && [ -f "$VERDICT_LOG" ]; then
    vlog_sha=$(sha256sum "$VERDICT_LOG" | cut -d' ' -f1)
  fi
  at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  # jq builds it so the digest set is copied, never retyped.
  jq -n \
    --slurpfile entry entry.json \
    --arg release "$release" \
    --arg station "$STATION" \
    --arg contract_id "$CONTRACT_ID" \
    --arg contract_sha256 "$CONTRACT_SHA" \
    --arg at "$at" \
    --arg vlog "$vlog_sha" \
    --arg entry_ref "$ENTRY_REF" \
    '{
      _type: "https://in-toto.io/Statement/v1",
      subject: [ $entry[0].images[]
                 | { name: .name,
                     digest: { "sha256": (.index_digest | sub("^sha256:"; "")) } } ],
      predicateType: "https://vexa.ai/attestations/station-verdict/v1",
      predicate: ({
        release: $release,
        station: $station,
        contract_id: $contract_id,
        contract_sha256: $contract_sha256,
        verdict: "ELIGIBLE",
        at: $at,
        source: $entry_ref
      } + (if $vlog == "" then {} else { verdict_log_sha256: $vlog } end))
    }' > "$VERDICT_OUT"
  ok "verdict written to $VERDICT_OUT (station $STATION)"
  if [ -z "$vlog_sha" ]; then
    echo "NOTE  no --verdict-log given, so the predicate carries no verdict_log_sha256;"
    echo "      the signed claim is then not bound to a transcript of this run."
  fi
fi
