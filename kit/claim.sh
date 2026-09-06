#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# vexa-kit claim — turn a short code read aloud on a call into a Secret in your
# cluster, without the credential ever being visible to a person.
#
# Your channel credential is minted by Vexa, sealed to the channel edge's key,
# and parked under an eight-character code with a fifteen-minute life. This
# script presents the code, receives the credential over TLS, and writes it into
# `vexa-station-credential` (keys `username`/`password`) in the namespace you
# name. THE VALUE NEVER REACHES YOUR TERMINAL, your shell history, your
# scrollback, or a file. The receipt is the station name and the Secret name.
#
#   ./kit/claim.sh --code ABCD-EFGH --edge https://channel.example/claim \
#                  --station acme --namespace vexa-prod
#
# The code is single-use and dies on first success. Five wrong attempts burn it
# and it expires on its own; either way the fix is the same — ask for a new one,
# which rotates the credential rather than resending it.
#
# THIS FILE IS ALSO A LIBRARY. `kit/install.sh --claim-code` sources it and
# calls `vexa_claim_fetch` directly, so there is one implementation of the
# exchange and the credential exists in exactly one place: a shell variable in
# the process that needs it. An install that shelled out to this script would
# have to get the value back somehow, and every way of doing that — stdout, a
# file, an environment variable in a child — is a way of writing it down.
set -euo pipefail

# NOT `usage`: install.sh SOURCES this file and has a usage() of its own.
# A same-named function would silently replace it — harmless today because
# install.sh parses argv before it sources, and a trap for whoever moves the
# source line.
claim_usage() {
  cat <<'EOF'
usage: claim.sh --code <code> --edge <url> --station <name> \
                [--namespace <ns>] [--rotate] [--print-once]

required
  --code        the claim code, as read to you (case and dashes do not matter)
  --edge        the channel's claim endpoint, e.g. https://channel.example/claim
  --station     your station name, from your onboarding pack

writing the Secret (the normal path)
  --namespace   namespace to write the Secret into. Required unless --print-once
  --secret-name Secret to write (default: vexa-station-credential, the name the
                station bundle expects; keys username/password)
  --rotate      overwrite a Secret that already exists. Without it an existing
                Secret is a refusal, because replacing a working credential by
                accident is indistinguishable from a rotation until the next pull
  --kubeconfig  kubeconfig path (default: ambient)

the mirror path
  --print-once  print the credential to stdout instead of writing a Secret, for
                pasting into a registry mirror's endpoint configuration (Harbor,
                Artifactory, ECR) that has no way to read a Kubernetes Secret.
                It is the ONE path here that puts the value on your screen: the
                code is spent either way, so the value is now yours to keep or
                lose. Never both --print-once and --namespace

other
  --dry-run     print what would happen; contact nothing, write nothing
EOF
  exit 2
}

# --------------------------------------------------------------------------
# The library half. Both this script's main() and install.sh call these.
# --------------------------------------------------------------------------

# vexa_claim_fetch <code> <edge> <station>
# On success sets VEXA_CLAIM_USER and VEXA_CLAIM_PASS in the CALLER's shell.
# Neither value is ever echoed, written, or passed as an argument to anything.
vexa_claim_fetch() {
  local code=$1 edge=$2 station=$3 payload response http body

  # The code goes to curl through a PIPE, never on its command line: argv is
  # world-readable in /proc and in `ps` output for the life of the process.
  # A here-string would do as well on bash 5.1+ and writes a temp file on the
  # bash 3.2 that ships with macOS, so it is a pipe.
  payload=$(printf '{"code":"%s","station":"%s"}' "$code" "$station")

  set +e
  response=$(printf '%s' "$payload" | curl -sS -X POST \
    -H 'Content-Type: application/json' -H 'Accept: application/json' \
    --data-binary @- -w '\n%{http_code}' --max-time 30 "$edge" 2>&1)
  local rc=$?
  set -e
  if [ $rc -ne 0 ]; then
    echo "claim: could not reach $edge (curl exit $rc)" >&2
    echo "  $response" >&2
    return 1
  fi

  http=${response##*$'\n'}
  body=${response%$'\n'*}

  if [ "$http" != "200" ]; then
    # The edge answers every refusal identically on purpose — wrong code,
    # expired, already claimed, burned, rate-limited all look the same, so that
    # a guesser learns nothing from the difference. That means this message
    # cannot tell you which it was either, and listing them is the honest
    # substitute for a reason the protocol deliberately withholds.
    echo "claim: the edge refused this claim (HTTP $http)." >&2
    echo "  The code may be wrong, expired (they live ~15 minutes), already" >&2
    echo "  used, burned by failed attempts, or bound to another station." >&2
    echo "  The edge answers all of those the same way. Ask for a new code —" >&2
    echo "  a re-issue rotates the credential rather than resending it." >&2
    return 1
  fi

  # Parsed through a pipe for the same reason it was sent through one.
  VEXA_CLAIM_USER=$(printf '%s' "$body" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["username"])') || {
      echo "claim: the edge answered 200 with a body this kit cannot read" >&2
      return 1
    }
  VEXA_CLAIM_PASS=$(printf '%s' "$body" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["password"])')
  if [ -z "$VEXA_CLAIM_USER" ] || [ -z "$VEXA_CLAIM_PASS" ]; then
    echo "claim: the edge returned an empty credential" >&2
    return 1
  fi
  return 0
}

# vexa_claim_write_secret <namespace> <secret-name> <user> <pass> [kubectl args...]
# Writes the Secret from STDIN as a manifest. `kubectl create secret
# --from-literal` would put the password in argv, which is the one place this
# whole design exists to keep it out of.
vexa_claim_write_secret() {
  local ns=$1 name=$2 user=$3 pass=$4; shift 4
  local u_b64 p_b64
  # printf is a bash builtin: no exec, so nothing appears in a process listing.
  u_b64=$(printf '%s' "$user" | base64 | tr -d '\n')
  p_b64=$(printf '%s' "$pass" | base64 | tr -d '\n')
  kubectl "$@" -n "$ns" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${name}
  namespace: ${ns}
  labels:
    app.kubernetes.io/name: vexa-station
    app.kubernetes.io/component: channel-credential
type: Opaque
data:
  username: ${u_b64}
  password: ${p_b64}
EOF
}

# --------------------------------------------------------------------------
# The CLI half. Runs only when this file is executed, not when it is sourced.
# --------------------------------------------------------------------------

claim_main() {
  local CODE="" EDGE="" STATION="" NAMESPACE="" SECRET_NAME="vexa-station-credential"
  local ROTATE=false PRINT_ONCE=false DRY_RUN=false
  local KUBECONFIG_ARG=()

  while [ $# -gt 0 ]; do
    case "$1" in
      --code) CODE=$2; shift 2;;
      --edge) EDGE=$2; shift 2;;
      --station) STATION=$2; shift 2;;
      --namespace) NAMESPACE=$2; shift 2;;
      --secret-name) SECRET_NAME=$2; shift 2;;
      --kubeconfig) KUBECONFIG_ARG=(--kubeconfig "$2"); shift 2;;
      --rotate) ROTATE=true; shift;;
      --print-once) PRINT_ONCE=true; shift;;
      --dry-run) DRY_RUN=true; shift;;
      *) claim_usage;;
    esac
  done

  [ -n "$CODE" ] && [ -n "$EDGE" ] && [ -n "$STATION" ] || claim_usage
  if $PRINT_ONCE && [ -n "$NAMESPACE" ]; then
    echo "claim: --print-once and --namespace are different deliveries of the same" >&2
    echo "  single-use code; pick one. The code is spent by whichever runs first." >&2
    exit 2
  fi
  if ! $PRINT_ONCE && [ -z "$NAMESPACE" ]; then claim_usage; fi

  kc() { kubectl ${KUBECONFIG_ARG[@]+"${KUBECONFIG_ARG[@]}"} "$@"; }

  if $DRY_RUN; then
    echo "== dry run: nothing is contacted and nothing is written"
    echo "   POST $EDGE  {\"code\": \"<the code>\", \"station\": \"$STATION\"}"
    if $PRINT_ONCE; then
      echo "   then print the credential to stdout, once"
    else
      echo "   then write Secret $SECRET_NAME (username/password) in namespace $NAMESPACE"
    fi
    return 0
  fi

  # The existence check happens BEFORE the claim. The code is single-use, so
  # discovering the conflict afterwards would leave the credential claimed,
  # unwritten and unrecoverable — one wasted code and one rotation, for a
  # condition that was knowable without spending anything.
  if ! $PRINT_ONCE; then
    if kc -n "$NAMESPACE" get secret "$SECRET_NAME" >/dev/null 2>&1 && ! $ROTATE; then
      echo "claim: Secret '$SECRET_NAME' already exists in namespace '$NAMESPACE'." >&2
      echo "  Pass --rotate if you mean to replace it. Replacing a working" >&2
      echo "  credential by accident looks identical to a rotation until the" >&2
      echo "  next pull fails." >&2
      exit 1
    fi
  fi

  vexa_claim_fetch "$CODE" "$EDGE" "$STATION" || exit 1

  if $PRINT_ONCE; then
    echo "# WARNING: this credential is on your screen and in this terminal's" >&2
    echo "#   scrollback. The claim code is now spent — nobody can re-read this" >&2
    echo "#   value, here or anywhere. Paste it into your mirror's endpoint" >&2
    echo "#   configuration and close this terminal." >&2
    printf '%s:%s\n' "$VEXA_CLAIM_USER" "$VEXA_CLAIM_PASS"
    return 0
  fi

  vexa_claim_write_secret "$NAMESPACE" "$SECRET_NAME" \
    "$VEXA_CLAIM_USER" "$VEXA_CLAIM_PASS" \
    ${KUBECONFIG_ARG[@]+"${KUBECONFIG_ARG[@]}"}

  # The receipt. Everything a support ticket needs and nothing a screenshot
  # should not carry.
  echo "claimed: station $STATION"
  echo "  secret:    $SECRET_NAME (keys username, password)"
  echo "  namespace: $NAMESPACE"
  echo "  the code is now spent; the credential is in the cluster and nowhere else"
}

# Executed, not sourced: run. `${BASH_SOURCE[0]}` equals `$0` only when this
# file IS the script bash was invoked on.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  claim_main "$@"
fi
