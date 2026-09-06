#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# No two rendered objects share a name — rehearsal defect 5.
#
# `install.sh` gave the Argo REPOSITORY Secret (Opaque, in ARGOCD_NS) and the
# KUBELET PULL Secret (kubernetes.io/dockerconfigjson, in each workload
# namespace) the same name: `vexa-channel-registry`. They never collided only
# because ARGOCD_NAMESPACE defaults to `argocd`. On ONE PROJECT — the shape the
# openshift profile exists for — they are one object: the second create failed
#
#     type: Invalid value: "kubernetes.io/dockerconfigjson": field is immutable
#
# and all nine ServiceAccounts were left pointing imagePullSecrets at an Opaque
# Argo secret the kubelet cannot use — the ImagePullBackOff the 30-line comment
# in install.sh exists to prevent, reintroduced by a namespace choice.
#
# The assertion is the general property, not the one name: every metadata.name
# in the render is checked for duplicates, so the next collision fails here too.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/kubectl" <<'EOF'
#!/usr/bin/env bash
# Echoes back the object it was asked to create, with the NAME it was given —
# which is the only thing this test reads.
case "$*" in *" -f -"*) cat >/dev/null;; esac
kind=""; name=""; prev=""
for a in "$@"; do
  case "$prev" in
    namespace) kind=Namespace; name=$a;;
    configmap) kind=ConfigMap; name=$a;;
    generic|docker-registry) kind=Secret; name=$a;;
  esac
  prev=$a
done
case "$*" in *jsonpath*) exit 0;; esac
[ -n "$kind" ] || exit 0
printf 'apiVersion: v1\nkind: %s\nmetadata:\n  name: %s\n' "$kind" "$name"
case "$*" in
  *"create secret docker-registry"*) printf 'type: kubernetes.io/dockerconfigjson\n';;
  *"create secret generic"*) printf 'type: Opaque\n';;
esac
exit 0
EOF
chmod +x "$TMP/kubectl"
export PATH="$TMP:$PATH"
echo "-----BEGIN PUBLIC KEY-----" > "$TMP/channel.pub"

fail() { echo "FAIL: $1" >&2; exit 1; }

export VEXA_CHANNEL_PASS='fixture-pass'
bash "$KIT/install.sh" --provider lke --registry reg.example:5000 \
  --channel acme-stable --channel-pubkey "$TMP/channel.pub" \
  --registry-user robot-vexa --skip-preflight --dry-run \
  --argocd skip --kyverno skip > "$TMP/render.txt" 2>&1 \
  || fail "install.sh --dry-run exited non-zero"

# The kubelet's Secret and Argo's repository Secret are now different objects
# with different names, and the render says so.
grep -q "name: vexa-channel-pull" "$TMP/render.txt" \
  || fail "the kubelet pull Secret is not named vexa-channel-pull"
REPO_NAMED=$(grep -c "^  name: vexa-channel-registry$" "$TMP/render.txt" || true)
[ "$REPO_NAMED" -eq 1 ] \
  || fail "vexa-channel-registry names $REPO_NAMED objects; exactly one (Argo's repository Secret) may carry it"

# ...and the general property, which is what stops the NEXT collision: one name
# may name only one kind of thing. The same Secret created in both workload
# namespaces is one object in two places and is fine; two DIFFERENT objects
# under one name are one object the moment those namespaces are the same, which
# is the whole defect.
python3 - "$TMP/render.txt" <<'PY' || exit 1
import collections, sys, yaml
blocks, cur = [], []
for line in open(sys.argv[1]):
    if line.startswith("--- would apply:"):
        blocks.append("".join(cur)); cur = []
    elif line.startswith("== ") or line.startswith("   "):
        continue
    else:
        cur.append(line)
blocks.append("".join(cur))

identities = collections.defaultdict(set)
for b in blocks:
    try:
        docs = list(yaml.safe_load_all(b))
    except yaml.YAMLError:
        continue
    for d in docs:
        if not isinstance(d, dict) or "kind" not in d:
            continue
        name = (d.get("metadata") or {}).get("name")
        if name:
            identities[name].add((d["kind"], d.get("type", "")))

bad = {n: v for n, v in identities.items() if len(v) > 1}
if bad:
    for n, v in sorted(bad.items()):
        print(f"FAIL: '{n}' names {len(v)} different objects: {sorted(v)}", file=sys.stderr)
    print("      On a single-namespace tenant these are ONE object, and the second "
          "create fails 'field is immutable'.", file=sys.stderr)
    sys.exit(1)
print(f"      checked {len(identities)} distinct object names, each naming one kind of thing")
PY

echo "PASS: install.sh object names (kubelet pull vs Argo repository, and no duplicates at all)"
