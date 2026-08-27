# VERIFY — offline verification of this channel entry

No network access and no call to Vexa is required; the bundle carries the
Sigstore trusted root. Run from this directory.

## 1 · Entry signature

```
cosign verify-blob --key <channel.pub> --bundle entry.json.sigstore.json \
  --new-bundle-format entry.json
```

The signing identity this entry declares: `sha256:20dd1eecd535f88d995f057a6b9dbade9aa3671907778490a4828ed429396748`
(mode `test_key`).

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
cosign verify-blob-attestation \
  --bundle evidence/source-provenance.sigstore.json --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/Vexa-ai/vexa/' \
  <path-to>/vexa-core-v0.12.23.tar.gz
```

The archive's sha256 must equal `6cc8ac6d9b992696abafbefc00056a41f41dbf9eac46013d315a834436cca8b3`.

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

## What this entry does NOT claim

- **image_provenance**: per-image SLSA attestations not produced by the OSS pipeline yet (vexa PRD §12 C1); images bind to source via the sha-pinned candidate map
- **chart**: OCI chart publishing pending (vexa PRD §12 C1); the OSS chart ships in the Vexa-ai/vexa tree
