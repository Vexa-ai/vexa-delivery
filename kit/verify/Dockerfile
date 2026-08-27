# SPDX-License-Identifier: Apache-2.0
# The verifier image. Apache-2.0, source in this directory — every line that
# runs in your cluster is readable here. Built from Alpine plus three stock
# tools: cosign (signatures), oras (OCI pull), jq (JSON). Nothing of Vexa's
# is compiled in; the logic is the shell script beside this file.
FROM alpine:3.21
RUN apk add --no-cache ca-certificates jq coreutils curl kubectl
COPY --from=ghcr.io/sigstore/cosign/cosign:v3.1.3 /ko-app/cosign /usr/local/bin/cosign
COPY --from=ghcr.io/oras-project/oras:v1.3.0 /bin/oras /usr/local/bin/oras
COPY vexa-verify.sh /usr/local/bin/vexa-verify
RUN chmod +x /usr/local/bin/vexa-verify
ENTRYPOINT ["/usr/local/bin/vexa-verify"]
