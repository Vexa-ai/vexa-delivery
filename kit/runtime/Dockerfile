# SPDX-License-Identifier: Apache-2.0
#
# THE KIT RUNTIME IMAGE — what the station chart's receipt sender actually runs.
#
# Through station chart 1.0.5 `receiptSender.image` had nothing to point at.
# The channel carried the kit as a TARBALL (`application/vnd.vexa.kit`, for an
# operator to unpack on a workstation), and a tarball is not something a Job
# can exec. So the sender was publishable, renderable, and unrunnable.
#
# Build context is the REPOSITORY ROOT, not this directory: the image carries
# the kit tree AND `station/chart/Chart.yaml`, because the tool stamps the
# station chart version into every receipt it produces (see
# `station_chart_version()` in kit/validate/vexa_validate.py) and reads it
# relative to the kit's parent.
#
#     docker build -f kit/runtime/Dockerfile -t <ref> .
#
# CONTENTS, AND NOTHING ELSE — the four things `vexa_validate.py --report
# --submit` shells out to or imports:
#
#   python3      the tool itself
#   PyYAML       reads the mounted contract
#   jsonschema   validates report.v1 BEFORE anything leaves the perimeter
#   kubectl      the T1-T3 collectors read workload STATUS with it
#   oras         `oras push` — the submit
#
# NO COSIGN, deliberately. The sender neither signs nor verifies: it produces a
# bundle and pushes it. Signature verification on this estate is Kyverno's job
# at admission and the PreSync verifier's job at sync, both of which have their
# own images. A cosign binary here would be an unused ~40MB of attack surface
# in a pod that holds a channel credential.
#
# NO GIT, and no `.git`. `git_revision()` degrades to a KIT_REVISION file
# written at build time — see below — rather than pulling a VCS into a
# production pod so that a provenance field can be non-null.
#
# THIS IMAGE IS ADMISSION-CHECKED. Its published reference contains `vexaai/`,
# which is exactly what the station's Kyverno ClusterPolicies match on: it must
# be referenced by digest and its cosign signature must live in the station's
# `signatureRepository` — the SAME repository the app images use, not the
# station-chart signature repository. An image signed in the wrong repository
# and an unsigned image are indistinguishable at admission; both deny.

# ---------------------------------------------------------------- kubectl
# Fetched and CHECKSUMMED in a builder stage. The published sha256 is pinned
# here, so a substituted binary fails the build rather than shipping.
# 1.35 matches the LKE version this estate runs (infra/main.tf k8s_version).
FROM python:3.12-slim-bookworm@sha256:4427763a1ba36f5aa8f656a03e5d00f3b8d61f5dd950c73df6c14f8c7640f8ab AS tools
ARG KUBECTL_VERSION=v1.35.4
ARG KUBECTL_SHA256=b529430df69a688fd61b64ad2299edb5fd71cb58be2a4779dba624c7d3510efd
RUN set -eu; \
    apt-get update && apt-get install -y --no-install-recommends curl ca-certificates; \
    curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"; \
    echo "${KUBECTL_SHA256}  /tmp/kubectl" | sha256sum -c -; \
    install -m 0755 /tmp/kubectl /usr/local/bin/kubectl; \
    kubectl version --client=true

# ---------------------------------------------------------------- runtime
FROM python:3.12-slim-bookworm@sha256:4427763a1ba36f5aa8f656a03e5d00f3b8d61f5dd950c73df6c14f8c7640f8ab

COPY --from=tools /usr/local/bin/kubectl /usr/local/bin/kubectl
COPY --from=ghcr.io/oras-project/oras:v1.3.0 /bin/oras /usr/local/bin/oras

# Pinned, and only these two. `--no-cache-dir` so the layer carries the
# packages and not a wheel cache nothing will ever read again.
RUN pip install --no-cache-dir PyYAML==6.0.2 jsonschema==4.23.0

# THE LAYOUT IS LOAD-BEARING and it is not `/kit` alone.
#
# The tool resolves its own file to find KIT, then KIT.parent to find the repo
# root, and reads `station/chart/Chart.yaml` from there. Unpacked at `/kit` the
# repo root would be `/`, so the station chart version — the one field in a
# receipt that says which machinery produced it — would be null on every
# receipt this image ever sends.
#
# So the tree lives at /opt/vexa-delivery and `/kit` is a SYMLINK to it.
# `Path.resolve()` follows the symlink, so the tool sees the real root, while
# the station chart's command line (`python3 /kit/validate/vexa_validate.py`)
# keeps working unchanged.
COPY kit /opt/vexa-delivery/kit
COPY station/chart/Chart.yaml /opt/vexa-delivery/station/chart/Chart.yaml
RUN ln -s /opt/vexa-delivery/kit /kit

# Provenance without a VCS. `git_revision()` prefers this file when git is not
# available, so a receipt names the exact commit the kit came from.
ARG KIT_COMMIT=unknown
ARG KIT_DESCRIBE=unknown
RUN printf 'commit=%s\ndescribe=%s\n' "$KIT_COMMIT" "$KIT_DESCRIBE" \
      > /opt/vexa-delivery/KIT_REVISION

# The chart runs this pod with runAsUser 65532, runAsNonRoot, and a READ-ONLY
# root filesystem; HOME is an emptyDir at /work. Nothing above writes at
# runtime, so the image matches that posture rather than merely tolerating it.
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/work
WORKDIR /work

ENTRYPOINT ["python3", "/kit/validate/vexa_validate.py"]
