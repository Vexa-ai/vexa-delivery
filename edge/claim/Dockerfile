# SPDX-License-Identifier: Apache-2.0
#
# THE CLAIM EDGE. Build context is THIS DIRECTORY, not the repository root:
#
#     docker build -t vexa/claim-edge:<tag> edge/claim
#
# That is a deliberate difference from kit/runtime/Dockerfile, which needs the
# kit tree and builds from the root. This service runs on an internet-facing
# host and holds the age identity that opens every parked credential, so its
# build context is two Python files and nothing else — there is no publisher
# tool, no ledger, no kit, and no `.git` in the image because none of it was
# ever in the context to be copied by accident.
#
# CONTENTS, and nothing else:
#   python3   the service; standard library only, no web framework
#   age       the one thing it shells out to, for decryption
#
# NOT BUILT AND NOT DEPLOYED by the change that added this file. The live edge
# is founder-owned (`prod:own`); README.md § Deploy is the note for whoever
# does it. Nobody has run this image.

# Digest resolved from Docker Hub on 2026-09-06 and pinned, the way every other
# base in this repository is. Nobody has built this image, so the pin is a claim
# about what the registry served that day and nothing more.
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

# age from Debian's own archive rather than a release tarball: it is the same
# binary the operator uses at the other end of this exchange, and apt is the
# only supply chain on this host that already gets patched without us.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends age python3 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    age --version; python3 --version

COPY vexa_claim.py claim_edge.py /app/

# Non-root, and NOT the owner of the spool it reads. The spool is bind-mounted
# with this uid as its owner (see compose.yaml); running as root here would mean
# a bug in an HTTP handler holds root on a host that also runs the registry.
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CLAIM_LISTEN=0.0.0.0:8088 \
    CLAIM_SPOOL=/spool \
    CLAIM_IDENTITY=/identity/claim-edge.key
WORKDIR /app
EXPOSE 8088

# The healthcheck asks the SERVING PROCESS, over the socket. `--check` validates
# configuration in a fresh process, which is the right thing to run by hand
# before the first start (a missing identity, a group-readable identity, a
# missing `age`, an unwritable spool — all otherwise invisible until the call
# where somebody reads a code aloud) and the wrong thing to run as a healthcheck,
# because it passes while the server is wedged.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["python3", "-c", \
  "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ['CLAIM_LISTEN'].rsplit(':',1)[1]+'/healthz',timeout=4).read()"]

ENTRYPOINT ["python3", "/app/claim_edge.py"]
