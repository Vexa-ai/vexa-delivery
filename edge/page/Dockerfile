# SPDX-License-Identifier: Apache-2.0
#
# THE CHANNEL PAGE. Build context is THIS DIRECTORY, not the repository root:
#
#     docker build -t vexa/page-edge:<tag> edge/page
#
# Same reasoning as edge/claim: this runs on an internet-facing host, so its
# build context is two Python files and nothing else — no publisher tool, no
# ledger, no kit, no `.git`, because none of it was ever in the context to be
# copied by accident. It differs from the claim edge in one way that matters:
# THIS SERVICE HOLDS NO SECRET AT ALL. No identity file, no htpasswd, no spool,
# no writable path. It reads the registry with the CALLER's credential and
# forgets it when the response is written.
#
# CONTENTS, and nothing else:
#   python3   the service; standard library only, no web framework
#
# NOT BUILT AND NOT DEPLOYED by the change that added this file. The live edge
# is founder-owned (`prod:own`); README.md § Deploy is the note for whoever
# does it. Nobody has run this image.

# The same base and digest the kit runtime image already pins, rather than a
# second pin resolved on a different day: one fewer base to track, and this one
# is already vouched for by an image in this repository.
FROM python:3.12-slim-bookworm@sha256:4427763a1ba36f5aa8f656a03e5d00f3b8d61f5dd950c73df6c14f8c7640f8ab

# The upstream is the edge's own HTTPS origin, so a missing trust store would
# make every render fail at the customer and nowhere else. Asserted rather than
# assumed — and asserted rather than `apt-get install`ed, because the base does
# ship one and reinstalling it would hide the day it stops.
RUN test -s /etc/ssl/certs/ca-certificates.crt \
    || { echo "no CA bundle in the base image; the upstream is HTTPS"; exit 1; }

COPY vexa_page.py page_edge.py /app/

# Non-root, and owner of nothing. There is no spool and no identity to own: the
# container needs no writable path at all, which is what `read_only: true` in
# compose.yaml then costs nothing to enforce.
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PAGE_LISTEN=0.0.0.0:8089
WORKDIR /app
EXPOSE 8089

# Ask the SERVING PROCESS over the socket. `--check` validates configuration in
# a fresh process, which is the right thing to run by hand before the first
# start and the wrong thing as a healthcheck: it passes while the server is
# wedged.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["python3", "-c", \
  "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ['PAGE_LISTEN'].rsplit(':',1)[1]+'/healthz',timeout=4).read()"]

ENTRYPOINT ["python3", "/app/page_edge.py"]
