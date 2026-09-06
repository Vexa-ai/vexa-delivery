{{/*
VERBATIM from Vexa-ai/vexa, branch minutes-mcp-viewer @ 33379e2c4,
deploy/helm/charts/vexa/templates/_helpers.tpl lines 98-162.

Only the four IMAGE resolvers are copied. Everything else in that file (names,
labels, DSNs, topology spread) decides where a pod lands, not which bytes it
runs, and this fixture exists to answer exactly one question: does the
publisher's pin reach every image the minutes chart renders. Copying the whole
chart would put 3000 lines of unrelated template between the test and its
subject and would drift on every unrelated chart change.

If a resolver changes upstream, this file is stale and the test is lying — so
it names its source commit. See the module docstring of test_minutes_chart.py.
*/}}

{{/* The on-demand bot image the runtime spawns (BROWSER_IMAGE). The bot is published, never built by
this chart. runtime.browserImage is the explicit value; global.imageTag (set) pins the standard repo. */}}
{{- define "vexa.botImage" -}}
{{- if .Values.runtime.browserImage -}}
{{- .Values.runtime.browserImage -}}
{{- else if .Values.global.imageTag -}}
{{- printf "vexaai/vexa-bot:%s" .Values.global.imageTag -}}
{{- else -}}
vexaai/vexa-bot:v012
{{- end -}}
{{- end -}}

{{/* The agent-api image ref (AGENT_IMAGE the runtime spawns workers from). global.imageTag wins. */}}
{{- define "vexa.agentImage" -}}
{{- if .Values.global.imageTag -}}
{{- printf "%s:%s" .Values.agentApi.image.repository .Values.global.imageTag -}}
{{- else -}}
{{- .Values.runtime.agentImage | default (printf "%s:%s" .Values.agentApi.image.repository .Values.agentApi.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* The agent-worker image ref (AGENT_WORKER_IMAGE; the dedicated worker build — core/agent/worker/Dockerfile — NOT the agent-api image). */}}
{{- define "vexa.agentWorkerImage" -}}
{{- if .Values.global.imageTag -}}
{{- printf "vexaai/v012-agent-worker:%s" .Values.global.imageTag -}}
{{- else -}}
{{- .Values.runtime.agentWorkerImage | default "vexaai/v012-agent-worker:v012" -}}
{{- end -}}
{{- end -}}

{{/* The flows-tier image ref (flows-api + flows-worker + flows-mailbox + the ensure-db
initContainer — one image, four entrypoints). Same shape as vexa.botImage: an explicit
flows.image wins, otherwise global.imageTag pins the standard repo, otherwise the chart's own
default tag. It used to be a bare `vexaai/v012-flows:dev` value — a MUTABLE tag, and one the
release's build-once promotion could never pin, so the flows tier alone floated while every other
service moved to the release digest (A12). */}}
{{- define "vexa.flowsImage" -}}
{{- /* BOTH SHAPES, on purpose (0.12.27). `flows.image` is the STRUCTURED {repository, tag} every
other v0.12 component uses — it had to become one for #1537, because the publisher's pin injector
merges {flows: {image: {tag: <version>@sha256:...}}} over these values and merging a map over a
string drops the repository silently. It is ALSO still accepted as a FLAT REF string, which is how
a publisher digest-pins the whole tier in one value; that override wins over everything. Otherwise
the tag follows `global.imageTag` exactly like admin-api, gateway, meeting-api, runtime and
terminal do, so the flows tier can no longer float on a mutable `:dev` while the rest of a release
moves to its digest (A12). One resolver, six call sites. */}}
{{- $img := .Values.flows.image -}}
{{- if and (kindIs "string" $img) (ne ($img | toString) "") -}}
{{- $img -}}
{{- else -}}
{{- $repo := "vexaai/v012-flows" -}}
{{- $tag := "v012" -}}
{{- if .Values.flows.imageRepository -}}{{- $repo = .Values.flows.imageRepository -}}{{- end -}}
{{- if .Values.flows.imageTag -}}{{- $tag = .Values.flows.imageTag -}}{{- end -}}
{{- if kindIs "map" $img -}}
{{- if (get $img "repository") -}}{{- $repo = (get $img "repository") -}}{{- end -}}
{{- if (get $img "tag") -}}{{- $tag = (get $img "tag") -}}{{- end -}}
{{- end -}}
{{- if .Values.global.imageTag -}}{{- $tag = .Values.global.imageTag -}}{{- end -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}
