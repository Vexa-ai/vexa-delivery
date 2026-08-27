{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{/*
The sender's pod spec, shared by the PostSync receipt Job and the cadenced
CronJob. ONE definition on purpose: two copies of a pod spec is two RBAC
postures, two credential mounts and two security contexts that drift apart
silently — and the one that drifts is always the one nobody looks at.
*/}}
{{- define "vexa.receiptSender.podSpec" -}}
serviceAccountName: vexa-receipt-sender
restartPolicy: Never
{{- /*
A SENDER THAT CANNOT BE SCHEDULED SENDS NOTHING (prod, 2026-08-26).

The fifth defect of one shape, and the fourth was the PreSync verify gate three
days earlier — same cluster, same cause, same symptom. Our production LKE has a
single node pool tainted `vexa.ai/pool=main:NoSchedule`. Both sender shapes
rendered with no tolerations and no nodeSelector, so the PostSync receipt Job's
pod sat Pending on "untolerated taint" until `activeDeadlineSeconds` fired and
the Job went DeadlineExceeded. The sync reported a failed hook; the receipt was
never collected, and the failure named the deadline rather than the taint.

This is a POD PLACEMENT problem and it belongs to whoever owns the cluster, so
it is a value and not a hard-coded toleration — the same reasoning that keeps a
subscriber's registry address out of the verify gate's NetworkPolicy.

The defaults are EMPTY and rendered with `with`, so an estate that asks for no
placement gets a pod spec with neither key present: every existing subscriber's
render is byte-identical, which is what makes the 1.0.6 → 1.0.7 diff readable.

ONE definition, both shapes. The Job and the CronJob share this pod spec (and a
test asserts they are equal), so placement cannot arrive on one cadence and be
missing from the other — which is exactly how the CronJob would have inherited
the same Pending three months from now with nobody watching.
*/}}
{{- with .Values.receiptSender.nodeSelector }}
nodeSelector:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .Values.receiptSender.tolerations }}
tolerations:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .Values.receiptSender.imagePullSecrets }}
imagePullSecrets:
{{ toYaml . | indent 2 }}
{{- end }}
{{- /*
THE CONTRACT THE SENDER READS IS NOT THE CONTRACT THE GATE READS, and until
1.0.6 this mount quietly assumed they were the same object.

The sender passes `--contract /contract/contract.yaml` and the tool reads
`report_scope` off it — tier, trigger, destination, allowed_files. That is the
station's own REPORT contract. `templates/contracts.yaml` renders a different
document — publication mode, evidence kinds, attestations — under the key
`policy.json`, into the ARGOCD namespace, for the PreSync verify gate. The
default `contractConfigMap` used to name one of those (`vexa-contract-prod`),
so the mount asked the argocd namespace's gate policy for a key it does not
have, from a namespace the sender's ServiceAccount cannot read. Two documents,
one name.

REFERENCE, NOT RENDER. The chart names the ConfigMap; the OPERATOR creates it,
in the station namespace, with the key `contract.yaml`. The report contract is
the customer's own declaration of what may leave their perimeter — a chart that
rendered its content would make Vexa the author of the document that bounds
Vexa, and the tier would then have two authorities that could disagree.

`items` NAMES THE KEY on purpose. Without it a ConfigMap holding some other key
mounts happily and the pod fails deep inside the tool on a missing file; with
it the kubelet refuses to start the pod and says which key is absent.
*/}}
volumes:
  - name: contract
    configMap:
      name: {{ .Values.receiptSender.contractConfigMap | quote }}
      items:
        - {key: contract.yaml, path: contract.yaml}
  - name: work
    emptyDir: {}
containers:
  - name: sender
    image: {{ .Values.receiptSender.image | quote }}
    command: ["/bin/sh", "-c"]
    args:
      - |
        set -eu
        # The contract rides in as a FILE and the tool reads the tier off it.
        # The values below say which app and which pin; they do not say which
        # rung, and cannot: the rung is the customer's declaration and lives
        # in the contract only.
        exec python3 /kit/validate/vexa_validate.py \
          --report \
          --namespace "$TARGET_NAMESPACE" \
          --contract /contract/contract.yaml \
          --station "$STATION_NAME" \
          --out /work \
          {{- if .Values.receiptSender.app }}
          --app "$ARGO_APP" \
          {{- end }}
          {{- if .Values.receiptSender.pin }}
          --pin "$PIN" \
          {{- end }}
          {{- if .Values.receiptSender.entrySeq }}
          --entry-seq "$ENTRY_SEQ" \
          {{- end }}
          {{- if .Values.receiptSender.entryDigest }}
          --entry-digest "$ENTRY_DIGEST" \
          {{- end }}
          {{- if ne (int .Values.receiptSender.windowHours) 24 }}
          --window-hours "$WINDOW_HOURS" \
          {{- end }}
          {{- if eq .Values.scope "namespace" }}
          --namespace-scoped \
          {{- end }}
          --submit --submit-destination "$SUBMIT_DESTINATION"{{ if .Values.receiptSender.dryRun }} --submit-dry-run{{ end }}
    env:
      - {name: TARGET_NAMESPACE, value: {{ .Values.prodNamespace | quote }}}
      - {name: STATION_NAME, value: {{ .Values.receiptSender.station | quote }}}
      - {name: SUBMIT_DESTINATION, value: {{ .Values.receiptSender.destination | quote }}}
      - {name: ARGO_APP, value: {{ .Values.receiptSender.app | quote }}}
      - {name: PIN, value: {{ .Values.receiptSender.pin | quote }}}
      - {name: ENTRY_SEQ, value: {{ .Values.receiptSender.entrySeq | quote }}}
      - {name: ENTRY_DIGEST, value: {{ .Values.receiptSender.entryDigest | quote }}}
      - {name: WINDOW_HOURS, value: {{ .Values.receiptSender.windowHours | quote }}}
      # FROM THE ENVIRONMENT, NEVER ARGV — a password on a command line lands
      # in every process listing on the node and in the pod's own spec.
      - name: VEXA_CHANNEL_USER
        valueFrom:
          secretKeyRef:
            name: {{ .Values.receiptSender.credentialSecret | quote }}
            key: username
      - name: VEXA_CHANNEL_PASS
        valueFrom:
          secretKeyRef:
            name: {{ .Values.receiptSender.credentialSecret | quote }}
            key: password
      - {name: HOME, value: /work}
    volumeMounts:
      - {name: contract, mountPath: /contract, readOnly: true}
      - {name: work, mountPath: /work}
    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: {drop: ["ALL"]}
      seccompProfile: {type: RuntimeDefault}
    resources:
      requests: {cpu: 50m, memory: 128Mi}
      limits:   {cpu: 500m, memory: 512Mi}
{{- end }}
