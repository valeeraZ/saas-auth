{{- define "saas-auth.image" -}}
{{- $image := required "An immutable image reference is required for every workload" . -}}
{{- if not (regexMatch "^.+@sha256:[a-f0-9]{64}$" $image) -}}
{{- fail "Images must use repository@sha256:<64 lowercase hex>" -}}
{{- end -}}
{{- $image -}}
{{- end -}}
{{- define "saas-auth.security" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}
