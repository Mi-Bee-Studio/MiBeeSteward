{{/*
mibee-steward chart helpers (#623).
*/}}
{{- define "mibee-steward.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mibee-steward.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "mibee-steward.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "mibee-steward.labels" -}}
app.kubernetes.io/name: {{ include "mibee-steward.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mibee-steward.secretName" -}}
{{- if .Values.secrets.existingName }}
{{- .Values.secrets.existingName }}
{{- else }}
{{- include "mibee-steward.fullname" . }}
{{- end }}
{{- end }}
