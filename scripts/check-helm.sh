#!/usr/bin/env bash
# Helm runtime-contract assertions: config path, persistent state path, PVC
# selection and non-root posture must stay aligned with the release image.
set -euo pipefail
cd "$(dirname "$0")/.."

chart="deploy/helm/mibee-steward"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

helm template steward "$chart" --set secrets.existingName=steward-secrets > "$tmp/prod.yaml"
grep -q 'mountPath: /app/configs/config.yaml' "$tmp/prod.yaml"
grep -q 'mountPath: /data' "$tmp/prod.yaml"
grep -q 'claimName: steward-mibee-steward-data' "$tmp/prod.yaml"
grep -q 'runAsNonRoot: true' "$tmp/prod.yaml"
grep -q 'allowPrivilegeEscalation: false' "$tmp/prod.yaml"
if grep -q '/opt/mibee-steward/data' "$tmp/prod.yaml"; then
  echo "chart still mounts the obsolete /opt data path" >&2
  exit 1
fi

helm template steward "$chart" --set secrets.create=true > "$tmp/eval.yaml"
grep -q 'claimName: steward-mibee-steward-data' "$tmp/eval.yaml"

helm template steward "$chart" --set persistence.enabled=false > "$tmp/ephemeral.yaml"
grep -q 'emptyDir: {}' "$tmp/ephemeral.yaml"

echo "Helm runtime contract: config=/app/configs/config.yaml data=/data PVC/non-root OK"
