# mibee-steward Helm chart (#623)

The center on Kubernetes/k3s. Architecture is **single-instance by design**:
state lives in SQLite (WAL) on a ReadWriteOnce PVC — `replicas: 1` is locked
and the strategy is `Recreate` (two writers are not a topology). More LAN
coverage means more **agents**, not more center replicas.

The pod deliberately does **not** use hostNetwork: a pod has no meaningful
LAN presence to scan from. The intended shape is the hybrid — center in the
cluster, one agent per target LAN outside it, talking to `http://<release>-mibee-steward:8080` (or the ingress URL) — see the distributed docs.

## Install

```bash
# 1. Secrets FIRST (never in values): an Opaque secret with
#    MIBEE_AUTH_JWT_SECRET (32+ chars), MIBEE_SECURITY_MASTER_KEY (32 bytes),
#    MIBEE_AUTH_INITIAL_ADMIN_PASSWORD (empty = browser first-run setup).
kubectl create secret generic steward-secrets \
  --from-literal=MIBEE_AUTH_JWT_SECRET="$(openssl rand -base64 32)" \
  --from-literal=MIBEE_SECURITY_MASTER_KEY="$(openssl rand -base64 32)" \
  --from-literal=MIBEE_AUTH_INITIAL_ADMIN_PASSWORD=""

# 2. The center (agent tokens are minted in the UI after first login).
helm install steward deploy/helm/mibee-steward \
  --set secrets.existingName=steward-secrets
```

Eval without any pre-created secret: `--set secrets.create=true` renders one
with a random `jwt_secret` and the browser first-run password flow (master
key stays unset — v3 credential storage disabled; production must provide
it via the existing-secret path).

## Values to know

| Key | Default | Notes |
|---|---|---|
| `image.tag` | chart appVersion | pin a release tag in production |
| `persistence.{enabled,size,storageClass,existingClaim}` | true / 2Gi / "" / "" | RWO is the contract |
| `secrets.existingName` | "" | the production path for credentials |
| `ingress.*` | disabled | ingressClassName + TLS as usual |
| `config.*` | reserved-targets off | any `MIBEE_*` env key goes here |
