# MiBee Steward Dockerfile — multi-stage, CGO-free.
#
# Network-probe capabilities are governed at RUNTIME (docker compose cap_add /
# network_mode), not at build time. The default build is unprivileged and ships
# raw-frame LLDP/CDP + eBPF as no-op stubs (see internal/service/scannerv2/
# discovery/*_stub.go and scannerv2/ebpf/observer_stub.go). To bake the real
# privileged probes in, pass BUILD_TAGS at build time, e.g.:
#     docker compose --profile host build --build-arg BUILD_TAGS=WITH_LLDP,WITH_CDP,WITH_EBPF
# Runtime caps (cap_add: [NET_RAW,NET_ADMIN] / [BPF]) must still be granted.

# Stage 1: Frontend build (SvelteKit SPA)
FROM node:20-alpine AS frontend
WORKDIR /app/web
# Allow overriding the npm registry for builds behind a slow/restricted network
# (e.g. registry.npmmirror.com in CN). Defaults to the official registry.
ARG NPM_REGISTRY=https://registry.npmjs.org
COPY web/package.json web/package-lock.json* ./
RUN npm config set registry "${NPM_REGISTRY}" && npm ci
COPY web/ .
# Vite + SvelteKit SSR-compile can exceed node's default heap on larger apps.
# Raise to 2GB. NOTE: the build host needs >=2GB RAM (swap alone won't save a
# heap that grows faster than the kernel can page). On memory-starved VMs
# (e.g. 1GB), build the frontend outside docker (make build-frontend) and copy
# web/dist in, or build on a beefier machine and push the image.
ENV NODE_OPTIONS="--max-old-space-size=2048"
RUN npm run build

# Stage 2: Backend build (Go binary)
FROM golang:1.26-alpine AS builder
WORKDIR /app
# Default empty = unprivileged build (LLDP/CDP/eBPF compiled as stubs).
# Override via --build-arg BUILD_TAGS=WITH_LLDP,WITH_CDP,WITH_EBPF for the
# privileged variant; runtime caps must still be granted by the orchestrator.
ARG BUILD_TAGS=""
# Allow overriding the Go module proxy for builds behind a restricted network
# (e.g. https://goproxy.cn in CN). Defaults to the official proxy.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/web/dist ./web/dist/
RUN CGO_ENABLED=0 GOOS=linux go build -tags "${BUILD_TAGS}" -ldflags="-s -w" -o /mibee-steward ./cmd/server/

# Stage 3: Runtime image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata curl libcap

# Create non-root user
RUN addgroup -S mibee && adduser -S mibee -G mibee
COPY --from=builder /mibee-steward /usr/local/bin/mibee-steward

# Grant the binary file capabilities so a NON-ROOT process can open raw sockets
# (AF_PACKET for LLDP/CDP, privileged ICMP). This only takes effect when the
# container's bounding set already contains the cap — i.e. compose granted it
# via `cap_add: [NET_RAW, NET_ADMIN]`. Without that runtime grant the file cap
# is inert but, worse, exec() refuses to run a setcap binary if a granted file
# cap is NOT in the process bounding set — that breaks the default bridge image.
# So SETCAP is opt-in via build arg; default OFF for the unprivileged image.
# Build the privileged variant with: --build-arg SETCAP=1
ARG SETCAP=0
RUN if [ "${SETCAP}" = "1" ]; then \
        setcap 'cap_net_raw,cap_net_admin+ep' /usr/local/bin/mibee-steward; \
    fi

WORKDIR /app
EXPOSE 8080
# Pre-create /data owned by mibee so the non-root USER can write the SQLite DB
# on a freshly-created docker volume (volumes inherit the image's ownership the
# first time they're mounted; without this /data is owned by root).
RUN mkdir -p /data && chown -R mibee:mibee /data
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/v1/health || exit 1

USER mibee
CMD ["mibee-steward", "-config", "/app/configs/config.yaml"]
