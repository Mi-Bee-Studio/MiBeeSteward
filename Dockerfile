# Stage 1: Frontend build (SvelteKit SPA)
FROM node:20-alpine AS frontend
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ .
RUN npm run build

# Stage 2: Backend build (Go binary)
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/web/dist ./web/dist/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mibee-steward ./cmd/server/

# Stage 3: Runtime image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user
RUN addgroup -S mibee && adduser -S mibee -G mibee
COPY --from=builder /mibee-steward /usr/local/bin/mibee-steward
WORKDIR /app
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/v1/health || exit 1

USER mibee
CMD ["mibee-steward", "-config", "/app/configs/config.yaml"]
