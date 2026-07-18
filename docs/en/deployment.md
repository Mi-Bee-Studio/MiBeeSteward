# Deployment Guide

This guide covers production deployment methods for MiBee Steward, including Systemd, Docker, Nginx reverse proxy, backup strategy, monitoring, and device systems deployment.

## Overview

MiBee Steward is a device management and monitoring system with a Go backend (Chi + SQLite) and embedded SvelteKit SPA. It supports SNMP/ICMP/TCP/HTTP probing, Prometheus metrics collection, heartbeat monitoring, and device systems management with auto-discovery capabilities.

## Deployment Options

### 1. Systemd Deployment (Recommended)

#### Build the Binary

**From source:**
```bash
# Clone repository
git clone https://github.com/Mi-Bee-Studio/MiBeeSteward.git
cd mibee-steward

# Build binary
make build

# Or cross-compile
make build-linux-amd64
```

#### Create System User

```bash
# Create mibee user with no login shell
sudo useradd -r -s /usr/sbin/nologin -d /opt/mibee-steward mibee
```

#### Install Application Files

```bash
# Create installation directories
sudo mkdir -p /opt/mibee-steward
sudo mkdir -p /opt/mibee-steward/data
sudo mkdir -p /opt/mibee-steward/data/uploads
sudo mkdir -p /opt/mibee-steward/data/backups
sudo mkdir -p /opt/mibee-steward/configs

# Copy binary and configuration
sudo cp mibee-steward /opt/mibee-steward/
sudo cp -r configs/* /opt/mibee-steward/configs/

# Set permissions
sudo chown -R mibee:mibee /opt/mibee-steward
sudo chmod +x /opt/mibee-steward/mibee-steward
```

#### Configure Production Environment

```bash
# Copy production configuration template
sudo cp /opt/mibee-steward/configs/config.production.yaml /opt/mibee-steward/configs/config.yaml

# Edit configuration
sudo nano /opt/mibee-steward/configs/config.yaml
```

**Critical Production Settings:**

```yaml
auth:
  jwt_secret: "<random-32-char>"  # Generate with: openssl rand -base64 32
  initial_admin_password: "<strong-password>"
  cookie_secure: true
  cookie_same_site: "strict"
```

#### Install Systemd Service

```bash
# Copy service file
sudo cp deploy/mibee-steward.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable mibee-steward
sudo systemctl start mibee-steward

# Check status
sudo systemctl status mibee-steward
```

The service includes security hardening:
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ReadWritePaths=/opt/mibee-steward/data`

### 2. Docker Deployment

#### Multi-stage Dockerfile

The Dockerfile uses a three-stage build:
- **Stage 1**: Node 20 Alpine for frontend build (SvelteKit SPA)
- **Stage 2**: Go 1.26 Alpine for backend compilation
- **Stage 3**: Alpine 3.19 runtime image

#### Docker Compose Setup

```yaml
services:
  mibee-steward:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - mibee-data:/data
      - ./configs/config.yaml:/app/configs/config.yaml:ro
    environment:
      - MIBEE_SERVER_PORT=8080
    restart: unless-stopped

volumes:
  mibee-data:
```

**Build and Start:**
```bash
# Build Docker image
docker compose build

# Start services
docker compose up -d

# Check status
docker compose ps
docker compose logs -f
```

**Environment Variables:**
- `MIBEE_SERVER_PORT`: Server port (default: 8080)
- `MIBEE_AUTH_JWT_SECRET`: JWT secret (required)
- `MIBEE_AUTH_INITIAL_ADMIN_PASSWORD`: Admin password (required)

#### Docker Network Mode Selection (Important)

MiBee Steward's scanner operates at the network-namespace level, so **the container's network mode directly determines probe effectiveness**. `docker-compose.yml` ships three profiles — pick one by deployment intent:

| Profile | Start command | Probe effectiveness | Use case | Limitations |
|---|---|---|---|---|
| `bridge` (default) | `docker compose --profile bridge up` | Only TCP/SNMP/HTTP/TLS/RTSP/ONVIF reliable; **ICMP and ARP/MAC discovery severely degraded** | UI demo, dev, admin panel | Can't see the real LAN; device MACs are mostly lost |
| `host` (**recommended**) | `docker compose --profile host up` | ≈ bare-metal, full probe fidelity (ICMP, `/proc/net/arp`, multicast) | **Production scanning** | Takes the host's port 8080; needs `cap_add: NET_RAW,NET_ADMIN` |
| `macvlan` | `docker compose --profile macvlan up` | Container gets its own LAN IP; ARP/MAC work | When the container must appear on the LAN as its own device | Host↔container is unrouted by default (needs a manual macvlan shim interface) |

> ⚠️ **Why bridge mode can't be used for real inventory**
> The default Docker bridge places the container behind NAT. Consequences:
> 1. **ARP/MAC broken**: `/proc/net/arp` inside the container only sees the bridge gateway entry; LAN device MACs are essentially unrecoverable (`ARPProbe`, `ARPCacheSource`, `LookupMACPostScan` all read this file).
> 2. **ICMP broken**: ping replies crossing NAT are often dropped, so the heartbeat's 30s active probe falsely marks LAN devices offline.
> 3. **Passive multicast broken**: the bridge doesn't forward 224/239 multicast, so mDNS/SSDP listeners self-disable.
>
> Partial workaround: in bridge mode, list your gateway router IPs in `scanner.router_arp.routers` so the scanner can SNMP-walk the router's ARP table for MACs — but this only recovers MACs, not ICMP or multicast.

**Full host-mode example** (production):

```bash
# 1. Prepare config (from the container template)
cp configs/config.docker.yaml configs/config.yaml
#    Edit jwt_secret / initial_admin_password / network.cidr

# 2. Build and start (host profile — container shares the host netns)
docker compose --profile host up -d --build

# 3. Verify
curl -s http://localhost:8080/api/v1/health
```

To enable the raw-frame LLDP/CDP listeners or the eBPF passive observer (compiled out by default), pass build tags and grant the matching runtime caps:

```bash
# Build (bakes raw-frame LLDP/CDP + eBPF into the binary)
BUILD_TAGS=WITH_LLDP,WITH_CDP,WITH_EBPF docker compose --profile host build

# Runtime (eBPF additionally needs cap_add: BPF, kernel >=5.8 + BTF).
# The host profile in docker-compose.yml already declares NET_RAW + NET_ADMIN;
# append `- BPF` to cap_add if you enable eBPF.
```

**Building behind a restricted network** (when registry.npmjs.org / proxy.golang.org are unreachable):

```bash
NPM_REGISTRY=https://registry.npmmirror.com \
GOPROXY=https://goproxy.cn,direct \
docker compose --profile host build
```

The Makefile wraps common flows: `make docker-up` (= host profile, recommended), `make docker-up-bridge` (demo), `make docker-up-macvlan`, `make docker-build-priv` (privileged image variant).

### 3. Nginx Reverse Proxy

#### Configuration

Place the following configuration at `/etc/nginx/sites-available/mibee-steward`:

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL certificate configuration
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "0" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Proxy to mibee-steward
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Buffering
        proxy_buffering off;
        proxy_request_buffering off;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Max upload size (100MB)
        client_max_body_size 100m;
    }

    # Prometheus metrics - localhost only
    location /metrics {
        proxy_pass http://127.0.0.1:8080;
        allow 127.0.0.1;
        deny all;
    }
}
```

#### Enable and Test

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/mibee-steward /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

#### SSL Certificate Setup

**Let's Encrypt with Certbot:**
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Request certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### 4. Backup Strategy

#### Backup Script

The `scripts/backup.sh` script provides safe SQLite backups:

```bash
#!/usr/bin/env bash
# Usage: ./scripts/backup.sh [DB_PATH] [BACKUP_DIR] [RETENTION_DAYS]

# Default parameters
DB_PATH="${1:-./data/mibee.db}"
BACKUP_DIR="${2:-./data/backups}"
RETENTION_DAYS="${3:-7}"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Generate timestamp-based filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/mibee-${TIMESTAMP}.db"

# Check database exists
if [ ! -f "$DB_PATH" ]; then
    echo "ERROR: Database file not found: $DB_PATH" >&2
    exit 1
fi

# Perform safe backup (no database locking)
echo "Backing up ${DB_PATH} to ${BACKUP_FILE}..."
sqlite3 "$DB_PATH" ".backup '${BACKUP_FILE}'"

# Verify backup integrity
if sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" | grep -q "ok"; then
    SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "Backup completed successfully: ${BACKUP_FILE} (${SIZE})"
else
    echo "ERROR: Backup integrity check failed: ${BACKUP_FILE}" >&2
    rm -f "$BACKUP_FILE"
    exit 1
fi

# Remove old backups
find "$BACKUP_DIR" -name "mibee-*.db" -mtime +"$RETENTION_DAYS" -delete -print | wc -l
```

#### Scheduled Backups

**Systemd/Cron:**
```bash
# Copy backup script
sudo cp scripts/backup.sh /opt/mibee-steward/

# Set permissions
sudo chmod +x /opt/mibee-steward/scripts/backup.sh
sudo chown mibee:mibee /opt/mibee-steward/scripts/backup.sh

# Daily backup at 2 AM
sudo crontab -e
# Add: 0 2 * * * /opt/mibee-steward/scripts/backup.sh /opt/mibee-steward/data/mibee.db /opt/mibee-steward/data/backups 30
```

#### Restore Process

```bash
# Stop service
sudo systemctl stop mibee-steward

# Restore database
sqlite3 /opt/mibee-steward/data/mibee.db < /path/to/backup/mibee-20240101_120000.db

# Start service
sudo systemctl start mibee-steward
```

### 5. Monitoring

#### Health Checks

**Service Health:**
```bash
# Check service status
curl -s http://localhost:8080/api/v1/health
# Response: {"status":"ok","db":"ok","version":"0.1.0"}
```

**Prometheus Metrics:**
```bash
# View metrics (localhost only via nginx)
curl -s http://localhost:8080/metrics
```

**Key Metrics:**
- `mibee_devices_total`: Total number of devices
- `mibee_heartbeat_checks_total`: Total heartbeat checks performed
- `mibee_heartbeat_latency_seconds`: Heartbeat check latency

#### Log Monitoring

**Systemd Logs:**
```bash
# View service logs
sudo journalctl -u mibee-steward -f

# JSON format logs (recommended)
sudo journalctl -u mibee-steward -f -o json
```

#### Monitoring Dashboard

The embedded SvelteKit SPA provides:
- Real-time device status dashboard
- Heartbeat monitoring charts
- System performance metrics
- Device uptime statistics

## Configuration Reference

### Key Production Settings

| Setting | Description | Recommended Value |
|---------|-------------|------------------|
| `auth.jwt_secret` | JWT signing secret | `openssl rand -base64 32` |
| `auth.initial_admin_password` | Initial admin password | Strong password (12+ chars) |
| `server.port` | Service port | `8080` |
| `server.host` | Listen address | `0.0.0.0` |
| `database.sqlite.path` | Database path | `./data/mibee.db` |
| `log.level` | Log level | `info` |
| `log.format` | Log format | `json` |
| `storage.max_file_size` | Max upload size | `104857600` (100MB) |

### Environment Variables

All configuration can be overridden with `MIBEE_*` prefixed environment variables:

```bash
export MIBEE_SERVER_PORT=8080
export MIBEE_AUTH_JWT_SECRET="your-secret-here"
export MIBEE_AUTH_INITIAL_ADMIN_PASSWORD="your-password"
export MIBEE_LOG_LEVEL=info
export MIBEE_AUTH_COOKIE_SECURE=true
```

## Security Best Practices

1. **Change Default Passwords**: Always change the default admin password
2. **Secure JWT Secret**: Generate a strong JWT secret with `openssl rand -base64 32`
3. **Use HTTPS**: Configure SSL/TLS with Let's Encrypt or other certificates
4. **Restrict Metrics Access`: Configure nginx to only allow localhost access to `/metrics`
5. **Regular Backups**: Implement automated daily backups
6. **Monitor Logs**: Set up log monitoring and alerts
7. **Firewall Configuration**: Only open necessary ports (80, 443)
8. **Security Updates**: Keep system packages up to date

## Troubleshooting

### Common Issues

**Service Won't Start:**
```bash
# Check service status
sudo systemctl status mibee-steward

# View detailed logs
sudo journalctl -u mibee-steward --no-pager -n 100

# Check configuration syntax
sudo -u mibee /opt/mibee-steward/mibee-steward --check-config
```

**Database Connection Issues:**
```bash
# Check database permissions
ls -la /opt/mibee-steward/data/

# Verify database tables
sqlite3 /opt/mibee-steward/data/mibee.db ".tables"

# Re-run migrations
# The database schema is automatically applied on startup via embedded schema.sql
```

**Nginx Configuration Errors:**
```bash
# Test nginx configuration
sudo nginx -t

# Check error logs
sudo tail -f /var/log/nginx/error.log
```

**Performance Issues:**
```bash
# Monitor resource usage
htop

# PProf analysis
curl -s http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

## Support

For additional support:
- Project documentation: https://github.com/Mi-Bee-Studio/MiBeeSteward
- Issue tracker: https://github.com/Mi-Bee-Studio/MiBeeSteward/issues
- Email support: support@example.com