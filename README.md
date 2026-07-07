# MiBee Steward

[![CI](https://github.com/Mi-Bee-Studio/MiBeeSteward/actions/workflows/ci.yml/badge.svg)](https://github.com/Mi-Bee-Studio/MiBeeSteward/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/mibee-steward.svg)](https://pkg.go.dev/mibee-steward)
[![Go Report Card](https://goreportcard.com/badge/github.com/Mi-Bee-Studio/MiBeeSteward)](https://goreportcard.com/report/github.com/Mi-Bee-Studio/MiBeeSteward)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm%20Noncommercial-blue)](https://polyformproject.org/licenses/noncommercial/1.0.0)
[![Frontend: SvelteKit 5](https://img.shields.io/badge/Frontend-SvelteKit%205-FF3E00?logo=svelte&logoColor=white)](https://svelte.dev)

**English** | [中文](README.zh-CN.md)

**Device/network-layer asset discovery, identification, and registry** — CMDB-lite for network and IoT assets. Automatically discovers what's on your network, infers what it is (brand/model via protocol fingerprints), and tracks it over time. Single zero-dependency binary; asset state flows to Prometheus via `/metrics` + `/sd`. Alerting/visualization are intentionally left to Alertmanager/Grafana. Built with Go + SvelteKit.

## Features

- **Device Management**: Add, configure, and monitor network devices
- **Multi-Protocol Probing**: SNMP, ICMP, TCP, and HTTP monitoring
- **Device Systems Management**: Each device can have multiple installed systems with entry URLs, displayed as card grid UI with category badges
- **Network Scanner (v2)**: Plugin-based 5-layer architecture (probe → classify → handler → persist → orchestrate) with cascading deep collection. Detects SSH/HTTP/RTSP/ONVIF/SNMP/Prometheus/node_exporter and infers device type/brand (e.g. cameras from RTSP+ONVIF). Extensible: add a protocol by registering one classifier + one handler.
- **eBPF Passive Observer**: Optional TC ingress program sniffs ONVIF WS-Discovery multicast + TCP magic bytes as a corroborating evidence source (build-tag gated; default build is dependency-free).
- **Heartbeat Monitoring**: Configurable intervals with automatic failure detection
- **Prometheus Integration**: Metrics endpoint at `/metrics` for monitoring, HTTP SD at `/sd` for auto-discovery
- **Embedded Web Interface**: SvelteKit SPA with real-time dashboards
- **JWT Authentication**: Role-based access control (admin/user)
- **Multi-Language Support**: English and Chinese with @inlang/paraglide-js
- **Audit Logging**: Comprehensive action tracking
- **Single Binary Deployment**: Frontend embedded via go:embed

## Tech Stack

### Backend
- **Go 1.26+** with Chi v5 web framework
- **SQLite** via modernc.org/sqlite (CGO_ENABLED=0)
- **sqlc** for type-safe database queries
- **koanf/v2** for configuration management
- **JWT authentication** with go-chi/jwtauth

### Frontend
- **SvelteKit 5** with file-based routing
- **Tailwind 4** for styling
- **ECharts** for data visualization
- **@inlang/paraglide-js** for internationalization

### Infrastructure
- **Prometheus metrics** integration
- **Systemd** service deployment
- **Nginx** reverse proxy with TLS
- **Docker** containerization support

## Quick Start

### Development
```bash
# Clone the repository
git clone https://github.com/Mi-Bee-Studio/MiBeeSteward.git
cd mibee-steward

# Install frontend dependencies
cd web && npm install
cd ..

# Start development server
make dev
```

### Production Build
```bash
# Build for production
make build

# Cross-compile for multiple platforms
make build-all
```

### Reset admin password

If you lose the admin password, reset it with the CLI subcommand:

```bash
# Interactive (prompts for password)
./mibee-steward reset-admin-password -config configs/config.yaml

# Non-interactive (password via flag or env)
./mibee-steward reset-admin-password -config configs/config.yaml -password 'newpass'
MIBEE_RESET_PASSWORD=newpass ./mibee-steward reset-admin-password -config configs/config.yaml
```

Check the build version:
```bash
./mibee-steward -version
```

### First Run
1. The application creates a SQLite database at `./data/mibee.db`
2. Set a strong admin password via `auth.initial_admin_password` in your config (required for production)
3. **Important**: Never use a default or weak password in production

## Documentation

- [Introduction](docs/en/introduction.md) — Project overview and features
- [Quick Start](docs/en/quick-start.md) — Get running in 5 minutes
- [Architecture](docs/en/architecture.md) — System design and data flow
- [API Reference](docs/en/api.md) — REST API documentation
- [Deployment](docs/en/deployment.md) — Production deployment guide
- [Development Guide](docs/en/development-guide.md) — Contributing and coding conventions
- [Configuration](docs/en/configuration.md) — Configuration reference

## Configuration

The application uses YAML configuration files with environment variable overrides. See `configs/config.example.yaml` for all available options:

```yaml
server:
  port: 8080
  host: 0.0.0.0

database:
  path: ./data/mibee.db

metrics:
  enabled: true
  path: /metrics
```

Environment variables prefixed with `MIBEE_` override configuration values.

## Architecture

```
├── cmd/server/           # Entry point
├── internal/
│   ├── api/             # HTTP handlers and middleware
│   ├── config/          # Configuration loading
│   ├── db/              # Single schema.sql + sqlc-generated database code
│   ├── domain/          # Business models
│   ├── repository/      # Data access layer
│   └── service/         # Business logic
├── web/                 # SvelteKit frontend
└── deploy/              # Deployment configurations
```

## Testing

```bash
# Run all tests
go test ./...

# Run integration tests
make test
```

## Security Notes

- Never edit `internal/db/*.go` files - they are sqlc-generated
- Use `.env` files for secrets, never commit them
- SQLite uses WAL mode for better performance
- All functional testing must be done on the test server (your-test-server)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run `make test` to ensure everything works
6. Submit a pull request

## License

This project is licensed under the [PolyForm Noncommercial License v1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) — commercial use is not permitted. See [LICENSE](LICENSE).

## Support

For support, please open an issue in the GitHub repository or contact the development team.