# Quick Start Guide

This guide will help you get MiBee Steward running in minutes. Follow these steps to set up the development environment and run your first monitoring system with device systems management.

## Prerequisites

- Go 1.26+ 
- Node.js 20+
- Git

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Mi-Bee-Studio/MiBeeSteward.git
cd mibee-steward
```

### 2. Install Frontend Dependencies

The frontend is built with SvelteKit and requires Node.js dependencies:

```bash
cd web
npm install
cd ..
```

### 3. Configure the Application

Copy the example configuration file and customize it:

```bash
cp configs/config.example.yaml configs/config.yaml
```

Edit `configs/config.yaml` if needed, but the defaults work for development:
- Server runs on port 8080
- SQLite database created at `./data/mibee.db`
- Prometheus metrics enabled
- Device systems management enabled by default
### 4. Start Development Mode

Start both frontend and backend in development mode:

```bash
make dev
```

This command:
- Starts the SvelteKit frontend in the background
- Launches the Go backend server
- Hot-reload for both frontend and backend changes

## First Run

### 5. Access the Application

Open your browser and navigate to:
```
http://localhost:8080
```

### 6. First Login

Log in with the admin credentials you configured:
- **Username**: `admin`
- **Password**: the value of `auth.initial_admin_password` from your `config.yaml`

### 7. Change Password (CRITICAL)

After logging in for the first time:

1. Navigate to user profile or settings
2. Change the admin password immediately
3. **Never use the default password in production**

## Available Commands

### Development Commands

```bash
# Start development server (frontend + backend)
make dev

# Run tests
make test

# Clean build artifacts
make clean
```

### Build Commands

```bash
# Build for production (frontend first, then backend)
make build

# Cross-compile for multiple platforms
make build-all              # linux amd64 + arm64
make build-linux-amd64      # linux amd64 only  
make build-linux-arm64      # linux arm64 only

# Build frontend only
make build-frontend

# Build server only
make build-server
```

### Frontend Commands

```bash
# Start frontend development server
cd web && npm run dev

# Build frontend for production
cd web && npm run build
```

### Database Commands

```bash
# Generate database queries after changing db/queries/*.sql
sqlc generate
```

## Access Points

Once running, you can access:

### Web Interface
- **Main Dashboard**: http://localhost:8080
- Login with your admin credentials

### API Endpoints
- **Health Check**: http://localhost:8080/api/v1/health
- **API Documentation**: http://localhost:8080/api/v1/docs (if available)
- **Metrics**: http://localhost:8080/metrics (Prometheus format)

### Development Features
- **Hot Reload**: Frontend automatically reloads on file changes
- **Developer Tools**: Available at http://localhost:8080
- **API Testing**: Use curl or Postman with the health endpoint

## Configuration

### Environment Variables

You can override configuration using environment variables with `MIBEE_` prefix:

```bash
# Override server port
export MIBEE_SERVER_PORT=9090

# Override database path
export MIBEE_DATABASE_SQLITE_PATH=/path/to/custom.db

# Override JWT secret
export MIBEE_AUTH_JWT_SECRET=your-secret-key
```

### Configuration File

The main configuration file is `configs/config.yaml`. Key sections:

```yaml
server:
  port: 8080
  host: "0.0.0.0"

database:
  type: "sqlite"
  sqlite:
    path: "./data/mibee.db"

auth:
  jwt_secret: "change-me-in-production"
  initial_admin_password: "change-me"
```

## Next Steps

1. **Add Your First Device**: Use the web interface to add a network device to monitor
2. **Add Device Systems**: For each device, add multiple systems with entry URLs and category badges
3. **Configure Probes**: Set up SNMP, ICMP, TCP, or HTTP monitoring for your devices
4. **Explore the API**: Check the `/api/v1/health` endpoint and device systems endpoints
5. **Set Up Production**: Follow the deployment guide for production setup
## Troubleshooting

### Port Already in Use
If port 8080 is already in use, either:
- Kill the existing process: `pkill -f mibee-steward`
- Change the port in configuration
- Use a different port with environment variable: `export MIBEE_SERVER_PORT=8081`

### Frontend Build Issues
If you encounter frontend build errors:
- Ensure Node.js 20+ is installed
- Delete `web/node_modules` and run `npm install` again
- Clear SvelteKit cache: `rm -rf web/.svelte-kit`

### Database Issues
If the database fails to create:
- Ensure the `data/` directory exists
- Check write permissions in the project directory
- Verify SQLite is working: `sqlite3 --version`

## Security Notes

⚠️ **IMPORTANT SECURITY WARNING**: Always set `auth.initial_admin_password` to a strong, unique value in your `config.yaml`. Never deploy with an empty or default password.

For more detailed information, see the full [Architecture](architecture.md) and [Configuration](configuration.md) documentation.