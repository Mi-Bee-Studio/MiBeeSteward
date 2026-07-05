# Introduction to MiBee Steward

## What is MiBee Steward

MiBee Steward is a comprehensive device management and monitoring system designed for network administrators and DevOps teams. Built with a Go backend featuring the Chi web framework and SQLite database, it includes an embedded SvelteKit single-page application that provides a modern web interface. The system offers real-time monitoring capabilities across multiple protocols including SNMP v2c, ICMP ping, TCP connect checks, and HTTP GET requests. Its single binary deployment architecture makes it easy to deploy and manage across various environments.

The system operates on a heartbeat monitoring principle where devices are probed at configurable intervals. If a device fails to respond after three consecutive attempts, its status is automatically updated to indicate an outage. This approach provides reliable, automated monitoring without requiring manual intervention. The entire application can be deployed as a single executable with just a configuration file, simplifying distribution and maintenance.

## Key Features

### Device Management
- Complete CRUD operations for network devices including creation, editing, deletion, and viewing
- Device grouping and categorization for organized management
- Device systems management with entry URLs and category badges
- Detailed device configuration with custom parameters and probe settings
- Bulk operations for efficient management of large device inventories
### Multi-Protocol Probing
- SNMP v2c support for monitoring network devices with community string authentication
- ICMP ping functionality for basic network connectivity testing
- TCP connect checks for specific port availability and service monitoring
- HTTP GET requests with customizable headers and timeout settings
- Exponential backoff retry mechanism (1s → 2s → 4s) for network errors only

### Heartbeat Monitoring
- Configurable monitoring intervals per device or device groups
- Three-strike failure detection with automatic status updates
- Automatic recovery detection when failed devices respond again
- Real-time status changes reflected in the web interface and metrics

### Prometheus Integration
- Comprehensive metrics endpoint at `/metrics` following Prometheus exposition format
- Device status gauges showing online/offline states
- Device systems auto-discovery at `/sd` endpoint with metrics_enabled=true
- Heartbeat counters for total and failed probe attempts
- Response time histograms for performance monitoring
- HTTP service discovery endpoint at `/sd` for auto-discovery
### Embedded Web Interface
- SvelteKit 5 single-page application embedded via go:embed
- Real-time dashboards using ECharts for data visualization
- Dark and light theme support with automatic system preference detection
- Responsive design optimized for desktop and mobile devices
- File upload functionality for device certificates and configuration files

### Authentication & Security
- JWT-based authentication with cookie-first approach
- Bearer token fallback for API clients and automation tools
- Role-based access control with admin (full access) and user (read-only) roles
- Comprehensive audit logging for all user actions including login attempts, device changes, and file uploads
- CSRF protection and security headers middleware

### Internationalization
- Full i18n support with English and Chinese language packs
- @inlang/paraglide-js for efficient message compilation
- Automatic language detection based on browser preferences
- Localized date/time formatting and error messages

## Use Cases

### Network Monitoring
MiBee Steward excels at monitoring network infrastructure including routers, switches, and firewalls. IT administrators can track device availability, response times, and service availability across their entire network. The SNMP probing capability allows monitoring of network statistics, interface counters, and system health metrics for comprehensive network visibility.

### IoT Device Management
Perfect for managing Internet of Things devices such as smart sensors, cameras, and industrial controllers. The system supports custom probe intervals and protocols specific to IoT devices, allowing monitoring of proprietary protocols via HTTP endpoints. Device grouping helps organize large numbers of IoT devices by location, function, or importance.

### Server Farm Monitoring
Ideal for monitoring server availability and service health in data centers. TCP connect checks ensure critical services are running, while HTTP GET probes verify web applications are responding correctly. The system can monitor servers across multiple availability zones and provide early warning of performance issues before they impact users.

### Lab Equipment Tracking
Essential for managing research laboratory equipment, test rigs, and measurement devices. The flexible probe configuration allows monitoring of custom equipment with specific protocols and intervals. Automatic failure detection ensures that expensive lab equipment issues are identified promptly, minimizing downtime and research delays.

## System Requirements

### Backend Requirements
- Go 1.26 or later for compilation and runtime
- SQLite via modernc.org/sqlite (CGO_ENABLED=0 build flag)
- Minimum 50MB disk space for the application and database
- Network access for device probing and metrics collection
- Optional: 100MB+ for file uploads and document storage

### Frontend Requirements
- Node.js 20+ for development and building
- Modern web browser with JavaScript support
- Optional: ECharts for dashboard visualization features

### Infrastructure Requirements
- Linux x86_64 (primary deployment platform)
- Optional: ARM64 support via cross-compilation
- Systemd for production service management
- Nginx for reverse proxy and TLS termination
- Docker for containerized deployment

### Performance Considerations
- Single SQLite database with WAL mode for concurrent access
- Memory usage typically under 100MB for most deployments
- CPU usage scales with number of active device probes
- Network bandwidth depends on probe frequency and response sizes

## Architecture

```
Browser → Nginx → Go Server (Chi)
                         ↓
               SQLite + Heartbeat Service (10s ticker)
                         ↓
               Prometheus Metrics / HTTP Service Discovery
```