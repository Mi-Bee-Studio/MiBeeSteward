-- Consolidated schema - final state of all migrations
-- Generated from 000001_init_schema, 000002_audit_logs, 000005_device_systems
-- with ALTER TABLE columns from 000003_account_lockout and 000004_force_password merged in.

-- Users table (includes columns added by 000003 and 000004)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    password_changed_at DATETIME,
    must_change_password BOOLEAN NOT NULL DEFAULT 0
);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'other' CHECK(type IN ('pc', 'embedded', 'iot', 'other', 'server', 'switch', 'router', 'firewall', 'nas', 'camera')),
    brand TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('online', 'offline', 'unknown')),
    ip_address TEXT NOT NULL DEFAULT '',
    mac_address TEXT NOT NULL DEFAULT '',
    serial_number TEXT NOT NULL DEFAULT '',
    purchase_date TEXT NOT NULL DEFAULT '',
    warranty_expiry TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '{}',
    scan_source TEXT NOT NULL DEFAULT 'manual',
    prometheus_labels TEXT NOT NULL DEFAULT '{}',
    last_scanned_at TIMESTAMP,
    last_scan_task_id INTEGER,
    open_ports TEXT NOT NULL DEFAULT '[]',
    detected_services TEXT NOT NULL DEFAULT '[]',
    prometheus_url TEXT NOT NULL DEFAULT '',
    node_exporter_url TEXT NOT NULL DEFAULT '',
    last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
    -- Dual JSON layer: scan_attributes (engine-written discovery aggregation)
    -- and user_attributes (free-form user-edited key/value map). See
    -- internal/domain/device_attributes.go for the typed structs.
    scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
    user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
    -- Hot-path generated columns extracted from scan_attributes for filtering/
    -- indexing. STORED so they can be indexed directly. Added via ALTER on
    -- existing DBs (see cmd/server/main.go rebuild migration); defined inline
    -- here so fresh installs get them automatically.
    scan_vendor   TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.vendor')) STORED,
    scan_mac      TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.mac')) STORED,
    scan_os       TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.os')) STORED,
    scan_hostname TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.hostname')) STORED,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Documents table
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'url' CHECK(type IN ('url', 'file')),
    url TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0,
    mime_type TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Device-Documents association (many-to-many)
CREATE TABLE IF NOT EXISTS device_documents (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, document_id)
);

-- Heartbeat configurations
CREATE TABLE IF NOT EXISTS heartbeat_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK(method IN ('icmp', 'http', 'tcp', 'snmp')),
    target TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 30,
    timeout_seconds INTEGER NOT NULL DEFAULT 5,
    snmp_community TEXT NOT NULL DEFAULT 'public',
    snmp_oid TEXT NOT NULL DEFAULT '1.3.6.1.2.1.1.3.0',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Heartbeat results
CREATE TABLE IF NOT EXISTS heartbeat_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    config_id INTEGER NOT NULL REFERENCES heartbeat_configs(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('success', 'fail', 'timeout')),
    latency_ms REAL NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Dashboard configurations
CREATE TABLE IF NOT EXISTS dashboard_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('gauge', 'line', 'bar', 'pie')),
    data_source TEXT NOT NULL DEFAULT 'prometheus' CHECK(data_source IN ('prometheus', 'victoriametrics')),
    query TEXT NOT NULL DEFAULT '',
    refresh_interval INTEGER NOT NULL DEFAULT 30,
    position TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs (from 000002)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Device systems table (from 000005)
CREATE TABLE IF NOT EXISTS device_systems (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    entry_url TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'custom' CHECK(category IN ('web_app', 'database', 'middleware', 'custom')),
    metrics_url TEXT NOT NULL DEFAULT '',
    metrics_enabled INTEGER NOT NULL DEFAULT 0,
    tags TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type);
-- NOTE: scan_attributes expression indexes are created in
-- cmd/server/main.go (runMigrations) AFTER the ALTER TABLE that adds the
-- scan_attributes column. They cannot live here because schema replay runs
-- before the ALTER on existing DBs and would fail with "no such column".
-- (Fresh installs get them via the same migration step, which is idempotent.)
CREATE INDEX IF NOT EXISTS idx_heartbeat_results_device ON heartbeat_results(device_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_heartbeat_results_checked_at ON heartbeat_results(checked_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_device_systems_device ON device_systems(device_id);
CREATE INDEX IF NOT EXISTS idx_device_systems_category ON device_systems(category);
CREATE INDEX IF NOT EXISTS idx_device_systems_metrics_enabled ON device_systems(metrics_enabled);

-- Notification channels
CREATE TABLE IF NOT EXISTS notification_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('webhook', 'email')),
    config TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Alert rules
CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    device_id INTEGER,
    condition_type TEXT NOT NULL CHECK(condition_type IN ('device_offline', 'heartbeat_fail', 'heartbeat_timeout')),
    threshold INTEGER NOT NULL DEFAULT 3,
    channel_id INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 1,
    cooldown_seconds INTEGER NOT NULL DEFAULT 300,
    last_triggered_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Notification log
CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER REFERENCES alert_rules(id) ON DELETE SET NULL,
    channel_id INTEGER REFERENCES notification_channels(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK(status IN ('sent', 'failed')),
    payload TEXT NOT NULL DEFAULT '{}',
    error_message TEXT NOT NULL DEFAULT '',
    sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- User TOTP (2FA)
CREATE TABLE IF NOT EXISTS user_totp (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    backup_codes TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for new tables
CREATE INDEX IF NOT EXISTS idx_notification_log_sent_at ON notification_log(sent_at);
CREATE INDEX IF NOT EXISTS idx_alert_rules_device_id ON alert_rules(device_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

-- Scan task schedules
CREATE TABLE IF NOT EXISTS scan_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    targets TEXT NOT NULL,
    cron_expr TEXT NOT NULL DEFAULT '0 */6 * * *',
    pipeline_config TEXT NOT NULL DEFAULT '{}',
    global_labels TEXT NOT NULL DEFAULT '{}',
    timeout INTEGER NOT NULL DEFAULT 300,
    concurrent_hosts INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    last_run_status TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    run_id INTEGER,
    ip TEXT NOT NULL,
    alive INTEGER NOT NULL DEFAULT 0,
    rtt_ms INTEGER NOT NULL DEFAULT 0,
    ports TEXT NOT NULL DEFAULT '[]',
    services TEXT NOT NULL DEFAULT '{}',
    snmp_data TEXT NOT NULL DEFAULT '{}',
    prometheus_detected INTEGER NOT NULL DEFAULT 0,
    prometheus_url TEXT NOT NULL DEFAULT '',
    node_exporter_detected INTEGER NOT NULL DEFAULT 0,
    node_exporter_url TEXT NOT NULL DEFAULT '',
    node_exporter_data TEXT NOT NULL DEFAULT '{}',
    scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_task_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    total_hosts INTEGER NOT NULL DEFAULT 0,
    alive_hosts INTEGER NOT NULL DEFAULT 0,
    new_hosts INTEGER NOT NULL DEFAULT 0,
    updated_hosts INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for scan tables
CREATE INDEX IF NOT EXISTS idx_scan_results_task ON scan_results(task_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip);
CREATE INDEX IF NOT EXISTS idx_scan_results_scanned_at ON scan_results(scanned_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_results_task_ip ON scan_results(task_id, ip);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_task ON scan_task_runs(task_id);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_status ON scan_task_runs(status);

-- NOTE: the UNIQUE indexes on devices(ip_address) and
-- heartbeat_configs(device_id, method) are NOT created here. They're created
-- by applyUniqueIndexMigrations() in cmd/server/main.go, which de-duplicates
-- existing rows first — necessary because long-running DBs may have accumulated
-- dupes via the original (un-guarded) insert path, and CREATE UNIQUE INDEX
-- would fail on those. On a fresh install the migration's de-dup is a no-op.

-- === scannerv2 (v2 engine) tables ===
-- These are written by the v2 pipeline's persistence layer and coexist with
-- the v1 scan_* tables above during the transition. They are independent of
-- scan_tasks/runs: a v2 scan records evidence + identities against the device
-- directly, decoupled from the run-oriented v1 schema.

-- service_evidence stores raw probe evidence for a host (sampling-controlled
-- by config scanner.persist_raw_evidence; when disabled, this table stays
-- empty). Useful for forensic re-classification and debugging.
CREATE TABLE IF NOT EXISTS service_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    source TEXT NOT NULL,         -- e.g. "active:tcp", "passive:ebpf:tc"
    kind TEXT NOT NULL,           -- e.g. "banner", "port_open", "snmp"
    port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '',
    raw_data TEXT NOT NULL DEFAULT '{}',  -- JSON object
    confidence REAL NOT NULL DEFAULT 0,
    observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_service_evidence_ip ON service_evidence(ip);
CREATE INDEX IF NOT EXISTS idx_service_evidence_observed ON service_evidence(observed_at);

-- host_services stores the classified service identities for a host. Each
-- scan replaces the host's row set (delete + insert within a tx). One row per
-- (ip, service, port) so multiple services coexist.
CREATE TABLE IF NOT EXISTS host_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    service TEXT NOT NULL,        -- "ssh", "http", "rtsp", "onvif", ...
    port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}',  -- JSON object (brand, version, ...)
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_services_ip_svc_port ON host_services(ip, service, port);
CREATE INDEX IF NOT EXISTS idx_host_services_service ON host_services(service);
