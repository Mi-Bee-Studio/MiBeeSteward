-- Consolidated schema - final state of all migrations
-- Generated from 000001_init_schema, 000002_audit_logs, 000005_device_systems
-- with ALTER TABLE columns from 000003_account_lockout and 000004_force_password merged in.

-- === Topology container tables (must precede devices: devices.network_id and
-- === vlans/subnets reference networks, and SQLite validates FK target tables
-- === exist at CREATE TABLE time.) Empty in the single-instance phase; exist so
-- === topology data can be added later without a migration on a populated DB.
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,    -- natural key; one row per named network (resolveNetworkID upserts on it)
    cidr TEXT,                    -- "192.168.63.0/24" (advisory; not enforced)
    site TEXT,                    -- site label (branch / datacenter / cloud)
    agent_id TEXT,                -- discovering agent id (distributed phase)
    metadata TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vlans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vlan_tag INTEGER NOT NULL,    -- 802.1Q tag (1-4094)
    name TEXT,
    description TEXT,
    network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    first_seen DATETIME,
    last_seen DATETIME,
    UNIQUE(vlan_tag, network_id)
);

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
    -- network_id ties a device to the logical network that discovered it
    -- (distributed/multi-LAN support). NULL = single-instance / unknown origin;
    -- the (ip_address, network_id) composite unique index is created in
    -- cmd/server/main.go (applyIdentityIndexMigrations) so existing rows can be
    -- de-duplicated first.
    network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    -- first_seen / last_seen record when the device was first/last observed
    -- ONLINE by a scan (distinct from created_at/updated_at which track the
    -- row's own lifetime and bump on any write). Needed for asset-freshness
    -- across distributed instances.
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
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

-- Notification log
-- rule_id is kept as a plain nullable integer (no FK) for historical rows
-- produced before the alert_rules table was removed. New rows insert NULL.
CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER,
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

-- Indexes for new tables
CREATE INDEX IF NOT EXISTS idx_notification_log_sent_at ON notification_log(sent_at);

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
-- created_at index backs the retention-sweeper DELETE (WHERE created_at < cutoff);
-- without it the prune scans the whole table.
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_created_at ON scan_task_runs(created_at);

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

-- host_tls_certs stores TLS/SSL certificates collected from TLS-speaking
-- services. The scanner probes the default TLS ports (443/8443/9443/4443 and
-- the well-known TLS-wrapped service ports 465/636/989/990/992/993/994/995)
-- and any port a classifier identifies as a TLS service. Each successful
-- handshake yields one or more rows here: one row per certificate in the
-- server's chain (cert_index 0 is the leaf/server cert, 1..N are issuers up
-- the chain). The full PEM is stored for the "view/export certificate" use
-- case; the typed columns support queryability (expiry sweeps, self-signed
-- inventory, etc.).
CREATE TABLE IF NOT EXISTS host_tls_certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 0,
    cert_index INTEGER NOT NULL DEFAULT 0,        -- 0 = leaf/server cert, 1..N = chain issuers
    -- Identity
    subject_cn TEXT NOT NULL DEFAULT '',
    subject_org TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',             -- full RFC 4514 distinguished name
    issuer_cn TEXT NOT NULL DEFAULT '',
    issuer_org TEXT NOT NULL DEFAULT '',
    issuer TEXT NOT NULL DEFAULT '',
    san_dns TEXT NOT NULL DEFAULT '',             -- comma-separated DNS names
    san_ip TEXT NOT NULL DEFAULT '',              -- comma-separated IP addresses
    san_email TEXT NOT NULL DEFAULT '',           -- comma-separated email addresses
    serial TEXT NOT NULL DEFAULT '',              -- decimal string (x509.SerialNumber.Text)
    -- Validity, ISO 8601 UTC for queryability (parsed from cert.NotBefore/NotAfter)
    not_before TEXT NOT NULL DEFAULT '',
    not_after TEXT NOT NULL DEFAULT '',
    -- Crypto details
    sig_algorithm TEXT NOT NULL DEFAULT '',       -- e.g. SHA256-RSA, ECDSA-SHA256
    key_algorithm TEXT NOT NULL DEFAULT '',       -- RSA, ECDSA, Ed25519
    key_bits INTEGER NOT NULL DEFAULT 0,          -- RSA modulus bits / ECDSA curve order bits
    is_ca INTEGER NOT NULL DEFAULT 0,             -- 1 if BasicConstraints CA=true
    self_signed INTEGER NOT NULL DEFAULT 0,       -- 1 if Subject == Issuer (cheap heuristic)
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',  -- uppercase hex of SHA-256(cert.Raw)
    pem TEXT NOT NULL DEFAULT '',                 -- full PEM ("-----BEGIN CERTIFICATE-----" ...)
    -- TLS handshake metadata (only meaningful for cert_index=0; empty for chain certs)
    tls_version TEXT NOT NULL DEFAULT '',         -- e.g. TLS 1.3
    cipher_suite TEXT NOT NULL DEFAULT '',        -- e.g. TLS_AES_128_GCM_SHA256
    trusted INTEGER NOT NULL DEFAULT 0,           -- 1 if chains to system roots (best-effort)
    error TEXT NOT NULL DEFAULT '',               -- non-empty when the handshake failed; port column still set
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_host_tls_certs_ip_port ON host_tls_certs(ip, port);
CREATE INDEX IF NOT EXISTS idx_host_tls_certs_expiring ON host_tls_certs(not_after);

-- === Topology / relationship / change layer ===
-- Schema groundwork for cross-network distributed discovery (see
-- docs/private/architecture-future.md §6). These tables are empty in the
-- single-instance phase; they exist so that topology/change data can be added
-- later WITHOUT a schema migration on a populated DB. The networks/subnets/
-- vlans tables are the container layer (agent deployment boundaries),
-- device_neighbors/topology_edges are the edge layer (LLDP/CDP/ARP "who-connects-
-- to-whom"), and change_log is the event stream produced by the change-detection
-- engine. All are CREATE TABLE IF NOT EXISTS — safe on existing installs.
-- (networks + vlans are defined near the top of this file because devices and
-- subnets reference them and SQLite validates FK targets at CREATE TABLE time.)

-- subnets: IP subnets within a network. One network may span several
-- subnets/VLANs (router-on-a-stick, multi-VLAN topology).
CREATE TABLE IF NOT EXISTS subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,
    vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
    gateway TEXT,
    metadata TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata)),
    first_seen DATETIME,
    last_seen DATETIME
);
CREATE INDEX IF NOT EXISTS idx_subnets_network ON subnets(network_id);

-- device_neighbors: L2 adjacency discovered via LLDP / CDP / Bridge-MIB / ARP.
-- The neighbor may not yet be a known device (neighbor_device_id NULL); it is
-- keyed by MAC so cross-agent topology merge can reconcile edges.
CREATE TABLE IF NOT EXISTS device_neighbors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,      -- local end
    neighbor_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,     -- remote end (NULL = unidentified)
    neighbor_mac TEXT NOT NULL,                                               -- remote MAC (merge key)
    protocol TEXT NOT NULL,                                                   -- LLDP / CDP / ARP / Bridge-MIB
    local_port TEXT,
    remote_port TEXT,
    network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    first_seen DATETIME,
    last_seen DATETIME,
    UNIQUE(device_id, neighbor_mac, protocol)
);
CREATE INDEX IF NOT EXISTS idx_device_neighbors_device ON device_neighbors(device_id);
CREATE INDEX IF NOT EXISTS idx_device_neighbors_neighbor_mac ON device_neighbors(neighbor_mac);
CREATE INDEX IF NOT EXISTS idx_device_neighbors_network ON device_neighbors(network_id);
CREATE INDEX IF NOT EXISTS idx_device_neighbors_last_seen ON device_neighbors(last_seen);

-- topology_edges: higher-level device-to-device edges (physical / l2 / l3).
-- Can be derived from device_neighbors or discovered independently (e.g. route
-- tables). confidence rises when multiple protocols corroborate an edge.
CREATE TABLE IF NOT EXISTS topology_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    to_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL,        -- physical / l2 / l3
    via_protocol TEXT,              -- LLDP / CDP / route-table
    confidence REAL,                -- 0.0-1.0
    metadata TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata)),
    first_seen DATETIME,
    last_seen DATETIME,
    UNIQUE(from_device_id, to_device_id, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_topology_edges_from ON topology_edges(from_device_id);
CREATE INDEX IF NOT EXISTS idx_topology_edges_to ON topology_edges(to_device_id);

-- change_log: the event stream produced by the change-detection engine
-- (added / lost / changed for devices, services, neighbors, topology edges).
-- Carries agent_id + network_id provenance so a future aggregation center can
-- reconcile changes from multiple agents. Populated from Phase 3 onward.
CREATE TABLE IF NOT EXISTS change_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    change_type TEXT NOT NULL,      -- device_added / device_lost / device_changed /
                                    -- service_added / ... / neighbor_added / ...
    entity_type TEXT NOT NULL,      -- device / service / neighbor / topology_edge
    entity_id INTEGER,
    before_data TEXT,               -- JSON snapshot (lost/changed)
    after_data TEXT,                -- JSON snapshot (added/changed)
    detected_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_change_log_type_time ON change_log(change_type, detected_at);
CREATE INDEX IF NOT EXISTS idx_change_log_entity ON change_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_change_log_detected_at ON change_log(detected_at);

-- === Agent authentication (distributed phase) ===
-- agent_tokens holds the long-lived opaque bearer tokens discovery agents
-- present to the center's ingestion endpoints (POST /api/v1/agents/report).
-- Only the SHA-256 hash is stored; the plaintext is returned once at creation
-- time. An admin creates a token per network/agent and hands it to the agent
-- operator. Revocation = setting revoked_at. This is the machine-auth path —
-- distinct from the human user JWT flow (users.role CHECK is admin/user only).
CREATE TABLE IF NOT EXISTS agent_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL UNIQUE,    -- stable identifier the agent reports as
    token_hash TEXT NOT NULL UNIQUE,  -- sha256(plaintext), hex-encoded
    network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    name TEXT NOT NULL DEFAULT '',    -- human label for the admin UI
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    revoked_at DATETIME               -- non-NULL = revoked (auth fails)
);
CREATE INDEX IF NOT EXISTS idx_agent_tokens_network ON agent_tokens(network_id);

-- === Change detection (Phase 3) ===
-- scan_snapshots tracks, per network+IP, the last-seen state and a miss counter
-- used to detect device_lost with a grace period (a device must be absent from
-- N consecutive scans before being declared lost — single missed scans from ICMP
-- drop / network jitter must not flap a device offline). This is NOT a full
-- per-scan snapshot; it's the minimal "known alive set + miss count" needed to
-- compute the alive-vs-known set difference after each scan.
--   - A device PRESENT in a scan → miss_count reset to 0, last_seen_at refreshed.
--   - A device ABSENT from a scan → miss_count incremented.
--   - miss_count >= lost_threshold AND devices.status='online' → device_lost.
-- See docs/private/architecture-future.md §8 (grace period / 去抖动).
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    task_id INTEGER,                       -- which scan task last touched it (NULL = agent report)
    ip TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',          -- MAC-primary identity key (empty when unknown)
    miss_count INTEGER NOT NULL DEFAULT 0, -- consecutive scans this IP was absent
    last_seen_at DATETIME NOT NULL,        -- last time this IP appeared alive in a scan
    UNIQUE(network_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_network ON scan_snapshots(network_id);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_miss ON scan_snapshots(miss_count);

-- === Agent command queue (Phase 5c) ===
-- agent_commands holds ad-hoc commands the center wants a specific agent to
-- execute (currently: "scan these targets now"). The agent polls
-- GET /api/v1/agents/commands on each report cycle and pops its pending
-- commands. This is the center→agent command channel — a pull model (the agent
-- fetches; no inbound connection needed from the center, which fits the
-- agent-behind-NAT deployment shape).
CREATE TABLE IF NOT EXISTS agent_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,              -- which agent should run this (agent_tokens.agent_id)
    command TEXT NOT NULL,               -- "scan" (extensible)
    payload TEXT NOT NULL DEFAULT '{}',  -- JSON: {"targets": "192.168.62.0/24", "timeout": 120}
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'acknowledged', 'done', 'failed')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at DATETIME,
    result TEXT                          -- JSON result/err from the agent (optional)
);
CREATE INDEX IF NOT EXISTS idx_agent_commands_agent_status ON agent_commands(agent_id, status);

