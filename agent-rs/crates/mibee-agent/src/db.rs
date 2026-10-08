//! Agent-local SQLite: schema v1 (verbatim port of the Go agentSchema),
//! Go open semantics (WAL, busy_timeout 15s, synchronous NORMAL, IMMEDIATE
//! transactions, user_version gate), and the retention sweeper (6h cadence,
//! same windows as Go cmd/agent/sweep.go).

use rusqlite::Connection;

pub const AGENT_SCHEMA_VERSION: i32 = 1;

pub const AGENT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS networks (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
	cidr TEXT, site TEXT, agent_id TEXT,
	metadata TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vlans (
	id INTEGER PRIMARY KEY AUTOINCREMENT, vlan_tag INTEGER NOT NULL, name TEXT,
	description TEXT, network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
	first_seen DATETIME, last_seen DATETIME, UNIQUE(vlan_tag, network_id)
);
CREATE TABLE IF NOT EXISTS snmp_credentials (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	security_level TEXT NOT NULL,
	community TEXT NOT NULL DEFAULT '',
	username TEXT NOT NULL DEFAULT '',
	auth_protocol TEXT NOT NULL DEFAULT '',
	auth_passphrase_enc TEXT NOT NULL DEFAULT '',
	priv_protocol TEXT NOT NULL DEFAULT '',
	priv_passphrase_enc TEXT NOT NULL DEFAULT '',
	notes TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_snmp_credentials_name ON snmp_credentials(name);
CREATE TABLE IF NOT EXISTS scan_tasks (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, targets TEXT NOT NULL,
	cron_expr TEXT NOT NULL DEFAULT '0 */6 * * *', pipeline_config TEXT NOT NULL DEFAULT '{}',
	global_labels TEXT NOT NULL DEFAULT '{}', timeout INTEGER NOT NULL DEFAULT 300,
	concurrent_hosts INTEGER NOT NULL DEFAULT 50,
	credential_id INTEGER, network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
	enabled INTEGER NOT NULL DEFAULT 1,
	last_run_at TIMESTAMP, next_run_at TIMESTAMP, last_run_status TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scan_task_runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
	status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','cancelled')),
	total_hosts INTEGER NOT NULL DEFAULT 0, alive_hosts INTEGER NOT NULL DEFAULT 0,
	new_hosts INTEGER NOT NULL DEFAULT 0, updated_hosts INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0, error_message TEXT NOT NULL DEFAULT '',
	started_at TIMESTAMP, finished_at TIMESTAMP,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_task ON scan_task_runs(task_id);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_status ON scan_task_runs(status);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_created_at ON scan_task_runs(created_at);
CREATE TABLE IF NOT EXISTS scan_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE, run_id INTEGER,
	ip TEXT NOT NULL, alive INTEGER NOT NULL DEFAULT 0, rtt_ms INTEGER NOT NULL DEFAULT 0,
	ports TEXT NOT NULL DEFAULT '[]', services TEXT NOT NULL DEFAULT '{}', snmp_data TEXT NOT NULL DEFAULT '{}',
	prometheus_detected INTEGER NOT NULL DEFAULT 0, prometheus_url TEXT NOT NULL DEFAULT '',
	node_exporter_detected INTEGER NOT NULL DEFAULT 0, node_exporter_url TEXT NOT NULL DEFAULT '',
	node_exporter_data TEXT NOT NULL DEFAULT '{}', scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_results_task_ip ON scan_results(task_id, ip);
CREATE INDEX IF NOT EXISTS idx_scan_results_task ON scan_results(task_id);
CREATE TABLE IF NOT EXISTS heartbeat_configs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	device_id INTEGER NOT NULL, method TEXT NOT NULL CHECK(method IN ('icmp','http','tcp','snmp')),
	target TEXT NOT NULL, interval_seconds INTEGER NOT NULL DEFAULT 30,
	timeout_seconds INTEGER NOT NULL DEFAULT 5, snmp_community TEXT NOT NULL DEFAULT 'public',
	snmp_oid TEXT NOT NULL DEFAULT '1.3.6.1.2.1.1.3.0', enabled INTEGER NOT NULL DEFAULT 1,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_heartbeat_configs_device_method ON heartbeat_configs(device_id, method);
CREATE TABLE IF NOT EXISTS devices (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
	type TEXT NOT NULL DEFAULT 'other', brand TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
	location TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'unknown', ip_address TEXT NOT NULL DEFAULT '', mac_address TEXT NOT NULL DEFAULT '',
	serial_number TEXT NOT NULL DEFAULT '', purchase_date TEXT NOT NULL DEFAULT '', warranty_expiry TEXT NOT NULL DEFAULT '',
	tags TEXT NOT NULL DEFAULT '{}', scan_source TEXT NOT NULL DEFAULT 'manual', prometheus_labels TEXT NOT NULL DEFAULT '{}',
	last_scanned_at TIMESTAMP, last_scan_task_id INTEGER, open_ports TEXT NOT NULL DEFAULT '[]',
	detected_services TEXT NOT NULL DEFAULT '[]', prometheus_url TEXT NOT NULL DEFAULT '', node_exporter_url TEXT NOT NULL DEFAULT '',
	last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
	scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
	user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
	network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
	first_seen TIMESTAMP, last_seen TIMESTAMP,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	device_uuid TEXT NOT NULL DEFAULT '', offline_since TIMESTAMP,
	ssh_credential_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_network ON devices(ip_address, network_id);
CREATE INDEX IF NOT EXISTS idx_devices_mac_address ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_scan_mac_expr ON devices(json_extract(scan_attributes, '$.mac'));
"#;

#[derive(Debug)]
pub enum DbError {
    Open(String),
    SchemaMismatch { found: i32, expected: i32 },
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Open(e) => write!(f, "agent db: {e}"),
            DbError::SchemaMismatch { found, expected } => write!(
                f,
                "agent db schema version {found} != {expected}: move agent.db aside and restart (no in-place upgrade)"
            ),
        }
    }
}

/// Open + gate + apply DDL (Go openAgentDB semantics).
pub fn open_agent_db(path: &str) -> Result<Connection, DbError> {
    let conn = Connection::open(path).map_err(|e| DbError::Open(e.to_string()))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| DbError::Open(format!("journal_mode: {e}")))?;
    conn.busy_timeout(std::time::Duration::from_millis(15_000))
        .map_err(|e| DbError::Open(format!("busy_timeout: {e}")))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| DbError::Open(format!("synchronous: {e}")))?;
    // user_version gate: an existing file with a different version is fatal.
    let found: i32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| DbError::Open(format!("user_version: {e}")))?;
    if found != 0 && found != AGENT_SCHEMA_VERSION {
        return Err(DbError::SchemaMismatch { found, expected: AGENT_SCHEMA_VERSION });
    }
    // reject when the file has non-system tables but a foreign version
    if found == 0 {
        let has_tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| DbError::Open(e.to_string()))?;
        if has_tables > 0 {
            // tables exist without a stamp — treat as incompatible legacy
            return Err(DbError::SchemaMismatch { found: 0, expected: AGENT_SCHEMA_VERSION });
        }
    }
    conn.execute_batch(AGENT_SCHEMA)
        .map_err(|e| DbError::Open(format!("apply schema: {e}")))?;
    conn.pragma_update(None, "user_version", AGENT_SCHEMA_VERSION)
        .map_err(|e| DbError::Open(format!("stamp user_version: {e}")))?;
    Ok(conn)
}

/// Begin an IMMEDIATE transaction (the Go _txlock=immediate DSN parameter:
/// take the write lock at BEGIN so read-then-write enrich can't hit
/// SQLITE_BUSY_SNAPSHOT).
pub fn tx_immediate(conn: &mut Connection) -> rusqlite::Result<rusqlite::Transaction<'_>> {
    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
}

/// One retention sweep (Go sweep.go statements; VACUUM only after a
/// substantial prune). Returns total pruned rows.
pub fn sweep_stale(conn: &Connection) -> usize {
    let mut total = 0usize;
    let steps: [(&str, &str); 4] = [
        ("devices_silent_mac_7d",
         "DELETE FROM devices WHERE (last_seen IS NOT NULL AND last_seen < datetime('now','-7 days')) OR (offline_since IS NOT NULL AND offline_since < datetime('now','-7 days'))"),
        ("devices_silent_no_mac_24h",
         "DELETE FROM devices WHERE mac_address = '' AND json_extract(scan_attributes,'$.mac') IS NULL AND COALESCE(json_extract(scan_attributes,'$.mac'),'') = '' AND last_seen IS NOT NULL AND last_seen < datetime('now','-24 hours')"),
        ("scan_results_72h",
         "DELETE FROM scan_results WHERE scanned_at < datetime('now','-72 hours')"),
        ("scan_task_runs_30d",
         "DELETE FROM scan_task_runs WHERE created_at < datetime('now','-30 days')"),
    ];
    for (name, sql) in steps {
        match conn.execute(sql, []) {
            Ok(n) => {
                total += n;
                if n > 0 {
                    eprintln!("sweep: {name} pruned {n}");
                }
            }
            Err(e) => eprintln!("sweep: {name} failed: {e}"),
        }
    }
    if total >= 1000 {
        let _ = conn.execute("VACUUM", []);
    }
    total
}

// ---------- scan task helpers ----------

#[derive(Debug, Clone, Default)]
pub struct ScanTaskRow {
    pub id: i64,
    pub name: String,
    pub targets: String,
    pub cron_expr: String,
    pub timeout: i64,
    pub concurrent_hosts: i64,
    pub enabled: bool,
    /// Bound SNMP credential (agent-local vault); NULL = global community.
    pub credential_id: Option<i64>,
}

pub fn list_enabled_tasks(conn: &Connection) -> Vec<ScanTaskRow> {
    let mut stmt = match conn.prepare(
        "SELECT id, name, targets, cron_expr, timeout, concurrent_hosts, enabled, credential_id FROM scan_tasks WHERE enabled = 1",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok(ScanTaskRow {
            id: r.get(0)?,
            name: r.get(1)?,
            targets: r.get(2)?,
            cron_expr: r.get(3)?,
            timeout: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
            concurrent_hosts: r.get::<_, Option<i64>>(5)?.unwrap_or(0),
            enabled: r.get::<_, i64>(6)? != 0,
            credential_id: r.get::<_, Option<i64>>(7)?,
        })
    });
    match rows {
        Ok(it) => it.filter_map(|x| x.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Create a throwaway run row for a command-driven scan (task_id=0 shape
/// via a synthetic run referencing the real task).
pub fn create_run(conn: &Connection, task_id: i64, total_hosts: i64) -> Option<i64> {
    conn.execute(
        "INSERT INTO scan_task_runs (task_id, status, total_hosts, started_at) VALUES (?, 'running', ?, CURRENT_TIMESTAMP)",
        rusqlite::params![task_id, total_hosts],
    )
    .ok()?;
    conn.last_insert_rowid().into()
}

pub fn finish_run(conn: &Connection, run_id: i64, status: &str, alive: i64, duration_ms: i64, err: &str) {
    let _ = conn.execute(
        "UPDATE scan_task_runs SET status = ?, alive_hosts = ?, duration_ms = ?, error_message = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
        rusqlite::params![status, alive, duration_ms, err, run_id],
    );
}

// ---------- snmp credential store ----------

pub fn list_credentials(conn: &Connection) -> Vec<crate::vault::SnmpCredential> {
    use crate::vault::SnmpCredential;
    let mut stmt = match conn.prepare(
        "SELECT id, name, security_level, community, username, auth_protocol, auth_passphrase_enc, priv_protocol, priv_passphrase_enc, notes FROM snmp_credentials ORDER BY id LIMIT 1000",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok(SnmpCredential {
            id: r.get(0)?,
            name: r.get(1)?,
            security_level: r.get(2)?,
            community: r.get(3)?,
            username: r.get(4)?,
            auth_protocol: r.get(5)?,
            auth_passphrase_enc: r.get(6)?,
            priv_protocol: r.get(7)?,
            priv_passphrase_enc: r.get(8)?,
            notes: r.get(9)?,
        })
    });
    match rows {
        Ok(it) => it.filter_map(|x| x.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

pub fn insert_credential(conn: &Connection, c: &crate::vault::SnmpCredential) -> Result<i64, String> {
    conn.execute(
        "INSERT INTO snmp_credentials (name, security_level, community, username, auth_protocol, auth_passphrase_enc, priv_protocol, priv_passphrase_enc, notes) VALUES (?,?,?,?,?,?,?,?,?)",
        rusqlite::params![
            c.name, c.security_level, c.community, c.username, c.auth_protocol,
            c.auth_passphrase_enc, c.priv_protocol, c.priv_passphrase_enc, c.notes
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

pub fn remove_credential(conn: &Connection, name: &str) -> Result<usize, String> {
    conn.execute("DELETE FROM snmp_credentials WHERE name = ?", rusqlite::params![name])
        .map_err(|e| e.to_string())
        .map(|n| {
            // bound tasks fall back to the community (no FK in the mini schema)
            let _ = conn.execute(
                "UPDATE scan_tasks SET credential_id = NULL WHERE credential_id IN (SELECT id FROM snmp_credentials WHERE name = ?)",
                rusqlite::params![name],
            );
            n
        })
}

/// Resolve a credential ID from a scheduler scan task against the local
/// vault. None -> community fallback (Go resolveAgentCredentialID).
pub fn find_credential_by_id(conn: &Connection, id: i64) -> Option<crate::vault::SnmpCredential> {
    list_credentials(conn).into_iter().find(|c| c.id == id)
}

/// Resolve a credential NAME from a center scan command against the local
/// vault. None -> community fallback (Go resolveAgentCredentialName).
pub fn find_credential_by_name(
    conn: &Connection,
    name: &str,
) -> Option<crate::vault::SnmpCredential> {
    list_credentials(conn).into_iter().find(|c| c.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdb() -> Connection {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.db");
        let s = p.to_str().unwrap().to_string();
        std::mem::forget(dir);
        open_agent_db(&s).unwrap()
    }

    #[test]
    fn opens_stamps_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        let path = path.to_str().unwrap().to_string();
        std::mem::forget(dir);
        {
            let conn = open_agent_db(&path).unwrap();
            let v: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
            assert_eq!(v, 1);
        }
        // reopen is fine (same version)
        drop(open_agent_db(&path).unwrap());
    }

    #[test]
    fn foreign_version_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        let path_s = path.to_str().unwrap().to_string();
        std::mem::forget(dir);
        {
            let conn = open_agent_db(&path_s).unwrap();
            conn.pragma_update(None, "user_version", 99).unwrap();
        }
        let err = open_agent_db(&path_s).unwrap_err();
        assert!(err.to_string().contains("move agent.db aside"), "{err}");
    }

    #[test]
    fn credential_roundtrip_and_removal() {
        let conn = tmpdb();
        let c = crate::vault::SnmpCredential {
            name: "router-snmp".into(),
            security_level: "authPriv".into(),
            username: "ops".into(),
            auth_protocol: "SHA".into(),
            auth_passphrase_enc: "ENC1".into(),
            priv_protocol: "AES".into(),
            priv_passphrase_enc: "ENC2".into(),
            ..Default::default()
        };
        insert_credential(&conn, &c).unwrap();
        assert_eq!(list_credentials(&conn).len(), 1);
        assert!(find_credential_by_name(&conn, "router-snmp").is_some());
        assert!(find_credential_by_name(&conn, "nope").is_none());
        assert_eq!(remove_credential(&conn, "router-snmp").unwrap(), 1);
        assert!(list_credentials(&conn).is_empty());
    }

    #[test]
    fn run_lifecycle() {
        let conn = tmpdb();
        conn.execute(
            "INSERT INTO scan_tasks (name, targets, cron_expr) VALUES ('t1', '192.0.2.0/30', '*/10 * * * *')",
            [],
        )
        .unwrap();
        let task_id = conn.last_insert_rowid();
        let run = create_run(&conn, task_id, 4).unwrap();
        finish_run(&conn, run, "completed", 3, 1200, "");
        let (status, alive): (String, i64) = conn
            .query_row("SELECT status, alive_hosts FROM scan_task_runs WHERE id = ?", [run], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((status.as_str(), alive), ("completed", 3));
        assert_eq!(list_enabled_tasks(&conn).len(), 1);
    }

    #[test]
    fn sweep_prunes_old_rows() {
        let conn = tmpdb();
        conn.execute(
            "INSERT INTO scan_tasks (name, targets) VALUES ('t', '192.0.2.1')",
            [],
        )
        .unwrap();
        let tid = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO scan_results (task_id, ip, scanned_at) VALUES (?, '192.0.2.1', datetime('now','-100 hours'))",
            [tid],
        )
        .unwrap();
        let n = sweep_stale(&conn);
        assert!(n >= 1, "swept {n}");
    }
}
