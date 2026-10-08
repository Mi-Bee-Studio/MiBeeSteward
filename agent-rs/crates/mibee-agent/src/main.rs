//! mibee-agent (Rust) — the distributed agent binary. Lifecycle mirrors the
//! Go cmd/agent: config -> agent.db -> engine (corpus precedence path >
//! synced dir > embedded) -> reporter/poller/prober/fpsync/discovery loops,
//! SIGINT/SIGTERM shutdown in Go's order (cancel -> sources -> poller ->
//! scheduler -> reporter final flush).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mibee_agent::center::{CenterClient, RealClock, Reporter};
use mibee_agent::config::Config;
use mibee_agent::engine::orchestrator::ScanEngine;
use mibee_agent::engine::{device_types::DeviceTypeRules, identify::SnmpTables, oui::Oui};
use mibee_agent::wire::{AgentCommand, ProbePlanCommand, ScanCommand};
use mibee_fingerprints::RuleClassifier;
use tokio::sync::{watch, Mutex as AsyncMutex};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMAND_POLL: Duration = Duration::from_secs(60);
const SWEEP_EVERY: Duration = Duration::from_secs(6 * 3600);
const SCAN_DEADLINE: Duration = Duration::from_secs(15 * 60);

/// 300-line log ring for remote logs-tail.
static LOG_RING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

fn log(line: String) {
    println!("{line}");
    if let Ok(mut ring) = LOG_RING.lock() {
        if ring.len() >= 300 {
            ring.pop_front();
        }
        ring.push_back(line);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-version" || a == "--version") {
        println!("mibee-agent {VERSION}");
        return;
    }
    if args.get(1).map(|s| s.as_str()) == Some("snmp-credential") {
        std::process::exit(snmp_credential_cli(&args[2..]));
    }
    let mut config_path = "configs/agent.yaml".to_string();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "-config" {
            if let Some(v) = it.next() {
                config_path = v.clone();
            }
        }
    }
    if let Err(e) = run(&config_path) {
        eprintln!("mibee-agent: fatal: {e}");
        std::process::exit(1);
    }
}

fn run(config_path: &str) -> Result<(), String> {
    mibee_agent::tls_provider::ensure_tls_provider();
    let cfg = Config::load(config_path)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(run_agent(cfg, config_path))
}

async fn run_agent(cfg: Config, config_path: &str) -> Result<(), String> {
    log(format!("mibee-agent {VERSION} starting (config {config_path})"));
    let db_path = Config::db_path(config_path);
    {
        let p = db_path.clone();
        tokio::task::spawn_blocking(move || mibee_agent::db::open_agent_db(&p))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
    }

    // corpus precedence: scanner.fingerprint_path -> <configdir>/fingerprints-sync -> embedded
    let corpus_dir = cfg.fingerprint_dir(config_path);
    let mut classifier = RuleClassifier::new();
    let corpus_used: String = match &corpus_dir {
        Some(dir) if classifier.load_from_dir(dir).is_ok() && classifier.loaded() => dir.clone(),
        _ => {
            let embedded = embedded_corpus_path();
            if std::path::Path::new(&embedded).is_dir() {
                classifier.load_from_dir(&embedded).map_err(|e| e.to_string())?;
            }
            "embedded".to_string()
        }
    };
    let fp_rev = match &corpus_dir {
        Some(dir) => mibee_agent::wire::corpus_rev(dir).unwrap_or_default(),
        None => String::new(),
    };
    log(format!(
        "corpus: {corpus_used} rules={} rev={}",
        classifier.rule_count(),
        fp_rev.get(..12).map(|s| s.to_string()).unwrap_or_default()
    ));

    let snmp_tables = SnmpTables::parse(&read_snmp_tables(&corpus_dir)).unwrap_or_default();
    let oui = Arc::new(Oui::parse(mibee_agent::engine::oui::EMBEDDED_OUI));
    let engine = Arc::new(ScanEngine {
        probes: mibee_agent::engine::probes::default_probes(),
        classifier: Arc::new(classifier),
        snmp_tables: Arc::new(snmp_tables),
        rules: Arc::new(DeviceTypeRules::load_embedded()),
        oui,
        port_spec: mibee_agent::engine::ports::parse_port_spec(
            mibee_agent::engine::ports::DEFAULT_PORT_SPEC,
        )?,
        per_host_timeout: Duration::from_secs(cfg.scanner.default_timeout.max(1) as u64),
        per_probe_timeout: Duration::from_secs(cfg.scanner.per_probe_timeout.max(1) as u64),
        max_concurrent_hosts: cfg.scanner.max_concurrent_hosts.max(1) as usize,
        community: cfg.scanner.snmp_community.clone(),
        snmp_port: 161,
        rdns_servers: cfg.scanner.rdns.dns_servers.clone(),
        routers: cfg.scanner.router_arp.routers.clone(),
        allow_reserved: cfg.scanner.allow_reserved_targets,
        seeds: AsyncMutex::new(std::collections::HashMap::new()),
    });

    let client = Arc::new(CenterClient::new(
        cfg.center.url.clone(),
        cfg.center.auth_token.clone(),
        Duration::from_secs(30),
    ));
    let mut reporter = Reporter::new(
        Arc::clone(&client),
        cfg.network.name.clone(),
        cfg.network.cidr.clone(),
        256,
        Arc::new(RealClock),
    );
    {
        let mut meta = mibee_agent::wire::AgentMeta {
            version: format!("mibee-agent-rs/{VERSION}"),
            go_version: format!("rust/{}", std::env::consts::ARCH),
            hostname: hostname_str(),
            ..Default::default()
        };
        meta.fingerprint_rev = fp_rev.clone();
        *reporter.meta.lock().unwrap() = meta;
    }
    let reporter = Arc::new(reporter);
    let prober = Arc::new(AsyncMutex::new(mibee_agent::prober::Prober::new(format!(
        "agent:{}",
        cfg.network.name
    ))));

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();

    // reporter flush loop
    {
        let reporter = Arc::clone(&reporter);
        let interval = Duration::from_secs(cfg.report_interval_secs());
        let mut stop = stop_rx.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => reporter.tick().await,
                    _ = stop.changed() => { reporter.stop_flush().await; return; }
                }
            }
        });
    }

    // fingerprint sync
    if cfg.center.fingerprint_sync.enabled {
        let sync_dir = PathBuf::from(config_path)
            .parent()
            .map(|p| p.join("fingerprints-sync"))
            .unwrap_or_default();
        let interval = Duration::from_secs(cfg.fingerprint_sync_secs());
        let client = Arc::clone(&client);
        let mut stop = stop_rx.clone();
        tasks.spawn(async move {
            mibee_agent::fpsync::run_sync_loop(client, sync_dir, interval, stop).await;
        });
    }

    // probe result poster
    {
        let prober = Arc::clone(&prober);
        let client = Arc::clone(&client);
        let mut stop = stop_rx.clone();
        tasks.spawn(async move {
            mibee_agent::prober::run_prober(prober, client, stop).await;
        });
    }

    // discovery sources + multicast listener
    if cfg.scanner.discovery.enabled {
        let sources = mibee_agent::discovery::DiscoverySources {
            enabled_dhcp_leases: cfg.scanner.discovery.dhcp_leases.enabled,
            enabled_arp_cache: cfg.scanner.discovery.arp_cache.enabled,
            enabled_conntrack: cfg.scanner.discovery.conntrack.enabled,
            enabled_hostapd: cfg.scanner.discovery.hostapd.enabled,
            hostapd_interfaces: cfg.scanner.discovery.hostapd.interfaces.clone(),
            enabled_router_arp: cfg.scanner.discovery.router_arp.enabled,
            routers: cfg.scanner.router_arp.routers.clone(),
            // Go agent: router_arp community falls back to the global SNMP
            // community when unset; timeout to the per-probe default.
            router_community: {
                let c = cfg.scanner.router_arp.community.clone();
                if c.is_empty() { cfg.scanner.snmp_community.clone() } else { c }
            },
            router_timeout: {
                let t = if cfg.scanner.router_arp.timeout > 0 {
                    cfg.scanner.router_arp.timeout
                } else {
                    cfg.scanner.per_probe_timeout
                };
                Duration::from_secs(t.max(3) as u64)
            },
            network_cidr: cfg.network.cidr.parse().ok(),
        };
        let engine_disc = Arc::clone(&engine);
        let reporter_disc = Arc::clone(&reporter);
        let mut state = mibee_agent::discovery::DiscoveryState::default();
        let interval = Duration::from_secs(cfg.scanner.discovery.interval.max(1) as u64);
        let mut stop = stop_rx.clone();
        tasks.spawn(async move {
            let engine = engine_disc;
            let reporter = reporter_disc;
            loop {
                for (ip, hostname, mac) in sources.sweep(&engine, &mut state).await {
                    let mut host = mibee_agent::wire::ReportedHost {
                        ip,
                        alive: true,
                        hostname: hostname.unwrap_or_default(),
                        mac: mac.unwrap_or_default(),
                        ..Default::default()
                    };
                    if host.mac.is_empty() {
                        // avoid empty-string wire fields (omitempty handles it)
                    }
                    reporter.report_passive(host).await;
                }
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = stop.changed() => return,
                }
            }
        });
        if cfg.scanner.discovery.multicast.enabled {
            let engine_mc = Arc::clone(&engine);
            let cidr = cfg.network.cidr.parse().ok();
            let stop = stop_rx.clone();
            tasks.spawn(async move {
                mibee_agent::discovery::run_multicast_listener(engine_mc, cidr, stop).await;
            });
        }
    }

    // retention sweeper (immediate first pass, then 6h)
    {
        let db_path = db_path.clone();
        let mut stop = stop_rx.clone();
        tasks.spawn(async move {
            loop {
                let p = db_path.clone();
                let n = tokio::task::spawn_blocking(move || {
                    mibee_agent::db::open_agent_db(&p)
                        .map(|c| mibee_agent::db::sweep_stale(&c))
                        .unwrap_or(0)
                })
                .await
                .unwrap_or(0);
                if n > 0 {
                    log(format!("sweep pruned {n} rows"));
                }
                tokio::select! {
                    _ = tokio::time::sleep(SWEEP_EVERY) => {}
                    _ = stop.changed() => return,
                }
            }
        });
    }

    // local cron scheduler-lite (agent's own scan_tasks, */N minute specs)
    {
        let engine_for_sched = Arc::clone(&engine);
        let reporter_for_sched = Arc::clone(&reporter);
        let db_path_sched = db_path.clone();
        let allow = cfg.scanner.allow_reserved_targets;
        let cidr_sched = cfg.network.cidr.clone();
        let cfg3_sched = cfg.clone();
        let mut stop = stop_rx.clone();
        tasks.spawn(async move {
            let engine = engine_for_sched;
            let reporter = reporter_for_sched;
            let db_path = db_path_sched;
            let cidr = cidr_sched;
            let cfg3 = cfg3_sched;
            let mut last_minute: i64 = -1;
            loop {
                let now = chrono::Local::now();
                let minute = now.timestamp() / 60;
                if minute != last_minute {
                    last_minute = minute;
                    let rows = {
                        let p = db_path.clone();
                        tokio::task::spawn_blocking(move || {
                            mibee_agent::db::open_agent_db(&p)
                                .map(|c| mibee_agent::db::list_enabled_tasks(&c))
                                .unwrap_or_default()
                        })
                        .await
                        .unwrap_or_default()
                    };
                    for t in rows {
                        if cron_due(&t.cron_expr, now) {
                            log(format!("scheduler: task {} {} -> {}", t.id, t.cron_expr, t.targets));
                            let e2 = engine.clone();
                            let r2 = reporter.clone();
                            let cred = {
                                let cid = t.credential_id.unwrap_or(0);
                                let cfg3 = cfg3.clone();
                                let p = db_path.clone();
                                tokio::task::spawn_blocking(move || {
                                    resolve_credential(&cfg3, &p, CredentialRef::ById(cid))
                                })
                                .await
                                .unwrap_or_default()
                            };
                            run_scan(e2, r2, t.targets.clone(), t.timeout, allow, &cidr, cred).await;
                        }
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = stop.changed() => return,
                }
            }
        });
    }

    // command poller (foreground)
    let poller_engine = Arc::clone(&engine);
    let poller_reporter = Arc::clone(&reporter);
    let poller_prober = Arc::clone(&prober);
    let cfg2 = cfg.clone();
    let db_path2 = db_path.clone();
    let client2 = Arc::clone(&client);
    let mut stop = stop_rx.clone();
    let poller = tokio::spawn(async move {
        let mut first = true;
        loop {
            if !first {
                tokio::select! {
                    _ = tokio::time::sleep(COMMAND_POLL) => {}
                    _ = stop.changed() => return,
                }
            }
            first = false;
            let cmds = match client2.get_commands().await {
                Ok(c) => c,
                Err(e) => {
                    log(format!("poller: {}", e.0));
                    continue;
                }
            };
            for cmd in cmds {
                if let Err(e) = client2.ack_command(cmd.id).await {
                    log(format!("poller: ack {}: {}", cmd.id, e.0));
                    continue;
                }
                execute_command(
                    cmd,
                    Arc::clone(&poller_engine),
                    Arc::clone(&poller_reporter),
                    Arc::clone(&poller_prober),
                    &cfg2,
                    &client2,
                    &db_path2,
                )
                .await;
            }
        }
    });

    wait_for_shutdown_signal().await;
    log("shutting down".to_string());
    let _ = stop_tx.send(true);
    let _ = poller.await;
    tasks.abort_all();
    reporter.stop_flush().await;
    log("stopped".to_string());
    Ok(())
}

async fn execute_command(
    cmd: AgentCommand,
    engine: Arc<ScanEngine>,
    reporter: Arc<Reporter>,
    prober: Arc<AsyncMutex<mibee_agent::prober::Prober>>,
    cfg: &Config,
    client: &Arc<CenterClient>,
    db_path: &str,
) {
    match cmd.command.as_str() {
        "scan" => {
            let result = match serde_json::from_str::<ScanCommand>(&cmd.payload) {
                Ok(sc) => match run_scan(
                    engine,
                    reporter,
                    sc.targets.clone(),
                    sc.timeout,
                    cfg.scanner.allow_reserved_targets,
                    &cfg.network.cidr,
                    resolve_credential(cfg, db_path, CredentialRef::ByName(&sc.credential_name)),
                )
                .await
                {
                    ScanOutcome::Done { run_id, alive } => format!(
                        r#"{{"run_id":{run_id},"targets":"{}","alive":{alive}}}"#,
                        sc.targets
                    ),
                    ScanOutcome::Rejected(why) => format!(r#"{{"error":"{why}"}}"#),
                },
                Err(e) => format!(r#"{{"error":"bad payload: {e}"}}"#),
            };
            let status = if result.contains("\"error\"") { "failed" } else { "done" };
            let _ = client.complete_command(cmd.id, status, &result).await;
        }
        "probe" => {
            let result = match serde_json::from_str::<ProbePlanCommand>(&cmd.payload) {
                Ok(plan) => {
                    let n = plan.targets.len();
                    prober
                        .lock()
                        .await
                        .apply_plan(&plan.fingerprint, plan.targets);
                    format!(r#"{{"applied":"{}","targets":{n}}}"#, plan.fingerprint)
                }
                Err(e) => format!(r#"{{"error":"bad payload: {e}"}}"#),
            };
            let status = if result.contains("\"error\"") { "failed" } else { "done" };
            let _ = client.complete_command(cmd.id, status, &result).await;
        }
        "restart" | "config-reload" => {
            let _ = client
                .complete_command(
                    cmd.id,
                    "done",
                    &format!(r#"{{"restarting":true,"command":"{}"}}"#, cmd.command),
                )
                .await;
            reexec_self();
        }
        "logs-tail" => {
            let lines: Vec<String> = LOG_RING
                .lock()
                .map(|r| r.iter().rev().take(50).rev().cloned().collect())
                .unwrap_or_default();
            let json = serde_json::to_string(&lines).unwrap_or_else(|_| "[]".into());
            let _ = client
                .complete_command(cmd.id, "done", &format!(r#"{{"lines":{json}}}"#))
                .await;
        }
        other => {
            let _ = client
                .complete_command(
                    cmd.id,
                    "failed",
                    &format!(r#"{{"error":"unknown command: {other}"}}"#),
                )
                .await;
        }
    }
}

/// Which credential a scan binds (name from center commands, id from
/// scheduler tasks) — resolved against the agent-local vault.
enum CredentialRef<'a> {
    None,
    ByName(&'a str),
    ById(i64),
}

#[allow(clippy::too_many_arguments)]
fn resolve_credential(
    cfg: &Config,
    db_path: &str,
    r: CredentialRef<'_>,
) -> mibee_agent::engine::orchestrator::ResolvedCredential {
    use mibee_agent::engine::orchestrator::ResolvedCredential;
    let name_or_id = match r {
        CredentialRef::None => return ResolvedCredential::default(),
        CredentialRef::ByName(n) if n.is_empty() => return ResolvedCredential::default(),
        CredentialRef::ByName(n) => format!("name {n:?}"),
        CredentialRef::ById(id) if id == 0 => return ResolvedCredential::default(),
        CredentialRef::ById(id) => format!("id {id}"),
    };
    if cfg.security.master_key.len() != 32 {
        log(format!("scan credential {name_or_id}: vault disabled (no master key); using global community"));
        return ResolvedCredential::default();
    }
    let vault = match mibee_agent::vault::Vault::new(&cfg.security.master_key) {
        Ok(v) => v,
        Err(e) => {
            log(format!("scan credential {name_or_id}: vault init failed ({e:?}); using global community"));
            return ResolvedCredential::default();
        }
    };
    // Resolution is best-effort: a stale reference degrades to a
    // community scan with a log line, never aborts the run (Go
    // resolveAgentCredentialID semantics for an operator mini-DB).
    let found = resolve_credential_row(db_path, r, &vault);
    match found {
        Some(c) => c,
        None => {
            log(format!("scan credential {name_or_id}: not found or undecryptable; using global community"));
            ResolvedCredential::default()
        }
    }
}

fn resolve_credential_row(
    db_path: &str,
    r: CredentialRef<'_>,
    vault: &mibee_agent::vault::Vault,
) -> Option<mibee_agent::engine::orchestrator::ResolvedCredential> {
    let conn = mibee_agent::db::open_agent_db(db_path).ok()?;
    let row = match r {
        CredentialRef::ByName(n) => mibee_agent::db::find_credential_by_name(&conn, n),
        CredentialRef::ById(id) => mibee_agent::db::find_credential_by_id(&conn, id),
        CredentialRef::None => None,
    }?;
    if row.security_level == "v1v2c" {
        let community = row.community.clone();
        return Some(mibee_agent::engine::orchestrator::ResolvedCredential {
            v3: None,
            community: if community.is_empty() { None } else { Some(community) },
        });
    }
    let auth_pass = if row.auth_passphrase_enc.is_empty() {
        String::new()
    } else {
        vault.decrypt(&row.auth_passphrase_enc).ok()?
    };
    let priv_pass = if row.priv_passphrase_enc.is_empty() {
        String::new()
    } else {
        vault.decrypt(&row.priv_passphrase_enc).ok()?
    };
    Some(mibee_agent::engine::orchestrator::ResolvedCredential {
        v3: Some(mibee_agent::engine::probes::SnmpV3Credential {
            username: row.username,
            security_level: row.security_level,
            auth_protocol: row.auth_protocol,
            auth_passphrase: auth_pass,
            priv_protocol: row.priv_protocol,
            priv_passphrase: priv_pass,
        }),
        community: None,
    })
}

enum ScanOutcome {
    Done { run_id: i64, alive: i64 },
    Rejected(String),
}

async fn run_scan(
    engine: Arc<ScanEngine>,
    reporter: Arc<Reporter>,
    targets: String,
    timeout: i64,
    allow_reserved: bool,
    network_cidr: &str,
    cred: mibee_agent::engine::orchestrator::ResolvedCredential,
) -> ScanOutcome {
    let ips = match mibee_agent::engine::targets::expand_targets(&targets, allow_reserved) {
        Ok(ips) => ips,
        Err(e) => return ScanOutcome::Rejected(format!("bad targets: {e:?}")),
    };
    if !network_cidr.is_empty() {
        if let Ok(net) = network_cidr.parse::<ipnet::Ipv4Net>() {
            let bad: Vec<String> = ips
                .iter()
                .filter(|ip| !net.contains(*ip))
                .map(|ip| ip.to_string())
                .collect();
            if !bad.is_empty() {
                let mut sample: Vec<String> = bad.iter().take(8).cloned().collect();
                if bad.len() > 8 {
                    sample.push("...".into());
                }
                return ScanOutcome::Rejected(format!(
                    "targets outside agent network: {} ({} of {} IPs out of network)",
                    sample.join(", "),
                    bad.len(),
                    ips.len()
                ));
            }
        }
    }
    let deadline = if timeout > 0 {
        Duration::from_secs((2 * timeout + 60) as u64).min(SCAN_DEADLINE)
    } else {
        SCAN_DEADLINE
    };
    log(format!("scan start: {targets} ({} hosts)", ips.len()));
    let started = std::time::Instant::now();
    let sem = Arc::new(tokio::sync::Semaphore::new(engine.max_concurrent_hosts.max(1)));
    let mut futures = Vec::new();
    for ip in ips {
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let engine = Arc::clone(&engine);
        let cred = cred.clone();
        futures.push(tokio::spawn(async move {
            let r = engine.scan_host_with(std::net::IpAddr::V4(ip), &cred).await;
            drop(permit);
            r
        }));
    }
    let mut alive_hosts = Vec::new();
    let mut alive_count = 0i64;
    if let Ok(results) = tokio::time::timeout(deadline, futures::future::join_all(futures)).await {
        for h in results {
            if let Ok(Some(host)) = h {
                alive_count += 1;
                alive_hosts.push(host);
            }
        }
    }
    if !alive_hosts.is_empty() {
        reporter.report(alive_hosts).await;
    }
    log(format!(
        "scan done: {targets} alive={alive_count} in {:.1}s",
        started.elapsed().as_secs_f64()
    ));
    ScanOutcome::Done { run_id: 0, alive: alive_count }
}

/// Cron matching is robfig/cron-v3 semantics (what the Go agent's gocron
/// scheduler uses) — see `mibee_agent::cron`.
fn cron_due(expr: &str, now: chrono::DateTime<chrono::Local>) -> bool {
    mibee_agent::cron::cron_due(expr, now)
}

fn reexec_self() {
    log("re-exec requested".to_string());
    #[cfg(target_os = "linux")]
    {
        let exe = std::env::current_exe().expect("exe");
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut cmd = std::process::Command::new(exe);
        cmd.args(&args);
        use std::os::unix::process::CommandExt;
        let _ = cmd.exec();
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::exit(0);
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("ctrl-c handler");
    }
}

fn hostname_str() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "agent".to_string())
}

/// Embedded corpus directory (build-time synced to assets/fingerprints/).
fn embedded_corpus_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/fingerprints")
        .to_string_lossy()
        .into_owned()
}

fn read_snmp_tables(corpus_dir: &Option<String>) -> String {
    if let Some(dir) = corpus_dir {
        let p = PathBuf::from(dir).join("snmp-data.yaml");
        if let Ok(text) = std::fs::read_to_string(p) {
            return text;
        }
    }
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/fingerprints/snmp-data.yaml"),
    )
    .unwrap_or_default()
}

/// snmp-credential CLI (add/list/remove). Passphrases never echo.
fn snmp_credential_cli(args: &[String]) -> i32 {
    use mibee_agent::vault;
    let mut config_path = "configs/agent.yaml".to_string();
    let mut action = "list".to_string();
    let mut flags: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-config" => {
                if let Some(v) = args.get(i + 1) {
                    config_path = v.clone();
                    i += 1;
                }
            }
            "-action" => {
                if let Some(v) = args.get(i + 1) {
                    action = v.clone();
                    i += 1;
                }
            }
            other if other.starts_with('-') => {
                let key = other.trim_start_matches('-').replace('-', "_");
                let next = args.get(i + 1).cloned().unwrap_or_default();
                if !next.starts_with('-') && !next.is_empty() {
                    flags.insert(key, next);
                    i += 1;
                } else {
                    flags.insert(key, String::new());
                }
            }
            _ => {}
        }
        i += 1;
    }
    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 1;
        }
    };
    let conn = match mibee_agent::db::open_agent_db(&Config::db_path(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("db: {e}");
            return 1;
        }
    };
    let flag = |k: &str| flags.get(k).cloned().unwrap_or_default();
    match action.as_str() {
        "list" => {
            for c in mibee_agent::db::list_credentials(&conn) {
                println!("{}", vault::masked_row(&c));
            }
            0
        }
        "add" => {
            let level = flag("security_level");
            if let Err(e) = vault::validate_add(
                &level,
                &flag("community"),
                &flag("username"),
                &flag("auth_protocol"),
                &flag("priv_protocol"),
            ) {
                eprintln!("add: {e}");
                return 1;
            }
            let vault_ = match vault::Vault::new(&cfg.security.master_key) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("vault: {e}");
                    return 1;
                }
            };
            let read_pass = |env_key: &str, flag_key: &str, prompt: &str| -> String {
                if let Ok(v) = std::env::var(env_key) {
                    return v;
                }
                let f = flag(flag_key);
                if !f.is_empty() {
                    return f;
                }
                eprint!("{prompt}: ");
                let _ = std::io::Write::flush(&mut std::io::stderr());
                let mut line = String::new();
                let _ = std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line);
                line.trim_end().to_string()
            };
            let c = vault::SnmpCredential {
                name: flag("name"),
                security_level: level,
                community: flag("community"),
                username: flag("username"),
                auth_protocol: flag("auth_protocol"),
                auth_passphrase_enc: vault_
                    .encrypt(&read_pass(
                        "MIBEE_AGENT_AUTH_PASSPHRASE",
                        "auth_passphrase",
                        "auth passphrase",
                    ))
                    .unwrap_or_default(),
                priv_protocol: flag("priv_protocol"),
                priv_passphrase_enc: vault_
                    .encrypt(&read_pass(
                        "MIBEE_AGENT_PRIV_PASSPHRASE",
                        "priv_passphrase",
                        "priv passphrase",
                    ))
                    .unwrap_or_default(),
                notes: flag("notes"),
                ..Default::default()
            };
            match mibee_agent::db::insert_credential(&conn, &c) {
                Ok(id) => {
                    println!("added credential #{id} ({})", c.name);
                    0
                }
                Err(e) => {
                    eprintln!("add: {e}");
                    1
                }
            }
        }
        "remove" => {
            let name = flag("name");
            if name.is_empty() {
                eprintln!("remove: -name required");
                return 1;
            }
            match mibee_agent::db::remove_credential(&conn, &name) {
                Ok(0) => {
                    println!("no credential named {name:?}");
                    0
                }
                Ok(n) => {
                    println!("removed {n} credential(s)");
                    0
                }
                Err(e) => {
                    eprintln!("remove: {e}");
                    1
                }
            }
        }
        other => {
            eprintln!("unknown action {other:?} (add|list|remove)");
            1
        }
    }
}
