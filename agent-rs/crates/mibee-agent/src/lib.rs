pub mod center;
pub mod config;
pub mod cron;
pub mod db;
pub mod discovery;

// The eBPF passive source exists only where its dependency does (Linux +
// the ebpf feature); the config section parses everywhere (schema stable).
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf_source;
pub mod engine;
pub mod fpsync;
pub mod prober;
pub mod tls_provider;
pub mod vault;
pub mod wire;

#[cfg(test)]
mod tests {
    use super::wire::*;

    #[test]
    fn duration_strings() {
        assert_eq!(duration_secs("30s"), 30);
        assert_eq!(duration_secs("2m"), 120);
        assert_eq!(duration_secs("10m"), 600);
        assert_eq!(duration_secs("1h"), 3600);
        assert_eq!(duration_secs("1m30s"), 90);
        assert_eq!(duration_secs(""), 0);
        assert_eq!(duration_secs("junk"), 0);
        assert_eq!(duration_secs("45"), 45);
    }

    #[test]
    fn agent_report_golden_shape() {
        let report = AgentReport {
            agent_id: "lan-63".into(),
            network_name: String::new(),
            network_cidr: "192.0.2.0/24".into(),
            scanned_at: "2026-10-05T01:00:00Z".into(),
            meta: Some(AgentMeta {
                version: "v0.1.0".into(),
                go_version: String::new(),
                hostname: "nanopineo".into(),
                uptime_sec: 0, // omitempty in Go
                scans_total: 12,
                fingerprint_rev: "abc".into(),
            }),
            hosts: Some(vec![ReportedHost {
                ip: "192.0.2.5".into(),
                alive: true,
                rtt_ms: 0,
                mac: "aa:bb:cc:dd:ee:ff".into(),
                inferred_type: "iot".into(),
                inferred_brand: "Viomi".into(),
                hostname: "viomi-waterheater-e13_miap5E55".into(),
                services: vec![ReportedService {
                    service: "miot".into(),
                    port: 0,
                    protocol: "hostname".into(),
                    metadata: Some(
                        [("inferred_brand".to_string(), "Viomi".to_string())]
                            .into_iter()
                            .collect(),
                    ),
                }],
                heartbeats: vec![],
                snmp: None,
                ..Default::default()
            }]),
            origin: String::new(),
        };
        let j = serde_json::to_value(&report).unwrap();
        for absent in [
            "network_name", "origin", "rtt_ms", "uptime_sec", "open_ports",
            "detected_services", "snmp", "prometheus_url", "go_version",
        ] {
            assert!(j.get(absent).is_none() || j[absent].is_null(), "{absent} should be omitted");
        }
        assert_eq!(j["hosts"][0]["services"][0]["metadata"]["inferred_brand"], "Viomi");
        assert_eq!(j["agent_id"], "lan-63");
        assert_eq!(j["meta"]["scans_total"], 12);
    }

    #[test]
    fn heartbeat_batch_hosts_null() {
        let report = AgentReport {
            agent_id: "a".into(),
            scanned_at: "2026-10-05T01:00:00Z".into(),
            hosts: None,
            ..Default::default()
        };
        let j = serde_json::to_string(&report).unwrap();
        assert!(j.contains("\"hosts\":null"), "{j}");
    }

    #[test]
    fn command_payload_is_double_encoded_string() {
        let raw = r#"[{"id":7,"agent_id":"agent-lan-63","command":"scan","payload":"{\"targets\":\"192.0.2.0/24\",\"timeout\":300,\"credential_name\":\"router-snmp\"}","status":"pending","created_at":"2026-10-05T08:00:00Z","acknowledged_at":null,"result":null}]"#;
        let cmds: Vec<AgentCommand> = serde_json::from_str(raw).unwrap();
        assert_eq!(cmds.len(), 1);
        let scan: ScanCommand = serde_json::from_str(&cmds[0].payload).unwrap();
        assert_eq!(scan.targets, "192.0.2.0/24");
        assert_eq!(scan.timeout, 300);
        assert_eq!(scan.credential_name, "router-snmp");
    }

    #[test]
    fn state_hash_is_deterministic_and_order_insensitive() {
        let mut h1 = ReportedHost { ip: "192.0.2.2".into(), mac: "m2".into(), ..Default::default() };
        h1.inferred_type = "pc".into();
        let mut h2 = ReportedHost { ip: "192.0.2.1".into(), mac: "m1".into(), ..Default::default() };
        h2.inferred_brand = "Apple".into();
        let a = network_state_hash(&[h1.clone(), h2.clone()]);
        #[allow(clippy::redundant_clone)]
        let b = network_state_hash(&[h2, h1.clone()]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        let mut h3 = h1.clone();
        h3.hostname = "x".into();
        assert_ne!(network_state_hash(&[h3]), network_state_hash(&[h1.clone()]));
    }

    #[test]
    fn corpus_rev_matches_go_fpsync_layout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.yaml"), "version: 1\nrules: []\n").unwrap();
        std::fs::write(dir.path().join("a.yaml"), "version: 1\nrules: []\n").unwrap();
        let r1 = corpus_rev(dir.path().to_str().unwrap()).unwrap();
        std::fs::write(dir.path().join("a.yaml"), "version: 1\nrules: []\n").unwrap();
        let r2 = corpus_rev(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(r1, r2);
        std::fs::write(dir.path().join("a.yaml"), "version: 1\nrules:\n  - id: x\n").unwrap();
        let r3 = corpus_rev(dir.path().to_str().unwrap()).unwrap();
        assert_ne!(r1, r3);
    }
}
