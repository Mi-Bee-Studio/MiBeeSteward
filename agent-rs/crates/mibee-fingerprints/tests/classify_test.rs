//! Classifier behavior tests: inline mini-corpus fixtures pinning the Go
//! semantics (loop A/B ordering, exclusive groups, fused confidence,
//! extractors, transforms, kind scoping), plus a full-corpus load test
//! against the main repo's `configs/fingerprints`.

use std::collections::BTreeMap;

use mibee_fingerprints::{Evidence, RuleClassifier, ServiceIdentity};

fn ev(kind: &str, field: &str, value: &str) -> Evidence {
    let mut raw = BTreeMap::new();
    raw.insert(field.to_string(), value.to_string());
    Evidence { kind: kind.into(), raw_data: Some(raw), ..Default::default() }
}

fn ev_conf(kind: &str, field: &str, value: &str, conf: f64) -> Evidence {
    let mut e = ev(kind, field, value);
    e.confidence = conf;
    e
}

fn load_inline(yaml: &str) -> RuleClassifier {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.yaml"), yaml).unwrap();
    let mut c = RuleClassifier::new();
    c.load_from_dir(dir.path().to_str().unwrap()).unwrap();
    assert!(c.loaded());
    c
}

const SSH_BANNER: &str = "version: 1\nrules:\n  - id: banner-ssh\n    match: { kind: banner, field: banner, op: prefix_ci, value: \"SSH-\" }\n    service: ssh\n    protocol: tcp\n    confidence: 0.95\n    extract:\n      metadata:\n        banner: { passthrough: banner }\n        version: { split: { delim: \"-\", index: 2 } }\n";

#[test]
fn prefix_ci_matches_and_extracts() {
    let c = load_inline(SSH_BANNER);
    let out = c.classify(&[ev("banner", "banner", "SSH-2.0-OpenSSH_9.6")]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].service, "ssh");
    assert_eq!(out[0].confidence, 0.95); // fused with evidence conf 0
    let md = out[0].metadata.as_ref().unwrap();
    assert_eq!(md.get("banner").unwrap(), "SSH-2.0-OpenSSH_9.6");
    // splitn(3, "-") on "SSH-2.0-OpenSSH_9.6" -> parts[2] = "OpenSSH_9.6"
    assert_eq!(md.get("version").unwrap(), "OpenSSH_9.6");
    // kind mismatch: no fire
    let out = c.classify(&[ev("http", "banner", "SSH-2.0-x")]);
    assert!(out.is_empty());
    // non-match
    let out = c.classify(&[ev("banner", "banner", "FTP server")]);
    assert!(out.is_empty());
}

#[test]
fn fused_confidence_formula() {
    let c = load_inline(SSH_BANNER);
    let out = c.classify(&[ev_conf("banner", "banner", "SSH-1.99-dropbear", 0.9)]);
    // 1 - (1-0.9)(1-0.95)
    assert!((out[0].confidence - 0.995).abs() < 1e-12, "{}", out[0].confidence);
}

#[test]
fn port_rules_loop_a_with_port_open() {
    let yaml = "version: 1\nrules:\n  - { id: port-smb, match: { op: port, value: 445 }, service: smb, protocol: tcp, confidence: 0.5, literal_confidence: true, exclusive_group: smb }\n";
    let c = load_inline(yaml);
    let mut e = ev("port_open", "banner", "");
    e.port = 445;
    let out = c.classify(&[e]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].service, "smb");
    assert_eq!(out[0].port, 445);
    assert_eq!(out[0].confidence, 0.5); // literal, never fused
    // no port_open evidence -> no fire
    let out = c.classify(&[]);
    assert!(out.is_empty());
}

#[test]
fn exclusive_group_first_match_per_evidence() {
    let yaml = "version: 1\nrules:\n  - id: high\n    priority: 100\n    exclusive_group: g\n    match: { kind: hostname, field: hostname, op: contains, value: \"viomi\" }\n    service: first\n    confidence: 0.9\n  - id: low\n    priority: 10\n    exclusive_group: g\n    match: { kind: hostname, field: hostname, op: contains, value: \"viomi\" }\n    service: second\n    confidence: 0.9\n  - id: other\n    match: { kind: hostname, field: hostname, op: contains, value: \"viomi\" }\n    service: third\n    confidence: 0.9\n";
    let c = load_inline(yaml);
    let e = ev("hostname", "hostname", "viomi-waterheater-e13");
    let out = c.classify(std::slice::from_ref(&e));
    // high suppresses low (same group, per evidence); other (no group) fires.
    let services: Vec<&str> = out.iter().map(|i| i.service.as_str()).collect();
    assert_eq!(services, vec!["first", "third"]);
    // A SECOND evidence piece gets its own fresh group state.
    let out = c.classify(&[e.clone(), e]);
    assert_eq!(out.len(), 4);
}

#[test]
fn regex_with_transform_strip_resp_code_and_capture() {
    let yaml = "version: 1\nrules:\n  - id: ftp-ms\n    match:\n      kind: banner\n      field: banner\n      op: regex\n      transform: strip_resp_code\n      value: '^([^ ]{1,512}) Microsoft FTP Service \\(Version ([1234]\\.[0-9]+)\\)\\.$'\n    service: ftp\n    protocol: tcp\n    confidence: 0.9\n    extract:\n      metadata:\n        inferred_brand: { const: Microsoft }\n        version: { regex_capture: 2 }\n";
    let c = load_inline(yaml);
    // v[3]==' ' (bare "220 " banner): the transform strips the code and the
    // stripped text "Microsoft FTP Service ..." does NOT match (the pattern
    // needs "<token> Microsoft FTP Service"). The unstrippable "220-QTV "
    // variant keeps its prefix and DOES match with token group = "220-QTV".
    let out_stripped = c.classify(&[ev("banner", "banner", "220 Microsoft FTP Service (Version 4.0).")]);
    assert_eq!(out_stripped.len(), 0, "stripped banner lacks the leading token");
    let out = c.classify(&[ev("banner", "banner", "220-QTV Microsoft FTP Service (Version 4.0).")]);
    assert_eq!(out.len(), 1);
    let md = out[0].metadata.as_ref().unwrap();
    assert_eq!(md.get("inferred_brand").unwrap(), "Microsoft");
    assert_eq!(md.get("version").unwrap(), "4.0");
}

#[test]
fn strip_ssh_prefix_transform() {
    let yaml = "version: 1\nrules:\n  - id: sshx\n    match:\n      kind: banner\n      op: regex\n      transform: strip_ssh_prefix\n      value: '^OpenSSH_([0-9.]+)'\n    service: ssh\n    confidence: 0.9\n    extract:\n      metadata: { version: { regex_capture: 1 } }\n";
    let c = load_inline(yaml);
    let out = c.classify(&[ev("banner", "banner", "SSH-2.0-OpenSSH_9.6p1")]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata.as_ref().unwrap().get("version").unwrap(), "9.6");
    // fewer than 3 dash-parts: transform is identity
    let out = c.classify(&[ev("banner", "banner", "OpenSSH_9.6")]);
    assert_eq!(out.len(), 1);
}

#[test]
fn keyword_map_first_entry_wins_and_ci() {
    let yaml = "version: 1\nrules:\n  - id: km\n    match: { kind: hostname, field: hostname, op: contains, value: viomi }\n    service: miot\n    confidence: 0.9\n    extract:\n      metadata:\n        appliance:\n          keyword_map:\n            field: hostname\n            ci: true\n            entries:\n              - { contains: dishwasher, set: dishwasher }\n              - { contains: washer, set: washing machine }\n";
    let c = load_inline(yaml);
    // "dishwasher" contains both "dishwasher" and "washer": specific first wins.
    let out = c.classify(&[ev("hostname", "hostname", "viomi-dishwasher-miap5E55")]);
    assert_eq!(out[0].metadata.as_ref().unwrap().get("appliance").unwrap(), "dishwasher");
    let out = c.classify(&[ev("hostname", "hostname", "viomi-WASHER-x")]);
    assert_eq!(out[0].metadata.as_ref().unwrap().get("appliance").unwrap(), "washing machine");
}

#[test]
fn when_equals_second_pass_and_metadata_all() {
    let yaml = "version: 1\nrules:\n  - id: onvif\n    match: { kind: onvif_response, op: kind_presence }\n    service: onvif\n    confidence: 0.85\n    extract:\n      metadata_all: true\n      metadata:\n        auth_required: { when_equals: { field: auth_required, value: \"true\", set: \"true\" } }\n        empty_const: { const: \"\" }\n";
    let c = load_inline(yaml);
    let mut e = ev("onvif_response", "status_code", "200");
    e.raw_data.as_mut().unwrap().insert("auth_required".into(), "true".into());
    let out = c.classify(&[e]);
    let md = out[0].metadata.as_ref().unwrap();
    assert_eq!(md.get("auth_required").unwrap(), "true");
    assert_eq!(md.get("status_code").unwrap(), "200"); // metadata_all
    assert!(!md.contains_key("empty_const"), "empty values are skipped");
}

#[test]
fn root_kind_scoping_children_ignore_kind() {
    // ssdp-hikvision shape: any: branches declare kind but that is
    // decorative — root kind gates the whole rule; branches match ANY
    // evidence field content.
    let yaml = "version: 1\nrules:\n  - id: ssdp-hik\n    match:\n      kind: ssdp\n      op: or\n      any:\n        - { kind: ssdp, field: server, op: contains, value: hikvision }\n        - { kind: ssdp, field: usn, op: contains, value: hikvision }\n    service: camera\n    confidence: 0.9\n";
    let c = load_inline(yaml);
    // matching server but wrong top kind: root gate rejects
    assert!(c.classify(&[ev("http", "server", "hikvision")]).is_empty());
    // right kind, match in the second branch (its own kind is ignored)
    let out = c.classify(&[ev("ssdp", "usn", "uuid:hikvision-abc")]);
    assert_eq!(out.len(), 1);
}

#[test]
fn duplicate_ids_load_and_both_fire() {
    let yaml = "version: 1\nrules:\n  - id: dup\n    match: { op: contains, value: x }\n    service: a\n    confidence: 0.9\n  - id: dup\n    match: { op: contains, value: x }\n    service: b\n    confidence: 0.9\n";
    let c = load_inline(yaml);
    assert_eq!(c.rule_count(), 2);
    let out = c.classify(&[ev("banner", "banner", "xx")]);
    assert_eq!(out.len(), 2);
}

#[test]
fn priority_desc_then_id_asc() {
    let yaml = "version: 1\nrules:\n  - id: b-low\n    priority: 5\n    match: { op: contains, value: x }\n    service: low\n    confidence: 0.9\n  - id: a-high\n    priority: 50\n    match: { op: contains, value: x }\n    service: high\n    confidence: 0.9\n  - id: aa-mid\n    priority: 50\n    match: { op: contains, value: x }\n    service: mid\n    confidence: 0.9\n";
    let c = load_inline(yaml);
    let out = c.classify(&[ev("banner", "banner", "x")]);
    let services: Vec<&str> = out.iter().map(|i| i.service.as_str()).collect();
    assert_eq!(services, vec!["high", "mid", "low"]); // pri desc, id asc: a-high < aa-mid
}

#[test]
fn lazy_compilation_stays_lazy() {
    let yaml = "version: 1\nrules:\n  - id: r1\n    match: { op: regex, value: '^ABC-[0-9]+$' }\n    service: x\n    confidence: 0.9\n  - id: r2\n    match: { op: regex, value: '^DEF-[0-9]+$' }\n    service: y\n    confidence: 0.9\n";
    let c = load_inline(yaml);
    assert_eq!(c.compiled_regex_count(), 0, "no regex resident after load");
    let out = c.classify(&[ev("banner", "banner", "ABC-12")]);
    assert_eq!(out.len(), 1);
    assert_eq!(c.compiled_regex_count(), 1, "exactly the fired rule compiled");
}

#[test]
fn unsupported_version_is_hard_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bad.yaml"), "version: 2\nrules: []\n").unwrap();
    let mut c = RuleClassifier::new();
    assert!(c.load_from_dir(dir.path().to_str().unwrap()).is_err());
}

#[test]
fn missing_dir_is_silent_unloaded() {
    let mut c = RuleClassifier::new();
    c.load_from_dir("Z:/definitely/not/here").unwrap();
    assert!(!c.loaded());
}

#[test]
fn empty_evidence_and_unloaded_classifier() {
    let c = RuleClassifier::new();
    assert!(c.classify(&[ev("banner", "banner", "SSH-x")]).is_empty());
    let c2 = load_inline(SSH_BANNER);
    assert!(c2.classify(&[]).is_empty());
}

#[test]
fn service_identity_json_shape_matches_go() {
    // Wire shape: omitempty on port/protocol/metadata/evidence keys must
    // mirror Go's tags (empty -> omitted).
    let ident = ServiceIdentity {
        service: "ssh".into(),
        port: 0,
        protocol: String::new(),
        confidence: 0.95,
        evidence: vec![],
        metadata: None,
    };
    let j = serde_json::to_string(&ident).unwrap();
    assert_eq!(j, r#"{"service":"ssh","confidence":0.95}"#);
}

// ---------- full corpus ----------

fn corpus_dir() -> String {
    // nested-in-main-repo layout first, then the original sibling checkout
    for p in [
        "../../../configs/fingerprints",
        "../../../MiBeeSteward/configs/fingerprints",
    ] {
        if std::path::Path::new(p).join("snmp-data.yaml").exists() {
            return p.to_string();
        }
    }
    "../../../configs/fingerprints".to_string()
}

#[test]
fn loads_full_corpus() {
    let mut c = RuleClassifier::new();
    c.load_from_dir(&corpus_dir()).unwrap();
    assert!(c.loaded());
    // The corpus only grows (curated additions + recog refreshes); pin a FLOOR,
    // not the exact count — an exact pin broke silently on every corpus batch
    // until CI started running this suite. 2639 at the time of the floor.
    assert!(
        c.rule_count() >= 2639,
        "main repo corpus rule count {} below floor (see configs/fingerprints)",
        c.rule_count()
    );
    assert_eq!(c.compiled_regex_count(), 0, "lazy: zero compiled at load");
}

#[test]
fn full_corpus_real_samples() {
    let mut c = RuleClassifier::new();
    c.load_from_dir(&corpus_dir()).unwrap();
    // Mijia hostname -> miot identity with brand/model via regex_capture.
    let out = c.classify(&[ev("hostname", "hostname", "viomi-waterheater-e13_miap5E55")]);
    let ident = out.iter().find(|i| i.service == "miot").expect("miot identity");
    let md = ident.metadata.as_ref().unwrap();
    assert_eq!(md.get("inferred_brand").unwrap(), "Viomi");
    assert_eq!(md.get("inferred_model").unwrap(), "e13");
    assert_eq!(md.get("ecosystem").unwrap(), "Xiaomi Mijia");

    // SSH banner -> ssh service with passthrough banner.
    let out = c.classify(&[ev("banner", "banner", "SSH-2.0-OpenSSH_for_Windows_9.5")]);
    let ssh = out.iter().find(|i| i.service == "ssh").expect("ssh identity");
    let md = ssh.metadata.as_ref().unwrap();
    assert_eq!(md.get("os_type").unwrap(), "Windows");

    // SNMP sysDescr -> snmp service with brand.
    let out = c.classify(&[ev("snmp", "sys_descr", "Linux rpi3b-storage 6.1.0 #1 SMP Raspberry Pi")]);
    assert!(out.iter().any(|i| i.service == "snmp"), "recog snmp rules fire");
}
