//! Identification chain: SNMP logic classifier (snmp-data.yaml tables),
//! host-level evidence fold, service-handler fold, and the device-type
//! decision ladder — ports of Go classify/snmp.go, orchestrator.go's fold,
//! handler/*, and runner/device_bridge.go.

use std::collections::BTreeMap;

use mibee_fingerprints::{Evidence, ServiceIdentity};

use crate::engine::device_types::{DeviceTypeRules, HostSignals};

// ---------- snmp-data tables ----------

#[derive(Default, Clone, Debug)]
pub struct SnmpTables {
    /// (prefix, type, brand) — declared order, first match wins.
    pub oid_prefixes: Vec<(String, String, String)>,
    /// (keywords, type) — sysdescr_types, ordered.
    pub sysdescr_types: Vec<(Vec<String>, String)>,
    /// (keyword, brand) — sysdescr_brands.
    pub sysdescr_brands: Vec<(String, String)>,
    /// (keywords, os) — sysdescr_os.
    pub sysdescr_os: Vec<(Vec<String>, String)>,
}

impl SnmpTables {
    /// Parse the `snmp-data.yaml` data shape (the rule evaluator ignores it;
    /// this is its consumer).
    pub fn parse(text: &str) -> Result<SnmpTables, String> {
        #[derive(serde::Deserialize)]
        struct Doc {
            #[serde(default)]
            oid_prefixes: Vec<OidEntry>,
            #[serde(default)]
            sysdescr_types: Vec<SysEntry>,
            #[serde(default)]
            sysdescr_brands: Vec<BrandEntry>,
            #[serde(default)]
            sysdescr_os: Vec<SysEntry>,
        }
        #[derive(serde::Deserialize)]
        struct OidEntry {
            prefix: String,
            #[serde(default)]
            r#type: String,
            #[serde(default)]
            brand: String,
        }
        #[derive(serde::Deserialize)]
        struct SysEntry {
            #[serde(default)]
            keywords: Vec<String>,
            #[serde(default)]
            r#type: String,
            #[serde(default)]
            os: String,
        }
        #[derive(serde::Deserialize)]
        struct BrandEntry {
            keyword: String,
            brand: String,
        }
        let doc: Doc = serde_yaml::from_str(text).map_err(|e| format!("snmp-data: {e}"))?;
        Ok(SnmpTables {
            oid_prefixes: doc.oid_prefixes.into_iter().map(|e| (e.prefix, e.r#type, e.brand)).collect(),
            sysdescr_types: doc.sysdescr_types.into_iter().map(|e| (e.keywords, e.r#type)).collect(),
            sysdescr_brands: doc.sysdescr_brands.into_iter().map(|e| (e.keyword, e.brand)).collect(),
            sysdescr_os: doc.sysdescr_os.into_iter().map(|e| (e.keywords, e.os)).collect(),
        })
    }
}

/// Go classify/snmp.go: one snmp identity fusing type/brand/os from the
/// merged varbinds. Port 161, protocol udp, confidence fused 0.95.
pub fn snmp_classify(tables: &SnmpTables, ev: &[Evidence]) -> Option<ServiceIdentity> {
    let snmp: Vec<&Evidence> = ev.iter().filter(|e| e.kind == "snmp").collect();
    if snmp.is_empty() {
        return None;
    }
    let mut raw: BTreeMap<String, String> = BTreeMap::new();
    for e in &snmp {
        if let Some(rd) = &e.raw_data {
            for (k, v) in rd {
                raw.insert(k.clone(), v.clone());
            }
        }
    }
    let descr = raw.get("sys_descr").cloned().unwrap_or_default();
    let services = raw.get("sys_services").cloned().unwrap_or_default();
    let obj_id = raw.get("sys_object_id").cloned().unwrap_or_default();
    let if_num = raw.get("if_number").cloned().unwrap_or_default();

    let mut md: BTreeMap<String, String> = BTreeMap::new();
    md.insert("sys_descr".into(), descr.clone());
    md.insert("sys_object_id".into(), obj_id.clone());
    let t = infer_type_from_snmp(tables, &services, &descr, &obj_id, &if_num);
    if !t.is_empty() {
        md.insert("inferred_type".into(), t);
    }
    let brand = infer_brand(tables, &descr, &obj_id);
    if !brand.is_empty() {
        md.insert("inferred_brand".into(), brand);
    }
    let os = os_from_sysdescr(tables, &descr.to_lowercase());
    if !os.is_empty() {
        md.insert("os_type".into(), os);
    }
    Some(ServiceIdentity {
        service: "snmp".into(),
        port: 161,
        protocol: "udp".into(),
        confidence: crate::engine::fuse_confidence(snmp[0].confidence, 0.95),
        evidence: snmp.into_iter().cloned().collect(),
        metadata: Some(md),
    })
}

fn atoi_safe(s: &str) -> i64 {
    let mut n: i64 = 0;
    for r in s.chars() {
        if !r.is_ascii_digit() {
            return 0;
        }
        n = n * 10 + (r as u8 - b'0') as i64;
    }
    n
}

fn infer_type_from_snmp(
    t: &SnmpTables,
    services: &str,
    descr: &str,
    obj_id: &str,
    if_number: &str,
) -> String {
    let lower = descr.to_lowercase();
    // 1. sysObjectID prefix table (strongest).
    for (prefix, ty, _) in &t.oid_prefixes {
        if obj_id.starts_with(prefix.as_str()) {
            return ty.clone();
        }
    }
    // 2. sysDescr keywords.
    for (keywords, ty) in &t.sysdescr_types {
        if keywords.iter().any(|k| lower.contains(k.as_str())) {
            return ty.clone();
        }
    }
    // 3. sysServices bitmask + ifNumber heuristic.
    let sv = atoi_safe(services);
    let has_l2 = sv & 1 != 0;
    let has_l3 = sv & 2 != 0;
    let ifn = atoi_safe(if_number);
    if has_l3 && !has_l2 && ifn <= 2 {
        return "router".into();
    }
    if has_l2 && has_l3 && ifn > 4 {
        return "switch".into();
    }
    if has_l2 && has_l3 {
        return "router".into();
    }
    if has_l2 && !has_l3 && ifn > 4 {
        return "switch".into();
    }
    if sv >= 72 {
        return "server".into();
    }
    String::new()
}

fn infer_brand(t: &SnmpTables, descr: &str, obj_id: &str) -> String {
    let lower = descr.to_lowercase();
    for (keyword, brand) in &t.sysdescr_brands {
        if lower.contains(keyword.as_str()) {
            return brand.clone();
        }
    }
    for (prefix, _, brand) in &t.oid_prefixes {
        if obj_id.starts_with(prefix.as_str()) {
            return brand.clone();
        }
    }
    String::new()
}

fn os_from_sysdescr(t: &SnmpTables, lower: &str) -> String {
    for (keywords, os) in &t.sysdescr_os {
        if keywords.iter().any(|k| lower.contains(k.as_str())) {
            return os.clone();
        }
    }
    String::new()
}

// ---------- host-level evidence fold (orchestrator.go) ----------

pub const WEB_SERVER_DENYLIST: [&str; 8] =
    ["nginx", "apache", "caddy", "lighttpd", "microsoft iis", "minidlna", "readymedia", "portable"];

pub fn is_web_server_name(brand: &str) -> bool {
    WEB_SERVER_DENYLIST.contains(&brand.to_lowercase().as_str())
}

pub fn looks_like_brand_junk(v: &str) -> bool {
    !v.chars().any(|c| c.is_ascii_alphabetic())
}

pub fn http_server_to_brand(server: &str) -> String {
    let l = server.to_lowercase();
    if l.contains("nginx") {
        "nginx".into()
    } else if l.contains("apache") {
        "Apache".into()
    } else if l.contains("caddy") {
        "Caddy".into()
    } else if l.contains("iis") || l.contains("microsoft") {
        "Microsoft IIS".into()
    } else if l.contains("lighttpd") {
        "lighttpd".into()
    } else {
        String::new()
    }
}

pub fn strip_wildcard_prefix(cn: &str) -> &str {
    if cn.len() >= 2 && cn.starts_with("*.") {
        &cn[2..]
    } else {
        cn
    }
}

pub fn cert_cn_to_brand(cn: &str) -> String {
    let l = cn.to_lowercase();
    let m = [
        (&["hikvision", "hik"][..], "Hikvision"),
        (&["dahua"], "Dahua"),
        (&["axis"], "Axis"),
        (&["unifi", "ubiquiti"], "Ubiquiti"),
        (&["synology"], "Synology"),
        (&["qnap"], "QNAP"),
        (&["cisco"], "Cisco"),
        (&["fortinet", "fortigate"], "Fortinet"),
        (&["openwrt"], "OpenWrt"),
        (&["istoreos"], "iStoreOS"),
        (&["gl-inet", "glinet"], "GL.iNet"),
    ];
    for (keys, brand) in m {
        if keys.iter().any(|k| l.contains(k)) {
            return brand.to_string();
        }
    }
    String::new()
}

pub fn cert_fields_to_brand(subject_cn: &str, issuer_org: &str) -> String {
    let b = cert_cn_to_brand(subject_cn);
    if !b.is_empty() {
        return b;
    }
    cert_cn_to_brand(issuer_org)
}

pub fn ssdp_server_to_os(server: &str) -> String {
    let first = server.split(' ').next().unwrap_or("");
    match first.split_once('/') {
        Some((os, _)) if !os.is_empty() => os.to_string(),
        _ => String::new(),
    }
}

pub fn ssdp_server_to_brand(server: &str) -> String {
    let tokens: Vec<&str> = server.split_whitespace().collect();
    if tokens.len() < 3 {
        return String::new();
    }
    for t in &tokens[2..] {
        let lt = t.to_lowercase();
        if lt.contains("upnp") || lt.contains("ssdp") {
            continue;
        }
        let product = t.split('/').next().unwrap_or(t);
        if !is_web_server_name(product) && !looks_like_brand_junk(product) {
            return product.to_string();
        }
    }
    String::new()
}

fn has_camera_evidence(ev: &[Evidence]) -> bool {
    ev.iter().any(|e| e.kind == "rtsp_banner" || e.kind == "onvif_response")
}

/// The device field bag produced by the fold chain (Go Device.Fields).
#[derive(Default, Clone, Debug)]
pub struct DeviceFields {
    pub map: BTreeMap<String, String>,
}

impl DeviceFields {
    fn set(&mut self, k: &str, v: &str) {
        if !v.is_empty() {
            self.map.insert(k.to_string(), v.to_string());
        }
    }
    fn set_if_empty(&mut self, k: &str, v: &str) {
        if !v.is_empty() && !self.map.contains_key(k) {
            self.map.insert(k.to_string(), v.to_string());
        }
    }
    fn get(&self, k: &str) -> &str {
        self.map.get(k).map(|s| s.as_str()).unwrap_or("")
    }
}

/// Fold host-level evidence kinds into device fields (orchestrator.go
/// host-level fold, exact semantics incl. fill-when-empty and the TLS
/// web-server-brand override).
pub fn fold_host_evidence(fields: &mut DeviceFields, ev: &[Evidence]) {
    for e in ev {
        let Some(rd) = &e.raw_data else { continue };
        match e.kind.as_str() {
            "mac" => {
                fields.set_if_empty("mac", &rd.get("mac").cloned().unwrap_or_default());
                fields.set_if_empty("inferred_brand", &rd.get("vendor").cloned().unwrap_or_default());
                fields.set("oui_prefix", &rd.get("oui_prefix").cloned().unwrap_or_default());
                fields.set("oui_vendor", &rd.get("oui_vendor").cloned().unwrap_or_default());
            }
            "hostname" => {
                fields.set_if_empty("node_hostname", &rd.get("hostname").cloned().unwrap_or_default());
            }
            "tls" => {
                let cn = rd.get("subject_cn").cloned().unwrap_or_default();
                fields.set_if_empty("node_hostname", strip_wildcard_prefix(&cn));
                let cn_brand = cert_fields_to_brand(
                    &cn,
                    &rd.get("issuer_org").cloned().unwrap_or_default(),
                );
                if !cn_brand.is_empty() {
                    let current = fields.get("inferred_brand");
                    if current.is_empty() || is_web_server_name(current) {
                        fields.set("inferred_brand", &cn_brand);
                    }
                }
            }
            "http" => {
                let server = rd.get("server").cloned().unwrap_or_default();
                if !server.is_empty()
                    && fields.get("inferred_brand").is_empty()
                    && !has_camera_evidence(ev)
                {
                    fields.set("inferred_brand", &http_server_to_brand(&server));
                }
            }
            "mdns" => {
                fields.set_if_empty("node_hostname", &rd.get("hostname").cloned().unwrap_or_default());
                for key in ["txt.vendor", "txt.manufacturer", "txt.md", "txt.ty"] {
                    if let Some(v) = rd.get(key) {
                        if !looks_like_brand_junk(v) && fields.get("inferred_brand").is_empty() {
                            fields.set("inferred_brand", v);
                            break;
                        }
                    }
                }
            }
            "ssdp" => {
                if let Some(server) = rd.get("server") {
                    if fields.get("os_type").is_empty() {
                        fields.set("os_type", &ssdp_server_to_os(server));
                    }
                    if fields.get("inferred_brand").is_empty() {
                        fields.set("inferred_brand", &ssdp_server_to_brand(server));
                    }
                }
            }
            "netbios" => {
                fields.set_if_empty("node_hostname", &rd.get("hostname").cloned().unwrap_or_default());
                fields.set_if_empty("netbios_workgroup", &rd.get("workgroup").cloned().unwrap_or_default());
                // deliberately NO os_type inference (Go parity note)
            }
            _ => {}
        }
    }
}

// ---------- handler fold ----------

/// Handler-known service names that imply `server` (handler/services.go
/// serverServiceNames) — the data-driven serverServiceHandler set.
pub const SERVER_SERVICES: [&str; 13] = [
    "mysql", "postgresql", "redis", "mongodb", "mssql", "memcached", "smtp", "pop3", "imap", "vnc",
    "rdp", "ldap", "smb",
];

/// Fold classified identities into device fields (the handler cascade's
/// EnrichDevice semantics, depth-0 order = identity list order).
pub fn fold_identities(fields: &mut DeviceFields, identities: &[ServiceIdentity], ev: &[Evidence]) {
    for ident in identities {
        let md = ident.metadata.clone().unwrap_or_default();
        match ident.service.as_str() {
            "ssh" => {
                // SSHHandler: os_type passthrough; Windows banner -> pc.
                if let Some(os) = md.get("os_type") {
                    fields.set_if_empty("os_type", os);
                }
                if let Some(v) = md.get("version") {
                    if v.to_lowercase().contains("windows") {
                        fields.set_if_empty("inferred_type", "pc");
                    }
                }
                if let Some(v) = md.get("version") {
                    fields.set_if_empty("ssh_version", v);
                }
            }
            "rtsp" | "onvif" => {
                // RTSP/ONVIF handlers claim camera (protocol-grade).
                fields.set_if_empty("inferred_type", "camera");
            }
            "snmp" => {
                // SNMPHandler: metadata passthrough.
                if let Some(v) = md.get("inferred_type") {
                    fields.set_if_empty("inferred_type", v);
                }
                if let Some(v) = md.get("inferred_brand") {
                    fields.set_if_empty("inferred_brand", v);
                }
                if let Some(v) = md.get("os_type") {
                    fields.set_if_empty("os_type", v);
                }
                if let Some(v) = md.get("sys_descr") {
                    fields.set_if_empty("inferred_description", v);
                }
                if let Some(v) = md.get("inferred_model") {
                    fields.set_if_empty("inferred_model", v);
                }
            }
            "miot" => {
                // MiotHandler: ecosystem brand OVERRIDES web-server brands;
                // never claims a type (honest ? badge upstream).
                if let Some(v) = md.get("inferred_brand") {
                    let current = fields.get("inferred_brand");
                    if current.is_empty() || is_web_server_name(current) {
                        fields.set("inferred_brand", v);
                    }
                }
                for key in ["inferred_model", "appliance", "inferred_description"] {
                    if let Some(v) = md.get(key) {
                        if key == "inferred_description" {
                            fields.set_if_empty("inferred_description", v);
                        } else if key == "inferred_model" {
                            fields.set_if_empty("inferred_model", v);
                        } else {
                            fields.set_if_empty("miot_appliance", v);
                        }
                    }
                }
                fields.set_if_empty("ecosystem", md.get("ecosystem").map(|s| s.as_str()).unwrap_or(""));
            }
            "mdns" | "ssdp" => {
                if let Some(v) = md.get("inferred_type") {
                    fields.set_if_empty("inferred_type", v);
                }
                if let Some(v) = md.get("inferred_brand") {
                    fields.set_if_empty("inferred_brand", v);
                }
            }
            s if SERVER_SERVICES.contains(&s) => {
                fields.set_if_empty("inferred_type", "server");
            }
            _ => {
                // rule corpus identities carrying inferred_type/device_type
                // metadata (e.g. http product rules).
                for key in ["inferred_type", "device_type"] {
                    if let Some(v) = md.get(key) {
                        fields.set_if_empty("inferred_type", v);
                    }
                }
                if let Some(v) = md.get("inferred_brand") {
                    fields.set_if_empty("inferred_brand", v);
                }
                if let Some(v) = md.get("inferred_model") {
                    fields.set_if_empty("inferred_model", v);
                }
            }
        }
    }
    let _ = ev;
}

// ---------- device-type decision ladder (device_bridge.go) ----------

pub const VALID_TYPES: [&str; 11] = [
    "router", "switch", "firewall", "server", "pc", "nas", "camera", "printer", "iot", "phone",
    "other",
];

fn heuristic_device_type(rules: &DeviceTypeRules, f: &DeviceFields) -> Option<(String, String)> {
    let signals = HostSignals {
        host: {
            let h = f.get("node_hostname");
            if h.is_empty() { f.get("sys_name").to_string() } else { h.to_string() }
        },
        brand: f.get("inferred_brand").to_string(),
        os_type: f.get("os_type").to_string(),
        services: Vec::new(), // filled by caller when identities are present
        open_ports: Vec::new(),
    };
    rules.match_type(&signals)
}

fn strong_type_signal(rules: &DeviceTypeRules, f: &DeviceFields, want: &str, services: &[ServiceIdentity], open_ports: &[u16]) -> bool {
    let host = {
        let h = f.get("node_hostname");
        if h.is_empty() { f.get("sys_name").to_string() } else { h.to_string() }
    };
    let hay = format!("{} {}", host.to_lowercase(), f.get("inferred_brand").to_lowercase());
    let signals = HostSignals {
        host: host.clone(),
        brand: f.get("inferred_brand").to_string(),
        os_type: f.get("os_type").to_string(),
        services: Vec::new(),
        open_ports: Vec::new(),
    };
    // host/brand keyword rules for the wanted type
    if let Some((t, _)) = rules.match_type(&signals) {
        if t == want {
            return true;
        }
    }
    // os_rules for the wanted type
    let os = f.get("os_type").to_lowercase();
    if !os.is_empty() {
        let os_signals = HostSignals { os_type: os.clone(), ..signals };
        if let Some((t, _)) = rules.match_type(&os_signals) {
            if t == want {
                return true;
            }
        }
    }
    // nas-only: smb on 445
    if want == "nas" {
        let smb445 = services
            .iter()
            .any(|s| s.service == "smb" && s.port == 445)
            || open_ports.contains(&445);
        if smb445 {
            return true;
        }
    }
    let _ = hay;
    false
}

/// The bridge: resolve (inferred_type, source) with the override ladder and
/// write back into fields. `services` feed port heuristics and strong gates.
pub fn apply_device_bridge(
    rules: &DeviceTypeRules,
    fields: &mut DeviceFields,
    services: &[ServiceIdentity],
    open_ports: &[u16],
) {
    let mut inferred_type = fields.get("inferred_type").to_string();
    if !inferred_type.is_empty() && !VALID_TYPES.contains(&inferred_type.as_str()) {
        inferred_type = String::new();
    }
    let mut type_source = String::new();
    if !inferred_type.is_empty() {
        // agent-carried source absent on the local path: protocol default,
        // except "other" (no-signal verdict must stay upgradeable).
        if inferred_type != "other" {
            type_source = "protocol".into();
        }
    }
    match inferred_type.as_str() {
        "camera" => {
            if strong_type_signal(rules, fields, "pc", services, open_ports) {
                inferred_type = "pc".into();
                type_source = "heuristic".into();
            } else if strong_type_signal(rules, fields, "nas", services, open_ports) {
                inferred_type = "nas".into();
                type_source = "heuristic".into();
            }
        }
        "iot" => {
            if type_source == "protocol"
                && strong_type_signal(rules, fields, "pc", services, open_ports)
            {
                inferred_type = "pc".into();
                type_source = "heuristic".into();
            }
        }
        "" | "server" | "pc" => {
            let signals = HostSignals {
                host: {
                    let h = fields.get("node_hostname");
                    if h.is_empty() { fields.get("sys_name").to_string() } else { h.to_string() }
                },
                brand: fields.get("inferred_brand").to_string(),
                os_type: fields.get("os_type").to_string(),
                services: services.iter().map(|s| s.service.clone()).collect(),
                open_ports: open_ports.to_vec(),
            };
            if let Some((t, src)) = rules.match_type(&signals) {
                if t != "server" && t != "pc" && !inferred_type.is_empty() {
                    // specialized heuristic beats the generic handler verdict
                    inferred_type = t.clone();
                    type_source = src;
                } else if inferred_type.is_empty() {
                    if !t.is_empty() {
                        type_source = src;
                    }
                    inferred_type = t;
                }
            }
        }
        _ => {}
    }
    if inferred_type.is_empty() {
        inferred_type = "other".into();
        type_source = String::new();
    }
    fields.set("inferred_type", &inferred_type);
    fields.set("inferred_type_source", &type_source);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
        Some(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }

    #[test]
    fn snmp_table_classification() {
        let tables = SnmpTables {
            oid_prefixes: vec![("1.3.6.1.4.1.9.1.1".into(), "router".into(), "Cisco".into())],
            sysdescr_types: vec![(vec!["routeros".into()], "router".into())],
            sysdescr_brands: vec![("mikrotik".into(), "MikroTik".into())],
            sysdescr_os: vec![(vec!["linux".into()], "Linux".into())],
        };
        let e = Evidence {
            kind: "snmp".into(),
            confidence: 0.95,
            raw_data: rd(&[
                ("sys_descr", "Linux rpi3b 6.1.0"),
                ("sys_services", "72"),
                ("sys_object_id", "1.3.6.1.4.1.8072.3.2.10"),
                ("if_number", "2"),
            ]),
            ..Default::default()
        };
        let ident = snmp_classify(&tables, std::slice::from_ref(&e)).unwrap();
        let md = ident.metadata.unwrap();
        assert_eq!(md["os_type"], "Linux");
        assert_eq!(md["inferred_type"], "server"); // sysServices >= 72
        // Cisco OID table hit
        let e2 = Evidence {
            raw_data: rd(&[
                ("sys_descr", "Cisco IOS Software"),
                ("sys_services", "78"),
                ("sys_object_id", "1.3.6.1.4.1.9.1.1.1"),
                ("if_number", "10"),
            ]),
            ..e.clone()
        };
        let md2 = snmp_classify(&tables, &[e2]).unwrap().metadata.unwrap();
        assert_eq!(md2["inferred_type"], "router");
        assert_eq!(md2["inferred_brand"], "Cisco");
    }

    #[test]
    fn fold_mac_hostname_tls_http() {
        let mut f = DeviceFields::default();
        let ev = vec![
            Evidence { kind: "mac".into(), raw_data: rd(&[("mac", "AA:BB:CC:11:22:33"), ("vendor", "Xiaomi Communications"), ("oui_prefix", "AABBCC")]), ..Default::default() },
            Evidence { kind: "hostname".into(), raw_data: rd(&[("hostname", "rpi3b-storage")]), ..Default::default() },
            Evidence { kind: "http".into(), raw_data: rd(&[("server", "nginx/1.24")]), ..Default::default() },
        ];
        fold_host_evidence(&mut f, &ev);
        assert_eq!(f.get("mac"), "AA:BB:CC:11:22:33");
        assert_eq!(f.get("inferred_brand"), "Xiaomi Communications");
        assert_eq!(f.get("node_hostname"), "rpi3b-storage");
        // http brand never overwrites OUI brand
        assert_eq!(f.get("inferred_brand"), "Xiaomi Communications");

        // TLS overrides a web-server brand
        let mut f2 = DeviceFields::default();
        let ev2 = vec![
            Evidence { kind: "http".into(), raw_data: rd(&[("server", "nginx")]), ..Default::default() },
            Evidence { kind: "tls".into(), raw_data: rd(&[("subject_cn", "iStoreOS-xx"), ("issuer_org", "OpenWrt")]), ..Default::default() },
        ];
        fold_host_evidence(&mut f2, &ev2);
        assert_eq!(f2.get("inferred_brand"), "iStoreOS");
        assert_eq!(f2.get("node_hostname"), "iStoreOS-xx");
    }

    #[test]
    fn mdns_junk_brand_rejected() {
        let mut f = DeviceFields::default();
        let ev = vec![Evidence {
            kind: "mdns".into(),
            raw_data: rd(&[("hostname", "appletv.local"), ("txt.md", "0,1,2"), ("txt.vendor", "Apple")]),
            ..Default::default()
        }];
        fold_host_evidence(&mut f, &ev);
        assert_eq!(f.get("inferred_brand"), "Apple"); // numeric flags never won
    }

    #[test]
    fn bridge_ladder_and_other() {
        let rules = DeviceTypeRules::load_embedded();
        // no signal -> other with empty source
        let mut f = DeviceFields::default();
        apply_device_bridge(&rules, &mut f, &[], &[]);
        assert_eq!(f.get("inferred_type"), "other");
        assert_eq!(f.get("inferred_type_source"), "");
        // handler camera + strong PC hostname -> pc/heuristic
        let mut f = DeviceFields::default();
        f.set("inferred_type", "camera");
        f.set("node_hostname", "MacBookPro.local");
        apply_device_bridge(&rules, &mut f, &[], &[]);
        assert_eq!(f.get("inferred_type"), "pc");
        assert_eq!(f.get("inferred_type_source"), "heuristic");
        // generic server upgraded by specialized heuristic
        let mut f = DeviceFields::default();
        f.set("inferred_type", "server");
        f.set("node_hostname", "nanopi-r4s");
        apply_device_bridge(&rules, &mut f, &[], &[]);
        assert_eq!(f.get("inferred_type"), "embedded");
    }

    #[test]
    fn ssdp_parsers() {
        assert_eq!(ssdp_server_to_os("Linux/4.4 UPnP/1.1 MyDevice/1.0"), "Linux");
        assert_eq!(ssdp_server_to_brand("Linux/4.4 UPnP/1.1 MyDevice/1.0"), "MyDevice");
        assert_eq!(ssdp_server_to_brand("lunzn,fastrhino-r68s UPnP/1.1"), "");
        assert_eq!(ssdp_server_to_os("lunzn,fastrhino-r68s UPnP/1.1"), ""); // no / in first token
    }
}
