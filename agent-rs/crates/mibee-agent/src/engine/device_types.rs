//! Device-type heuristic ladder from device_types.yaml (rules → os_rules →
//! port_rules, ordered first-match-wins, CI substring contains) — port of
//! Go internal/service/scannerv2/runner/device_type_rules.go.

use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Doc {
    #[serde(default)]
    rules: Vec<KeywordRule>,
    #[serde(default)]
    os_rules: Vec<OsRule>,
    #[serde(default)]
    port_rules: Vec<PortRule>,
}

#[derive(Deserialize, Debug)]
struct KeywordRule {
    r#type: String,
    #[serde(default)]
    field: String, // host | brand | hint
    #[serde(default)]
    keywords: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct OsRule {
    keywords: Vec<String>,
    #[serde(rename = "type")]
    ty: String,
}

#[derive(Deserialize, Debug, Clone)]
struct PortRule {
    #[serde(default)]
    service: String,
    #[serde(default)]
    require: Vec<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    port_any: Vec<u16>,
    #[serde(default)]
    exclude_ports: Vec<u16>,
    #[serde(default)]
    exclude_services: Vec<String>,
    #[serde(rename = "type")]
    ty: String,
}

pub struct DeviceTypeRules {
    doc: Doc,
    /// keywords lowercased once at load (Go parity).
    rules: Vec<(String, String, Vec<String>)>, // (type, field, keywords)
    os_rules: Vec<(Vec<String>, String)>,
    port_rules: Vec<PortRule>,
}

/// Inputs to the heuristic from one host's fold.
#[derive(Default, Clone)]
pub struct HostSignals {
    pub host: String,      // node_hostname or sys_name
    pub brand: String,     // inferred_brand
    pub os_type: String,
    /// Classified service names (loop-B identities + handler services).
    pub services: Vec<String>,
    /// Open ports from port_open evidence.
    pub open_ports: Vec<u16>,
}

impl DeviceTypeRules {
    pub fn load(text: &str) -> Result<Self, String> {
        let doc: Doc = serde_yaml::from_str(text).map_err(|e| format!("device_types: {e}"))?;
        let rules = doc
            .rules
            .iter()
            .map(|r| {
                (
                    r.r#type.clone(),
                    r.field.clone(),
                    r.keywords.iter().map(|k| k.to_lowercase()).collect::<Vec<_>>(),
                )
            })
            .collect();
        let os_rules = doc
            .os_rules
            .iter()
            .map(|r| (r.keywords.iter().map(|k| k.to_lowercase()).collect::<Vec<_>>(), r.ty.clone()))
            .collect();
                Ok(DeviceTypeRules { rules, os_rules, port_rules: doc.port_rules.clone(), doc })
    }

    pub fn load_embedded() -> Self {
        Self::load(crate::engine::EMBEDDED_DEVICE_TYPES).expect("embedded device_types.yaml parses")
    }

    /// matchDeviceType: ordered keyword rules over host/brand/hint, then
    /// os_rules, then port_rules. First match wins; all verdicts carry
    /// source "heuristic". None when nothing matches.
    pub fn match_type(&self, s: &HostSignals) -> Option<(String, String)> {
        let host = s.host.to_lowercase();
        let brand = s.brand.to_lowercase();
        let hint = format!("{} {} {}", host, brand, s.os_type.to_lowercase());
        for (ty, field, keywords) in &self.rules {
            let text = match field.as_str() {
                "host" => host.as_str(),
                "brand" => brand.as_str(),
                _ => hint.as_str(),
            };
            if keywords.iter().any(|k| text.contains(k)) {
                return Some((ty.clone(), "heuristic".to_string()));
            }
        }
        let os = s.os_type.to_lowercase();
        for (keywords, ty) in &self.os_rules {
            if keywords.iter().any(|k| os.contains(k)) {
                return Some((ty.clone(), "heuristic".to_string()));
            }
        }
        for rule in &self.port_rules {
            let mut positive = false;
            if !rule.service.is_empty() {
                if !s.services.iter().any(|svc| svc == &rule.service) {
                    continue;
                }
                positive = true;
            }
            if !rule.require.is_empty() {
                if rule.require.iter().all(|req| s.services.iter().any(|svc| svc == req)) {
                    positive = true;
                } else {
                    continue;
                }
            }
            if let Some(p) = rule.port {
                if s.open_ports.contains(&p) {
                    positive = true;
                } else {
                    continue;
                }
            }
            if !rule.port_any.is_empty() {
                if rule.port_any.iter().any(|p| s.open_ports.contains(p)) {
                    positive = true;
                } else {
                    continue;
                }
            }
            if !positive {
                continue; // needs at least one positive condition
            }
            if rule.exclude_ports.iter().any(|p| s.open_ports.contains(p)) {
                continue;
            }
            // exclude_services veto: fires when the excluded service is
            // CLASSIFIED on a keyed port (approximated as classified at all;
            // the refined per-port check needs the port-bearing service list
            // the engine passes in HostSignals.services).
            if !rule.exclude_services.is_empty()
                && s.services.iter().any(|svc| {
                    rule.exclude_services.iter().any(|x| x.eq_ignore_ascii_case(svc))
                })
            {
                continue;
            }
            return Some((rule.ty.clone(), "heuristic".to_string()));
        }
        None
    }

    /// Strong-signal check used by the camera/pc/nas override ladder: is
    /// there a heuristic verdict of `ty` for this host?
    pub fn strong_signal(&self, ty: &str, s: &HostSignals) -> bool {
        self.match_type(s).map(|(t, _)| t == ty).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_fire_on_known_families() {
        let r = DeviceTypeRules::load_embedded();
        // SBC hostnames type "embedded" (device_types.yaml line 44-47)
        let v = r.match_type(&HostSignals {
            host: "orangepi-zero3".into(),
            ..Default::default()
        });
        assert_eq!(v.unwrap().0, "embedded");
        // Mijia hostname keyword
        let v = r.match_type(&HostSignals { host: "viomi-waterheater-e13_miap5E55".into(), ..Default::default() });
        assert_eq!(v.unwrap().0, "iot");
        // brand field
        let v = r.match_type(&HostSignals { brand: "QNAP Systems".into(), ..Default::default() });
        let ty = v.map(|(t, _)| t).unwrap_or_default();
        assert_eq!(ty, "nas", "QNAP brand -> nas");
        // os rule
        let v = r.match_type(&HostSignals { os_type: "Windows".into(), ..Default::default() });
        assert_eq!(v.unwrap().0, "pc");
    }

    #[test]
    fn port_rules_with_exclusion_shape() {
        let r = DeviceTypeRules::load_embedded();
        // 9100 JetDirect fallback vs node_exporter veto
        let mut s = HostSignals::default();
        s.services = vec!["prometheus".into()];
        s.open_ports = vec![9100];
        let v = r.match_type(&s);
        // node_exporter-classified 9100 must not type printer; with the
        // prometheus service present the veto applies.
        assert_ne!(v.map(|(t, _)| t).unwrap_or_default(), "printer");
    }

    #[test]
    fn unknown_host_no_match() {
        let r = DeviceTypeRules::load_embedded();
        assert!(r.match_type(&HostSignals::default()).is_none());
    }
}
