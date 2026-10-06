//! mibee-fingerprints — Rust port of the MiBee fingerprint rule classifier
//! (`github.com/Mi-Bee-Studio/mibee-fingerprints-go`). The corpus is data:
//! rule YAML files are loaded from a directory; identical inputs must
//! produce byte-identical `ServiceIdentity` output (pinned by differential
//! tests against the Go implementation).

pub mod gates;
pub mod gostr;
pub mod lazyregex;
pub mod matcher;
pub mod perlfix;
pub mod tables;

pub use matcher::{Evidence, ServiceIdentity};

use std::collections::HashMap;
use std::path::Path;

use gates::RuleGate;
use lazyregex::RegexCache;
use matcher::{compile_rules_from_str, CompiledRule, LoadError};

/// Mirrors Go `fp.RuleClassifier`. `regex_cache_size` must be set before
/// `load_from_dir` (same contract as the Go field).
pub struct RuleClassifier {
    pub regex_cache_size: usize,
    rules: Vec<CompiledRule>,
    loaded: bool,
    cache: Option<RegexCache>,
}

impl Default for RuleClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleClassifier {
    pub fn new() -> Self {
        RuleClassifier { regex_cache_size: 0, rules: Vec::new(), loaded: false, cache: None }
    }

    pub fn service(&self) -> &'static str {
        "rule-based"
    }

    pub fn loaded(&self) -> bool {
        self.loaded
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn compiled_regex_count(&self) -> usize {
        self.cache.as_ref().map(|c| c.len()).unwrap_or(0)
    }

    /// Load all top-level `*.yaml` files from `dir` in filename order.
    /// A missing dir loads nothing (silent, Go parity); an empty `dir`
    /// string stays unloaded. Any parse/validation failure is a hard error.
    pub fn load_from_dir(&mut self, dir: &str) -> Result<(), LoadError> {
        if dir.is_empty() {
            return Ok(());
        }
        let path = Path::new(dir);
        let rd = match std::fs::read_dir(path) {
            Ok(rd) => rd,
            Err(_) => return Ok(()), // missing/unreadable dir: silent, unloaded
        };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".yaml"))
            .collect();
        names.sort();
        let mut all: Vec<CompiledRule> = Vec::new();
        for name in &names {
            let text = std::fs::read_to_string(path.join(name))
                .map_err(|e| LoadError(format!("fingerprint {name}: {e}")))?;
            let mut rules = compile_rules_from_str(&text, name)?;
            all.append(&mut rules);
        }
        // Priority DESC, id ASC, stable over the filename-ordered concat.
        all.sort_by(|a, b| {
            b.sort_priority.cmp(&a.sort_priority).then_with(|| a.sort_id.cmp(&b.sort_id))
        });
        self.loaded = !all.is_empty();
        self.cache = Some(RegexCache::new(self.regex_cache_size));
        self.rules = all;
        Ok(())
    }

    /// Go `Classify`: host-scoped port rules first, then per-evidence rules
    /// with per-evidence exclusive-group suppression and gate checks.
    pub fn classify(&self, ev: &[Evidence]) -> Vec<ServiceIdentity> {
        let cache = match &self.cache {
            Some(c) => c,
            None => return Vec::new(),
        };
        let mut out: Vec<ServiceIdentity> = Vec::new();
        if !self.loaded {
            return out;
        }

        // Evidence index: positions by port (port 0 excluded, Go parity).
        let mut by_port: HashMap<i64, Vec<usize>> = HashMap::new();
        for (i, e) in ev.iter().enumerate() {
            if e.port != 0 {
                by_port.entry(e.port).or_default().push(i);
            }
        }
        let port_has_open = |port: i64| {
            by_port
                .get(&port)
                .map(|idxs| idxs.iter().any(|&i| ev[i].kind == "port_open"))
                .unwrap_or(false)
        };

        // Loop A — host-scoped port rules (sorted order, never gated, groups
        // do not apply between them).
        for rl in &self.rules {
            let Some(port) = rl.host_port else { continue };
            if !port_has_open(port) {
                continue;
            }
            let evidence = by_port
                .get(&port)
                .map(|idxs| idxs.iter().map(|&i| ev[i].clone()).collect())
                .unwrap_or_default();
            out.push(ServiceIdentity {
                service: rl.service.clone(),
                port,
                protocol: rl.protocol.clone(),
                confidence: rl.conf, // literal, never fused
                evidence,
                metadata: None,
            });
        }

        // Loop B — per-evidence rules.
        for e in ev {
            let mut fired_groups: Vec<String> = Vec::new();
            let mut texts: HashMap<(String, bool, bool, bool), String> = HashMap::new();
            for rl in &self.rules {
                if rl.host_port.is_some() {
                    continue;
                }
                if !rl.group.is_empty() && fired_groups.iter().any(|g| g == &rl.group) {
                    continue;
                }
                if let Some(g) = &rl.gate {
                    if !gate_passes(g, e, &mut texts) {
                        continue;
                    }
                }
                if !rl.matcher.matches(e, cache) {
                    continue;
                }
                let conf = if rl.literal_conf {
                    rl.conf
                } else {
                    fuse_confidence(e.confidence, rl.conf)
                };
                let md = rl.extract.apply(&rl.root_regex, &rl.match_transform, e, cache);
                out.push(ServiceIdentity {
                    service: rl.service.clone(),
                    port: e.port,
                    protocol: rl.protocol.clone(),
                    confidence: conf,
                    evidence: vec![e.clone()],
                    metadata: if md.is_empty() { None } else { Some(md) },
                });
                if !rl.group.is_empty() {
                    fired_groups.push(rl.group.clone());
                }
            }
        }
        out
    }
}

fn gate_passes(
    g: &RuleGate,
    e: &Evidence,
    texts: &mut HashMap<(String, bool, bool, bool), String>,
) -> bool {
    if g.literals.is_empty() {
        return true;
    }
    let key = (g.field.clone(), g.transform.is_some(), g.trim, g.ci);
    let text = texts
        .entry(key)
        .or_insert_with(|| {
            let mut t = matcher::field_of(e, &g.field, g.trim);
            if let Some(x) = &g.transform {
                t = x.apply(&t);
            }
            if g.ci {
                t = gostr::go_to_lower(&t);
            }
            t
        })
        .clone();
    if g.ci && !text.is_ascii() {
        return true; // case-orbit guard
    }
    g.literals.iter().any(|lit| text.contains(lit))
}

/// Go fuseConfidence: 1 - (1-a)(1-b) with both clamps, capped at 1.
pub fn fuse_confidence(a: f64, b: f64) -> f64 {
    let a = a.clamp(0.0, 1.0);
    let b = b.clamp(0.0, 1.0);
    (1.0 - (1.0 - a) * (1.0 - b)).min(1.0)
}
