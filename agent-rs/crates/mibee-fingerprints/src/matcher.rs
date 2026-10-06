//! Rule schema, loading, and the compiled matcher tree.
//!
//! Byte-exact port of mibee-fingerprints-go's `rule_classifier.go` matching
//! semantics (see docs/en/fingerprint-spec.md; where spec and Go code
//! disagree, the Go code is normative — notably `prefix` is case-insensitive
//! just like `prefix_ci`).

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde_yaml::Value as Yaml;

use crate::gates::{extract_gate, RuleGate};
use crate::gostr::{go_equal_fold, go_to_lower, go_to_upper, go_trim_space};
use crate::lazyregex::RegexCache;
use crate::perlfix::{rewrite_perl_classes, validate_syntax};

/// One evidence piece, wire shape identical to the Go library
/// (`fp.Evidence`); `observed_at` is an RFC3339 passthrough string.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, serde::Serialize)]
pub struct Evidence {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observed_at: String,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

impl Evidence {
    pub fn raw(&self, key: &str) -> String {
        self.raw_data.as_ref().and_then(|m| m.get(key)).cloned().unwrap_or_default()
    }
}

/// Classified identity, wire shape identical to Go `fp.ServiceIdentity`.
/// Go `encoding/json` sorts map keys; BTreeMap keeps the same output order.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ServiceIdentity {
    pub service: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub port: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

// ---------- YAML schema ----------

#[derive(Deserialize)]
struct RuleFile {
    version: i64,
    #[serde(default)]
    rules: Vec<RawRule>,
    // oid_prefixes / sysdescr_* are data consumed elsewhere; the rule
    // evaluator ignores them (same as Go's ruleFile).
}

#[derive(Deserialize)]
struct RawRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    source: String,
    r#match: Option<MatchSpec>,
    #[serde(default)]
    service: String,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    confidence: f64,
    #[serde(default)]
    literal_confidence: bool,
    #[serde(default)]
    priority: i64,
    #[serde(rename = "exclusive_group", default)]
    group: String,
    #[serde(default)]
    extract: RawExtract,
}

#[derive(Deserialize, Default)]
struct RawExtract {
    #[serde(default)]
    metadata_all: bool,
    #[serde(default)]
    metadata: serde_yaml::Mapping,
}

#[derive(Deserialize, Clone)]
pub(crate) struct MatchSpec {
    #[serde(default)]
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) field: String,
    #[serde(default)]
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) value: Yaml,
    #[serde(default)]
    pub(crate) ci: bool,
    #[serde(default)]
    pub(crate) trim: bool,
    #[serde(default)]
    pub(crate) transform: String,
    #[serde(default)]
    pub(crate) r#and: Vec<MatchSpec>,
    #[serde(default)]
    pub(crate) any: Vec<MatchSpec>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Transform {
    StripSshPrefix,
    StripRespCode,
}

impl Transform {
    pub(crate) fn parse(s: &str) -> Result<Option<Transform>, String> {
        match s {
            "" => Ok(None),
            "strip_ssh_prefix" => Ok(Some(Transform::StripSshPrefix)),
            "strip_resp_code" => Ok(Some(Transform::StripRespCode)),
            other => Err(format!("unknown transform {other:?}")),
        }
    }

    /// Go applyTransform.
    pub fn apply(&self, v: &str) -> String {
        match self {
            Transform::StripSshPrefix => {
                // strings.SplitN(v, "-", 3); >=3 parts -> parts[2] else v.
                let mut parts = v.splitn(3, '-');
                match (parts.next(), parts.next(), parts.next()) {
                    (Some(_), Some(_), Some(third)) => third.to_string(),
                    _ => v.to_string(),
                }
            }
            Transform::StripRespCode => {
                let bs = v.as_bytes();
                if bs.len() > 4
                    && bs[3] == b' '
                    && bs[0].is_ascii_digit()
                    && bs[1].is_ascii_digit()
                    && bs[2].is_ascii_digit()
                {
                    v[4..].to_string()
                } else {
                    v.to_string()
                }
            }
        }
    }
}

// ---------- compiled matcher ----------

#[derive(Clone, Debug)]
pub enum Matcher {
    /// Root-only kind scoping: wrapper rejects evidence of another kind;
    /// children never re-check kind (Go compileMatch quirk).
    RootKind { kind: String, inner: Box<Matcher> },
    KindPresence { kind: String },
    PortEq(i64),
    /// `prefix` AND `prefix_ci` — both compare case-insensitively via
    /// ToUpper on both sides (Go hasPrefix; the spec doc is wrong here).
    Prefix { field: String, trim: bool, needles_upper: Vec<String> },
    Contains { field: String, trim: bool, ci: bool, needles: Vec<String> },
    Equals { field: String, trim: bool, ci: bool, value: String },
    Regex { field: String, transform: Option<Transform>, pattern_original: String },
    And(Vec<Matcher>),
    Or(Vec<Matcher>),
    True,
}

impl Matcher {
    pub fn matches(&self, e: &Evidence, cache: &RegexCache) -> bool {
        match self {
            Matcher::RootKind { kind, inner } => e.kind == *kind && inner.matches(e, cache),
            Matcher::KindPresence { kind } => e.kind == *kind,
            Matcher::PortEq(p) => e.port == *p,
            Matcher::Prefix { field, trim, needles_upper } => {
                let v = go_to_upper(&field_of(e, field, *trim));
                needles_upper.iter().any(|n| v.starts_with(n))
            }
            Matcher::Contains { field, trim, ci, needles } => {
                let raw = field_of(e, field, *trim);
                if *ci {
                    let v = go_to_lower(&raw);
                    needles.iter().any(|n| v.contains(n))
                } else {
                    needles.iter().any(|n| raw.contains(n))
                }
            }
            Matcher::Equals { field, trim, ci, value } => {
                let v = field_of(e, field, *trim);
                if *ci {
                    go_equal_fold(&v, value)
                } else {
                    v == *value
                }
            }
            Matcher::Regex { field, transform, pattern_original } => {
                let text = field_of_transformed(e, field, transform);
                match cache.get(pattern_original) {
                    Some(re) => re.is_match(&text),
                    None => false, // compile error at match time: non-match (Go parity)
                }
            }
            Matcher::And(list) => list.iter().all(|m| m.matches(e, cache)),
            Matcher::Or(list) => list.iter().any(|m| m.matches(e, cache)),
            Matcher::True => true,
        }
    }
}

/// Go fieldOf: RawData[field] (default "banner"), optional TrimSpace.
pub fn field_of(e: &Evidence, field: &str, trim: bool) -> String {
    let v = e.raw(field);
    if trim {
        go_trim_space(&v).to_string()
    } else {
        v
    }
}

/// Go fieldOfTransformed: RawData[field], then the match transform (regex
/// path never trims).
pub fn field_of_transformed(e: &Evidence, field: &str, t: &Option<Transform>) -> String {
    let v = field_of(e, field, false);
    match t {
        Some(t) => t.apply(&v),
        None => v,
    }
}

// ---------- extract spec ----------

#[derive(Clone, Debug)]
pub enum Extractor {
    Const(String),
    Passthrough(String),
    Split { delim: String, index: usize },
    SubstringAfter { field: String, delim: String, until: Vec<String> },
    KeywordMap { field: String, ci: bool, entries: Vec<KwEntry> },
    WhenEquals { field: String, value: String, set: String },
    RegexCapture(usize),
}

#[derive(Clone, Debug)]
pub struct KwEntry {
    contains_any: Vec<String>,
    contains: String,
    set: String,
}

#[derive(Clone, Debug, Default)]
pub struct ExtractSpec {
    pub metadata_all: bool,
    pub metadata: Vec<(String, Extractor)>,
}

impl ExtractSpec {
    /// Go applyExtract: always a (possibly empty) map; empty metadata values
    /// are skipped; when_equals runs in a second pass.
    pub fn apply(
        &self,
        root: &Option<RootRegexRef>,
        match_transform: &Option<Transform>,
        e: &Evidence,
        cache: &RegexCache,
    ) -> BTreeMap<String, String> {
        let mut md: BTreeMap<String, String> = BTreeMap::new();
        if self.metadata_all {
            if let Some(rd) = &e.raw_data {
                for (k, v) in rd {
                    md.insert(k.clone(), v.clone());
                }
            }
        }
        for (key, ex) in &self.metadata {
            if matches!(ex, Extractor::WhenEquals { .. }) {
                continue; // second pass
            }
            let val = eval_extractor(ex, root, match_transform, e, cache);
            if !val.is_empty() {
                md.insert(key.clone(), val);
            }
        }
        // Second pass: when_equals entries (exact, case-sensitive equality).
        for (key, ex) in &self.metadata {
            if let Extractor::WhenEquals { field, value, set } = ex {
                if e.raw(field) == *value {
                    md.insert(key.clone(), set.clone());
                }
            }
        }
        md
    }
}

fn eval_extractor(
    ex: &Extractor,
    root: &Option<RootRegexRef>,
    match_transform: &Option<Transform>,
    e: &Evidence,
    cache: &RegexCache,
) -> String {
    match ex {
        Extractor::Const(c) => c.clone(), // empty consts fall through the is_empty skip
        Extractor::Passthrough(f) => e.raw(f),
        Extractor::Split { delim, index } => {
            // Go: hardcoded field "banner", SplitN(b, delim, index+1)[index].
            let banner = e.raw("banner");
            let parts: Vec<&str> = banner.splitn(index + 1, delim.as_str()).collect();
            parts.get(*index).map(|s| s.to_string()).unwrap_or_default()
        }
        Extractor::SubstringAfter { field, delim, until } => {
            // Go quirks: only delim's FIRST BYTE and each until entry's FIRST
            // BYTE participate.
            let s = e.raw(field);
            let Some(d0) = delim.as_bytes().first() else {
                return String::new();
            };
            let Some(i) = s.as_bytes().iter().position(|b| b == d0) else {
                return String::new();
            };
            let rest = &s[i + 1..];
            let stops: Vec<u8> = until.iter().filter_map(|u| u.as_bytes().first().copied()).collect();
            match rest.as_bytes().iter().position(|b| stops.contains(b)) {
                Some(j) => rest[..j].to_string(),
                None => rest.to_string(),
            }
        }
        Extractor::KeywordMap { field, ci, entries } => {
            let raw = e.raw(field);
            let s = if *ci { go_to_lower(&raw) } else { raw };
            for ent in entries {
                let hit = if !ent.contains_any.is_empty() {
                    ent.contains_any.iter().any(|kw| {
                        if *ci { s.contains(&go_to_lower(kw)) } else { s.contains(kw.as_str()) }
                    })
                } else if *ci {
                    s.contains(&go_to_lower(&ent.contains))
                } else {
                    s.contains(ent.contains.as_str())
                };
                if hit {
                    return ent.set.clone(); // first matching entry wins
                }
            }
            String::new()
        }
        Extractor::WhenEquals { .. } => String::new(), // handled in pass 2
        Extractor::RegexCapture(n) => {
            let Some(root) = root else { return String::new() };
            let text = field_of_transformed(e, &root.match_field, match_transform);
            match cache.get(&root.original) {
                Some(re) => match re.captures(&text) {
                    Some(caps) => {
                        let groups: Vec<Option<&str>> = caps.iter().map(|m| m.map(|x| x.as_str())).collect();
                        match groups.get(*n) {
                            Some(Some(g)) => (*g).to_string(),
                            _ => String::new(),
                        }
                    }
                    None => String::new(),
                },
                None => String::new(),
            }
        }
    }
}

/// Root-regex reference for regex_capture extractors.
#[derive(Clone, Debug)]
pub struct RootRegexRef {
    pub original: String,
    pub rewritten: String,
    pub match_field: String,
}

// ---------- compile ----------

/// A rule fully compiled for matching (matcher tree + gate + extractors).
pub struct CompiledRule {
    pub id: String,
    pub service: String,
    pub protocol: String,
    pub conf: f64,
    pub literal_conf: bool,
    pub group: String,
    /// Some(port) for host-scoped `op: port` rules (loop A).
    pub host_port: Option<i64>,
    pub matcher: Matcher,
    pub gate: Option<RuleGate>,
    pub extract: ExtractSpec,
    pub match_transform: Option<Transform>,
    pub root_regex: Option<RootRegexRef>,
    /// Sort keys (priority DESC, id ASC) applied by the loader.
    pub sort_priority: i64,
    pub sort_id: String,
}

#[derive(Debug)]
pub struct LoadError(pub String);

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn to_strings(v: &Yaml) -> Vec<String> {
    match v {
        Yaml::String(s) => vec![s.clone()],
        Yaml::Sequence(seq) => seq
            .iter()
            .filter_map(|item| match item {
                Yaml::String(s) => Some(s.clone()),
                _ => None, // non-string elements silently dropped (Go parity)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Go's single-string assertion (`v.(string)`): non-strings become "".
fn to_string_exact(v: &Yaml) -> String {
    match v {
        Yaml::String(s) => s.clone(),
        _ => String::new(),
    }
}

fn to_int(v: &Yaml) -> Result<i64, String> {
    match v {
        Yaml::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else {
                n.as_f64().map(|f| f as i64).ok_or_else(|| format!("bad number {v:?}"))
            }
        }
        Yaml::String(s) => s.parse::<i64>().map_err(|e| format!("bad int {s:?}: {e}")),
        other => Err(format!("bad port value {other:?}")),
    }
}

fn compile_inner(spec: &MatchSpec, ctx: &str) -> Result<Matcher, LoadError> {
    let field = if spec.field.is_empty() { "banner".to_string() } else { spec.field.clone() };
    let err = |msg: String| LoadError(format!("{ctx}: {msg}"));
    match spec.op.as_str() {
        "kind_presence" => Ok(Matcher::KindPresence { kind: spec.kind.clone() }),
        "port_eq" => Ok(Matcher::PortEq(to_int(&spec.value).map_err(&err)?)),
        "prefix" | "prefix_ci" => Ok(Matcher::Prefix {
            needles_upper: to_strings(&spec.value).iter().map(|s| go_to_upper(s)).collect(),
            field,
            trim: spec.trim,
        }),
        "contains" | "contains_any" => {
            let needles = to_strings(&spec.value);
            let needles = if spec.ci { needles.iter().map(|s| go_to_lower(s)).collect() } else { needles };
            Ok(Matcher::Contains { field, trim: spec.trim, ci: spec.ci, needles })
        }
        "equals" => Ok(Matcher::Equals {
            field,
            trim: spec.trim,
            ci: spec.ci,
            value: to_string_exact(&spec.value),
        }),
        "regex" => {
            let pattern = to_string_exact(&spec.value);
            let transform = Transform::parse(&spec.transform).map_err(&err)?;
            // Go validates the pattern compiles at load (hard error); a
            // syntax-only parse carries the same guarantee at load time
            // without building 2.6k programs eagerly.
            validate_syntax(&pattern).map_err(|e| err(format!("regex {pattern:?}: {e}")))?;
            rewrite_perl_classes(&pattern).map_err(|e| err(format!("regex {pattern:?}: {e}")))?;
            Ok(Matcher::Regex { field, transform, pattern_original: pattern })
        }
        "compound" => {
            let children = spec.r#and.iter().map(|s| compile_inner(s, ctx)).collect::<Result<Vec<_>, _>>()?;
            Ok(Matcher::And(children))
        }
        "or" => {
            let children = spec.any.iter().map(|s| compile_inner(s, ctx)).collect::<Result<Vec<_>, _>>()?;
            Ok(Matcher::Or(children))
        }
        other => Err(err(format!("unknown op {other:?}"))),
    }
}

fn compile_root(spec: &MatchSpec, ctx: &str) -> Result<Matcher, LoadError> {
    let inner = compile_inner(spec, ctx)?;
    // Go compileMatch: kind scoping applies ONLY at the root, and only for
    // ops other than kind_presence/port.
    if !spec.kind.is_empty() && spec.op != "kind_presence" && spec.op != "port" {
        Ok(Matcher::RootKind { kind: spec.kind.clone(), inner: Box::new(inner) })
    } else {
        Ok(inner)
    }
}

fn parse_extract(raw: &RawExtract, ctx: &str) -> Result<ExtractSpec, LoadError> {
    let err = |msg: String| LoadError(format!("{ctx}: {msg}"));
    let mut out = ExtractSpec { metadata_all: raw.metadata_all, metadata: Vec::new() };
    for (k, v) in raw.metadata.iter() {
        let Some(key) = k.as_str() else { return Err(err("metadata key not a string".into())) };
        let key = key.to_string();
        let ex: RawExtractor =
            serde_yaml::from_value(v.clone()).map_err(|e| err(format!("extractor {key:?}: {e}")))?;
        let compiled = match ex {
            RawExtractor::Const { r#const } => Extractor::Const(r#const),
            RawExtractor::Passthrough { passthrough } => Extractor::Passthrough(passthrough),
            RawExtractor::Split { split } => Extractor::Split { delim: split.delim, index: split.index },
            RawExtractor::SubstringAfter { substring_after } => Extractor::SubstringAfter {
                field: substring_after.field,
                delim: substring_after.delim,
                until: substring_after.until,
            },
            RawExtractor::KeywordMap { keyword_map } => Extractor::KeywordMap {
                field: keyword_map.field,
                ci: keyword_map.ci,
                entries: keyword_map
                    .entries
                    .into_iter()
                    .map(|ent| KwEntry {
                        contains_any: ent.contains_any.unwrap_or_default(),
                        contains: ent.contains,
                        set: ent.set,
                    })
                    .collect(),
            },
            RawExtractor::WhenEquals { when_equals } => Extractor::WhenEquals {
                field: when_equals.field,
                value: when_equals.value,
                set: when_equals.set,
            },
            RawExtractor::RegexCapture { regex_capture } => {
                if !(1..=100).contains(&regex_capture) {
                    return Err(err(format!("regex_capture group {regex_capture} out of range")));
                }
                Extractor::RegexCapture(regex_capture as usize)
            }
        };
        out.metadata.push((key, compiled));
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawExtractor {
    Const { r#const: String },
    Passthrough { passthrough: String },
    Split { split: RawSplit },
    SubstringAfter { substring_after: RawSubstringAfter },
    KeywordMap { keyword_map: RawKeywordMap },
    WhenEquals { when_equals: RawWhenEquals },
    RegexCapture { regex_capture: i64 },
}

#[derive(Deserialize)]
struct RawSplit {
    delim: String,
    index: usize,
}

#[derive(Deserialize)]
struct RawSubstringAfter {
    field: String,
    delim: String,
    #[serde(default)]
    until: Vec<String>,
}

#[derive(Deserialize)]
struct RawKeywordMap {
    field: String,
    #[serde(default)]
    ci: bool,
    #[serde(default)]
    entries: Vec<RawKwEntry>,
}

#[derive(Deserialize)]
struct RawKwEntry {
    #[serde(default)]
    contains_any: Option<Vec<String>>,
    #[serde(default)]
    contains: String,
    set: String,
}

#[derive(Deserialize)]
struct RawWhenEquals {
    field: String,
    value: String,
    set: String,
}

/// Compile one rule file's YAML text into rules (unsorted; caller sorts).
pub fn compile_rules_from_str(text: &str, file: &str) -> Result<Vec<CompiledRule>, LoadError> {
    let rf: RuleFile = serde_yaml::from_str(text).map_err(|e| LoadError(format!("fingerprint {file}: {e}")))?;
    if rf.version != 1 {
        return Err(LoadError(format!("fingerprint {file}: unsupported version {}", rf.version)));
    }
    let mut out = Vec::with_capacity(rf.rules.len());
    for raw in &rf.rules {
        let ctx = format!("fingerprint {file} rule {:?}", raw.id);
        let Some(spec) = &raw.r#match else { return Err(LoadError(format!("{ctx}: missing match"))) };
        let host_port = if spec.op == "port" {
            Some(to_int(&spec.value).map_err(|e| LoadError(format!("{ctx}: {e}")))?)
        } else {
            None
        };
        let matcher = if host_port.is_some() { Matcher::True } else { compile_root(spec, &ctx)? };
        let gate = if host_port.is_some() { None } else { extract_gate(spec) };
        let extract = parse_extract(&raw.extract, &ctx)?;
        let match_transform = if spec.op == "regex" {
            Transform::parse(&spec.transform).map_err(|e| LoadError(format!("{ctx}: {e}")))?
        } else {
            None
        };
        let root_regex = if spec.op == "regex" {
            let field = if spec.field.is_empty() { "banner".to_string() } else { spec.field.clone() };
            let original = to_string_exact(&spec.value);
            let rewritten = rewrite_perl_classes(&original)
                .map_err(|e| LoadError(format!("{ctx}: regex {original:?}: {e}")))?;
            Some(RootRegexRef { original, rewritten, match_field: field })
        } else {
            None
        };
        out.push(CompiledRule {
            id: raw.id.clone(),
            service: raw.service.clone(),
            protocol: raw.protocol.clone(),
            conf: raw.confidence,
            literal_conf: raw.literal_confidence,
            group: raw.group.clone(),
            host_port,
            matcher,
            gate,
            extract,
            match_transform,
            root_regex,
            sort_priority: raw.priority,
            sort_id: raw.id.clone(),
        });
    }
    // Priority DESC, then id ASC, stable (Go sort.SliceStable on the
    // filename-ordered concatenation).
    out.sort_by(|a, b| b.sort_priority.cmp(&a.sort_priority).then_with(|| a.sort_id.cmp(&b.sort_id)));
    Ok(out)
}
