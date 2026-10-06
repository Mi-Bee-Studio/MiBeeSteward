//! Literal gates: provably-required substrings that must appear in the
//! evidence text for a rule to match, letting the classifier skip regex work
//! without ever skipping a match (Go `gates.go` port).
//!
//! Soundness rules mirrored exactly:
//! - gate literals are ASCII-only, non-blank;
//! - CI gates never skip non-ASCII text (case-orbit guard);
//! - prefix ops gate with ci=true (both are CI in the matcher);
//! - alternation gates on the longest common prefix of branch literals;
//! - `or` / port / port_eq / kind_presence never gate.

use std::collections::HashMap;

use regex_syntax::ast::{Ast, FlagsItemKind, RepetitionKind, RepetitionRange};

use crate::gostr::{go_to_lower, go_trim_space};
use crate::matcher::{field_of, Evidence, MatchSpec, Transform};

pub struct RuleGate {
    pub field: String,
    pub transform: Option<Transform>,
    pub trim: bool,
    pub ci: bool,
    /// ASCII, non-blank; lowercase when ci.
    pub literals: Vec<String>,
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct GateKey {
    field: String,
    transform: bool,
    trim: bool,
    ci: bool,
}

impl RuleGate {
    /// passes() with the caller-owned per-evidence text cache (Go parity).
    pub fn passes(&self, e: &Evidence, texts: &mut HashMap<GateKey, String>) -> bool {
        if self.literals.is_empty() {
            return true;
        }
        let key = GateKey {
            field: self.field.clone(),
            transform: self.transform.is_some(),
            trim: self.trim,
            ci: self.ci,
        };
        let text = texts
            .entry(key)
            .or_insert_with(|| {
                let mut t = field_of(e, &self.field, self.trim);
                if let Some(x) = &self.transform {
                    t = x.apply(&t);
                }
                if self.ci {
                    t = go_to_lower(&t);
                }
                t
            })
            .clone();
        if self.ci && !text.is_ascii() {
            return true; // case-orbit guard (ſ/ß/İ...): never skip non-ASCII
        }
        self.literals.iter().any(|lit| text.contains(lit))
    }
}

fn gate_literal_ok(s: &str) -> bool {
    !s.is_empty() && !go_trim_space(s).is_empty() && s.is_ascii()
}

/// Go extractGate: compute the strongest provable gate for a match spec.
pub fn extract_gate(spec: &MatchSpec) -> Option<RuleGate> {
    let mut gate = extract_gate_from(spec)?;
    if gate.field.is_empty() {
        gate.field = "banner".to_string();
    }
    if gate.ci {
        gate.literals = gate.literals.iter().map(|l| go_to_lower(l)).collect();
    }
    gate.literals.retain(|l| gate_literal_ok(l));
    if gate.literals.is_empty() {
        return None;
    }
    Some(RuleGate {
        field: gate.field,
        transform: gate.transform,
        trim: gate.trim,
        ci: gate.ci,
        literals: gate.literals,
    })
}

struct RawGate {
    field: String,
    transform: Option<Transform>,
    trim: bool,
    ci: bool,
    literals: Vec<String>,
}

fn spec_values(spec: &MatchSpec) -> Vec<String> {
    match &spec.value {
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|i| i.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

fn extract_gate_from(spec: &MatchSpec) -> Option<RawGate> {
    match spec.op.as_str() {
        "contains" | "contains_any" | "equals" => {
            let literals: Vec<String> = spec_values(spec).into_iter().filter(|v| gate_literal_ok(v)).collect();
            Some(RawGate { field: spec.field.clone(), transform: None, trim: spec.trim, ci: spec.ci, literals })
        }
        "prefix" | "prefix_ci" => {
            let literals: Vec<String> = spec_values(spec).into_iter().filter(|v| gate_literal_ok(v)).collect();
            Some(RawGate { field: spec.field.clone(), transform: None, trim: spec.trim, ci: true, literals })
        }
        "regex" => {
            let pattern = match spec.value.as_str() {
                Some(p) => p.to_string(),
                None => return None,
            };
            let (lit, fold) = mandatory_literals(&pattern)?;
            if !gate_literal_ok(&lit) {
                return None;
            }
            Some(RawGate {
                field: spec.field.clone(),
                transform: Transform::parse(&spec.transform).ok().flatten(),
                trim: false,
                ci: fold,
                literals: vec![lit],
            })
        }
        "compound" => {
            // Strongest (longest max-literal-length) sub-gate among children.
            let mut best: Option<RawGate> = None;
            for child in &spec.r#and {
                if let Some(g) = extract_gate_from(child) {
                    let len = g.literals.iter().map(|l| l.len()).max().unwrap_or(0);
                    let best_len =
                        best.as_ref().and_then(|b| b.literals.iter().map(|l| l.len()).max()).unwrap_or(0);
                    if !g.literals.is_empty() && len > best_len {
                        best = Some(g);
                    }
                }
            }
            best
        }
        // or / port / port_eq / kind_presence / unknown: never gate.
        _ => None,
    }
}

/// Go mandatoryLiterals: the longest mandatory literal of a pattern (with
/// whether it is case-folded), via an AST walk.
///
/// Go's regexp/syntax bakes FoldCase into OpLiteral runs; regex-syntax
/// exposes single-char Literals with flags tracked by `(?i)` items, so the
/// Concat walker gathers maximal literal runs under a tracked fold state.
fn mandatory_literals(pattern: &str) -> Option<(String, bool)> {
    let ast = regex_syntax::ast::parse::Parser::new()
        .parse(pattern)
        .map_err(|e| format!("gate parse {pattern:?}: {e}"))
        .ok()?;
    let (lit, lfold) = ast_mandatory(&ast, false)?;
    if lfold {
        Some((go_to_lower(&lit), true))
    } else {
        Some((lit, false))
    }
}

fn ast_mandatory(ast: &Ast, fold: bool) -> Option<(String, bool)> {
    match ast {
        Ast::Literal(l) => Some((l.c.to_string(), fold)),
        Ast::Repetition(rep) => {
            let min = match rep.op.kind {
                RepetitionKind::ZeroOrOne | RepetitionKind::ZeroOrMore => 0,
                RepetitionKind::OneOrMore => 1,
                RepetitionKind::Range(RepetitionRange::Exactly(m)) => m,
                RepetitionKind::Range(RepetitionRange::AtLeast(m)) => m,
                RepetitionKind::Range(RepetitionRange::Bounded(m, _)) => m,
            };
            if min >= 1 {
                ast_mandatory(&rep.ast, fold)
            } else {
                None
            }
        }
        Ast::Group(g) => {
            // (?i:...) groups carry their flags as a Flags item at the head
            // of the body; recursing into the body handles them naturally.
            ast_mandatory(&g.ast, fold)
        }
        Ast::Concat(_) => concat_mandatory(ast, fold),
        Ast::Alternation(_) => alternation_mandatory(ast, fold),
        // Empty/Flags/Dot/Assertion/classes/comments can never contribute a
        // mandatory literal.
        _ => None,
    }
}

fn keep_best(best: &mut Option<(String, bool)>, cand: (String, bool)) {
    if !cand.0.is_empty() && best.as_ref().map(|b| b.0.len() < cand.0.len()).unwrap_or(true) {
        *best = Some(cand);
    }
}

fn concat_mandatory(ast: &Ast, fold: bool) -> Option<(String, bool)> {
    let items: &[Ast] = match ast {
        Ast::Concat(c) => &c.asts,
        _ => return None,
    };
    // Linear walk tracking (?i)/(?-i) toggles; gather maximal literal runs.
    let mut best: Option<(String, bool)> = None;
    let mut run = String::new();
    let mut run_fold = fold;
    let mut cur_fold = fold;
    for item in items.iter() {
        match item {
            Ast::Flags(f) => {
                // `(?i)`/`(?-i)` parse as Flag/Negation items; a Negation
                // applies to the flag item that follows it.
                let mut negated = false;
                for fi in &f.flags.items {
                    match &fi.kind {
                        FlagsItemKind::Negation => negated = true,
                        FlagsItemKind::Flag(op) => {
                            use regex_syntax::ast::Flag as F;
                            if matches!(op, F::CaseInsensitive) {
                                cur_fold = !negated;
                            }
                            negated = false;
                        }
                    }
                }
            }
            Ast::Literal(l) => {
                if run.is_empty() {
                    run_fold = cur_fold;
                    run.push(l.c);
                } else if run_fold == cur_fold {
                    run.push(l.c);
                } else {
                    keep_best(&mut best, (std::mem::take(&mut run), run_fold));
                    run_fold = cur_fold;
                    run.push(l.c);
                }
            }
            other => {
                // Nested structure: a mandatory literal inside still counts
                // (Go: any one child's literal — all children must occur).
                keep_best(&mut best, (std::mem::take(&mut run), run_fold));
                if let Some(g) = ast_mandatory(other, cur_fold) {
                    keep_best(&mut best, g);
                }
            }
        }
    }
    keep_best(&mut best, (std::mem::take(&mut run), run_fold));
    best
}

fn alternation_mandatory(ast: &Ast, fold: bool) -> Option<(String, bool)> {
    let alt = match ast {
        Ast::Alternation(a) => a,
        _ => return None,
    };
    // Longest common byte prefix of each branch's (lowercased-if-fold)
    // mandatory literal; result is CI. Empty prefix or any branch without a
    // literal -> no gate (Go parity).
    let mut prefix: Option<String> = None;
    for branch in &alt.asts {
        let Some((lit, lfold)) = ast_mandatory(branch, fold) else {
            return None;
        };
        let lit = if lfold { go_to_lower(&lit) } else { lit };
        if lit.is_empty() {
            return None;
        }
        prefix = Some(match prefix {
            None => lit,
            Some(p) => {
                let common = p
                    .as_bytes()
                    .iter()
                    .zip(lit.as_bytes())
                    .take_while(|(a, b)| a == b)
                    .count();
                p[..common].to_string()
            }
        });
        if prefix.as_ref().map(|p| p.is_empty()).unwrap_or(true) {
            return None;
        }
    }
    prefix.map(|p| (p, true))
}
