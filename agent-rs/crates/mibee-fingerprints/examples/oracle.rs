//! Differential-test oracle: mirror of difftest/go_oracle_main.go.
//!
//! Input line:  {"dir":"<corpus dir>","evidence":[{...}]}
//! Output line: {"line":N,"identities":[...]}
//! Compare byte-for-byte against the Go oracle over the same battery.

use std::io::{BufRead, Write};

use mibee_fingerprints::{Evidence, RuleClassifier, ServiceIdentity};
use serde::Serialize;

#[derive(Serialize)]
struct Resp {
    line: usize,
    // Go's Classify returns a nil slice when nothing matches, which
    // marshals as JSON null (not []); mirror that for byte parity.
    identities: Option<Vec<ServiceIdentity>>,
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut line_no = 0usize;
    let mut classifier = RuleClassifier::new();
    let mut loaded_dir = String::new();
    for line in stdin.lock().lines() {
        let line = line.expect("read stdin");
        line_no += 1;
        let mut v: serde_json::Value = serde_json::from_str(&line).expect("battery line JSON");
        let dir = v["dir"].as_str().unwrap_or_default().to_string();
        let evidence: Vec<Evidence> =
            serde_json::from_value(v["evidence"].take()).expect("evidence array");
        if dir != loaded_dir {
            classifier = RuleClassifier::new();
            classifier.load_from_dir(&dir).expect("load corpus");
            loaded_dir = dir;
        }
        let identities = classifier.classify(&evidence);
        let identities = if identities.is_empty() { None } else { Some(identities) };
        let resp = Resp { line: line_no, identities };
        // Go's encoding/json prints float64 1 as "1" (no ".0"); serde_json
        // prints "1.0". Normalize integer-valued floats for byte parity
        // (preserve_order keeps the struct field order in the Value tree).
        let mut jv = serde_json::to_value(&resp).unwrap();
        normalize_floats(&mut jv);
        serde_json::to_writer(&mut out, &jv).unwrap();
        out.write_all(b"\n").unwrap();
    }
}

fn normalize_floats(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if f == f.trunc() && f.abs() < 1e15 {
                    *n = serde_json::Number::from(f as i64);
                }
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(normalize_floats),
        serde_json::Value::Object(o) => o.iter_mut().for_each(|(_, x)| normalize_floats(x)),
        _ => {}
    }
}
