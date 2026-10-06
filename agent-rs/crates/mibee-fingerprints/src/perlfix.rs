//! Rewrite Go-RE2 Perl classes to ASCII-only classes for Rust's `regex`.
//!
//! Go's `\d`/`\w`/`\s` are ASCII-only; Rust's are Unicode-aware. A non-ASCII
//! HTTP title containing an Arabic-Indic digit would make Rust `\d` match
//! where Go does not. We rewrite, outside character classes:
//!   `\d`->`[0-9]`  `\D`->`[^0-9]`  `\w`->`[0-9A-Za-z_]`  `\W`->`[^0-9A-Za-z_]`
//!   `\s`->`[\t\n\f\r ]`  `\S`->`[^\t\n\f\r ]`
//! and inside character classes the positive forms to ranges:
//!   `[\d]`->`[0-9]` `[\w]`->`[0-9A-Za-z_]` `[\s]`->`[\t\n\f\r ]`
//! Negated forms inside a class are left untouched (none exist in the
//! corpus; the loader rejects any pattern still containing them so the
//! divergence cannot ship silently — see `assert_no_inner_negated`).
//!
//! The transformer is a small state machine: it skips escaped backslashes
//! (`\\d` is a literal `d`), tracks class nesting, and leaves everything else
//! (including `(?...)` groups) byte-identical. Every rewritten pattern must
//! still compile; the loader enforces that, and the differential oracle
//! against the Go implementation is the final arbiter.

pub fn rewrite_perl_classes(pat: &str) -> Result<String, String> {
    let mut out = String::with_capacity(pat.len() + 16);
    let mut in_class = false;
    let mut it = pat.char_indices().peekable();
    while let Some((idx, c)) = it.next() {
        if c != '\\' {
            if c == '[' && !in_class {
                // Sole-member negated classes ([\S]/[\D]/[\W]) rewrite as
                // whole-bracket ASCII negations; mixed-member negated classes
                // have no safe textual rewrite and stay rejected (the corpus
                // has exactly one sole-member case and zero mixed).
                if let Some((replacement, span)) = sole_negated_class(pat, idx) {
                    out.push_str(&replacement);
                    let end = idx + span;
                    while let Some(&(j, _)) = it.peek() {
                        if j < end {
                            it.next();
                        } else {
                            break;
                        }
                    }
                    continue;
                }
                in_class = true;
            } else if c == ']' {
                in_class = false;
            }
            out.push(c);
            continue;
        }
        let Some((_, next)) = it.next() else {
            out.push('\\');
            break;
        };
        match (in_class, next) {
            (false, 'd') => out.push_str("[0-9]"),
            (false, 'D') => out.push_str("[^0-9]"),
            (false, 'w') => out.push_str("[0-9A-Za-z_]"),
            (false, 'W') => out.push_str("[^0-9A-Za-z_]"),
            (false, 's') => out.push_str("[\\t\\n\\f\\r ]"),
            (false, 'S') => out.push_str("[^\\t\\n\\f\\r ]"),
            (true, 'd') => out.push_str("0-9"),
            (true, 'w') => out.push_str("0-9A-Za-z_"),
            (true, 's') => out.push_str("\\t\\n\\f\\r "),
            (true, 'D') | (true, 'W') | (true, 'S') => {
                return Err(format!(
                    "negated perl class \\{next} inside a character class has no ASCII rewrite"
                ))
            }
            _ => {
                out.push('\\');
                out.push(next);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_outside_classes() {
        assert_eq!(rewrite_perl_classes(r"^(\d+)\.\d$").unwrap(), r"^([0-9]+)\.[0-9]$");
        assert_eq!(
            rewrite_perl_classes(r"\w+-\w+").unwrap(),
            r"[0-9A-Za-z_]+-[0-9A-Za-z_]+"
        );
        assert_eq!(rewrite_perl_classes(r"\s*\S").unwrap(), r"[\t\n\f\r ]*[^\t\n\f\r ]");
    }

    #[test]
    fn rewrites_inside_classes() {
        assert_eq!(rewrite_perl_classes(r"^[\d\-\.]+$").unwrap(), r"^[0-9\-\.]+$");
        assert_eq!(rewrite_perl_classes(r"[\w.]+").unwrap(), r"[0-9A-Za-z_.]+");
    }

    #[test]
    fn leaves_escaped_backslash_and_others() {
        assert_eq!(rewrite_perl_classes(r"\\d").unwrap(), r"\\d");
        assert_eq!(rewrite_perl_classes(r"\d{2}\:\d").unwrap(), r"[0-9]{2}\:[0-9]");
        assert_eq!(rewrite_perl_classes(r"(?i)abc").unwrap(), r"(?i)abc");
    }

    #[test]
    fn sole_negated_class_rewrites() {
        assert_eq!(rewrite_perl_classes(r"([\S]+) x").unwrap(), r"([^\t\n\f\r ]+) x");
        assert_eq!(rewrite_perl_classes(r"[\D]{2}").unwrap(), r"[^0-9]{2}");
    }

    #[test]
    fn mixed_negated_in_class_rejected() {
        assert!(rewrite_perl_classes(r"[a\D]+").is_err());
    }

    #[test]
    fn rewritten_patterns_compile() {
        for pat in [
            r"^SSH-[\d.]+",
            r"(?i)^viomi-(?:[^-_.]*-)*?([0-9a-z]+)(?:\.[0-9a-z-]+)*$",
            r"^([\w ]{1,512}) FTP server",
            r"Version (\d+)\.(\d+)",
        ] {
            let rewritten = rewrite_perl_classes(pat).unwrap();
            regex::Regex::new(&rewritten).unwrap_or_else(|e| panic!("{pat} -> {rewritten}: {e}"));
        }
    }
}

/// Syntax-only validation (regex-syntax parse) — as fast as the Go loader's
/// regexp.Compile check, without eagerly building programs (armv7 corpus
/// load: ~40s with full compile, sub-second with this).
pub fn validate_syntax(pattern: &str) -> Result<(), String> {
    regex_syntax::parse(pattern).map(|_| ()).map_err(|e| e.to_string())
}

/// Compile a (rewritten) pattern with a size limit generous enough for the
/// corpus's bounded repeats (`{1,512}` char classes). Go's RE2 compiles
/// these fine; Rust's default 10 MiB cap rejects them.
pub fn compile_regex(rewritten: &str) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(rewritten)
        .size_limit(256 * 1024 * 1024)
        .dfa_size_limit(256 * 1024 * 1024)
        .build()
}

/// If `pat` starting at the `[` at byte position `at` is a bracket whose
/// content is exactly `\S`, `\D`, or `\W`, return the ASCII negated-class
/// replacement and how many chars the bracket spans.
fn sole_negated_class(pat: &str, at: usize) -> Option<(String, usize)> {
    let bytes = pat.as_bytes();
    if bytes.get(at) != Some(&b'[') {
        return None;
    }
    let mut i = at + 1;
    // "[]]"-style literal brackets don't occur in this corpus; first ']' closes.
    while i < bytes.len() && bytes[i] != b']' {
        if bytes[i] == b'\\' {
            i += 1;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let body = &pat[at + 1..i];
    let replacement = match body {
        "\\S" => "[^\\t\\n\\f\\r ]",
        "\\D" => "[^0-9]",
        "\\W" => "[^0-9A-Za-z_]",
        // "any character" complement-pair idioms == dotall dot.
        "\\s\\S" | "\\S\\s" | "\\d\\D" | "\\D\\d" | "\\w\\W" | "\\W\\w" => "(?s:.)",
        _ => return None,
    };
    Some((replacement.to_string(), i - at + 1))
}
