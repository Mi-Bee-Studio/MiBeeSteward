//! Shared LRU cache of compiled regexes, keyed by the ORIGINAL pattern
//! string; the compiled program is the ASCII-class-rewritten pattern
//! (Go `lazyregex.go` port).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::perlfix::{compile_regex, rewrite_perl_classes};

pub struct RegexCache {
    max: usize,
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    map: HashMap<String, regex::Regex>,
    order: VecDeque<String>, // front = least recent, back = most recent
}

impl RegexCache {
    pub fn new(max: usize) -> Self {
        RegexCache {
            max: if max == 0 { 512 } else { max },
            inner: Mutex::new(CacheInner { map: HashMap::new(), order: VecDeque::new() }),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|i| i.map.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get (compiling on miss) the regex for an original pattern. Compile
    /// errors are returned as None and never cached (match-time compile
    /// errors are impossible after load validation; None = non-match).
    pub fn get(&self, pattern: &str) -> Option<regex::Regex> {
        let mut inner = self.inner.lock().ok()?;
        if let Some(re) = inner.map.get(pattern) {
            let re = re.clone();
            if let Some(pos) = inner.order.iter().position(|p| p == pattern) {
                inner.order.remove(pos);
                inner.order.push_back(pattern.to_string());
            }
            return Some(re);
        }
        let rewritten = rewrite_perl_classes(pattern).ok()?;
        let re = compile_regex(&rewritten).ok()?;
        inner.map.insert(pattern.to_string(), re.clone());
        inner.order.push_back(pattern.to_string());
        while inner.order.len() > self.max {
            if let Some(evict) = inner.order.pop_front() {
                inner.map.remove(&evict);
            }
        }
        Some(re)
    }
}
