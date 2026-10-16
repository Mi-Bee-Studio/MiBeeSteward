//! fpsync::sync_once end-to-end against a minimal in-process mock center.
//! Pins the sync semantics the Go agent had: rev negotiation (204 keeps
//! state), tarball validation chain (shape -> classifier loader -> swap),
//! rollback-on-reject, and the deferred-reexec rate limit (a fresh marker
//! file forces Deferred so tests never re-exec themselves).

use std::path::{Path, PathBuf};
use std::time::Duration;

use mibee_agent::center::CenterClient;
use mibee_agent::fpsync::{sync_once, SyncOutcome};

// ---------- tiny canned-response HTTP mock ----------

enum Reply {
    NotModified,
    Unavailable,
    Tarball { rev: String, body: Vec<u8> },
}

async fn spawn_mock(reply: Reply) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // drain the request head (GETs carry no body)
            let mut buf = Vec::new();
            let mut chunk = [0u8; 2048];
            loop {
                let n = tokio::io::AsyncReadExt::read(&mut sock, &mut chunk)
                    .await
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            log2.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf).to_string());
            let resp: Vec<u8> = match &reply {
                Reply::NotModified => b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..].to_vec(),
                Reply::Unavailable => b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 11\r\nConnection: close\r\n\r\nunavailable"[..].to_vec(),
                Reply::Tarball { rev, body } => {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nX-Fingerprint-Rev: {rev}\r\nContent-Type: application/gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let mut resp = head.into_bytes();
                    resp.extend_from_slice(body);
                    resp
                }
            };
            let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, &resp).await;
        }
    });
    (format!("http://{addr}"), log)
}

// ---------- fixtures ----------

fn build_flat_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (name, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, &content[..])
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz = Vec::new();
    {
        use flate2::write::GzEncoder;
        let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        std::io::Write::write_all(&mut e, &tar_bytes).unwrap();
        e.finish().unwrap();
    }
    gz
}

/// A real corpus member (port-shape rules) — guarantees the tarball passes
/// the classifier's own loader with rules > 0.
fn real_rule_yaml() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/fingerprints/ports.yaml");
    std::fs::read(&path).expect("embedded corpus member ports.yaml")
}

/// Pre-create the reexec rate-limit marker so maybe_reexec() takes the
/// Deferred branch: on Linux an absent marker would re-exec the test binary.
fn pin_reexec_marker() {
    let marker = std::env::temp_dir().join(format!("mibee-agent-reexec-{}", std::process::id()));
    std::fs::write(&marker, b"").unwrap();
}

fn client(base: &str) -> CenterClient {
    CenterClient::new(
        base.to_string(),
        "test-token".into(),
        Duration::from_secs(10),
    )
}

/// sync_dir pre-seeded with an old corpus file + .rev, proving the swap.
fn seeded_sync_dir(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let sync_dir = dir.path().join(tag);
    std::fs::create_dir_all(&sync_dir).unwrap();
    std::fs::write(sync_dir.join("old-corpus.yaml"), b"version: 1\nrules: []\n").unwrap();
    std::fs::write(rev_path(&sync_dir), b"oldrev\n").unwrap();
    (dir, sync_dir)
}

fn rev_path(sync_dir: &Path) -> PathBuf {
    PathBuf::from(format!("{}.rev", sync_dir.display()))
}

// ---------- the sync contract ----------

#[tokio::test]
async fn not_modified_keeps_disk_state() {
    let (base, _log) = spawn_mock(Reply::NotModified).await;
    let (_guard, sync_dir) = seeded_sync_dir("fp-a");
    let outcome = sync_once(&client(&base), &sync_dir).await;
    assert_eq!(outcome, SyncOutcome::NotModified);
    assert_eq!(
        std::fs::read_to_string(rev_path(&sync_dir)).unwrap(),
        "oldrev\n"
    );
    assert!(
        sync_dir.join("old-corpus.yaml").exists(),
        "corpus untouched"
    );
}

#[tokio::test]
async fn applies_valid_corpus_swaps_dirs_and_defers_reexec() {
    pin_reexec_marker();
    let gz = build_flat_tar_gz(&[("ports.yaml", &real_rule_yaml())]);
    let (base, log) = spawn_mock(Reply::Tarball {
        rev: "r2".into(),
        body: gz,
    })
    .await;
    let (_guard, sync_dir) = seeded_sync_dir("fp-b");
    let outcome = sync_once(&client(&base), &sync_dir).await;
    assert_eq!(
        outcome,
        SyncOutcome::Applied {
            rev: "r2".into(),
            reexec_deferred: true
        },
        "fresh marker forces the Deferred branch"
    );
    assert!(sync_dir.join("ports.yaml").exists(), "new corpus is live");
    assert!(
        !sync_dir.join("old-corpus.yaml").exists(),
        "old corpus rotated out"
    );
    assert!(
        !PathBuf::from(format!("{}.staging", sync_dir.display())).exists(),
        "staging cleaned"
    );
    // deferred semantics: the .rev is dropped so the next poll re-attempts
    assert!(!rev_path(&sync_dir).exists());
    // wire: rev negotiation + bearer token (hyper lowercases header names)
    let req = log.lock().unwrap()[0].clone();
    assert!(
        req.contains("GET /api/v1/agents/fingerprints?rev=oldrev"),
        "req: {req}"
    );
    assert!(
        req.to_lowercase()
            .contains("authorization: bearer test-token"),
        "req: {req}"
    );
}

#[tokio::test]
async fn rejects_zero_rule_corpus_and_keeps_the_old_one() {
    let gz = build_flat_tar_gz(&[("empty.yaml", b"version: 1\nrules: []\n")]);
    let (base, _log) = spawn_mock(Reply::Tarball {
        rev: "r3".into(),
        body: gz,
    })
    .await;
    let (_guard, sync_dir) = seeded_sync_dir("fp-c");
    let outcome = sync_once(&client(&base), &sync_dir).await;
    assert_eq!(
        outcome,
        SyncOutcome::RejectedInvalid("corpus loaded zero rules")
    );
    assert!(
        sync_dir.join("old-corpus.yaml").exists(),
        "a rejected corpus never displaces a working one"
    );
    assert!(
        !PathBuf::from(format!("{}.staging", sync_dir.display())).exists(),
        "staging cleaned on reject"
    );
    assert_eq!(
        std::fs::read_to_string(rev_path(&sync_dir)).unwrap(),
        "oldrev\n"
    );
}

#[tokio::test]
async fn rejects_empty_archive_without_touching_state() {
    let gz = build_flat_tar_gz(&[]);
    let (base, _log) = spawn_mock(Reply::Tarball {
        rev: "r4".into(),
        body: gz,
    })
    .await;
    let (_guard, sync_dir) = seeded_sync_dir("fp-d");
    let outcome = sync_once(&client(&base), &sync_dir).await;
    assert_eq!(
        outcome,
        SyncOutcome::RejectedInvalid("archive carries no rules")
    );
    assert!(sync_dir.join("old-corpus.yaml").exists());
}

#[tokio::test]
async fn unavailable_center_is_reported_not_fatal() {
    let (base, _log) = spawn_mock(Reply::Unavailable).await;
    let (_guard, sync_dir) = seeded_sync_dir("fp-e");
    assert_eq!(
        sync_once(&client(&base), &sync_dir).await,
        SyncOutcome::Unavailable
    );
    assert!(sync_dir.join("old-corpus.yaml").exists());
}
