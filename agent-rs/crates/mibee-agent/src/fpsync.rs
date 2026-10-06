//! Fingerprint corpus sync: poll GET /agents/fingerprints?rev=, extract the
//! deterministic tar.gz (flat *.yaml only, Go fpsync limits), validate with
//! the classifier's own loader, swap the synced dir (with rollback), write
//! .rev, and re-exec the process rate-limited to once per 5 minutes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mibee_fingerprints::RuleClassifier;

use crate::center::{CenterClient, FingerprintFetch};

pub const MIN_RESTART_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub enum SyncOutcome {
    NotModified,
    Applied { rev: String, reexec_deferred: bool },
    Unavailable,
    RejectedInvalid(&'static str),
    Error(String),
}

/// One sync attempt. `sync_dir` is <configdir>/fingerprints-sync; `rev_path`
/// is `<sync_dir>.rev` (Go layout).
pub async fn sync_once(
    client: &CenterClient,
    sync_dir: &Path,
) -> SyncOutcome {
    let rev_path = PathBuf::from(format!("{}.rev", sync_dir.display()));
    let current_rev = std::fs::read_to_string(&rev_path).unwrap_or_default();
    let fetch = match client.get_fingerprints(current_rev.trim()).await {
        Ok(f) => f,
        Err(e) => return SyncOutcome::Error(e.to_string()),
    };
    match fetch {
        FingerprintFetch::NotModified => SyncOutcome::NotModified,
        FingerprintFetch::Unavailable => SyncOutcome::Unavailable,
        FingerprintFetch::Tarball { rev, bytes } => {
            if bytes.len() > MAX_ARCHIVE_BYTES {
                return SyncOutcome::RejectedInvalid("archive exceeds 16 MiB");
            }
            // extract to a staging dir
            let staging = PathBuf::from(format!("{}.staging", sync_dir.display()));
            let _ = std::fs::remove_dir_all(&staging);
            if let Err(e) = std::fs::create_dir_all(&staging) {
                return SyncOutcome::Error(format!("staging dir: {e}"));
            }
            match extract_flat_yaml_tar_gz(&bytes, &staging) {
                Ok(count) if count > 0 => {}
                Ok(_) => return SyncOutcome::RejectedInvalid("archive carries no rules"),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&staging);
                    return SyncOutcome::RejectedInvalid(e);
                }
            }
            // validate through the rule engine's own loader (a broken corpus
            // never displaces a working one)
            let mut probe = RuleClassifier::new();
            match probe.load_from_dir(staging.to_string_lossy().as_ref()) {
                Ok(()) if probe.loaded() && probe.rule_count() > 0 => {}
                Ok(()) => {
                    let _ = std::fs::remove_dir_all(&staging);
                    return SyncOutcome::RejectedInvalid("corpus loaded zero rules");
                }
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&staging);
                    return SyncOutcome::Error(format!("corpus rejected by loader: {e}"));
                }
            }
            // swap: old -> .old, staging -> live, drop .old
            let old = PathBuf::from(format!("{}.old", sync_dir.display()));
            let _ = std::fs::remove_dir_all(&old);
            if sync_dir.exists() {
                if let Err(e) = std::fs::rename(sync_dir, &old) {
                    let _ = std::fs::remove_dir_all(&staging);
                    return SyncOutcome::Error(format!("park old dir: {e}"));
                }
            }
            if let Err(e) = std::fs::rename(&staging, sync_dir) {
                let _ = std::fs::rename(&old, sync_dir); // rollback
                return SyncOutcome::Error(format!("activate: {e}"));
            }
            let _ = std::fs::remove_dir_all(&old);
            if let Err(e) = std::fs::write(&rev_path, &rev) {
                return SyncOutcome::Error(format!("write .rev: {e}"));
            }
            // rate-limited re-exec; when deferred, drop the .rev so the next
            // poll re-attempts (Go semantics: the rate-limit window coalesces)
            match maybe_reexec() {
                Reexec::Performed => SyncOutcome::Applied { rev, reexec_deferred: false },
                Reexec::Deferred => {
                    let _ = std::fs::remove_file(&rev_path);
                    SyncOutcome::Applied { rev, reexec_deferred: true }
                }
            }
        }
    }
}

/// Extract a tar.gz that must contain ONLY flat *.yaml entries (Go fpsync
/// ExtractTarGz rules: any other shape rejects the whole archive).
pub fn extract_flat_yaml_tar_gz(bytes: &[u8], out_dir: &Path) -> Result<usize, &'static str> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    let mut count = 0usize;
    for entry in archive.entries().map_err(|_| "bad tar stream")? {
        let mut entry = entry.map_err(|_| "bad tar entry")?;
        count += 1;
        if count > MAX_FILES {
            return Err("more than 64 files");
        }
        let path = entry.path().map_err(|_| "bad entry path")?.to_path_buf();
        let name = path.to_string_lossy().into_owned();
        if name.contains('/') || name.contains('\\') {
            return Err("nested path in archive");
        }
        if !name.ends_with(".yaml") {
            return Err("non-yaml entry in archive");
        }
        let header_size = entry.header().size().map_err(|_| "bad entry size")?;
        if header_size as usize > MAX_FILE_BYTES {
            return Err("file exceeds 4 MiB");
        }
        let mut buf = Vec::with_capacity(header_size as usize);
        std::io::Read::read_to_end(&mut entry, &mut buf).map_err(|_| "entry read failed")?;
        std::fs::write(out_dir.join(&name), &buf).map_err(|_| "write failed")?;
    }
    Ok(count)
}

enum Reexec {
    Performed,
    Deferred,
}

fn last_restart_marker() -> PathBuf {
    let dir = std::env::temp_dir();
    dir.join(format!("mibee-agent-reexec-{}", std::process::id()))
}

fn maybe_reexec() -> Reexec {
    let marker = last_restart_marker();
    if let Ok(meta) = std::fs::metadata(&marker) {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().map(|e| e < MIN_RESTART_INTERVAL).unwrap_or(true) {
                return Reexec::Deferred;
            }
        }
    }
    let _ = std::fs::write(&marker, b"");
    // re-exec the current binary with the same argv (unix exec semantics)
    #[cfg(target_os = "linux")]
    {
        let exe = std::env::current_exe().expect("current exe");
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut cmd = std::process::Command::new(exe);
        cmd.args(&args);
        use std::os::unix::process::CommandExt;
        let _ = cmd.exec();
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("fpsync: re-exec requested (no-op on this platform for tests)");
    }
    Reexec::Performed
}

/// The poll loop (interval from config, clamped >= 60s upstream).
pub async fn run_sync_loop(client: Arc<CenterClient>, sync_dir: PathBuf, interval: std::time::Duration, mut stop: tokio::sync::watch::Receiver<bool>) {
    loop {
        match sync_once(&client, &sync_dir).await {
            SyncOutcome::Applied { rev, reexec_deferred } => {
                eprintln!("fpsync: applied corpus rev {rev} (reexec deferred: {reexec_deferred})");
            }
            SyncOutcome::NotModified => {}
            SyncOutcome::Unavailable => {}
            SyncOutcome::RejectedInvalid(why) => eprintln!("fpsync: corpus rejected: {why}"),
            SyncOutcome::Error(e) => eprintln!("fpsync: {e}"),
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = stop.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_flat_yaml_and_rejects_other_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("x");
        std::fs::create_dir_all(&out).unwrap();
        // build a valid flat archive
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            let content = b"version: 1\nrules: []\n";
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, "a.yaml", &content[..]).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = Vec::new();
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            let mut e = GzEncoder::new(&mut gz, Compression::default());
            std::io::Write::write_all(&mut e, &tar_bytes).unwrap();
            e.finish().unwrap();
        }
        assert_eq!(extract_flat_yaml_tar_gz(&gz, &out).unwrap(), 1);
        assert!(out.join("a.yaml").exists());

        // nested path rejects the whole archive
        let mut tar2 = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let content = b"x";
        header.set_size(1);
        header.set_cksum();
        tar2.append_data(&mut header, "sub/dir.yaml", &content[..]).unwrap();
        tar2.finish().unwrap();
        let raw = tar2.into_inner().unwrap();
        let mut gz2 = Vec::new();
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            let mut e = GzEncoder::new(&mut gz2, Compression::default());
            std::io::Write::write_all(&mut e, &raw).unwrap();
            let _ = e.finish();
        }
        assert!(extract_flat_yaml_tar_gz(&gz2, &out).is_err());
    }
}
