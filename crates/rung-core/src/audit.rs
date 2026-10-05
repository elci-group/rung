//! Local audit trail for enforcement decisions and authorization access.
//!
//! Records are append-only JSONL under `.rung/audit/`. The directory is mode
//! `0700` and each log is mode `0600` on Unix. A symlink anywhere on that path
//! is rejected. The candidate digest excludes this directory, so writing a
//! record does not change the decision it records.
//!
//! Retention is two generations. The previous generation is `*.jsonl.1`, and
//! it is removed after 90 days. Operators archive anything they must keep
//! longer than that.

use crate::RungError;
use rung_model::Decision;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AUDIT_DIR: &str = ".rung/audit";
const DECISIONS_LOG: &str = "decisions.jsonl";
const ACCESS_LOG: &str = "access.jsonl";
const ROTATE_AT_BYTES: u64 = 1_048_576;
const PREVIOUS_GENERATION_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// Linux `O_NOFOLLOW` (`0400000`). Opening with this flag refuses a symlink
/// that appears between the metadata check and the write.
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0x20000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessAction {
    Check,
    Authorize,
}

pub fn record_decision(root: &Path, decision: &Decision) -> Result<(), RungError> {
    let violation_ids: Vec<&str> = decision
        .violations
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    let line = json!({
        "schema_version": 1,
        "kind": "decision",
        "timestamp_unix_ms": unix_ms()?,
        "outcome": decision.outcome,
        "baseline_revision": decision.baseline_revision,
        "candidate_digest": decision.candidate_digest,
        "violation_ids": violation_ids,
        "governance_violations": decision.governance_violations,
    });
    append(root, DECISIONS_LOG, &line, ROTATE_AT_BYTES)
}

pub fn record_access(
    root: &Path,
    action: AccessAction,
    baseline_revision: &str,
    subject: Option<&str>,
) -> Result<(), RungError> {
    let action = match action {
        AccessAction::Check => "check",
        AccessAction::Authorize => "authorize",
    };
    let line = json!({
        "schema_version": 1,
        "kind": "access",
        "timestamp_unix_ms": unix_ms()?,
        "action": action,
        "baseline_revision": baseline_revision,
        "subject": subject,
    });
    append(root, ACCESS_LOG, &line, ROTATE_AT_BYTES)
}

fn unix_ms() -> Result<u64, RungError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RungError::Analysis(format!("system clock: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| RungError::Analysis("clock overflow".into()))
}

fn append(
    root: &Path,
    name: &str,
    value: &serde_json::Value,
    rotate_at_bytes: u64,
) -> Result<(), RungError> {
    let dir = prepare_dir(root)?;
    let path = dir.join(name);
    expire_previous(&path)?;
    rotate_if_needed(&path, rotate_at_bytes)?;
    let mut file = open_log(&path)?;
    serde_json::to_writer(&mut file, value)
        .map_err(|error| RungError::Analysis(format!("audit record: {error}")))?;
    file.write_all(b"\n")?;
    file.flush()?;
    restrict_file(&path)?;
    Ok(())
}

fn prepare_dir(root: &Path) -> Result<PathBuf, RungError> {
    let parent = root.join(".rung");
    reject_symlink(&parent)?;
    let dir = root.join(AUDIT_DIR);
    match fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(RungError::Analysis(format!(
                "symlink in audit path: {}",
                dir.display()
            )));
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(RungError::Analysis(format!(
                "audit path is not a directory: {}",
                dir.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&dir)?;
        }
        Err(error) => return Err(error.into()),
    }
    restrict_dir(&dir)?;
    Ok(dir)
}

fn reject_symlink(path: &Path) -> Result<(), RungError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(RungError::Analysis(format!(
                "symlink in audit path: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn previous_generation(path: &Path) -> Result<PathBuf, RungError> {
    let name = path
        .file_name()
        .ok_or_else(|| RungError::Analysis("audit log has no file name".into()))?;
    let mut next = name.to_os_string();
    next.push(".1");
    Ok(path.with_file_name(next))
}

fn expire_previous(path: &Path) -> Result<(), RungError> {
    let previous = previous_generation(path)?;
    let meta = match fs::symlink_metadata(&previous) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if meta.file_type().is_symlink() {
        return Err(RungError::Analysis(format!(
            "audit log is a symlink: {}",
            previous.display()
        )));
    }
    let age = match SystemTime::now().duration_since(meta.modified()?) {
        Ok(age) => age,
        Err(_) => Duration::ZERO,
    };
    if age > PREVIOUS_GENERATION_TTL {
        fs::remove_file(previous)?;
    }
    Ok(())
}

fn rotate_if_needed(path: &Path, rotate_at_bytes: u64) -> Result<(), RungError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if meta.file_type().is_symlink() {
        return Err(RungError::Analysis(format!(
            "audit log is a symlink: {}",
            path.display()
        )));
    }
    if meta.len() < rotate_at_bytes {
        return Ok(());
    }
    let previous = previous_generation(path)?;
    if let Ok(previous_meta) = fs::symlink_metadata(&previous) {
        if previous_meta.file_type().is_symlink() {
            return Err(RungError::Analysis(format!(
                "audit log is a symlink: {}",
                previous.display()
            )));
        }
        fs::remove_file(&previous)?;
    }
    fs::rename(path, previous)?;
    Ok(())
}

fn open_log(path: &Path) -> Result<fs::File, RungError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(RungError::Analysis(format!(
                "audit log is a symlink: {}",
                path.display()
            )));
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(path)
            .map_err(Into::into)
    }
    #[cfg(not(target_os = "linux"))]
    {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(Into::into)
    }
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<(), RungError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> Result<(), RungError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), RungError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<(), RungError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rung_model::EnforcementDecision;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn decision() -> Decision {
        Decision {
            schema_version: 1,
            outcome: EnforcementDecision::Allow,
            baseline_revision: "abc".into(),
            candidate_digest: "digest".into(),
            ledger_digest: "ledger".into(),
            policy_digest: "policy".into(),
            governance_violations: Vec::new(),
            violations: Vec::new(),
            assessments: Vec::new(),
        }
    }

    #[test]
    fn rotation_keeps_one_previous_generation() -> TestResult {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        append(root, DECISIONS_LOG, &json!({"n": 1}), 1)?;
        append(root, DECISIONS_LOG, &json!({"n": 2}), 1)?;
        append(root, DECISIONS_LOG, &json!({"n": 3}), 1)?;
        let dir = root.join(AUDIT_DIR);
        assert!(dir.join(DECISIONS_LOG).is_file());
        assert!(dir.join(format!("{DECISIONS_LOG}.1")).is_file());
        assert!(!dir.join(format!("{DECISIONS_LOG}.2")).exists());
        let current = fs::read_to_string(dir.join(DECISIONS_LOG))?;
        assert!(current.contains("\"n\":3") || current.contains("\"n\":2"));
        assert!(!current.contains("\"n\":1"));
        Ok(())
    }

    #[test]
    fn previous_generation_expires_after_ninety_days() -> TestResult {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        append(root, ACCESS_LOG, &json!({"n": 1}), ROTATE_AT_BYTES)?;
        let previous = root.join(AUDIT_DIR).join(format!("{ACCESS_LOG}.1"));
        fs::write(&previous, "{\"n\":0}\n")?;
        let old = SystemTime::now()
            .checked_sub(Duration::from_secs(91 * 24 * 60 * 60))
            .ok_or("clock predates the retention window")?;
        fs::File::open(&previous)?.set_modified(old)?;
        append(root, ACCESS_LOG, &json!({"n": 2}), ROTATE_AT_BYTES)?;
        assert!(!previous.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_audit_directory_is_rejected() -> TestResult {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        let outside = temp.path().join("outside");
        fs::create_dir_all(root.join(".rung"))?;
        fs::create_dir(&outside)?;
        std::os::unix::fs::symlink(&outside, root.join(AUDIT_DIR))?;
        match record_decision(root, &decision()) {
            Err(error) => assert!(error.to_string().contains("symlink")),
            Ok(()) => return Err("symlink audit directory was accepted".into()),
        }
        assert!(fs::read_dir(&outside)?.next().is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn logs_are_owner_readable_only() -> TestResult {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        record_access(root, AccessAction::Check, "main", None)?;
        record_decision(root, &decision())?;
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = fs::symlink_metadata(root.join(AUDIT_DIR))?
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::symlink_metadata(root.join(AUDIT_DIR).join(DECISIONS_LOG))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        let access = fs::read_to_string(root.join(AUDIT_DIR).join(ACCESS_LOG))?;
        assert!(access.contains("\"action\":\"check\""));
        assert!(!access.contains("private"));
        Ok(())
    }
}
