use rung_core::{candidate_snapshot, check, default_policy, revision_snapshot, Snapshot};
use rung_model::{Capability, EnforcementDecision, Evidence, EvidenceKind, Ledger, Rung};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn git(root: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {args:?}: {stderr}").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn governed_repo(root: &Path) -> TestResult<String> {
    git(root, &["init", "-b", "main"])?;
    git(root, &["config", "user.name", "Rung Test"])?;
    git(root, &["config", "user.email", "rung@example.invalid"])?;
    fs::create_dir(root.join("src"))?;
    fs::write(root.join("src/lib.rs"), "pub fn feature_a() {}\n")?;
    let ledger = Ledger {
        schema_version: 1,
        capabilities: vec![Capability {
            id: "CAP-A".into(),
            name: "feature-a".into(),
            rung: Rung::R2,
            threshold: 1,
            evidence: vec![Evidence {
                kind: EvidenceKind::Symbol,
                value: "feature_a".into(),
                weight: 1,
            }],
        }],
    };
    fs::create_dir(root.join(".rung"))?;
    fs::write(root.join(".rung/ledger.toml"), toml::to_string(&ledger)?)?;
    fs::write(
        root.join(".rung/policy.toml"),
        toml::to_string(&default_policy())?,
    )?;
    git(root, &["add", "."])?;
    git(root, &["commit", "-m", "baseline"])?;
    git(root, &["rev-parse", "HEAD"])
}

#[test]
fn check_appends_decision_and_access_records() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let baseline = governed_repo(root)?;
    let repo = git2::Repository::open(root)?;
    let decision = check(&repo, &baseline, None)?;
    assert_eq!(decision.outcome, EnforcementDecision::Allow);
    let decisions = fs::read_to_string(root.join(".rung/audit/decisions.jsonl"))?;
    let access = fs::read_to_string(root.join(".rung/audit/access.jsonl"))?;
    let decision_line: serde_json::Value =
        serde_json::from_str(decisions.lines().next().ok_or("decision")?)?;
    let access_line: serde_json::Value =
        serde_json::from_str(access.lines().next().ok_or("access")?)?;
    assert_eq!(decision_line["schema_version"], 1);
    assert_eq!(decision_line["kind"], "decision");
    assert_eq!(decision_line["outcome"], "allow");
    assert_eq!(decision_line["baseline_revision"], baseline);
    assert_eq!(access_line["kind"], "access");
    assert_eq!(access_line["action"], "check");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = fs::symlink_metadata(root.join(".rung/audit"))?
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::symlink_metadata(root.join(".rung/audit/decisions.jsonl"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
    check(&repo, &baseline, None)?;
    let again = fs::read_to_string(root.join(".rung/audit/decisions.jsonl"))?;
    assert_eq!(again.lines().count(), 2);
    Ok(())
}

#[test]
fn audit_records_do_not_change_the_candidate_digest() -> TestResult {
    let mut files = BTreeMap::new();
    files.insert("src/lib.rs".into(), b"pub fn feature_a() {}".to_vec());
    files.insert(".rung/audit/decisions.jsonl".into(), b"one\n".to_vec());
    let first = Snapshot {
        revision: "accepted".into(),
        files: files.clone(),
    };
    files.insert(".rung/audit/decisions.jsonl".into(), b"two\n".to_vec());
    files.insert(".rung/audit/access.jsonl".into(), b"access\n".to_vec());
    let second = Snapshot {
        revision: "accepted".into(),
        files,
    };
    assert_eq!(first.digest(), second.digest());
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_candidates_and_revisions_are_rejected() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let baseline = governed_repo(root)?;
    std::os::unix::fs::symlink("src/lib.rs", root.join("link.rs"))?;
    let repo = git2::Repository::open(root)?;
    match candidate_snapshot(&repo) {
        Err(error) => assert!(error.to_string().contains("symlink")),
        Ok(_) => return Err("worktree symlink was accepted".into()),
    }
    fs::remove_file(root.join("link.rs"))?;
    std::os::unix::fs::symlink("src/lib.rs", root.join("link.rs"))?;
    git(root, &["add", "link.rs"])?;
    git(root, &["commit", "-m", "add symlink"])?;
    let revision = git(root, &["rev-parse", "HEAD"])?;
    let repo = git2::Repository::open(root)?;
    match revision_snapshot(&repo, &revision) {
        Err(error) => assert!(error.to_string().contains("symlink")),
        Ok(_) => return Err("committed symlink was accepted".into()),
    }
    match check(&repo, &baseline, None) {
        Err(error) => assert!(error.to_string().contains("symlink")),
        Ok(_) => return Err("check accepted a symlink candidate".into()),
    }
    let access = fs::read_to_string(root.join(".rung/audit/access.jsonl"))?;
    assert!(access.contains("\"action\":\"check\""));
    Ok(())
}
