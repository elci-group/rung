//! Four production transcripts: scan is idle, loss blocks, a signature allows,
//! and the audit trail does not change the candidate digest.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn git(root: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {args:?}: {stderr}").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn rung(root: &Path, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_rung"))
        .arg("--repo")
        .arg(root)
        .args(args)
        .output()?)
}

fn success(root: &Path, args: &[&str]) -> TestResult<String> {
    let output = rung(root, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("rung {args:?}: {stderr}").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

#[test]
fn production_pilot_four_transcripts() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("pilot");
    fs::create_dir(&root)?;
    git(&root, &["init", "-b", "main"])?;
    git(&root, &["config", "user.name", "Rung Pilot"])?;
    git(&root, &["config", "user.email", "pilot@example.invalid"])?;
    fs::create_dir(root.join("src"))?;
    fs::write(root.join("src/lib.rs"), "pub fn feature_a() {}\n")?;

    let scan = success(&root, &["--format", "json", "scan"])?;
    let discovery: serde_json::Value = serde_json::from_str(&scan)?;
    if discovery["schema_version"] != 1 || discovery["kind"] != "discovery" {
        return Err("scan document".into());
    }
    if root.join(".rung").exists() {
        return Err("scan created .rung".into());
    }

    success(&root, &["init"])?;
    success(
        &root,
        &[
            "protect",
            "CAP-A",
            "--name",
            "feature-a",
            "--rung",
            "r2",
            "--threshold",
            "1",
            "--evidence",
            "symbol:feature_a",
        ],
    )?;
    let key = temp.path().join("alice.key");
    fs::write(&key, "11".repeat(32))?;
    let public = success(
        &root,
        &["public-key", "--key", key.to_str().ok_or("key path")?],
    )?;
    let policy_path = root.join(".rung/policy.toml");
    let mut policy = fs::read_to_string(&policy_path)?;
    policy.push_str(&format!(
        "\n[[authorities]]\nactor = \"alice\"\nrole = \"developer\"\npublic_key = \"{public}\"\n"
    ));
    fs::write(&policy_path, policy)?;
    git(&root, &["add", "."])?;
    git(&root, &["commit", "-m", "protect feature_a"])?;
    let baseline = git(&root, &["rev-parse", "HEAD"])?;

    let ledger_before = fs::read(root.join(".rung/ledger.toml"))?;
    success(&root, &["scan"])?;
    if fs::read(root.join(".rung/ledger.toml"))? != ledger_before {
        return Err("scan modified the ledger".into());
    }
    if root.join(".rung/audit").exists() {
        return Err("scan wrote the audit trail".into());
    }

    fs::write(root.join("src/lib.rs"), "pub fn renamed() {}\n")?;
    let blocked = rung(
        &root,
        &["--format", "json", "check", "--against", &baseline],
    )?;
    if blocked.status.code() != Some(1) {
        return Err(format!(
            "expected block, got {:?} {}",
            blocked.status.code(),
            String::from_utf8_lossy(&blocked.stderr)
        )
        .into());
    }
    let blocked_report: serde_json::Value = serde_json::from_slice(&blocked.stdout)?;
    if blocked_report["outcome"] != "block" {
        return Err("block outcome".into());
    }
    let digest = blocked_report["candidate_digest"].clone();

    success(
        &root,
        &[
            "indifferent",
            "CAP-A",
            "--against",
            &baseline,
            "--reason",
            "Loss understood and accepted",
            "--actor",
            "alice",
            "--key",
            key.to_str().ok_or("key path")?,
        ],
    )?;
    let allowed = rung(
        &root,
        &["--format", "json", "check", "--against", &baseline],
    )?;
    if allowed.status.code() != Some(0) {
        return Err(format!(
            "expected allow, got {:?} {}",
            allowed.status.code(),
            String::from_utf8_lossy(&allowed.stderr)
        )
        .into());
    }
    let allowed_report: serde_json::Value = serde_json::from_slice(&allowed.stdout)?;
    if allowed_report["outcome"] != "allow"
        || allowed_report["assessments"][0]["authorized"] != true
    {
        return Err("allow outcome".into());
    }
    if allowed_report["candidate_digest"] != digest {
        return Err("audit or authorization changed the candidate digest".into());
    }
    let decisions = fs::read_to_string(root.join(".rung/audit/decisions.jsonl"))?;
    if decisions.lines().count() < 2 {
        return Err("decision audit".into());
    }
    Ok(())
}
