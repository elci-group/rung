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

fn utf8_path(path: &Path) -> TestResult<&str> {
    path.to_str().ok_or("path is not utf-8".into())
}

#[test]
fn stale_branch_blocks_then_signed_indifference_allows() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("repo");
    fs::create_dir(&root)?;
    git(&root, &["init", "-b", "main"])?;
    git(&root, &["config", "user.name", "Rung Test"])?;
    git(&root, &["config", "user.email", "rung@example.invalid"])?;
    fs::create_dir(root.join("src"))?;
    fs::write(root.join("src/lib.rs"), "pub fn base() {}\n")?;
    git(&root, &["add", "."])?;
    git(&root, &["commit", "-m", "before feature"])?;
    let old = git(&root, &["rev-parse", "HEAD"])?;

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
            "--evidence",
            "symbol:feature_a",
        ],
    )?;
    let key = temp.path().join("key.hex");
    fs::write(&key, "11".repeat(32))?;
    let public = success(&root, &["public-key", "--key", utf8_path(&key)?])?;
    let policy = root.join(".rung/policy.toml");
    let mut policy_text = fs::read_to_string(&policy)?;
    policy_text.push_str(&format!(
        "\n[[authorities]]\nactor = \"alice\"\nrole = \"developer\"\npublic_key = \"{public}\"\n"
    ));
    fs::write(&policy, policy_text)?;
    fs::write(
        root.join("src/lib.rs"),
        "pub fn base() {}\npub fn feature_a() {}\n",
    )?;
    let saved_ledger = fs::read(root.join(".rung/ledger.toml"))?;
    let saved_policy = fs::read(&policy)?;
    git(&root, &["add", "."])?;
    git(&root, &["commit", "-m", "establish feature"])?;
    let baseline = git(&root, &["rev-parse", "HEAD"])?;

    git(&root, &["checkout", "-b", "stale", &old])?;
    fs::create_dir_all(root.join(".rung"))?;
    fs::write(root.join(".rung/ledger.toml"), saved_ledger)?;
    fs::write(&policy, saved_policy)?;
    let blocked = rung(
        &root,
        &["--format", "json", "check", "--against", &baseline],
    )?;
    assert_eq!(
        blocked.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&blocked.stdout)?;
    assert_eq!(report["outcome"], "block");
    assert_eq!(report["assessments"][0]["capability_id"], "CAP-A");
    let violation_id = report["violations"][0]["id"]
        .as_str()
        .ok_or("violation id")?;
    assert!(violation_id.starts_with("RUNG-VIOLATION-"));

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
            utf8_path(&key)?,
        ],
    )?;
    let allowed = rung(
        &root,
        &["--format", "json", "check", "--against", &baseline],
    )?;
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&allowed.stdout)?;
    assert_eq!(report["outcome"], "allow");
    assert_eq!(report["assessments"][0]["authorized"], true);

    fs::write(root.join("unrelated.txt"), "candidate changed")?;
    let replayed = rung(&root, &["check", "--against", &baseline])?;
    assert_eq!(replayed.status.code(), Some(5));

    fs::remove_file(root.join("unrelated.txt"))?;
    let mut entries = fs::read_dir(root.join(".rung/authorizations"))?;
    let auth_path = entries.next().ok_or("authorization record")??.path();
    let signed = fs::read_to_string(&auth_path)?;
    fs::write(
        &auth_path,
        signed.replace("Loss understood and accepted", "Forged reason"),
    )?;
    let forged = rung(&root, &["check", "--against", &baseline])?;
    assert_eq!(forged.status.code(), Some(5));
    Ok(())
}

#[test]
fn ledger_removal_is_governance_violation() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    git(root, &["init", "-b", "main"])?;
    git(root, &["config", "user.name", "Rung Test"])?;
    git(root, &["config", "user.email", "rung@example.invalid"])?;
    success(root, &["init"])?;
    git(root, &["add", ".rung"])?;
    git(root, &["commit", "-m", "baseline"])?;
    let baseline = git(root, &["rev-parse", "HEAD"])?;
    fs::remove_file(root.join(".rung/ledger.toml"))?;
    let result = rung(root, &["--format", "json", "check", "--against", &baseline])?;
    assert_eq!(result.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    let violation = report["governance_violations"][0]
        .as_str()
        .ok_or("violation")?;
    assert!(violation.contains("GOV-RUNG-001"));

    let baseline_ledger = git(root, &["show", "HEAD:.rung/ledger.toml"])?;
    fs::write(root.join(".rung/ledger.toml"), baseline_ledger)?;
    let policy_path = root.join(".rung/policy.toml");
    let original_policy = fs::read_to_string(&policy_path)?;
    fs::write(
        &policy_path,
        original_policy.replace("approvals = 1", "approvals = 0"),
    )?;
    let changed_policy = rung(root, &["--format", "json", "check", "--against", &baseline])?;
    assert_eq!(changed_policy.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&changed_policy.stdout)?;
    let violation = report["governance_violations"][0]
        .as_str()
        .ok_or("violation")?;
    assert!(violation.contains("GOV-RUNG-004"));
    Ok(())
}

#[test]
fn scan_reports_candidates_without_creating_a_ledger() -> TestResult {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    git(root, &["init", "-b", "main"])?;
    git(root, &["config", "user.name", "Rung Test"])?;
    git(root, &["config", "user.email", "rung@example.invalid"])?;
    fs::create_dir(root.join("src"))?;
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[features]\nfancy = []\n",
    )?;
    fs::write(
        root.join("src/lib.rs"),
        "pub fn feature_a() {}\n#[get(\"/health\")]\nfn health() {}\n#[derive(Subcommand)]\nenum Commands { Check }\n",
    )?;
    let first = success(root, &["--format", "json", "scan"])?;
    let second = success(root, &["--format", "json", "scan"])?;
    assert_eq!(first, second);
    assert!(!root.join(".rung").exists());
    let report: serde_json::Value = serde_json::from_str(&first)?;
    assert_eq!(report["kind"], "discovery");
    let candidates = report["candidates"].as_array().ok_or("candidates")?;
    let ids: Vec<&str> = candidates
        .iter()
        .map(|candidate| candidate["suggested_id"].as_str())
        .collect::<Option<Vec<&str>>>()
        .ok_or("id")?;
    assert!(ids.contains(&"api-feature-a"));
    assert!(ids.contains(&"cargo-demo-fancy"));
    assert!(ids.contains(&"cli-check"));
    assert!(ids.contains(&"route-get-health"));
    Ok(())
}
