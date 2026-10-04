use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8 git output")
        .trim()
        .to_string()
}

fn rung(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rung"))
        .arg("--repo")
        .arg(root)
        .args(args)
        .output()
        .expect("run rung")
}

fn success(root: &Path, args: &[&str]) -> String {
    let output = rung(root, args);
    assert!(
        output.status.success(),
        "rung {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8 rung output")
        .trim()
        .to_string()
}

#[test]
fn stale_branch_blocks_then_signed_indifference_allows() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir(&root).expect("create repo");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["config", "user.name", "Rung Test"]);
    git(&root, &["config", "user.email", "rung@example.invalid"]);
    fs::create_dir(root.join("src")).expect("src");
    fs::write(root.join("src/lib.rs"), "pub fn base() {}\n").expect("initial source");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "before feature"]);
    let old = git(&root, &["rev-parse", "HEAD"]);

    success(&root, &["init"]);
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
    );
    let key = temp.path().join("key.hex");
    fs::write(&key, "11".repeat(32)).expect("key");
    let public = success(
        &root,
        &["public-key", "--key", key.to_str().expect("key path")],
    );
    let policy = root.join(".rung/policy.toml");
    let mut policy_text = fs::read_to_string(&policy).expect("policy");
    policy_text.push_str(&format!(
        "\n[[authorities]]\nactor = \"alice\"\nrole = \"developer\"\npublic_key = \"{public}\"\n"
    ));
    fs::write(&policy, policy_text).expect("policy authority");
    fs::write(
        root.join("src/lib.rs"),
        "pub fn base() {}\npub fn feature_a() {}\n",
    )
    .expect("feature source");
    let saved_ledger = fs::read(root.join(".rung/ledger.toml")).expect("ledger");
    let saved_policy = fs::read(&policy).expect("policy");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "establish feature"]);
    let baseline = git(&root, &["rev-parse", "HEAD"]);

    git(&root, &["checkout", "-b", "stale", &old]);
    fs::create_dir_all(root.join(".rung")).expect("rung state");
    fs::write(root.join(".rung/ledger.toml"), saved_ledger).expect("ledger");
    fs::write(&policy, saved_policy).expect("policy");
    let blocked = rung(
        &root,
        &["--format", "json", "check", "--against", &baseline],
    );
    assert_eq!(
        blocked.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&blocked.stdout).expect("report");
    assert_eq!(report["outcome"], "block");
    assert_eq!(report["assessments"][0]["capability_id"], "CAP-A");
    assert!(report["violations"][0]["id"]
        .as_str()
        .expect("violation id")
        .starts_with("RUNG-VIOLATION-"));

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
            key.to_str().expect("key path"),
        ],
    );
    let allowed = rung(
        &root,
        &["--format", "json", "check", "--against", &baseline],
    );
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&allowed.stdout).expect("report");
    assert_eq!(report["outcome"], "allow");
    assert_eq!(report["assessments"][0]["authorized"], true);

    fs::write(root.join("unrelated.txt"), "candidate changed").expect("change");
    let replayed = rung(&root, &["check", "--against", &baseline]);
    assert_eq!(replayed.status.code(), Some(5));

    fs::remove_file(root.join("unrelated.txt")).expect("restore candidate");
    let auth_path = fs::read_dir(root.join(".rung/authorizations"))
        .expect("authorization directory")
        .next()
        .expect("authorization record")
        .expect("authorization entry")
        .path();
    let signed = fs::read_to_string(&auth_path).expect("signed authorization");
    fs::write(
        &auth_path,
        signed.replace("Loss understood and accepted", "Forged reason"),
    )
    .expect("tamper authorization");
    let forged = rung(&root, &["check", "--against", &baseline]);
    assert_eq!(forged.status.code(), Some(5));
}

#[test]
fn ledger_removal_is_governance_violation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    git(root, &["init", "-b", "main"]);
    git(root, &["config", "user.name", "Rung Test"]);
    git(root, &["config", "user.email", "rung@example.invalid"]);
    success(root, &["init"]);
    git(root, &["add", ".rung"]);
    git(root, &["commit", "-m", "baseline"]);
    let baseline = git(root, &["rev-parse", "HEAD"]);
    fs::remove_file(root.join(".rung/ledger.toml")).expect("remove ledger");
    let result = rung(root, &["--format", "json", "check", "--against", &baseline]);
    assert_eq!(result.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).expect("report");
    assert!(report["governance_violations"][0]
        .as_str()
        .expect("violation")
        .contains("GOV-RUNG-001"));

    let baseline_ledger = git(root, &["show", "HEAD:.rung/ledger.toml"]);
    fs::write(root.join(".rung/ledger.toml"), baseline_ledger).expect("restore ledger");
    let policy_path = root.join(".rung/policy.toml");
    let original_policy = fs::read_to_string(&policy_path).expect("policy");
    fs::write(
        &policy_path,
        original_policy.replace("approvals = 1", "approvals = 0"),
    )
    .expect("weaken policy");
    let changed_policy = rung(root, &["--format", "json", "check", "--against", &baseline]);
    assert_eq!(changed_policy.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&changed_policy.stdout).expect("report");
    assert!(report["governance_violations"][0]
        .as_str()
        .expect("violation")
        .contains("GOV-RUNG-004"));
}

#[test]
fn scan_reports_candidates_without_creating_a_ledger() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    git(root, &["init", "-b", "main"]);
    git(root, &["config", "user.name", "Rung Test"]);
    git(root, &["config", "user.email", "rung@example.invalid"]);
    fs::create_dir(root.join("src")).expect("src");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[features]\nfancy = []\n",
    )
    .expect("manifest");
    fs::write(
        root.join("src/lib.rs"),
        "pub fn feature_a() {}\n#[get(\"/health\")]\nfn health() {}\n#[derive(Subcommand)]\nenum Commands { Check }\n",
    )
    .expect("source");
    let first = success(root, &["--format", "json", "scan"]);
    let second = success(root, &["--format", "json", "scan"]);
    assert_eq!(first, second);
    assert!(!root.join(".rung").exists());
    let report: serde_json::Value = serde_json::from_str(&first).expect("scan json");
    assert_eq!(report["kind"], "discovery");
    let ids: Vec<&str> = report["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .map(|candidate| candidate["suggested_id"].as_str().expect("id"))
        .collect();
    assert!(ids.contains(&"api-feature-a"));
    assert!(ids.contains(&"cargo-demo-fancy"));
    assert!(ids.contains(&"cli-check"));
    assert!(ids.contains(&"route-get-health"));
}
