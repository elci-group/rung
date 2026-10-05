use rung_core::{compare, default_policy, discover, Snapshot};
use rung_model::{
    Capability, EnforcementDecision, Evidence, EvidenceKind, Ledger, PresenceDisposition, Rung,
};
use std::collections::BTreeMap;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn snapshot(files: &[(&str, &str)]) -> Snapshot {
    let mut stored = BTreeMap::new();
    for (path, text) in files {
        stored.insert((*path).to_string(), text.as_bytes().to_vec());
    }
    Snapshot {
        revision: "accepted-commit".into(),
        files: stored,
    }
}

fn governed(files: &[(&str, &str)], capability: Capability) -> TestResult<Snapshot> {
    let ledger = Ledger {
        schema_version: 1,
        capabilities: vec![capability],
    };
    let mut stored = snapshot(files);
    stored.files.insert(
        ".rung/ledger.toml".into(),
        toml::to_string(&ledger)?.into_bytes(),
    );
    stored.files.insert(
        ".rung/policy.toml".into(),
        toml::to_string(&default_policy())?.into_bytes(),
    );
    Ok(stored)
}

fn capability(kind: EvidenceKind, value: &str) -> Capability {
    Capability {
        id: "CAP-A".into(),
        name: "feature-a".into(),
        rung: Rung::R2,
        threshold: 1,
        evidence: vec![Evidence {
            kind,
            value: value.into(),
            weight: 1,
        }],
    }
}

fn ids(snapshot: &Snapshot) -> TestResult<Vec<String>> {
    Ok(discover(snapshot)?
        .candidates
        .into_iter()
        .map(|candidate| candidate.suggested_id)
        .collect())
}

#[test]
fn scan_finds_reachable_surfaces_and_skips_private_modules() -> TestResult {
    let found = snapshot(&[
        (
            "src/lib.rs",
            r#"
            pub mod api;
            mod hidden;
            pub use api::feature_a;
            pub struct Service;
            #[derive(Deserialize)]
            pub struct AppConfig;
            #[get("/health")]
            fn health() {}
            fn router() {
                app.route("/users", get(list_users).post(create_user));
            }
            #[tokio::test]
            fn feature_a_roundtrip() {}
            #[cfg(test)]
            fn not_a_test() {}
            #[derive(Parser)]
            #[command(name = "demo")]
            struct Cli {}
            #[derive(Subcommand)]
            enum Commands {
                FalseMatch,
                #[command(name = "public-key")]
                PublicKey,
            }
            "#,
        ),
        ("src/api.rs", "pub fn feature_a() {}\n"),
        ("src/hidden.rs", "pub fn secret() {}\n"),
        (
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[features]\nfancy = []\n",
        ),
        (
            "crates/extra/Cargo.toml",
            "[package]\nname = \"extra\"\nversion = \"0.1.0\"\n\n[features]\nextra_on = []\n",
        ),
    ]);
    let report = discover(&found)?;
    assert!(report
        .candidates
        .windows(2)
        .all(|pair| pair[0].suggested_id <= pair[1].suggested_id));
    let names = ids(&found)?;
    for id in [
        "api-feature-a",
        "api-service",
        "cargo-demo-fancy",
        "cargo-extra-extra-on",
        "cli-demo",
        "cli-false-match",
        "cli-public-key",
        "config-app-config",
        "route-get-health",
        "route-get-users",
        "route-post-users",
        "test-feature-a-roundtrip",
    ] {
        assert!(
            names.iter().any(|found| found == id),
            "missing {id}: {names:?}"
        );
    }
    assert!(!names.iter().any(|id| id.contains("secret")));
    assert!(!names.iter().any(|id| id.contains("not-a-test")));
    assert!(names.iter().all(|id| {
        !id.is_empty()
            && id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    }));
    let feature = report
        .candidates
        .iter()
        .find(|candidate| candidate.suggested_id == "api-feature-a")
        .ok_or("feature candidate")?;
    assert_eq!(
        feature.locations,
        vec!["src/api.rs".to_string(), "src/lib.rs".to_string()]
    );
    Ok(())
}

#[test]
fn path_attribute_module_is_public_and_private_copy_still_matches() -> TestResult {
    let moved = snapshot(&[
        (
            "src/lib.rs",
            "#[path = \"elsewhere.rs\"]\npub mod api;\nmod hidden;\n",
        ),
        ("src/elsewhere.rs", "pub fn feature_a() {}\n"),
        ("src/hidden.rs", "pub fn secret() {}\n"),
    ]);
    assert!(ids(&moved)?.contains(&"api-feature-a".to_string()));
    assert!(!ids(&moved)?.iter().any(|id| id.contains("secret")));
    let hidden = governed(
        &[
            ("src/lib.rs", "mod hidden;\n"),
            ("src/hidden.rs", "pub fn secret() {}\n"),
        ],
        capability(EvidenceKind::Symbol, "secret"),
    )?;
    let decision = compare(&hidden, &hidden)?;
    assert_eq!(decision.outcome, EnforcementDecision::Allow);
    Ok(())
}

#[test]
fn symbol_survives_move_into_inherent_method_and_tokio_test() -> TestResult {
    let ledger = Ledger {
        schema_version: 1,
        capabilities: vec![Capability {
            id: "CAP-A".into(),
            name: "feature-a".into(),
            rung: Rung::R2,
            threshold: 2,
            evidence: vec![
                Evidence {
                    kind: EvidenceKind::Symbol,
                    value: "feature_a".into(),
                    weight: 1,
                },
                Evidence {
                    kind: EvidenceKind::Test,
                    value: "feature_a_roundtrip".into(),
                    weight: 1,
                },
            ],
        }],
    };
    let baseline = governed(
        &[(
            "src/lib.rs",
            "pub fn feature_a() {}\n#[test]\nfn feature_a_roundtrip() {}\n",
        )],
        ledger.capabilities[0].clone(),
    )?;
    let candidate = governed(
        &[(
            "src/lib.rs",
            "pub struct Service;\nimpl Service { pub fn feature_a() {} }\n#[tokio::test]\nfn feature_a_roundtrip() {}\n",
        )],
        ledger.capabilities[0].clone(),
    )?;
    let decision = compare(&baseline, &candidate)?;
    assert_eq!(decision.outcome, EnforcementDecision::Allow);
    assert_eq!(
        decision.assessments[0].candidate,
        PresenceDisposition::Present
    );
    Ok(())
}

#[test]
fn route_loss_blocks_and_member_feature_matches() -> TestResult {
    let baseline = governed(
        &[("src/lib.rs", "#[get(\"/health\")]\nfn health() {}\n")],
        capability(EvidenceKind::Route, "get /health"),
    )?;
    let candidate = governed(
        &[("src/lib.rs", "fn health() {}\n")],
        capability(EvidenceKind::Route, "get /health"),
    )?;
    let decision = compare(&baseline, &candidate)?;
    assert_eq!(decision.outcome, EnforcementDecision::Block);
    assert_eq!(
        decision.assessments[0].candidate,
        PresenceDisposition::Absent
    );

    // The workspace manifest has no features table; the member feature is enough.
    let bare = governed(
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"crates/extra\"]\n"),
            (
                "crates/extra/Cargo.toml",
                "[package]\nname = \"extra\"\nversion = \"0.1.0\"\n\n[features]\nextra_on = []\n",
            ),
            ("src/lib.rs", "pub fn keep() {}\n"),
        ],
        capability(EvidenceKind::CargoFeature, "extra_on"),
    )?;
    let decision = compare(&bare, &bare)?;
    assert_eq!(decision.outcome, EnforcementDecision::Allow);
    let qualified = governed(
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"crates/extra\"]\n"),
            (
                "crates/extra/Cargo.toml",
                "[package]\nname = \"extra\"\nversion = \"0.1.0\"\n\n[features]\nextra_on = []\n",
            ),
            ("src/lib.rs", "pub fn keep() {}\n"),
        ],
        capability(EvidenceKind::CargoFeature, "extra/extra_on"),
    )?;
    let decision = compare(&qualified, &qualified)?;
    assert_eq!(decision.outcome, EnforcementDecision::Allow);
    Ok(())
}

#[test]
fn invalid_route_evidence_is_configuration_failure() -> TestResult {
    let state = governed(
        &[("src/lib.rs", "pub fn feature_a() {}\n")],
        capability(EvidenceKind::Route, "health"),
    )?;
    match compare(&state, &state) {
        Err(error) => assert!(error.to_string().contains("route evidence")),
        Ok(_) => return Err("invalid route was accepted".into()),
    }
    Ok(())
}

#[test]
fn syntax_errors_fail_discovery() -> TestResult {
    let broken = snapshot(&[("src/lib.rs", "pub fn {")]);
    match discover(&broken) {
        Err(error) => assert!(error.to_string().contains("src/lib.rs")),
        Ok(_) => return Err("syntax error was accepted".into()),
    }
    Ok(())
}
