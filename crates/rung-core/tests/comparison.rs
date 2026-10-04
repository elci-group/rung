use rung_core::{
    canonical, compare, default_policy, digest, public_key, sign_authorization, Snapshot,
};
use rung_model::{
    Authority, Authorization, Capability, EnforcementDecision, Evidence, EvidenceKind, Ledger,
    OmissionKind, Policy, Rung,
};
use std::collections::BTreeMap;

fn state(source_path: &str, source: &str, ledger: &Ledger) -> Snapshot {
    state_policy(source_path, source, ledger, &default_policy())
}

fn state_policy(source_path: &str, source: &str, ledger: &Ledger, policy: &Policy) -> Snapshot {
    let mut files = BTreeMap::new();
    files.insert(source_path.into(), source.as_bytes().to_vec());
    files.insert(
        ".rung/ledger.toml".into(),
        toml::to_string(ledger).expect("ledger TOML").into_bytes(),
    );
    files.insert(
        ".rung/policy.toml".into(),
        toml::to_string(policy).expect("policy TOML").into_bytes(),
    );
    Snapshot {
        revision: "accepted-commit".into(),
        files,
    }
}

fn authority(policy: &mut Policy, actor: &str, role: &str, key: &str) {
    policy.authorities.push(Authority {
        actor: actor.into(),
        role: role.into(),
        public_key: public_key(key).expect("public key"),
    });
}

fn record(
    baseline: &Snapshot,
    candidate: &Snapshot,
    ledger: &Ledger,
    policy: &Policy,
    disposition: OmissionKind,
    successor: Option<String>,
) -> Authorization {
    Authorization {
        schema_version: 1,
        authorization_id: "AUTH-TEST".into(),
        created_at_unix_ms: 1,
        capability: "CAP-A".into(),
        disposition,
        baseline_revision: baseline.revision.clone(),
        candidate_digest: candidate.digest(),
        ledger_digest: digest(&canonical(ledger).expect("ledger canonical")),
        policy_digest: digest(&canonical(policy).expect("policy canonical")),
        reason: "approved change".into(),
        successor,
        migration: None,
        signatures: Vec::new(),
    }
}

fn add_record(snapshot: &mut Snapshot, record: &Authorization) {
    snapshot.files.insert(
        format!(".rung/authorizations/{}.toml", record.authorization_id),
        toml::to_string(record)
            .expect("authorization TOML")
            .into_bytes(),
    );
}

fn ledger() -> Ledger {
    Ledger {
        schema_version: 1,
        capabilities: vec![Capability {
            id: "CAP-A".into(),
            name: "feature-a".into(),
            rung: Rung::R2,
            threshold: 1,
            evidence: vec![
                Evidence {
                    kind: EvidenceKind::File,
                    value: "src/old.rs".into(),
                    weight: 1,
                },
                Evidence {
                    kind: EvidenceKind::Symbol,
                    value: "feature_a".into(),
                    weight: 1,
                },
            ],
        }],
    }
}

#[test]
fn rename_keeps_capability_when_public_symbol_survives() {
    let ledger = ledger();
    let baseline = state("src/old.rs", "pub fn feature_a() {}", &ledger);
    let candidate = state("src/new.rs", "pub fn feature_a() {}", &ledger);
    let decision = compare(&baseline, &candidate).expect("compare");
    assert_eq!(decision.outcome, EnforcementDecision::Allow);
    assert!(!decision.assessments[0].observations[0].found);
    assert!(decision.assessments[0].observations[1].found);
}

#[test]
fn candidate_rung_downgrade_blocks_even_with_feature_present() {
    let ledger = ledger();
    let baseline = state("src/old.rs", "pub fn feature_a() {}", &ledger);
    let mut downgraded = ledger;
    downgraded.capabilities[0].rung = Rung::R1;
    let candidate = state("src/old.rs", "pub fn feature_a() {}", &downgraded);
    let decision = compare(&baseline, &candidate).expect("compare");
    assert_eq!(decision.outcome, EnforcementDecision::Block);
    assert!(decision.governance_violations[0].contains("GOV-RUNG-002"));
}

#[test]
fn partial_evidence_requires_review_and_stays_closed() {
    let mut ledger = ledger();
    ledger.capabilities[0].threshold = 2;
    let baseline = state("src/old.rs", "pub fn feature_a() {}", &ledger);
    let candidate = state("src/new.rs", "pub fn feature_a() {}", &ledger);
    let decision = compare(&baseline, &candidate).expect("compare");
    assert_eq!(decision.outcome, EnforcementDecision::RequireReview);
}

#[test]
fn supersession_requires_a_present_successor_and_signature() {
    let mut ledger = ledger();
    ledger.capabilities[0].evidence = vec![Evidence {
        kind: EvidenceKind::Symbol,
        value: "feature_a".into(),
        weight: 1,
    }];
    ledger.capabilities.push(Capability {
        id: "CAP-B".into(),
        name: "feature-b".into(),
        rung: Rung::R2,
        threshold: 1,
        evidence: vec![Evidence {
            kind: EvidenceKind::Symbol,
            value: "feature_b".into(),
            weight: 1,
        }],
    });
    let key = "11".repeat(32);
    let mut policy = default_policy();
    authority(&mut policy, "alice", "developer", &key);
    let baseline = state_policy(
        "src/lib.rs",
        "pub fn feature_a() {}\npub fn feature_b() {}",
        &ledger,
        &policy,
    );
    let mut candidate = state_policy("src/lib.rs", "pub fn feature_b() {}", &ledger, &policy);
    let mut auth = record(
        &baseline,
        &candidate,
        &ledger,
        &policy,
        OmissionKind::Supersede,
        Some("CAP-B".into()),
    );
    sign_authorization(&mut auth, "alice", &key).expect("sign");
    add_record(&mut candidate, &auth);
    let decision = compare(&baseline, &candidate).expect("compare");
    assert_eq!(decision.outcome, EnforcementDecision::Allow);
    assert!(decision.assessments[0].authorized);
}

#[test]
fn r4_requires_two_distinct_maintainer_signatures() {
    let mut ledger = ledger();
    ledger.capabilities[0].rung = Rung::R4;
    ledger.capabilities[0].evidence = vec![Evidence {
        kind: EvidenceKind::Symbol,
        value: "feature_a".into(),
        weight: 1,
    }];
    let key_a = "11".repeat(32);
    let key_b = "22".repeat(32);
    let mut policy = default_policy();
    authority(&mut policy, "alice", "maintainer", &key_a);
    authority(&mut policy, "bob", "maintainer", &key_b);
    let baseline = state_policy("src/lib.rs", "pub fn feature_a() {}", &ledger, &policy);
    let mut candidate = state_policy("src/lib.rs", "", &ledger, &policy);
    let mut auth = record(
        &baseline,
        &candidate,
        &ledger,
        &policy,
        OmissionKind::Omit,
        None,
    );
    sign_authorization(&mut auth, "alice", &key_a).expect("first signature");
    add_record(&mut candidate, &auth);
    assert_eq!(
        compare(&baseline, &candidate).expect("compare").outcome,
        EnforcementDecision::Block
    );
    sign_authorization(&mut auth, "bob", &key_b).expect("second signature");
    add_record(&mut candidate, &auth);
    assert_eq!(
        compare(&baseline, &candidate).expect("compare").outcome,
        EnforcementDecision::Allow
    );
}
