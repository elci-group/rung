//! Deterministic repository observation, comparison, policy, authorization, and audit.

mod audit;
mod authorization;
mod discover;
mod evidence;
mod repository;

pub use discover::discover;

pub use authorization::{
    public_key, sign_authorization, verify_authorization, AuthorizationBinding,
};
pub use repository::{candidate_snapshot, open_repository, revision_snapshot, Snapshot};

use rung_model::{
    Assessment, Authorization, Decision, EnforcementDecision, Ledger, OmissionKind, Policy,
    PresenceDisposition, Rung, Violation,
};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;
use tracing::instrument;

const LEDGER_PATH: &str = ".rung/ledger.toml";
const POLICY_PATH: &str = ".rung/policy.toml";

#[derive(Debug, Error)]
pub enum RungError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Git error: {0}")]
    Git(#[from] git2::Error),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("analysis failure: {0}")]
    Analysis(String),
    #[error("baseline unavailable: {0}")]
    Baseline(String),
    #[error("authorization failure: {0}")]
    Authorization(String),
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, RungError> {
    serde_json::to_vec(value).map_err(|error| RungError::Config(error.to_string()))
}

fn load_baseline(snapshot: &Snapshot) -> Result<(Ledger, Policy), RungError> {
    let ledger = snapshot.files.get(LEDGER_PATH).ok_or_else(|| {
        RungError::Baseline(format!("{LEDGER_PATH} missing from accepted baseline"))
    })?;
    let policy = snapshot.files.get(POLICY_PATH).ok_or_else(|| {
        RungError::Baseline(format!("{POLICY_PATH} missing from accepted baseline"))
    })?;
    let ledger: Ledger = parse_toml(ledger, "baseline ledger")?;
    let policy: Policy = parse_toml(policy, "baseline policy")?;
    validate(&ledger, &policy)?;
    Ok((ledger, policy))
}

fn parse_toml<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, RungError> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| RungError::Config(format!("{label}: {e}")))?;
    toml::from_str(text).map_err(|e| RungError::Config(format!("{label}: {e}")))
}

pub fn validate(ledger: &Ledger, policy: &Policy) -> Result<(), RungError> {
    if ledger.schema_version != 1 || policy.schema_version != 1 {
        return Err(RungError::Config("unsupported schema version".into()));
    }
    let mut ids = BTreeSet::new();
    for cap in &ledger.capabilities {
        if cap.id.is_empty()
            || !cap
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            || !ids.insert(&cap.id)
            || cap.evidence.is_empty()
            || cap.threshold == 0
        {
            return Err(RungError::Config(format!("invalid capability {}", cap.id)));
        }
        let mut total = 0u32;
        for item in &cap.evidence {
            if item.weight == 0 || item.value.is_empty() {
                return Err(RungError::Config(format!(
                    "{} has invalid evidence",
                    cap.id
                )));
            }
            total += u32::from(item.weight);
        }
        if u32::from(cap.threshold) > total {
            return Err(RungError::Config(format!(
                "{} threshold exceeds evidence weight",
                cap.id
            )));
        }
    }
    let mut requirement_rungs = BTreeSet::new();
    for requirement in &policy.requirements {
        if !requirement.rung.protected()
            || requirement.role.is_empty()
            || requirement.approvals == 0
            || !requirement_rungs.insert(requirement.rung)
        {
            return Err(RungError::Config(
                "invalid or duplicate policy requirement".into(),
            ));
        }
    }
    for cap in &ledger.capabilities {
        if cap.rung.protected() && !requirement_rungs.contains(&cap.rung) {
            return Err(RungError::Config(format!(
                "missing policy for {:?}",
                cap.rung
            )));
        }
    }
    let mut authority_actors = BTreeSet::new();
    for authority in &policy.authorities {
        let key = hex::decode(&authority.public_key)
            .map_err(|_| RungError::Config("invalid authority public key".into()))?;
        if key.len() != 32
            || authority.actor.is_empty()
            || authority.role.is_empty()
            || !authority_actors.insert(&authority.actor)
        {
            return Err(RungError::Config("invalid authority".into()));
        }
    }
    Ok(())
}

fn governance(
    baseline: &Snapshot,
    candidate: &Snapshot,
    ledger: &Ledger,
    policy: &Policy,
) -> Result<Vec<String>, RungError> {
    let mut violations = Vec::new();
    match candidate.files.get(LEDGER_PATH) {
        None => violations.push("GOV-RUNG-001: candidate capability ledger is missing".into()),
        Some(bytes) => match parse_toml::<Ledger>(bytes, "candidate ledger") {
            Err(_) => {
                violations.push("GOV-RUNG-001: candidate capability ledger is invalid".into())
            }
            Ok(other) => {
                let by_id: BTreeMap<_, _> = other
                    .capabilities
                    .iter()
                    .map(|c| (c.id.as_str(), c))
                    .collect();
                for cap in &ledger.capabilities {
                    match by_id.get(cap.id.as_str()) {
                        None => violations.push(format!("GOV-RUNG-001: {} record deleted", cap.id)),
                        Some(candidate_cap) if canonical(cap)? != canonical(candidate_cap)? => {
                            violations.push(format!(
                                "GOV-RUNG-002: {} protection metadata changed",
                                cap.id
                            ))
                        }
                        _ => {}
                    }
                }
            }
        },
    }
    match candidate.files.get(POLICY_PATH) {
        None => violations.push("GOV-RUNG-004: candidate policy is missing".into()),
        Some(bytes) => match parse_toml::<Policy>(bytes, "candidate policy") {
            Ok(other) if canonical(policy)? == canonical(&other)? => {}
            _ => violations
                .push("GOV-RUNG-004: candidate policy differs from accepted baseline".into()),
        },
    }
    for (path, bytes) in baseline
        .files
        .iter()
        .filter(|(p, _)| p.starts_with(".rung/authorizations/"))
    {
        if candidate.files.get(path) != Some(bytes) {
            violations.push(format!(
                "GOV-RUNG-003: authorization history changed: {path}"
            ));
        }
    }
    Ok(violations)
}

pub fn default_policy() -> Policy {
    use rung_model::Requirement;
    Policy {
        schema_version: 1,
        authorities: Vec::new(),
        requirements: vec![
            Requirement {
                rung: Rung::R2,
                role: "developer".into(),
                approvals: 1,
                migration_required: false,
            },
            Requirement {
                rung: Rung::R3,
                role: "maintainer".into(),
                approvals: 1,
                migration_required: false,
            },
            Requirement {
                rung: Rung::R4,
                role: "maintainer".into(),
                approvals: 2,
                migration_required: false,
            },
            Requirement {
                rung: Rung::R5,
                role: "maintainer".into(),
                approvals: 2,
                migration_required: true,
            },
        ],
    }
}

#[instrument(skip(repository))]
pub fn check(
    repository: &git2::Repository,
    against: &str,
    candidate_revision: Option<&str>,
) -> Result<Decision, RungError> {
    if let Some(root) = repository.workdir() {
        audit::record_access(root, audit::AccessAction::Check, against, None)?;
    }
    let baseline = revision_snapshot(repository, against)
        .map_err(|e| RungError::Baseline(format!("cannot resolve {against}: {e}")))?;
    let candidate = match candidate_revision {
        Some(revision) => revision_snapshot(repository, revision)?,
        None => candidate_snapshot(repository)?,
    };
    let decision = compare(&baseline, &candidate)?;
    if let Some(root) = repository.workdir() {
        audit::record_decision(root, &decision)?;
    }
    Ok(decision)
}

#[instrument(skip(baseline, candidate))]
pub fn compare(baseline: &Snapshot, candidate: &Snapshot) -> Result<Decision, RungError> {
    let (ledger, policy) = load_baseline(baseline)?;
    let ledger_digest = digest(&canonical(&ledger)?);
    let policy_digest = digest(&canonical(&policy)?);
    let candidate_digest = candidate.digest();
    let binding = AuthorizationBinding {
        baseline_revision: &baseline.revision,
        candidate_digest: &candidate_digest,
        ledger_digest: &ledger_digest,
        policy_digest: &policy_digest,
    };
    let violations = governance(baseline, candidate, &ledger, &policy)?;
    let mut assessments = Vec::new();
    let mut capability_violations = Vec::new();
    let mut blocked = !violations.is_empty();
    let mut review = false;
    let mut warned = false;
    for cap in &ledger.capabilities {
        let baseline_assessment = evidence::assess(cap, baseline)?;
        if baseline_assessment.0 != PresenceDisposition::Present {
            return Err(RungError::Baseline(format!(
                "{} is not established in baseline",
                cap.id
            )));
        }
        let (mut presence, confidence, observations) = evidence::assess(cap, candidate)?;
        if presence == PresenceDisposition::Present
            && observations
                .iter()
                .zip(&baseline_assessment.2)
                .any(|(current, previous)| current.found != previous.found)
        {
            presence = PresenceDisposition::Mutated;
        }
        let missing = !matches!(
            presence,
            PresenceDisposition::Present | PresenceDisposition::Mutated
        );
        let mut authorized = false;
        let reason = if !missing {
            "capability evidence meets the protected threshold".to_string()
        } else if cap.rung.protected() {
            match relevant_authorization(candidate, &cap.id, &binding) {
                Ok(Some(auth)) => match verify_authorization(
                    &auth,
                    cap,
                    &policy,
                    &binding,
                    &ledger.capabilities,
                    candidate,
                ) {
                    Ok(()) => {
                        authorized = true;
                        format!(
                            "loss authorized as {:?} ({})",
                            auth.disposition, auth.authorization_id
                        )
                    }
                    Err(error) => {
                        blocked = true;
                        format!("authorization rejected: {error}")
                    }
                },
                Ok(None) => {
                    if presence == PresenceDisposition::ProbablyAbsent {
                        review = true;
                    } else {
                        blocked = true;
                    }
                    "protected capability cannot be established; no authorization".into()
                }
                Err(error) => {
                    blocked = true;
                    format!("authorization rejected: {error}")
                }
            }
        } else {
            warned |= cap.rung == Rung::R1;
            "capability evidence below threshold".into()
        };
        if missing && cap.rung.protected() && !authorized {
            let key = format!(
                "{}:{}:{}:{}:{}",
                cap.id, baseline.revision, candidate_digest, ledger_digest, policy_digest
            );
            capability_violations.push(Violation {
                id: format!("RUNG-VIOLATION-{}", &digest(key.as_bytes())[..16]),
                capability_id: cap.id.clone(),
                rung: cap.rung,
                baseline_revision: baseline.revision.clone(),
                candidate_digest: candidate_digest.clone(),
                confidence,
                missing_evidence: observations
                    .iter()
                    .filter(|item| !item.found)
                    .cloned()
                    .collect(),
                reason: reason.clone(),
            });
        }
        assessments.push(Assessment {
            capability_id: cap.id.clone(),
            baseline: baseline_assessment.0,
            candidate: presence,
            confidence,
            observations,
            authorized,
            reason,
        });
    }
    let outcome = if blocked {
        EnforcementDecision::Block
    } else if review {
        EnforcementDecision::RequireReview
    } else if warned {
        EnforcementDecision::AllowWithWarnings
    } else {
        EnforcementDecision::Allow
    };
    Ok(Decision {
        schema_version: 1,
        outcome,
        baseline_revision: baseline.revision.clone(),
        candidate_digest,
        ledger_digest,
        policy_digest,
        governance_violations: violations,
        violations: capability_violations,
        assessments,
    })
}

fn relevant_authorization(
    candidate: &Snapshot,
    capability: &str,
    binding: &AuthorizationBinding<'_>,
) -> Result<Option<Authorization>, RungError> {
    let mut had_record = false;
    let mut matching = None;
    for (path, bytes) in candidate
        .files
        .iter()
        .filter(|(path, _)| path.starts_with(".rung/authorizations/") && path.ends_with(".toml"))
    {
        let record: Authorization = parse_toml(bytes, "authorization")
            .map_err(|e| RungError::Authorization(e.to_string()))?;
        if path != &format!(".rung/authorizations/{}.toml", record.authorization_id) {
            return Err(RungError::Authorization(format!(
                "authorization ID/path mismatch: {path}"
            )));
        }
        if record.capability != capability {
            continue;
        }
        had_record = true;
        let bound = record.baseline_revision == binding.baseline_revision
            && record.candidate_digest == binding.candidate_digest
            && record.ledger_digest == binding.ledger_digest
            && record.policy_digest == binding.policy_digest;
        if bound && matching.replace(record).is_some() {
            return Err(RungError::Authorization(
                "multiple records are bound to this capability and candidate".into(),
            ));
        }
    }
    if matching.is_some() {
        return Ok(matching);
    }
    if had_record {
        return Err(RungError::Authorization(
            "no record is bound to this baseline and candidate".into(),
        ));
    }
    Ok(None)
}

pub fn draft_authorization(
    repository: &git2::Repository,
    against: &str,
    capability: &str,
    disposition: OmissionKind,
    reason: String,
    successor: Option<String>,
    migration: Option<String>,
) -> Result<Authorization, RungError> {
    let baseline = revision_snapshot(repository, against)
        .map_err(|e| RungError::Baseline(format!("cannot resolve {against}: {e}")))?;
    let candidate = candidate_snapshot(repository)?;
    let (ledger, policy) = load_baseline(&baseline)?;
    let cap = ledger
        .capabilities
        .iter()
        .find(|c| c.id == capability)
        .ok_or_else(|| RungError::Config(format!("unknown capability {capability}")))?;
    if !cap.rung.protected() {
        return Err(RungError::Config(
            "capability is not at a permissioned rung".into(),
        ));
    }
    if reason.trim().is_empty() {
        return Err(RungError::Config("reason is required".into()));
    }
    let baseline_presence = evidence::assess(cap, &baseline)?.0;
    if baseline_presence != PresenceDisposition::Present {
        return Err(RungError::Baseline(format!(
            "{capability} not present in baseline"
        )));
    }
    let created_at_unix_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| RungError::Analysis(format!("system clock: {e}")))?
        .as_millis()
        .try_into()
        .map_err(|_| RungError::Analysis("clock overflow".into()))?;
    let candidate_digest = candidate.digest();
    let authorization_id = format!(
        "AUTH-{}",
        &digest(
            format!(
                "{capability}:{}:{candidate_digest}:{created_at_unix_ms}",
                baseline.revision
            )
            .as_bytes()
        )[..20]
    );
    let auth = Authorization {
        schema_version: 1,
        authorization_id,
        created_at_unix_ms,
        capability: capability.into(),
        disposition,
        baseline_revision: baseline.revision,
        candidate_digest,
        ledger_digest: digest(&canonical(&ledger)?),
        policy_digest: digest(&canonical(&policy)?),
        reason,
        successor,
        migration,
        signatures: Vec::new(),
    };
    Ok(auth)
}

pub fn write_authorization(root: &Path, authorization: &Authorization) -> Result<(), RungError> {
    let name = &authorization.authorization_id;
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(RungError::Config("unsafe authorization id for path".into()));
    }
    let dir = root.join(".rung/authorizations");
    std::fs::create_dir_all(&dir)?;
    let bytes =
        toml::to_string_pretty(authorization).map_err(|e| RungError::Config(e.to_string()))?;
    std::fs::write(dir.join(format!("{name}.toml")), bytes)?;
    audit::record_access(
        root,
        audit::AccessAction::Authorize,
        &authorization.baseline_revision,
        Some(name),
    )?;
    Ok(())
}
