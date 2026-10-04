//! Stable, serializable domain types. This crate has no repository or UI dependencies.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rung {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
}

impl Rung {
    pub const fn protected(self) -> bool {
        matches!(self, Self::R2 | Self::R3 | Self::R4 | Self::R5)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub schema_version: u32,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub id: String,
    pub name: String,
    pub rung: Rung,
    /// Minimum sum of satisfied evidence weights, from 1 to total weight.
    pub threshold: u16,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub value: String,
    #[serde(default = "one")]
    pub weight: u16,
}

const fn one() -> u16 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    File,
    Symbol,
    Test,
    CargoFeature,
    /// Clap `Parser` / `Subcommand` command name.
    CliCommand,
    /// `METHOD /path`, for example `GET /health`.
    Route,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorities: Vec<Authority>,
    #[serde(default)]
    pub requirements: Vec<Requirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub actor: String,
    pub role: String,
    /// Ed25519 public key as 64 hexadecimal characters.
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub rung: Rung,
    pub role: String,
    pub approvals: usize,
    #[serde(default)]
    pub migration_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionKind {
    Omit,
    Indifferent,
    Supersede,
    FalseMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub schema_version: u32,
    pub authorization_id: String,
    pub created_at_unix_ms: u64,
    pub capability: String,
    pub disposition: OmissionKind,
    pub baseline_revision: String,
    pub candidate_digest: String,
    pub ledger_digest: String,
    pub policy_digest: String,
    pub reason: String,
    pub successor: Option<String>,
    pub migration: Option<String>,
    #[serde(default)]
    pub signatures: Vec<Approval>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub actor: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceDisposition {
    Present,
    Mutated,
    ProbablyAbsent,
    Absent,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementDecision {
    Allow,
    AllowWithWarnings,
    RequireReview,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Confidence(u16);

impl Confidence {
    pub fn new(basis_points: u16) -> Option<Self> {
        (basis_points <= 10_000).then_some(Self(basis_points))
    }
    pub const fn basis_points(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u16::deserialize(deserializer)?;
        Self::new(value)
            .ok_or_else(|| serde::de::Error::custom("confidence exceeds 10000 basis points"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceObservation {
    pub kind: EvidenceKind,
    pub value: String,
    pub found: bool,
    pub weight: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub capability_id: String,
    pub baseline: PresenceDisposition,
    pub candidate: PresenceDisposition,
    pub confidence: Confidence,
    pub observations: Vec<EvidenceObservation>,
    pub authorized: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub id: String,
    pub capability_id: String,
    pub rung: Rung,
    pub baseline_revision: String,
    pub candidate_digest: String,
    pub confidence: Confidence,
    pub missing_evidence: Vec<EvidenceObservation>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub schema_version: u32,
    pub outcome: EnforcementDecision,
    pub baseline_revision: String,
    pub candidate_digest: String,
    pub ledger_digest: String,
    pub policy_digest: String,
    pub governance_violations: Vec<String>,
    pub violations: Vec<Violation>,
    pub assessments: Vec<Assessment>,
}

/// Where a discovered candidate came from. Discovery never protects a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryKind {
    PublicApi,
    CliCommand,
    CargoFeature,
    Test,
    Route,
    Configuration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredCandidate {
    /// Stable suggestion safe to use as a capability id. Promotion is still explicit.
    pub suggested_id: String,
    pub name: String,
    pub kind: DiscoveryKind,
    pub evidence: Vec<Evidence>,
    pub locations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    pub schema_version: u32,
    pub candidates: Vec<DiscoveredCandidate>,
}
