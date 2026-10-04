use crate::{canonical, evidence, repository::Snapshot, RungError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rung_model::{Approval, Authorization, Capability, OmissionKind, Policy, PresenceDisposition};
use std::collections::BTreeSet;
use tracing::instrument;

fn unsigned_bytes(record: &Authorization) -> Result<Vec<u8>, RungError> {
    let mut unsigned = record.clone();
    unsigned.signatures.clear();
    canonical(&unsigned)
}

pub struct AuthorizationBinding<'a> {
    pub baseline_revision: &'a str,
    pub candidate_digest: &'a str,
    pub ledger_digest: &'a str,
    pub policy_digest: &'a str,
}

pub fn sign_authorization(
    record: &mut Authorization,
    actor: &str,
    signing_key_hex: &str,
) -> Result<(), RungError> {
    let bytes = hex::decode(signing_key_hex.trim())
        .map_err(|_| RungError::Authorization("signing key must be 32-byte hex".into()))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RungError::Authorization("signing key must be 32-byte hex".into()))?;
    let signing_key = SigningKey::from_bytes(&key);
    let signature = signing_key.sign(&unsigned_bytes(record)?);
    if record.signatures.iter().any(|s| s.actor == actor) {
        return Err(RungError::Authorization(
            "actor already signed this record".into(),
        ));
    }
    record.signatures.push(Approval {
        actor: actor.into(),
        signature: hex::encode(signature.to_bytes()),
    });
    Ok(())
}

pub fn public_key(signing_key_hex: &str) -> Result<String, RungError> {
    let bytes = hex::decode(signing_key_hex.trim())
        .map_err(|_| RungError::Authorization("signing key must be 32-byte hex".into()))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RungError::Authorization("signing key must be 32-byte hex".into()))?;
    Ok(hex::encode(
        SigningKey::from_bytes(&key).verifying_key().to_bytes(),
    ))
}

#[instrument(skip(record, policy, binding, capabilities, candidate))]
pub fn verify_authorization(
    record: &Authorization,
    capability: &Capability,
    policy: &Policy,
    binding: &AuthorizationBinding<'_>,
    capabilities: &[Capability],
    candidate: &Snapshot,
) -> Result<(), RungError> {
    if record.schema_version != 1
        || record.capability != capability.id
        || record.baseline_revision != binding.baseline_revision
        || record.candidate_digest != binding.candidate_digest
        || record.ledger_digest != binding.ledger_digest
        || record.policy_digest != binding.policy_digest
    {
        return Err(RungError::Authorization(
            "record is not bound to this baseline, candidate, ledger, and policy".into(),
        ));
    }
    if record.reason.trim().is_empty() {
        return Err(RungError::Authorization("reason is required".into()));
    }
    if record.disposition == OmissionKind::Supersede {
        let successor_id = record
            .successor
            .as_ref()
            .ok_or_else(|| RungError::Authorization("supersession needs a successor".into()))?;
        if successor_id == &capability.id {
            return Err(RungError::Authorization(
                "capability cannot supersede itself".into(),
            ));
        }
        let successor = capabilities
            .iter()
            .find(|c| &c.id == successor_id)
            .ok_or_else(|| {
                RungError::Authorization("successor is not in accepted ledger".into())
            })?;
        if evidence::assess(successor, candidate)?.0 != PresenceDisposition::Present {
            return Err(RungError::Authorization(
                "successor not established in candidate".into(),
            ));
        }
    }
    if record.disposition == OmissionKind::FalseMatch
        && !record
            .migration
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty())
    {
        return Err(RungError::Authorization(
            "false match needs evidence correction reference".into(),
        ));
    }
    let requirement = policy
        .requirements
        .iter()
        .find(|r| r.rung == capability.rung)
        .ok_or_else(|| RungError::Config("missing protection requirement".into()))?;
    if requirement.migration_required
        && !record
            .migration
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty())
    {
        return Err(RungError::Authorization(
            "migration reference required".into(),
        ));
    }
    let message = unsigned_bytes(record)?;
    let mut actors = BTreeSet::new();
    let mut qualified = 0usize;
    for approval in &record.signatures {
        if !actors.insert(&approval.actor) {
            return Err(RungError::Authorization("duplicate signer".into()));
        }
        let authority = policy
            .authorities
            .iter()
            .find(|a| a.actor == approval.actor)
            .ok_or_else(|| {
                RungError::Authorization(format!("unknown signer {}", approval.actor))
            })?;
        let public_bytes = hex::decode(&authority.public_key)
            .map_err(|_| RungError::Config("invalid authority key".into()))?;
        let public: [u8; 32] = public_bytes
            .try_into()
            .map_err(|_| RungError::Config("invalid authority key length".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&public)
            .map_err(|_| RungError::Config("invalid authority public key".into()))?;
        let signature_bytes = hex::decode(&approval.signature)
            .map_err(|_| RungError::Authorization("invalid signature encoding".into()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| RungError::Authorization("invalid signature length".into()))?;
        verifying_key.verify(&message, &signature).map_err(|_| {
            RungError::Authorization(format!("invalid signature from {}", approval.actor))
        })?;
        if authority.role == requirement.role {
            qualified += 1;
        }
    }
    if qualified < requirement.approvals {
        return Err(RungError::Authorization(format!(
            "requires {} distinct {} signature(s)",
            requirement.approvals, requirement.role
        )));
    }
    Ok(())
}
