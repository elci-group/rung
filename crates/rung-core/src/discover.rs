//! Candidate discovery. Findings are suggestions; they do not change the ledger.

use crate::evidence::{self, CargoFeature, Surface};
use crate::{RungError, Snapshot};
use rung_model::{DiscoveredCandidate, Discovery, DiscoveryKind, Evidence, EvidenceKind};
use std::collections::{BTreeMap, BTreeSet};
use tracing::instrument;

fn slug(prefix: &str, raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut body = String::new();
    let mut dash = false;
    for (index, &ch) in chars.iter().enumerate() {
        if ch.is_ascii_alphanumeric() {
            let prev_lower = index > 0 && chars[index - 1].is_ascii_lowercase();
            let prev_upper = index > 0 && chars[index - 1].is_ascii_uppercase();
            let next_lower = chars
                .get(index + 1)
                .is_some_and(|next| next.is_ascii_lowercase());
            if ch.is_ascii_uppercase()
                && !body.is_empty()
                && !dash
                && (prev_lower || (prev_upper && next_lower))
            {
                body.push('-');
            }
            body.push(ch.to_ascii_lowercase());
            dash = false;
        } else if !body.is_empty() && !dash {
            body.push('-');
            dash = true;
        }
    }
    while body.ends_with('-') {
        body.pop();
    }
    if body.is_empty() {
        format!("{prefix}-unnamed")
    } else {
        format!("{prefix}-{body}")
    }
}

fn allocate(used: &mut BTreeSet<String>, prefix: &str, raw: &str) -> String {
    let base = slug(prefix, raw);
    let mut id = base.clone();
    let mut suffix = 2u32;
    while !used.insert(id.clone()) {
        id = format!("{base}-{suffix}");
        suffix += 1;
    }
    id
}

fn evidence(kind: EvidenceKind, value: &str) -> Evidence {
    Evidence {
        kind,
        value: value.to_string(),
        weight: 1,
    }
}

fn push_named(
    candidates: &mut Vec<DiscoveredCandidate>,
    used: &mut BTreeSet<String>,
    prefix: &str,
    kind: DiscoveryKind,
    evidence_kind: EvidenceKind,
    names: &BTreeMap<String, BTreeSet<String>>,
) {
    for (name, paths) in names {
        candidates.push(DiscoveredCandidate {
            suggested_id: allocate(used, prefix, name),
            name: name.clone(),
            kind,
            evidence: vec![evidence(evidence_kind, name)],
            locations: paths.iter().cloned().collect(),
        });
    }
}

fn from_surface(surface: &Surface, features: &[CargoFeature]) -> Discovery {
    let mut used = BTreeSet::new();
    let mut candidates = Vec::new();
    push_named(
        &mut candidates,
        &mut used,
        "api",
        DiscoveryKind::PublicApi,
        EvidenceKind::Symbol,
        &surface.public_api,
    );
    push_named(
        &mut candidates,
        &mut used,
        "config",
        DiscoveryKind::Configuration,
        EvidenceKind::Symbol,
        &surface.configuration,
    );
    for (name, paths) in &surface.cli_locations {
        candidates.push(DiscoveredCandidate {
            suggested_id: allocate(&mut used, "cli", name),
            name: name.clone(),
            kind: DiscoveryKind::CliCommand,
            evidence: vec![evidence(EvidenceKind::CliCommand, name)],
            locations: paths.iter().cloned().collect(),
        });
    }
    for feature in features {
        let value = format!("{}/{}", feature.package, feature.feature);
        candidates.push(DiscoveredCandidate {
            suggested_id: allocate(&mut used, "cargo", &value),
            name: value.clone(),
            kind: DiscoveryKind::CargoFeature,
            evidence: vec![evidence(EvidenceKind::CargoFeature, &value)],
            locations: vec![feature.path.clone()],
        });
    }
    for (name, paths) in &surface.test_locations {
        candidates.push(DiscoveredCandidate {
            suggested_id: allocate(&mut used, "test", name),
            name: name.clone(),
            kind: DiscoveryKind::Test,
            evidence: vec![evidence(EvidenceKind::Test, name)],
            locations: paths.iter().cloned().collect(),
        });
    }
    for (route, paths) in &surface.route_locations {
        candidates.push(DiscoveredCandidate {
            suggested_id: allocate(&mut used, "route", route),
            name: route.clone(),
            kind: DiscoveryKind::Route,
            evidence: vec![evidence(EvidenceKind::Route, route)],
            locations: paths.iter().cloned().collect(),
        });
    }
    candidates.sort_by(|left, right| left.suggested_id.cmp(&right.suggested_id));
    Discovery {
        schema_version: 1,
        candidates,
    }
}

#[instrument(skip(snapshot))]
pub fn discover(snapshot: &Snapshot) -> Result<Discovery, RungError> {
    let surface = evidence::index(snapshot)?;
    let features = evidence::cargo_features(snapshot)?;
    Ok(from_surface(&surface, &features))
}
