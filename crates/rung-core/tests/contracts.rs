//! production contract: schema_version 1 documents match the serialized types.

use rung_model::{Decision, DiscoveredCandidate};
use std::fs;
use std::path::PathBuf;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn read_json(relative: &str) -> TestResult<serde_json::Value> {
    let text = fs::read_to_string(repo_file(relative))?;
    Ok(serde_json::from_str(&text)?)
}

fn require_keys(schema_path: &str, document: &serde_json::Value) -> TestResult {
    let schema = read_json(schema_path)?;
    let required = schema["required"]
        .as_array()
        .ok_or("schema required array")?;
    for key in required {
        let key = key.as_str().ok_or("required key")?;
        if document.get(key).is_none() {
            return Err(format!("{schema_path} missing {key}").into());
        }
    }
    Ok(())
}

#[test]
fn decision_fixture_matches_schema_and_type() -> TestResult {
    let fixture = read_json("schemas/fixtures/decision.json")?;
    require_keys("schemas/decision.schema.json", &fixture)?;
    let decision: Decision = serde_json::from_value(fixture)?;
    let encoded = serde_json::to_value(&decision)?;
    require_keys("schemas/decision.schema.json", &encoded)?;
    if decision.schema_version != 1 {
        return Err("decision schema_version".into());
    }
    Ok(())
}

#[test]
fn discovery_fixture_matches_schema_and_type() -> TestResult {
    let fixture = read_json("schemas/fixtures/discovery.json")?;
    require_keys("schemas/discovery.schema.json", &fixture)?;
    if fixture["kind"] != "discovery" {
        return Err("discovery kind".into());
    }
    let candidates: Vec<DiscoveredCandidate> =
        serde_json::from_value(fixture["candidates"].clone())?;
    if candidates.len() != 1 {
        return Err("discovery candidate count".into());
    }
    Ok(())
}

#[test]
fn audit_fixtures_match_their_schemas() -> TestResult {
    let decision = read_json("schemas/fixtures/audit-decision.json")?;
    require_keys("schemas/audit-decision.schema.json", &decision)?;
    let access = read_json("schemas/fixtures/audit-access.json")?;
    require_keys("schemas/audit-access.schema.json", &access)?;
    if decision["kind"] != "decision" || access["kind"] != "access" {
        return Err("audit kind".into());
    }
    if access["action"] != "check" {
        return Err("audit action".into());
    }
    Ok(())
}
