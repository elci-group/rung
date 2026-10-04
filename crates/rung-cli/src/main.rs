use clap::{Parser, Subcommand, ValueEnum};
use rung_core::{
    check, default_policy, discover, draft_authorization, open_repository, public_key,
    sign_authorization, write_authorization, RungError,
};
use rung_model::{
    Authorization, Capability, Decision, DiscoveredCandidate, DiscoveryKind, EnforcementDecision,
    Evidence, EvidenceKind, Ledger, OmissionKind, Rung,
};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "rung", version, about = "Capability preservation gate")]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    repo: PathBuf,
    #[arg(long, global = true, value_enum, default_value_t = Format::Human)]
    format: Format,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
    Jsonl,
}

#[derive(Subcommand)]
enum Command {
    /// Create repository-local ledger and policy.
    Init,
    /// Register a capability in the current worktree ledger.
    Protect {
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long, value_parser = parse_rung)]
        rung: Rung,
        #[arg(long, default_value_t = 1)]
        threshold: u16,
        #[arg(long = "evidence", required = true)]
        evidence: Vec<String>,
    },
    /// List candidate capabilities without changing the ledger.
    Scan,
    /// Compare candidate against an immutable accepted baseline revision.
    Check {
        #[arg(long)]
        against: String,
        #[arg(long)]
        candidate: Option<String>,
    },
    /// Explain one capability in a check report.
    Explain {
        capability: String,
        #[arg(long)]
        against: String,
        #[arg(long)]
        candidate: Option<String>,
    },
    /// Create an intentional-removal authorization.
    Omit(AuthArgs),
    /// Accept a loss without intentionally removing the capability.
    Indifferent(AuthArgs),
    /// Link a lost capability to a verified successor.
    Supersede {
        #[command(flatten)]
        auth: AuthArgs,
        #[arg(long = "with")]
        successor: String,
    },
    /// Record a false positive and its evidence-correction reference.
    FalseMatch {
        #[command(flatten)]
        auth: AuthArgs,
        #[arg(long)]
        correction: String,
    },
    /// Add a distinct signature to an existing authorization.
    Authorize {
        authorization_id: String,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        key: PathBuf,
    },
    /// Derive an Ed25519 public key from a 32-byte hex private key file.
    PublicKey {
        #[arg(long)]
        key: PathBuf,
    },
}

#[derive(clap::Args)]
struct AuthArgs {
    capability: String,
    #[arg(long)]
    against: String,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    actor: String,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    migration: Option<String>,
}

fn parse_rung(value: &str) -> Result<Rung, String> {
    match value.to_ascii_lowercase().as_str() {
        "r0" => Ok(Rung::R0),
        "r1" => Ok(Rung::R1),
        "r2" => Ok(Rung::R2),
        "r3" => Ok(Rung::R3),
        "r4" => Ok(Rung::R4),
        "r5" => Ok(Rung::R5),
        _ => Err("rung must be r0, r1, r2, r3, r4, or r5".into()),
    }
}

fn parse_evidence(value: &str) -> Result<Evidence, RungError> {
    let (kind, raw) = value
        .split_once(':')
        .ok_or_else(|| RungError::Config("evidence must be kind:value".into()))?;
    let kind = match kind {
        "file" => EvidenceKind::File,
        "symbol" => EvidenceKind::Symbol,
        "test" => EvidenceKind::Test,
        "cargo_feature" => EvidenceKind::CargoFeature,
        "cli_command" => EvidenceKind::CliCommand,
        "route" => EvidenceKind::Route,
        _ => {
            return Err(RungError::Config(format!(
                "unsupported evidence kind: {kind}"
            )))
        }
    };
    Ok(Evidence {
        kind,
        value: raw.into(),
        weight: 1,
    })
}

fn repo_root(repo: &git2::Repository) -> Result<&Path, RungError> {
    repo.workdir()
        .ok_or_else(|| RungError::Config("bare repository unsupported".into()))
}

fn read_key(path: &Path) -> Result<String, RungError> {
    fs::read_to_string(path).map_err(Into::into)
}

fn print_decision(decision: &Decision, format: Format) -> Result<(), RungError> {
    match format {
        Format::Human => {
            println!(
                "{:?}  baseline={} candidate={}",
                decision.outcome, decision.baseline_revision, decision.candidate_digest
            );
            for issue in &decision.governance_violations {
                println!("  BLOCK {issue}");
            }
            for violation in &decision.violations {
                println!("  {} {}", violation.id, violation.reason);
            }
            for assessment in &decision.assessments {
                println!(
                    "  {} {:?} confidence={:.1}%: {}",
                    assessment.capability_id,
                    assessment.candidate,
                    f64::from(assessment.confidence.basis_points()) / 100.0,
                    assessment.reason
                );
                if assessment.candidate != rung_model::PresenceDisposition::Present {
                    for observation in &assessment.observations {
                        println!(
                            "    {} {:?} {}",
                            if observation.found { "+" } else { "-" },
                            observation.kind,
                            observation.value
                        );
                    }
                }
            }
        }
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(decision).map_err(|e| RungError::Config(e.to_string()))?
        ),
        Format::Jsonl => {
            println!(
                "{}",
                serde_json::json!({"schema_version": 1, "kind": "decision", "outcome": decision.outcome,
                "baseline_revision": decision.baseline_revision, "candidate_digest": decision.candidate_digest})
            );
            for issue in &decision.governance_violations {
                println!(
                    "{}",
                    serde_json::json!({"schema_version": 1, "kind": "governance_violation", "reason": issue})
                );
            }
            for violation in &decision.violations {
                println!(
                    "{}",
                    serde_json::json!({"schema_version": 1, "kind": "violation", "data": violation})
                );
            }
            for assessment in &decision.assessments {
                println!(
                    "{}",
                    serde_json::json!({"schema_version": 1, "kind": "assessment", "data": assessment})
                );
            }
        }
    }
    Ok(())
}

fn evidence_token(evidence: &Evidence) -> String {
    let kind = match evidence.kind {
        EvidenceKind::File => "file",
        EvidenceKind::Symbol => "symbol",
        EvidenceKind::Test => "test",
        EvidenceKind::CargoFeature => "cargo_feature",
        EvidenceKind::CliCommand => "cli_command",
        EvidenceKind::Route => "route",
    };
    format!("{kind}:{}", evidence.value)
}

fn discovery_kind(kind: DiscoveryKind) -> &'static str {
    match kind {
        DiscoveryKind::PublicApi => "public_api",
        DiscoveryKind::CliCommand => "cli_command",
        DiscoveryKind::CargoFeature => "cargo_feature",
        DiscoveryKind::Test => "test",
        DiscoveryKind::Route => "route",
        DiscoveryKind::Configuration => "configuration",
    }
}

fn format_candidate(candidate: &DiscoveredCandidate) -> String {
    let evidence = candidate
        .evidence
        .iter()
        .map(evidence_token)
        .collect::<Vec<_>>()
        .join(", ");
    let locations = candidate.locations.join(", ");
    format!(
        "{}\t{}\t{}\t{}\t{locations}",
        candidate.suggested_id,
        discovery_kind(candidate.kind),
        candidate.name,
        evidence
    )
}

fn print_action(format: Format, action: &str, detail: &str, capability: Option<&str>) {
    match format {
        Format::Human => println!("{detail}"),
        Format::Json | Format::Jsonl => println!(
            "{}",
            serde_json::json!({
                "schema_version": 1, "kind": "action", "action": action,
                "capability": capability, "detail": detail
            })
        ),
    }
}

fn exit_for(decision: &Decision) -> i32 {
    if decision.assessments.iter().any(|a| {
        a.reason.starts_with("authorization rejected:")
            || a.reason.starts_with("authorization record invalid:")
    }) {
        return 5;
    }
    if matches!(
        decision.outcome,
        EnforcementDecision::Block | EnforcementDecision::RequireReview
    ) {
        1
    } else {
        0
    }
}

fn create_auth(
    repo: &git2::Repository,
    format: Format,
    args: AuthArgs,
    disposition: OmissionKind,
    successor: Option<String>,
    correction: Option<String>,
) -> Result<(), RungError> {
    let mut record = draft_authorization(
        repo,
        &args.against,
        &args.capability,
        disposition,
        args.reason,
        successor,
        correction.or(args.migration),
    )?;
    sign_authorization(&mut record, &args.actor, &read_key(&args.key)?)?;
    write_authorization(repo_root(repo)?, &record)?;
    print_action(
        format,
        "authorize",
        &format!(
            "wrote {} for {} bound to baseline {} and candidate {}",
            record.authorization_id,
            record.capability,
            record.baseline_revision,
            record.candidate_digest
        ),
        Some(&record.capability),
    );
    Ok(())
}

fn run(cli: Cli) -> Result<i32, RungError> {
    if let Command::PublicKey { key } = &cli.command {
        let key = public_key(&read_key(key)?)?;
        match cli.format {
            Format::Human => println!("{key}"),
            Format::Json | Format::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "schema_version": 1, "kind": "public_key", "public_key": key
                })
            ),
        }
        return Ok(0);
    }
    let repo = open_repository(&cli.repo)?;
    let root = repo_root(&repo)?;
    match cli.command {
        Command::Init => {
            let dir = root.join(".rung");
            fs::create_dir_all(&dir)?;
            let ledger_path = dir.join("ledger.toml");
            let policy_path = dir.join("policy.toml");
            if ledger_path.exists() || policy_path.exists() {
                return Err(RungError::Config(
                    "Rung state already exists; refusing overwrite".into(),
                ));
            }
            let ledger = Ledger {
                schema_version: 1,
                capabilities: Vec::new(),
            };
            fs::write(
                ledger_path,
                toml::to_string_pretty(&ledger).map_err(|e| RungError::Config(e.to_string()))?,
            )?;
            fs::write(
                policy_path,
                toml::to_string_pretty(&default_policy())
                    .map_err(|e| RungError::Config(e.to_string()))?,
            )?;
            print_action(
                cli.format,
                "init",
                "created .rung/ledger.toml and .rung/policy.toml",
                None,
            );
            Ok(0)
        }
        Command::Protect {
            id,
            name,
            rung,
            threshold,
            evidence,
        } => {
            let path = root.join(".rung/ledger.toml");
            let text = fs::read_to_string(&path)?;
            let mut ledger: Ledger =
                toml::from_str(&text).map_err(|e| RungError::Config(format!("ledger: {e}")))?;
            if ledger.capabilities.iter().any(|cap| cap.id == id) {
                return Err(RungError::Config(format!("capability {id} already exists")));
            }
            let evidence = evidence
                .iter()
                .map(|raw| parse_evidence(raw))
                .collect::<Result<Vec<_>, _>>()?;
            ledger.capabilities.push(Capability {
                id: id.clone(),
                name,
                rung,
                threshold,
                evidence,
            });
            let policy: rung_model::Policy =
                toml::from_str(&fs::read_to_string(root.join(".rung/policy.toml"))?)
                    .map_err(|e| RungError::Config(format!("policy: {e}")))?;
            rung_core::validate(&ledger, &policy)?;
            fs::write(
                path,
                toml::to_string_pretty(&ledger).map_err(|e| RungError::Config(e.to_string()))?,
            )?;
            print_action(
                cli.format,
                "protect",
                &format!("protected {id} at {rung:?}"),
                Some(&id),
            );
            Ok(0)
        }
        Command::Scan => {
            let snapshot = rung_core::candidate_snapshot(&repo)?;
            let discovery = discover(&snapshot)?;
            match cli.format {
                Format::Human => {
                    if discovery.candidates.is_empty() {
                        println!("no candidate capabilities");
                    }
                    for candidate in &discovery.candidates {
                        println!("{}", format_candidate(candidate));
                    }
                    println!(
                        "{} candidates; scan does not modify the ledger",
                        discovery.candidates.len()
                    );
                }
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema_version": discovery.schema_version,
                        "kind": "discovery",
                        "candidates": discovery.candidates,
                    }))
                    .map_err(|error| RungError::Config(error.to_string()))?
                ),
                Format::Jsonl => {
                    for candidate in &discovery.candidates {
                        println!(
                            "{}",
                            serde_json::json!({
                                "schema_version": discovery.schema_version,
                                "kind": "candidate",
                                "candidate": candidate,
                            })
                        );
                    }
                }
            }
            Ok(0)
        }
        Command::Check { against, candidate } => {
            let decision = check(&repo, &against, candidate.as_deref())?;
            print_decision(&decision, cli.format)?;
            Ok(exit_for(&decision))
        }
        Command::Explain {
            capability,
            against,
            candidate,
        } => {
            let mut decision = check(&repo, &against, candidate.as_deref())?;
            decision
                .assessments
                .retain(|a| a.capability_id == capability);
            if decision.assessments.is_empty() {
                return Err(RungError::Config(format!(
                    "unknown capability {capability}"
                )));
            }
            print_decision(&decision, cli.format)?;
            Ok(exit_for(&decision))
        }
        Command::Omit(args) => {
            create_auth(&repo, cli.format, args, OmissionKind::Omit, None, None)?;
            Ok(0)
        }
        Command::Indifferent(args) => {
            create_auth(
                &repo,
                cli.format,
                args,
                OmissionKind::Indifferent,
                None,
                None,
            )?;
            Ok(0)
        }
        Command::Supersede { auth, successor } => {
            create_auth(
                &repo,
                cli.format,
                auth,
                OmissionKind::Supersede,
                Some(successor),
                None,
            )?;
            Ok(0)
        }
        Command::FalseMatch { auth, correction } => {
            create_auth(
                &repo,
                cli.format,
                auth,
                OmissionKind::FalseMatch,
                None,
                Some(correction),
            )?;
            Ok(0)
        }
        Command::Authorize {
            authorization_id,
            actor,
            key,
        } => {
            if !authorization_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(RungError::Config("unsafe authorization id".into()));
            }
            let path = root.join(format!(".rung/authorizations/{authorization_id}.toml"));
            let mut record: Authorization = toml::from_str(&fs::read_to_string(&path)?)
                .map_err(|e| RungError::Authorization(format!("invalid authorization: {e}")))?;
            if record.authorization_id != authorization_id {
                return Err(RungError::Authorization(
                    "authorization ID/path mismatch".into(),
                ));
            }
            sign_authorization(&mut record, &actor, &read_key(&key)?)?;
            write_authorization(root, &record)?;
            print_action(
                cli.format,
                "authorize",
                &format!("added signature by {actor} to {authorization_id}"),
                Some(&record.capability),
            );
            Ok(0)
        }
        Command::PublicKey { .. } => Ok(0),
    }
}

fn main() {
    let cli = Cli::parse();
    let format = cli.format;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let code = match run(cli) {
        Ok(code) => code,
        Err(error) => {
            let code = match &error {
                RungError::Config(_) => 2,
                RungError::Analysis(_) | RungError::Io(_) | RungError::Git(_) => 3,
                RungError::Baseline(_) => 4,
                RungError::Authorization(_) => 5,
            };
            match format {
                Format::Human => eprintln!("rung: {error}"),
                Format::Json | Format::Jsonl => eprintln!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1, "kind": "error", "exit_code": code,
                        "message": error.to_string()
                    })
                ),
            }
            code
        }
    };
    std::process::exit(code);
}
