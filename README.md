# Rung

Rung is a Rust capability-preservation gate. It compares the current worktree
or a Git revision against the capability ledger **in an accepted baseline
commit**. A candidate cannot erase a capability merely by deleting its own
ledger record. Protected losses block until a signed, candidate-bound
authorization accounts for them.

> Addition is permissive. Mutation is observable. Destruction is permissioned.

This is an early implementation. v0.1 supports manual registration and
deterministic file, Rust symbol, Rust test, and Cargo feature evidence. v0.2
adds read-only discovery (`rung scan`) plus `cli_command` and `route` evidence.
Presence is a threshold over evidence weights. Syntax is parsed with `syn`;
source is never executed and `#[cfg]` is not evaluated. A passing presence
check establishes representation, not correct runtime behaviour. Keep builds
and behavioural tests in CI.

## Install and try

```sh
cargo build --release -p rung
# In the Git repository you want to protect:
/path/to/rung/target/release/rung init
/path/to/rung/target/release/rung protect CAP-A \
  --name feature-a --rung r2 --threshold 2 \
  --evidence symbol:feature_a --evidence test:feature_a_roundtrip
```

`init` creates `.rung/ledger.toml` and `.rung/policy.toml`. Commit both after
registering the capability. For R2 or higher, the policy must name trusted
Ed25519 public keys before authorizations can succeed. Generate a 32-byte
private key outside the repository, keep it secret, and add its public key to
the policy:

```sh
openssl rand -hex 32 > /secure/location/alice.key
rung public-key --key /secure/location/alice.key
```

```toml
[[authorities]]
actor = "alice"
role = "developer"
public_key = "<64 hex characters from rung public-key>"
```

The default policy requires one developer signature for R2, one maintainer
for R3, two distinct maintainers for R4, and two maintainers plus a migration
reference for R5. Requirements are data in `.rung/policy.toml`, not hard-coded
in the comparison engine. The ledger and policy in the accepted baseline commit
are authoritative; a candidate's modified policy cannot lower the gate.

## Check against the accepted lineage

```sh
rung scan
rung check --against main
rung --format json check --against main
rung --format jsonl check --against main --candidate <commit>
rung explain CAP-A --against main
```

The checker resolves `main` to a commit ID and includes that immutable ID in
its report. In CI, supply a protected target branch or exact accepted release
commit with `--against`. The default candidate is the worktree; `--candidate`
uses a Git commit. Run on a checkout of the candidate branch, with the accepted
baseline fetched and available locally. Rung does not use `HEAD~1`.

When the current candidate lacks CAP-A, a check blocks. An authorized
disposition can then be recorded:

```sh
rung indifferent CAP-A --against main \
  --reason "Loss understood and accepted" \
  --actor alice --key /secure/location/alice.key
rung check --against main
```

`omit` records intentional retirement. `indifferent` records accepted loss.
`supersede CAP-A --with CAP-B` requires CAP-B to be registered in the baseline
ledger and present in the candidate. `false-match` requires an evidence
correction reference. `authorize` adds another signature for R4/R5:

```sh
rung authorize AUTH-<id printed by rung omit> --actor bob --key /secure/location/bob.key
```

Authorization records have unique IDs and timestamps under
`.rung/authorizations/`. Signatures cover the
baseline commit ID, candidate content digest, accepted ledger and policy
digests, disposition, reason, and successor or migration reference. The
candidate digest excludes authorization files so adding signatures does not
invalidate the record. Any other candidate file change invalidates it.
Previous authorization files in the baseline cannot be removed or rewritten
by a candidate without a governance violation. Each unresolved protected loss
has a stable `RUNG-VIOLATION-*` ID with its missing evidence in JSON reports.

`check` and `explain` append an audit record before returning. Decision
records go to `.rung/audit/decisions.jsonl` and access records go to
`.rung/audit/access.jsonl`. On Unix the directory is mode `0700` and each file
is mode `0600`. A symlink on that path fails the command with exit code 3.
The log keeps the current file and one previous generation (`*.jsonl.1`);
the previous generation is removed after 90 days. Archive anything that must
outlive that window. The candidate digest excludes `.rung/audit/`, so the log
does not invalidate an authorization. Records contain outcome, revision,
digests, and violation ids. They do not contain private keys. A bare
repository has no worktree, so it does not receive this trail. `scan` does
not write it.

## Ledger format

```toml
schema_version = 1

[[capabilities]]
id = "CAP-A"
name = "feature-a"
rung = "r2"
threshold = 2

[[capabilities.evidence]]
kind = "symbol"
value = "feature_a"
weight = 1

[[capabilities.evidence]]
kind = "test"
value = "feature_a_roundtrip"
weight = 1
```

Evidence kinds are `file`, `symbol`, `test`, `cargo_feature`, `cli_command`,
and `route`. `symbol` matches a public Rust item, a public inherent method, a
public trait item, or a `pub use` name. Glob re-exports are not resolved.
`test` matches a function whose attribute path ends in `test`, including
`#[test]` and `#[tokio::test]`. `cargo_feature` matches a key in any
`Cargo.toml` `[features]` table. `package/feature` matches that package only.
`cli_command` matches a Clap `Parser` or `Subcommand` command: an explicit
`#[command(name = "...")]`, or the kebab-case form of an enum variant.
`route` matches `METHOD /path` from a method attribute such as
`#[get("/health")]` or from `.route("/health", get(handler))`.

`rung scan` lists these surfaces as candidate capabilities. It does not create
or modify `.rung/ledger.toml`. Public API candidates are limited to items
reachable through public modules from crate roots. Symbol checks still see
public names in private modules, so a rename into a private copy can keep a
symbol match. Scan output is not protection. Promote a candidate explicitly:

```sh
rung protect CAP-HEALTH --name health --rung r2 \
  --evidence 'route:GET /health'
```

The resolver reports every found and missing observation and a bounded
confidence score based on observed weight. Multiple evidence types can
preserve a capability through a file move or implementation rewrite.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Permitted, possibly with warnings |
| 1 | Capability or governance violation |
| 2 | Configuration or policy error |
| 3 | Repository observation or analysis failure |
| 4 | Baseline unavailable or invalid |
| 5 | Authorization failure |

R0 losses are informational, R1 losses warn, and R2–R5 losses block or require
review unless authorized. Partial evidence produces `require_review`, which
still exits 1. Missing or changed governance records block before authorization
can permit a release. Decisions are schema-versioned in JSON and JSONL.

## Security limits and roadmap

Git commit IDs make the baseline immutable, but the caller must choose a
trusted ref. Protect that ref in the forge: `main` on this repository requires
a pull request, one approving review, and the `CI / rust` status check.
Rung still cannot discover that protection by itself.

The worktree walker and the Git tree walker both reject symbolic links,
including Git mode `120000`. That rejection is required on every platform.
The current scanner reads the worktree without a filesystem snapshot, so a
concurrent modification during a check is outside the v0.1 integrity model.
Run checks in an isolated CI checkout and keep private signing keys outside
the repository.

Observation uses `git2` (libgit2). `pkg-config` remains a build dependency of
`libgit2-sys` and `libz-sys` in `Cargo.lock` because those crates always
declare it. `cargo audit` is the vulnerability gate for the locked versions.
`ed25519-dalek`, `git2`, `sha2`, `serde`, and `tracing` stay: they implement
signatures, repository observation, digests, and decision reports.

`rung scan` is deterministic discovery only. This version does not perform
behavioural execution, semantic inference, or cross-language analysis. It does
not yet implement every lifecycle adapter or proposed CLI command. Those can
consume the `rung-core` and `rung-model` crates without changing the
enforcement rule. Inference must not turn a block into an allow.

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```
