# RUNG-PROD-001 — Production readiness directive

**Program.** Bring `github.com/elci-group/rung` to production readiness at version `0.1.0`.
**Baseline at issue.** `origin/main` before this program.
**Acceptance tool.** [`deliver`](https://github.com/elci-group/deliver) `0.2.0`, commit `93a90de52b18e9e0a1dd7e89988d2d055c91cae6`.
**Completion command.** `deliver --spec deliver.toml --strict` from the repository root. Exit 0 is the only completion signal.

This directive is the order for the production program. `docs/production/ROADMAP.md` is the phase plan. Each phase has its own spec under `deliver/`. The root `deliver.toml` is the union and the release gate. A phase is closed only after its spec passes with `--strict`. The program is closed only after the root spec passes.

## Production readiness

The repository is production ready when a clean checkout, using toolchain `1.98.1`, can build the `rung` binary, run the capability gate, and prove the following with the committed tests and schemas:

- `rung scan` lists candidates and does not create or modify `.rung/ledger.toml` or the audit trail.
- `rung check` against an immutable baseline blocks a protected loss.
- A signed authorization bound to that baseline and that candidate digest permits the same loss.
- Appending `.rung/audit/` does not change the candidate digest.
- Decision, discovery, and audit records match the `schema_version` 1 documents in `schemas/`.
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace --all-features`, `cargo doc --workspace --no-deps`, `cargo audit`, and `cargo deny check licenses advisories` pass inside the deliver gate.
- The GitHub Actions job named `rust` runs that same root spec.

Product law stays in force. Addition is permissive. Mutation is observable. Destruction is permissioned.

## Deliver integration

`deliver` is the planner and the closer. Specs are written before the work they accept. A narrative claim does not close a phase.

| Phase | Spec | What the spec accepts |
| --- | --- | --- |
| P0 Plan | `deliver/p0-plan.toml` | This directive, the roadmap, and the spec set exist and name `RUNG-PROD-001` |
| P1 Identity | `deliver/p1-identity.toml` | Workspace description and repository URL, member inheritance, comparison, distribution prohibition |
| P2 Contract | `deliver/p2-contract.toml` | `schema_version` 1 JSON Schemas and fixtures |
| P3 Pilot | `deliver/p3-pilot.toml` | `production_pilot_four_transcripts` passes |
| P4 Release | `deliver.toml` | File contracts plus fmt, clippy, full test, doc, audit, and deny |

Run a phase spec from the repository root:

```sh
deliver --spec deliver/p0-plan.toml --strict
```

The root spec repeats the file contracts so a single command is sufficient for release. CI installs deliver from the pinned revision above, installs `cargo-audit` and `cargo-deny`, and runs the root spec. The required status check remains the job name `rust`.

`deliver` reads files and runs commands. It does not commit, push, sign an authorization, or decide a capability. `rung check` remains the authority on protected loss.

## Update path

[Theosis](https://github.com/elci-group/theosis) is the updater for an installed `rung` binary. It reads a literal `A.B.C` from the first `[package]` table in the root `Cargo.toml`, then asks `baby` to install. This repository keeps that literal on package `rung-dist` (`publish = false`) equal to `[workspace.package].version` and to `VERSION`. `.baby.toml` is the recipe theosis passes to baby, and it builds `--bin rung -p rung`. Theosis does not decide a capability. Exit `10` from `theosis check` means the installed binary is newer than the remote and must not be overwritten.

## Standing prohibitions

1. `rung-model` stays free of CLI and Git. `check`, `explain`, and `scan` stay free of models, network calls, and semantic inference.
2. `scan` does not protect. Promotion is `rung protect`.
3. Symlink rejection stays, including Git mode `120000` and `is_symlink()` on the worktree. Audit paths stay mode `0700` / `0600`, with `O_NOFOLLOW` on Linux.
4. The candidate digest excludes `.rung/authorizations/` and `.rung/audit/`.
5. `ed25519-dalek`, `git2`, `sha2`, `serde`, and `tracing` stay while they implement signatures, observation, digests, and reports. `cargo audit` on `Cargo.lock` is the vulnerability evidence. Vendored libgit2 stays off.
6. Do not publish this workspace. crates.io already has `rung` 0.2.0, `rung-cli` 1.0.0, and `rung-core` 1.0.0, owned by other projects. Checked 2026-10-05.
7. Do not plant compliance metadata. Do not commit private keys, an actuating kaptaind config, or analyzer state.
8. Exit codes `0`–`5` stay as documented in the README. Version stays `0.1.0` for this program.

## Out of this program

These remain open and are not production-readiness failures:

- A design-partner repository other than `elci-group/rung`.
- Enabling `enforce_admins` on `main`. That waits until a second maintainer can approve the author's pull requests.
- An isopod PASS that depends on collector-written metadata booleans.
- A crates.io release under a new, non-colliding name. That needs a separate naming decision.

## Control

Successor directives cite `RUNG-PROD-001`. Replacing the root spec or the pinned deliver revision requires a change to this file in the same commit as the spec.
