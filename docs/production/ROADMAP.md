# RUNG-PROD-001 roadmap

Program status: closed

Production readiness is defined in `docs/production/DIRECTIVE.md`. A phase closes when its deliver spec exits 0 under `--strict`. The program closes when `deliver --spec deliver.toml --strict` exits 0, and this line then reads `Program status: closed`.

| Phase | Intent | Spec | Exit evidence |
| --- | --- | --- | --- |
| P0 Plan | Freeze the order and the acceptance contracts before product edits | `deliver/p0-plan.toml` | Directive, roadmap, and `deliver/*.toml` name `RUNG-PROD-001` |
| P1 Identity | Make the workspace identifiable and state the publish prohibition | `deliver/p1-identity.toml` | `repository` and `description` in the workspace; members inherit both; README comparison and distribution sections |
| P2 Contract | Pin `schema_version` 1 documents for decision, discovery, and audit records | `deliver/p2-contract.toml` | Schemas and fixtures under `schemas/`; `contracts` tests deserialize them |
| P3 Pilot | Prove the four operator transcripts in one test | `deliver/p3-pilot.toml` | `production_pilot_four_transcripts` passes |
| P4 Release | Run the union gate locally and in the `rust` CI job | `deliver.toml` | fmt, clippy, full tests, doc, `cargo audit`, `cargo deny`, and the file contracts |

## Phase order

P0 is documentation and specs. P1 edits manifest and README text. P2 adds schema files and a contract test. P3 adds one integration test. P4 points GitHub Actions at the root spec and installs deliver from `elci-group/deliver` commit `93a90de52b18e9e0a1dd7e89988d2d055c91cae6`.

No phase bumps `0.1.0`. No phase publishes a crate. No phase changes the allow or deny rule.

## Operator sequence

```sh
deliver --spec deliver/p0-plan.toml --strict
deliver --spec deliver/p1-identity.toml --strict
deliver --spec deliver/p2-contract.toml --strict
deliver --spec deliver/p3-pilot.toml --strict
deliver --spec deliver.toml --strict
```

The last command is the release gate. CI runs that command in the job named `rust`.
