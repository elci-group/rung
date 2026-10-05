# Contributing

Keep the model free of CLI and Git dependencies. Put deterministic observation,
comparison, policy, and signature verification in `rung-core`. The CLI should
only parse arguments, call the core, and render its decision.

Run before submitting changes:

```sh
deliver --spec deliver.toml --strict
```

That command runs `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo doc --workspace --no-deps`, `cargo audit`, and `cargo deny check licenses advisories`. The phase specs under `deliver/` are the planning contracts for `docs/production/ROADMAP.md`.

Add an integration fixture for changes to baseline selection, governance,
authorization, or exit semantics. Never commit a private signing key.

Changes to `main` land through a pull request. Use the pull request template.
One approving review is required, and the `rust` check must pass. Do not
force-push `main`. Leave analyzer and daemon state untracked: `.uni/`,
`.kaptaind/`, `.lwoodz/`, `.crush/`, and generated `lwoodz.toml`, `poka.toml`,
and `traci.toml`.

The enforcement audit trail is `.rung/audit/` in the repository being checked.
Keep its directory at mode `0700` and its files at mode `0600`. Do not commit
private keys into it, and do not replace it with a symlink.

