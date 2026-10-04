# Contributing

Keep the model free of CLI and Git dependencies. Put deterministic observation,
comparison, policy, and signature verification in `rung-core`. The CLI should
only parse arguments, call the core, and render its decision.

Run before submitting changes:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

Add an integration fixture for changes to baseline selection, governance,
authorization, or exit semantics. Never commit a private signing key.

