# Security

Report suspected bypasses or signing failures privately to the maintainers of
the repository where Rung is deployed. Do not include private signing keys or
credentials in a report or test fixture.

Rung trusts the baseline revision supplied by the caller and the public keys
in that baseline's policy. Protect those Git refs and keep private keys outside
the repository. A candidate's policy edits are not accepted as authority.

Current limitations are documented in the README. The checker reads a live
worktree and checks structural presence rather than runtime behaviour.

Symbolic links are rejected in the candidate worktree and in Git trees
(mode `120000`). Replacing `.rung/audit` or an audit log with a symlink is
also rejected. That control is part of observation on every platform.

`check` and `explain` fail closed when they cannot append
`.rung/audit/decisions.jsonl` and `.rung/audit/access.jsonl`. On Unix those
files are mode `0600` and the directory is mode `0700`. The trail keeps two
generations and deletes the previous generation after 90 days. It records
the action, outcome, baseline revision, candidate digest, and violation ids.
It does not record private keys. `scan` does not write the trail.

`cargo audit` against `Cargo.lock` is the supply-chain vulnerability check.
The production acceptance gate is `deliver --spec deliver.toml --strict`,
which runs `cargo audit` and `cargo deny check licenses advisories` with the
fmt, clippy, test, and doc gates.
Historical advisory counts attached to a crate name are not a finding against
the locked version. `ed25519-dalek`, `git2`, `sha2`, `serde`, and `tracing`
stay in the build: they implement signatures, repository observation, digests,
and decision reports. Vendored libgit2 stays off.

