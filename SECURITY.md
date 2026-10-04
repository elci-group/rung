# Security

Report suspected bypasses or signing failures privately to the maintainers of
the repository where Rung is deployed. Do not include private signing keys or
credentials in a report or test fixture.

Rung trusts the baseline revision supplied by the caller and the public keys
in that baseline's policy. Protect those Git refs and keep private keys outside
the repository. A candidate's policy edits are not accepted as authority.

Current limitations are documented in the README. In particular, v0.1 uses a
live worktree scan and checks structural presence rather than runtime behaviour.

