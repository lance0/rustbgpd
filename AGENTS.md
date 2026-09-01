# Repository guidance

This file records repository-wide expectations for contributors and coding tools. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, command details, commit conventions, and the
project structure. Read the nearest crate documentation and tests before changing a subsystem.

## Establish the current behavior

- Treat issues, roadmaps, and review notes as statements of intent. Confirm the current code,
  tests, and published documentation before deciding what remains to change.
- Trace the relevant callers and data flow before editing a shared function. Fix the cause at the
  narrowest shared boundary instead of patching one observed path.
- Reuse existing types, helpers, and test harnesses. Prefer the standard library or an existing
  workspace dependency before adding another dependency.
- Use a direct implementation until a second proven use requires an abstraction or configuration
  point.
- Keep changes focused, but include the tests and documentation required to make the behavior
  complete. Do not add speculative extension points or unrelated cleanup.

## Preserve compatibility

Configuration, command-line output, metrics, log events, RPCs, protocol buffers, public Rust APIs,
and wire behavior are compatibility surfaces.

- Identify affected consumers before changing a compatibility surface.
- Update tests, examples, reference documentation, changelogs, and upgrade notes when observable
  behavior changes.
- For wire-format changes, test both accepted and rejected input. An additive Rust API change can
  still change decoder behavior.
- Run the stable-surface and generated-fixture checks when changing versioned RPC contracts. Do not
  rewrite an expected fixture to hide an unintended compatibility change.
- Describe limitations and unsupported behavior directly. Remove or narrow a limitation only when
  code and tests establish the new boundary.

## Follow the Rust conventions

- Use the workspace Rust version and edition declared in `Cargo.toml`.
- Add dependencies through the workspace dependency table when they are shared by workspace crates.
- Prefer explicit error propagation over panics in runtime paths and code that handles external
  input. Keep assertions for internal invariants that cannot be recovered from safely.
- Every crate denies unsafe code. Preserve the reviewed, documented exceptions; any allowed lint
  requires the reason expected by `scripts/check-clippy-reasons.py`.
- Match existing error types, tracing fields, and ownership patterns in the affected crate.
- Add a regression test for each non-trivial bug fix. Include boundary and negative cases for
  parsers, validators, and protocol state changes.

## Run proportionate checks

Start with the smallest test that exercises the change. Expand validation when the edited surface
is shared or user-visible.

- Run `cargo fmt --all -- --check` for Rust changes.
- Run focused package or test targets while iterating.
- Run `just gate` as the broad local baseline before submitting a substantive change.
- Run `just gate-rib` after changing feature-gated RIB, transport, API, or benchmark internals.
- Run `just gate-deps` after changing the standalone scale harnesses or their separate lockfile.
- Run `just gate-contract` after changing Criterion benchmark code or its shared dependencies.
- Run a checker's companion tests before relying on that checker after changing it.

Hosted continuous integration covers additional platforms, toolchains, contracts, and privileged
tests. Check the applicable workflow when local prerequisites are unavailable. Report what ran and
what did not; do not describe a pending or skipped check as successful.

## Keep documentation and evidence truthful

- Write public documentation in neutral project voice. Do not add private tracker identifiers,
  machine-specific paths, tool attribution, or internal process commentary.
- Preserve dated performance receipts, architecture decision records, soak reports, and postmortems
  as historical evidence. Do not edit an old record to describe the current system.
- Scope performance and comparison claims to the measured shape, version, and receipt. Flag stale
  claims instead of deriving replacement numbers during unrelated work.
- Keep raw artifacts that support a published finding under `docs/artifacts/` and reference them by
  repository-relative path.
- Use primary sources and pinned versions for interoperability and comparison claims. Apply the same
  standard to claims about rustbgpd.

## Review the complete change

- Inspect the full diff, including generated files and lockfiles, before considering work complete.
- Preserve unrelated worktree changes. Do not rewrite or discard files outside the requested scope.
- Confirm new files are tracked and generated outputs match their source inputs.
- Summarize the behavior change, compatibility impact, and checks performed. State remaining
  uncertainty plainly.
- Keep commit messages and public contribution text focused on the project change. Do not add
  attribution or boilerplate for the tool used to produce it.

Add nested `AGENTS.md` files only when a directory has stable, non-obvious rules that differ from
this root guidance. Keep those rules close to the code they govern and avoid repeating this file.
