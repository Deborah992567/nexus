# Testing

NEXUS is a workspace of independent crates plus a couple of thin
applications. Each component ships its own unit tests, and the whole
workspace is verified with a single command.

## Running the tests

```sh
cargo test --workspace
```

This builds every crate and binary and runs all unit tests. The CLI and the
desktop TUI have no end-to-end test harness yet; their behaviour is exercised
manually and covered by the crates they depend on.

## Where the tests live

Each crate keeps its tests at the bottom of `src/lib.rs` in a `#[cfg(test)]`
module, so there is no separate `tests/` tree for the crates. The crates with
meaningful coverage include:

- `nexus-core`: health scoring and model construction from snapshots.
- `nexus-process`: anomaly detection (e.g. high memory, sleeping-with-high-memory)
  and process-tree building.
- `nexus-storage`: path classification, formatting, and the reclaimable-space
  judgment.
- `nexus-security`: per-process risk assessment and signal generation using
  fixed, deterministic fixtures so the tests are stable.
- `nexus-diagnostics`: correlation rules that tie evidence to findings.
- `nexus-sandbox`: profile construction plus a test that genuinely proves
  sandbox-exec blocks file writes when the host supports it.
- `nexus-config`: mode and confirmation-policy persistence against a memory
  backend.
- `nexus-ai`: deterministic advisory generation with evidence and provenance.
- `tests/`: the `tests/README.md` explains the end-to-end expectations for
  each binary.

## Style notes

- Tests must be deterministic — no dependence on wall-clock timing or machine
  state. Engine tests use in-memory fixtures rather than live snapshots.
- Platform-specific behaviour (e.g. the seatbelt sandbox on macOS) is guarded
  with `#[cfg(target_os = ...)]` and enabled-conditionally so tests stay green
  on hosts without the mechanism.
- The project never fakes failure or success: if a subsystem cannot be
  exercised truthfully on the current host, the documented behaviour is to
  report `PLATFORM-LIMITED` rather than pretend otherwise.
