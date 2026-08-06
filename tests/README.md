# NEXUS Test Strategy

## Layers

- **Unit tests**: shared types, policy decisions, scoring, parsing, and capability classification.
- **Platform tests**: Linux and macOS-specific collectors run only on matching hosts.
- **Integration tests**: end-to-end observation and reporting flows.
- **Security tests**: verify that unsupported actions fail closed and that no fake data is emitted.

## Initial acceptance criteria

- Workspace builds cleanly once the Rust toolchain is available.
- Platform abstraction compiles on Linux and macOS targets.
- Unsupported features are surfaced explicitly.
- No module claims to observe a capability it does not actually implement.
