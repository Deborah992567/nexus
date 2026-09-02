# NEXUS

NEXUS is an OS observability, diagnostics, and guardrail stack written in
Rust. It observes real system facts, reasons about them, and can perform
policy-checked, user-confirmed actions — all with an honest attitude toward
its own limits. It is not an OS replacement; it is a platform that lives on
top of your OS.

**Core principle: no fake features.** Every value you see comes from a real
system source. Anything NEXUS cannot genuinely do is reported as
`PLATFORM-LIMITED` / NOT IMPLEMENTED rather than fabricated.

## Status

All roadmap phases through Phase 10 are implemented on macOS (Linux targets
are wired through the same `SystemPlatform` abstraction):

| Phase | Focus | Status |
|-------|-------|--------|
| 0 | Foundation (workspace, OS abstraction, docs, test strategy) | ✅ |
| 1 | System Observer (CPU, memory, disk, uptime, processes, health) | ✅ |
| 2 | Process Intelligence (tree, inspect, resource attribution, anomalies) | ✅ |
| 3 | Storage Intelligence (large files, cache classify, reclaim) | ✅ |
| 4 | Network Intelligence (interfaces, live bandwidth) | ✅ |
| 5 | Security Engine (risk scoring, evidence alerts) + audit | ✅ |
| 6 | Diagnostics Engine (correlation / reasoning) | ✅ |
| 7 | Action Engine (risk, permission, confirmation, execute, verify, audit) | ✅ |
| 8 | AI (local-first, deterministic, honest not-LLM advisory) | ✅ |
| 9 | Sandbox (genuine OS-level sandboxing via seatbelt) | ✅ |
| 10 | Desktop Experience (Simple/Developer modes + terminal dashboard) | ✅ |

## Layout

- `apps/nexus-cli` — the command-line interface
- `apps/nexus-desktop` — a live terminal dashboard
- `crates/nexus-core` — shared snapshot/health types
- `crates/nexus-platform` — OS abstraction (`SystemPlatform`)
- `crates/nexus-resource` — snapshot collection
- `crates/nexus-process` — process intelligence + anomalies
- `crates/nexus-storage` — storage analysis + classification
- `crates/nexus-network` — interface counters + live bandwidth
- `crates/nexus-diagnostics` — correlated diagnosis
- `crates/nexus-security` — evidence-based risk assessment
- `crates/nexus-policy` — risk classification + permission policy
- `crates/nexus-audit` — JSONL audit journal
- `crates/nexus-actions` — controlled, verified action execution
- `crates/nexus-ai` — deterministic advisory provider layer
- `crates/nexus-sandbox` — OS-level sandboxing (seatbelt)
- `crates/nexus-config` — Simple/Developer mode + persisted settings
- `crates/nexus-api` — programmatic facade composing every engine

## Commands

```
nexus status        JSON snapshot (CPU/mem/disk/processes)
nexus health        summary + issues
nexus processes     top processes (list | inspect <pid> | tree)
nexus storage       storage analysis (default: your home directory)
nexus network       interface counters + live bandwidth
nexus diagnostics   correlated diagnosis of the current snapshot
nexus security      evidence-based process risk assessment
nexus advice        advisory recommendations with evidence
nexus audit         the persisted action journal
nexus act           plan / execute a policy-checked action
nexus sandbox       OS-level sandboxing status + live demo
nexus mode          show/change UI mode (simple | developer)
nexus config        show persisted configuration
```

```
nexus-desktop               live dashboard (honors Simple/Developer mode)
nexus-desktop once          render a single frame
nexus-desktop --simple      force Simple mode for a run
nexus-desktop --developer   force Developer mode for a run
```

## Examples

```sh
cargo run -p nexus-cli -- health
cargo run -p nexus-cli -- security
cargo run -p nexus-cli -- sandbox demo      # proves a write is blocked
cargo run -p nexus-desktop -- once          # render one TUI frame
```

## Testing

```sh
cargo test          # run the whole workspace test-suite
cargo test -p nexus-sandbox   # includes a genuine enforcement assertion
```

Several tests exercise live data (process counts, health scores, bandwidth).
The sandbox test actually enforces a seatbelt profile and confirms a write is
blocked — only on hosts that provide the mechanism.

## Honesty manifest

- Deterministic `nexus-ai` states plainly that it is **not an LLM**.
- `nexus-sandbox` refuses to run (rather than fake success) when the host has
  no sandbox mechanism.
- The audit journal records only actions NEXUS genuinely performed.
- Network connection/port mapping is `PLATFORM-LIMITED` rather than guessed.
