# Architecture

## Layers

NEXUS is organized as a workspace of focused crates flowing from raw OS data
up to user-facing interfaces.

**Observation**
- `nexus-platform` — OS-specific probes behind the `SystemPlatform` trait
  (sysctl, libproc, `proc_*`, passwd on macOS; `/proc` + `statvfs` on Linux).
- `nexus-resource` — assembles a normalized `Snapshot` (CPU, memory, disks,
  processes, uptime).
- `nexus-process` — process restructuring: CPU ordering, process tree,
  resource attribution, anomaly detection.
- `nexus-network` — interface counters plus two-sample live bandwidth.
- `nexus-storage` — read-only storage analysis, path classification, and
  reclaim estimation.

**Reasoning**
- `nexus-security` — evidence-based per-process risk assessment with
  confidence/weighted signals.
- `nexus-diagnostics` — correlates CPU/memory/disk/process signals into
  explanations with evidence.
- `nexus-ai` — deterministic advisory layer (a provider abstraction whose
  only registered backend is a rule-based `LocalAnalyst`; clearly not an LLM).

**Governance**
- `nexus-policy` — action risk classification and permission decisions.
- `nexus-actions` — the controlled action engine: plan -> permission ->
  confirmation -> execute -> verify -> audit.
- `nexus-audit` — append-only JSONL journal of actions genuinely performed.
- `nexus-sandbox` — OS-level enforcement via seatbelt (`sandbox-exec`),
  refusing to run when the mechanism is absent.

**Experience**
- `nexus-config` — persisted Simple/Developer UI mode and consent settings.
- `nexus-api` — programmatic facade composing every engine behind one handle.
- `nexus-cli` — command-line interface.
- `nexus-desktop` — live terminal dashboard.

## Data flow

```
OS            -> nexus-platform / resource  -> Snapshot
Snapshot      -> nexus-process              -> order / tree / anomalies
Snapshot      -> nexus-network|storage      -> bandwidth / reclaim
Snapshot      -> nexus-diagnostics/security -> findings / assessments
findings      -> nexus-ai                  -> recommendations (with evidence)
request       -> nexus-policy              -> permission + risk
permission    -> nexus-actions             -> execute + verify
execution     -> nexus-audit               -> JSONL journal
```

## Invariants

1. No fabricated metrics. Every value is read from a real OS source.
2. Platform-specific code lives behind `cfg(target_os = ...)` gates and the
   `SystemPlatform` trait.
3. Limited platforms return explicit errors or limited data; never guesses.
4. Health scoring is deterministic and derived from the latest snapshot.
5. Actions only run after permission + confirmation, are verified, and are
   recorded in the audit journal.
6. Sandboxing is only claimed when the host genuinely provides a mechanism.
