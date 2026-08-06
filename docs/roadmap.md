# NEXUS Roadmap

## Phase 0 — Foundation

Deliverables:
- Rust workspace layout
- OS abstraction plan
- Linux/macOS module boundaries
- documentation
- testing strategy
- no fake features

## Phase 1 — System Observer

Deliver real system facts for:
- CPU
- memory
- disk
- uptime
- processes
- basic health summary

## Phase 2 — Process Intelligence

Add:
- process tree
- process inspection
- resource attribution
- lifecycle information
- suspicious usage signals

## Phase 3 — Storage Intelligence

Add:
- large file detection
- cache classification
- reclaim estimates
- safe cleanup recommendations

## Phase 4 — Network Intelligence

Add:
- connections
- listening ports
- process-to-connection mapping
- bandwidth and DNS facts

## Phase 5 — Security Engine

Add:
- security events
- risk scoring
- evidence-backed alerts
- audit records

## Phase 6 — Diagnostics Engine

Correlate processes, storage, network, logs, and services to explain likely causes.

## Phase 7 — Action Engine

Implement safe actions with:
- risk classification
- permission checks
- user confirmation
- execution
- verification
- audit trail

## Phase 8 — AI

Add local-first AI explanations.

## Phase 9 — Sandbox

Build genuine OS-level sandboxing where supported.

## Phase 10 — Desktop Experience

Deliver Simple Mode and Developer Mode with a polished interface.
