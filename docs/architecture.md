# Architecture

## Layers

- `nexus-platform`: OS-specific probes and data collection.
- `nexus-resource`: normalized resource snapshot assembly.
- `nexus-process`: process normalization and process-list shaping.
- `nexus-core`: shared types and health evaluation.
- `nexus-cli`: command-line entry point.

## Invariants

1. No fabricated metrics.
2. Platform-specific code must be behind `cfg` gates.
3. Limited platforms return explicit errors or limited data.
4. Health scoring is deterministic and derived from the latest snapshot.
