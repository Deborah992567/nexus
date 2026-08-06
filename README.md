# NEXUS

Phase 0 workspace scaffold for the NEXUS system observability stack.

## Commands

- `nexus status` — structured system snapshot
- `nexus health` — human-readable health summary

## Design notes

- Metrics come from real OS sources.
- Linux uses `/proc`, `statvfs`, and passwd lookups.
- macOS code is gated behind `cfg(target_os = "macos")` and uses native APIs.
- Unsupported features return `PlatformLimited` instead of being faked.
