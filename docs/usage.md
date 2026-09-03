# Usage

NEXUS is a command-line observability tool. Everything below reflects the real,
non-faked behaviour of the current build — anything that cannot be measured or
performed truthfully on the host is reported as `PLATFORM-LIMITED` rather than
invented.

## Overview command

Running `nexus` with no arguments shows a snapshot-style overview. The default
presentation follows the configured UI mode:

- `simple` — a friendly plain-language summary (health, CPU, memory, disks).
- `developer` — the full command reference.

Switch modes with `nexus mode simple|developer`.

## The JSON subcommands

Five read-only commands can emit machine-readable output for piping into
scripts or tooling:

| Command                       | Output                                             |
| ----------------------------- | -------------------------------------------------- |
| `nexus status`                | JSON snapshot (CPU / memory / disk / processes)    |
| `nexus health json`           | health score, status, and per-issue details        |
| `nexus processes json`        | process list (sorted by CPU) as a JSON array       |
| `nexus processes csv`         | process list (sorted by CPU) as a CSV document     |
| `nexus storage --top N [dir]` | N largest files found while scanning `dir`         |
| `nexus network json`          | per-interface name/index/cumulative byte counters  |
| `nexus network live`          | continuous per-interface bandwidth readout         |
| `nexus diagnostics json`      | correlated report with findings and evidence       |
| `nexus security json`         | per-process risk assessment and evidence signals   |
| `nexus advice json`           | model info plus recommendations with provenance    |
| `nexus audit json`            | the persisted action journal as a JSON array       |
| `nexus doctor`                | per-subsystem self-check (pass/fail on live data)  |

Every `json` variant quotes and escapes strings, so output is valid JSON that
can be parsed by `jq` or any JSON consumer.

## Capabilities by area

- **Processes** — `nexus processes` (top by CPU), `inspect <pid>`, `tree`, `json`, `csv`.
- **Storage** — `nexus storage --top N [dir]`; read-only, never deletes anything.
- **Network** — `nexus network` (interface counters), `network live`
  (bandwidth), `network json`.
- **Diagnostics** — `nexus diagnostics` correlates CPU/memory/disk signals into
  findings and suggests safe next steps.
- **Security** — `nexus security` lists evidence-based per-process signals
  (temp executables, impersonation, shells spawned by services, etc.).
- **Advisor** — `nexus advice` produces deterministic, evidence-backed
  recommendations note descriptions; **not an LLM**.
- **Actions** — `nexus act plan <action> <target>` then `nexus act
  <action> <target> --yes`. Every executed action is written to the audit log.
- **Sandbox** — `nexus sandbox status|demo` reports on OS-level sandboxing
  support (seatbelt / `sandbox-exec` on macOS).
- **Mode & config** — `nexus mode`, `nexus config` manage the persisted UI
  mode.
- **Self-check** — `nexus doctor` runs every engine against live data and
  exits non-zero if any subsystem fails.
