//! NEXUS Diagnostics Engine.
//!
//! Phase 6 of the roadmap. This is the reasoning layer that correlates real
//! system telemetry (processes + CPU + memory + disk + network + storage) to
//! determine the likely causes of a problem and answer questions like
//! "Why is my computer slow?".
//!
//! It deliberately does **not** invent facts: every [`Finding`] is derived
//! from concrete evidence in the supplied [`Snapshot`] (and, optionally, a
//! [`StorageAnalysis`]). The AI/explanation layer above this consumes the
//! findings; it must never fabricate values.

use nexus_core::Snapshot;
use nexus_storage::StorageAnalysis;

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// Which subsystem a finding relates to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Cpu,
    Memory,
    Disk,
    Network,
    Process,
    Overall,
}

/// A single correlated diagnosis with its supporting evidence.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<String>,
    /// A concrete, safe next step NEXUS could offer. Never destructive on
    /// its own; it is a recommendation to present to the user.
    pub suggested_action: String,
}

/// The aggregated diagnostic result for a snapshot.
#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    pub platform: String,
    pub overall: Severity,
    pub findings: Vec<Finding>,
}

/// Thresholds used by the correlation rules.
pub const CPU_HIGH: f64 = 80.0;
pub const MEM_LOW_RATIO: f64 = 0.10;
pub const DISK_FULL_PERCENT: f64 = 90.0;

/// Analyze a system snapshot (plus optional storage analysis) and produce a
/// correlated diagnostic report.
pub fn analyze(snapshot: &Snapshot, storage: Option<&StorageAnalysis>) -> DiagnosticReport {
    let mut findings = Vec::new();

    // ---- CPU ----
    if snapshot.cpu.usage_percent > CPU_HIGH {
        // Correlate: which process is consuming most CPU?
        let hot = snapshot
            .processes
            .iter()
            .max_by(|a, b| a.cpu_percent.partial_cmp(&b.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
        if let Some(p) = hot {
            findings.push(Finding {
                severity: Severity::Warning,
                category: Category::Cpu,
                title: "High CPU utilization".into(),
                explanation: format!(
                    "CPU is at {:.1}%. The process using the most CPU is {} ({}), at {:.1}%.",
                    snapshot.cpu.usage_percent, p.name, p.pid, p.cpu_percent
                ),
                evidence: vec![
                    format!("cpu_usage_percent={:.2}", snapshot.cpu.usage_percent),
                    format!("top_process={} pid={} cpu={:.2}", p.name, p.pid, p.cpu_percent),
                ],
                suggested_action: format!(
                    "Investigate whether {} is expected to be busy; if not, consider stopping it.",
                    p.name
                ),
            });
        } else {
            findings.push(Finding {
                severity: Severity::Warning,
                category: Category::Cpu,
                title: "High CPU utilization".into(),
                explanation: format!("CPU is at {:.1}% but no heavy process was found in the sample.", snapshot.cpu.usage_percent),
                evidence: vec![format!("cpu_usage_percent={:.2}", snapshot.cpu.usage_percent)],
                suggested_action: "Re-sample briefly to catch the source of the load.".into(),
            });
        }
    }

    // ---- Memory ----
    let avail_ratio = snapshot
        .memory
        .available_bytes as f64
        / snapshot.memory.total_bytes.max(1) as f64;
    if avail_ratio < MEM_LOW_RATIO {
        // Correlate: which processes hold the most resident memory?
        let mut procs: Vec<&nexus_core::ProcessSnapshot> = snapshot.processes.iter().collect();
        procs.sort_by(|a, b| b.rss_bytes.cmp(&a.rss_bytes));
        let top: Vec<String> = procs
            .iter()
            .take(3)
            .map(|p| format!("{} ({}) ~{:.1} MB", p.name, p.pid, p.rss_bytes as f64 / 1024.0 / 1024.0))
            .collect();
        findings.push(Finding {
            severity: Severity::Critical,
            category: Category::Memory,
            title: "Low available memory".into(),
            explanation: format!(
                "Only {:.1}% of memory is available. The largest consumers are: {}.",
                avail_ratio * 100.0,
                top.join(", ")
            ),
            evidence: vec![
                format!("available_bytes={}", snapshot.memory.available_bytes),
                format!("total_bytes={}", snapshot.memory.total_bytes),
                format!("top_rss=[{}]", top.join(", ")),
            ],
            suggested_action: "Consider closing or suspending the largest memory consumers.".into(),
        });
    }

    // ---- Disk ----
    for disk in &snapshot.disks {
        if disk.usage_percent > DISK_FULL_PERCENT {
            let hint = storage.map(|s| {
                format!(
                    "Storage analysis found ~{} of safely reclaimable space.",
                    nexus_storage::format_bytes(s.reclaimable_bytes)
                )
            });
            findings.push(Finding {
                severity: Severity::Critical,
                category: Category::Disk,
                title: format!("Disk {} is nearly full", disk.mount_point),
                explanation: format!(
                    "Disk {} is {:.1}% full ({} used). {}",
                    disk.mount_point,
                    disk.usage_percent,
                    nexus_storage::format_bytes(disk.used_bytes),
                    hint.unwrap_or_default()
                ),
                evidence: vec![
                    format!("mount={} used_percent={:.2}", disk.mount_point, disk.usage_percent),
                    format!("total={} used={}", disk.total_bytes, disk.used_bytes),
                ],
                suggested_action: "Run 'nexus storage' to review safe cleanup candidates.".into(),
            });
        }
    }

    // ---- Overall ----
    let overall = if findings.iter().any(|f| f.severity == Severity::Critical) {
        Severity::Critical
    } else if findings.iter().any(|f| f.severity == Severity::Warning) {
        Severity::Warning
    } else {
        Severity::Info
    };

    if findings.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            category: Category::Overall,
            title: "System appears healthy".into(),
            explanation: "No critical or warning-level conditions were detected across CPU, memory, or disk.".into(),
            evidence: vec![format!("cpu={:.2}", snapshot.cpu.usage_percent)],
            suggested_action: "No action needed.".into(),
        });
    }

    DiagnosticReport {
        platform: snapshot.platform.clone(),
        overall,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::{CpuSnapshot, DiskSnapshot, MemorySnapshot, ProcessSnapshot};

    fn snapshot(cpu: f64, avail: u64, total: u64, disks: Vec<DiskSnapshot>) -> Snapshot {
        Snapshot {
            platform: "macos".into(),
            uptime_seconds: 100,
            cpu: CpuSnapshot { usage_percent: cpu, cores: 8 },
            memory: MemorySnapshot { total_bytes: total, available_bytes: avail, used_bytes: total.saturating_sub(avail) },
            disks,
            processes: vec![ProcessSnapshot {
                pid: 7, ppid: 1, name: "worker".into(), user: "u".into(), status: "R".into(),
                cpu_percent: 90.0, rss_bytes: 500 * 1024 * 1024, vmsize_bytes: 0,
                runtime_seconds: 10, start_time_ticks: 0, threads: 1, cmdline: vec![], exe_path: None, fd_count: None,
            }],
        }
    }

    #[test]
    fn flags_high_cpu_with_correlation() {
        let s = snapshot(94.0, 500 * 1024 * 1024, 100 * 1024 * 1024 * 1024, vec![]);
        let report = analyze(&s, None);
        let cpu = report.findings.iter().find(|f| f.category == Category::Cpu).unwrap();
        assert_eq!(cpu.severity, Severity::Warning);
        assert!(cpu.explanation.contains("worker"));
    }

    #[test]
    fn flags_low_memory_as_critical() {
        let s = snapshot(10.0, 1, 100, vec![]);
        let report = analyze(&s, None);
        assert!(report.findings.iter().any(|f| f.category == Category::Memory && f.severity == Severity::Critical));
        assert_eq!(report.overall, Severity::Critical);
    }

    #[test]
    fn flags_disk_full_and_uses_storage_hint() {
        let s = snapshot(10.0, 50, 100, vec![DiskSnapshot {
            mount_point: "/".into(), fs_type: "apfs".into(),
            total_bytes: 100, available_bytes: 2, used_bytes: 98, usage_percent: 98.0,
        }]);
        let report = analyze(&s, None);
        assert!(report.findings.iter().any(|f| f.category == Category::Disk && f.severity == Severity::Critical));
    }

    #[test]
    fn reports_healthy_when_nothing_wrong() {
        let s = snapshot(10.0, 50, 100, vec![]);
        let report = analyze(&s, None);
        assert_eq!(report.overall, Severity::Info);
        assert!(report.findings.iter().any(|f| f.title == "System appears healthy"));
    }
}
