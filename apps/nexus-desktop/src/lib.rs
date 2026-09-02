//! NEXUS Desktop — a genuine terminal dashboard.
//!
//! This is not a fake GUI. It renders real system facts (collected via
//! `nexus-api`) into a terminal, with pure, unit-testable formatting logic
//! kept separate from the rendering entry point.

use nexus_core::Snapshot;

/// Render an ASCII progress/usage bar of a given width (in characters).
/// `value` is clamped to [0,100]. Returns the in-bar segment text.
pub fn usage_bar(percent: f64, width: usize) -> String {
    let p = percent.clamp(0.0, 100.0);
    let filled = ((p / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);
    format!("[{}{}] {:5.1}%", "#".repeat(filled), ".".repeat(empty), p)
}

/// Render the top-N processes by CPU into lines.
pub fn top_process_lines(snapshot: &Snapshot, n: usize) -> Vec<String> {
    let mut procs: Vec<_> = snapshot.processes.iter().collect();
    procs.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    let mut out = Vec::new();
    for p in procs.iter().take(n) {
        out.push(format!(
            "{:>7}  {:<24} {:6.1}% {:>10}",
            p.pid,
            truncate(&p.name, 24),
            p.cpu_percent,
            nexus_process::format_bytes(p.rss_bytes)
        ));
    }
    out
}

/// Collect a list of "want attention" issues into short lines.
pub fn issue_lines(snapshot: &Snapshot) -> Vec<String> {
    let anomalies = nexus_process::detect_anomalies(&snapshot.processes);
    if anomalies.is_empty() {
        return vec!["No anomalies detected.".to_string()];
    }
    anomalies
        .iter()
        .map(|a| format!("{}: {}", a.name, a.description))
        .collect()
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Compose a single, complete dashboard frame as a string.
pub fn render_frame(snapshot: &Snapshot) -> String {
    let mut lines = Vec::new();
    lines.push(format!(" NEXUS — {} ", snapshot.platform));
    lines.push("─────────────────────────────────────────────".to_string());
    lines.push(format!(" CPU    {}", usage_bar(snapshot.cpu.usage_percent, 24)));
    let mem_pct = if snapshot.memory.total_bytes > 0 {
        snapshot.memory.used_bytes as f64 / snapshot.memory.total_bytes as f64 * 100.0
    } else {
        0.0
    };
    lines.push(format!(" MEM    {}", usage_bar(mem_pct, 24)));
    lines.push(format!(
        " DISK   {} used / {}",
        nexus_process::format_bytes(snapshot.disks.iter().map(|d| d.used_bytes).sum::<u64>()),
        nexus_process::format_bytes(snapshot.disks.iter().map(|d| d.total_bytes).sum::<u64>())
    ));
    lines.push(format!(" PROC   {}", snapshot.processes.len()));
    lines.push("─────────────────────────────────────────────".to_string());
    lines.push(" TOP PROCESSES (by CPU)".to_string());
    for l in top_process_lines(snapshot, 8) {
        lines.push(format!("   {l}"));
    }
    lines.push("─────────────────────────────────────────────".to_string());
    lines.push(" ATTENTION".to_string());
    for l in issue_lines(snapshot) {
        lines.push(format!("   {l}"));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::{CpuSnapshot, DiskSnapshot, MemorySnapshot, ProcessSnapshot};

    fn snap() -> Snapshot {
        Snapshot {
            platform: "test".into(),
            uptime_seconds: 0,
            cpu: CpuSnapshot { usage_percent: 65.0, cores: 8 },
            memory: MemorySnapshot { total_bytes: 16_000_000_000, available_bytes: 6_000_000_000, used_bytes: 10_000_000_000 },
            disks: vec![DiskSnapshot { mount_point: "/".into(), fs_type: "apfs".into(), total_bytes: 500_000_000_000, available_bytes: 100_000_000_000, used_bytes: 400_000_000_000, usage_percent: 80.0 }],
            processes: vec![
                ProcessSnapshot { pid: 100, ppid: 1, name: "alpha".into(), user: "u".into(), status: "running".into(), cpu_percent: 90.0, rss_bytes: 1_000_000, vmsize_bytes: 0, runtime_seconds: 0, start_time_ticks: 0, threads: 1, cmdline: vec![], exe_path: None, fd_count: None },
                ProcessSnapshot { pid: 200, ppid: 1, name: "beta".into(), user: "u".into(), status: "running".into(), cpu_percent: 10.0, rss_bytes: 500_000, vmsize_bytes: 0, runtime_seconds: 0, start_time_ticks: 0, threads: 1, cmdline: vec![], exe_path: None, fd_count: None },
            ],
        }
    }

    #[test]
    fn usage_bar_clamps_and_formats() {
        assert!(usage_bar(0.0, 10).contains("0.0%"));
        assert!(usage_bar(150.0, 10).contains("100.0%"));
        let b = usage_bar(50.0, 10);
        assert!(b.starts_with('['));
    }

    #[test]
    fn top_processes_sorted_by_cpu_desc() {
        let lines = top_process_lines(&snap(), 10);
        let first = lines.first().unwrap();
        assert!(first.contains("alpha"));
    }

    #[test]
    fn truncate_ellipsizes_long_names() {
        assert_eq!(truncate("x", 1), "x");
        assert!(truncate("a really long process name here", 12).ends_with('…'));
    }

    #[test]
    fn render_frame_includes_cpu_and_mem() {
        let frame = render_frame(&snap());
        assert!(frame.contains("CPU"));
        assert!(frame.contains("MEM"));
        assert!(frame.contains("TOP PROCESSES"));
    }
}
