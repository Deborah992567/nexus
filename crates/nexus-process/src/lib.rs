use nexus_core::ProcessSnapshot;
use std::cmp::Ordering;
use std::collections::HashMap;
use thiserror::Error;

pub const CPU_HIGH_THRESHOLD: f64 = 20.0;
pub const RSS_HIGH_THRESHOLD: u64 = 500 * 1024 * 1024;
pub const INACTIVE_DURATION_THRESHOLD: u64 = 2 * 60 * 60;

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("process {0} not found")]
    NotFound(i32),
    #[error("permission denied for process {0}")]
    PermissionDenied(i32),
    #[error("invalid process tree")]
    InvalidTree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    HighCpu,
    HighMemory,
    SleepingWithHighMemory,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    pub pid: i32,
    pub name: String,
    pub kind: AnomalyKind,
    pub description: String,
    pub potential_recovery_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessNode {
    pub pid: i32,
    pub ppid: i32,
    pub name: String,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub children: Vec<ProcessNode>,
}

pub fn sort_by_cpu(mut processes: Vec<ProcessSnapshot>) -> Vec<ProcessSnapshot> {
    processes.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(Ordering::Equal)
    });
    processes
}

pub fn build_tree(processes: &[ProcessSnapshot]) -> Vec<ProcessNode> {
    let mut children: HashMap<i32, Vec<&ProcessSnapshot>> = HashMap::new();
    let mut by_pid: HashMap<i32, &ProcessSnapshot> = HashMap::new();

    for process in processes {
        by_pid.insert(process.pid, process);
        children.entry(process.ppid).or_default().push(process);
    }

    for node_children in children.values_mut() {
        node_children.sort_by(|a, b| a.pid.cmp(&b.pid));
    }

    let mut roots: Vec<&ProcessSnapshot> = processes
        .iter()
        .filter(|p| p.ppid == 0 || !by_pid.contains_key(&p.ppid))
        .collect();
    roots.sort_by(|a, b| a.pid.cmp(&b.pid));

    roots
        .into_iter()
        .map(|process| build_node(process, &children))
        .collect()
}

fn build_node(
    process: &ProcessSnapshot,
    children: &HashMap<i32, Vec<&ProcessSnapshot>>,
) -> ProcessNode {
    let kids = children
        .get(&process.pid)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|child| build_node(child, children))
        .collect();

    ProcessNode {
        pid: process.pid,
        ppid: process.ppid,
        name: process.name.clone(),
        cpu_percent: process.cpu_percent,
        rss_bytes: process.rss_bytes,
        children: kids,
    }
}

pub fn detect_anomalies(processes: &[ProcessSnapshot]) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    for process in processes {
        if process.cpu_percent > CPU_HIGH_THRESHOLD {
            anomalies.push(Anomaly {
                pid: process.pid,
                name: process.name.clone(),
                kind: AnomalyKind::HighCpu,
                description: format!(
                    "{} is using {:.1}% CPU, which is above the sustained threshold.",
                    pretty_name(&process.name),
                    process.cpu_percent
                ),
                potential_recovery_bytes: None,
            });
        }

        if process.rss_bytes > RSS_HIGH_THRESHOLD {
            anomalies.push(Anomaly {
                pid: process.pid,
                name: process.name.clone(),
                kind: AnomalyKind::HighMemory,
                description: format!(
                    "{} is using approximately {} of memory.",
                    pretty_name(&process.name),
                    format_bytes(process.rss_bytes)
                ),
                potential_recovery_bytes: Some(process.rss_bytes.saturating_sub(RSS_HIGH_THRESHOLD)),
            });
        }

        if process.status.starts_with('S') && process.runtime_seconds > INACTIVE_DURATION_THRESHOLD && process.rss_bytes > RSS_HIGH_THRESHOLD {
            let recovery = process.rss_bytes.saturating_sub(RSS_HIGH_THRESHOLD);
            anomalies.push(Anomaly {
                pid: process.pid,
                name: process.name.clone(),
                kind: AnomalyKind::SleepingWithHighMemory,
                description: format!(
                    "{} has been sleeping for more than 2 hours while still holding {} of memory. Potential memory recovery: {}.",
                    pretty_name(&process.name),
                    format_bytes(process.rss_bytes),
                    format_bytes(recovery)
                ),
                potential_recovery_bytes: Some(recovery),
            });
        }
    }

    anomalies
}

pub fn anomalies_as_issues(anomalies: &[Anomaly]) -> Vec<String> {
    anomalies
        .iter()
        .map(|anomaly| format!("PID {}: {}", anomaly.pid, anomaly.description))
        .collect()
}

pub fn process_summary(process: &ProcessSnapshot) -> String {
    format!(
        "{:>6} {:<24} {:>6.1}% {:>8} {:<6} {:>7}s",
        process.pid,
        truncate(&process.name, 24),
        process.cpu_percent,
        format_mib(process.rss_bytes),
        process.status,
        process.runtime_seconds,
    )
}

fn pretty_name(name: &str) -> String {
    if name.is_empty() {
        "Process".to_string()
    } else {
        let mut chars = name.chars();
        match chars.next() {
            Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            None => "Process".to_string(),
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out = s.chars().take(max.saturating_sub(1)).collect::<String>();
        out.push('…');
        out
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MB", bytes as f64 / MIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_mib(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: i32, ppid: i32, name: &str, cpu: f64, rss: u64) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            ppid,
            name: name.into(),
            user: "u".into(),
            status: "R".into(),
            cpu_percent: cpu,
            rss_bytes: rss,
            vmsize_bytes: rss,
            runtime_seconds: 100,
            start_time_ticks: 0,
            threads: 1,
            cmdline: vec![],
            exe_path: None,
            fd_count: None,
        }
    }

    #[test]
    fn sorts_descending() {
        let out = sort_by_cpu(vec![proc(1, 0, "a", 1.0, 1), proc(2, 0, "b", 5.0, 1)]);
        assert_eq!(out[0].pid, 2);
    }

    #[test]
    fn detects_high_memory_and_sleeping() {
        let p = ProcessSnapshot {
            status: "S".into(),
            runtime_seconds: INACTIVE_DURATION_THRESHOLD + 1,
            ..proc(1, 0, "chrome", 1.0, RSS_HIGH_THRESHOLD + 1)
        };
        let anomalies = detect_anomalies(&[p]);
        assert!(anomalies.iter().any(|a| matches!(a.kind, AnomalyKind::HighMemory)));
        assert!(anomalies.iter().any(|a| matches!(a.kind, AnomalyKind::SleepingWithHighMemory)));
    }

    #[test]
    fn builds_tree() {
        let tree = build_tree(&[
            proc(1, 0, "init", 0.0, 1),
            proc(2, 1, "shell", 0.0, 1),
            proc(3, 2, "child", 0.0, 1),
        ]);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].children[0].children[0].pid, 3);
    }
}
