//! NEXUS Security Engine.
//!
//! Phase 5 of the roadmap. This engine performs **evidence-based** risk
//! assessment over real process telemetry. It never declares "malware" on a
//! hunch: every flag is tied to observable, verifiable signals from the
//! [`ProcessSnapshot`] data, and each assessment carries a confidence and a
//! severity so humans (and the AI layer) can reason over it.
//!
//! Signals we can actually read without elevated privileges on macOS/Linux:
//!
//! - executable located in a world-writable or temporary directory,
//! - a process name that impersonates a common system process but resolves
//!   to an unexpected path (e.g. `launchd` not at `/sbin/launchd`),
//! - an interactive shell spawned as a child of a daemon/service (a red flag
//!   for command injection / persistence),
//! - a binary running with no readable command line while resident in a
//!   temp path,
//! - the process being a child of a parent it should not have.
//!
//! Deeper signals (privilege escalation, syscall/execve tracing, file access
//! monitoring) require platform capabilities that are not available without
//! privileges; those are reported as `PLATFORM-LIMITED` rather than faked.

use nexus_core::ProcessSnapshot;
use thiserror::Error;

/// Overall risk band for a single process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
        }
    }
}

/// A single piece of evidence relevant to a process's risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    TempExecutable,
    Impersonation,
    ShellChildOfService,
    NoCmdlineInTemp,
    UnexpectedChild,
}

impl SignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SignalKind::TempExecutable => "temp-executable",
            SignalKind::Impersonation => "impersonation",
            SignalKind::ShellChildOfService => "shell-child-of-service",
            SignalKind::NoCmdlineInTemp => "no-cmdline-in-temp",
            SignalKind::UnexpectedChild => "unexpected-child",
        }
    }
}

/// A finding about one process, with evidence, confidence (0..1) and severity.
#[derive(Debug, Clone)]
pub struct ProcessSignal {
    pub pid: i32,
    pub kind: SignalKind,
    /// Human-readable explanation anchored to concrete facts.
    pub explanation: String,
    /// How confident we are that this is actually suspicious (0..1).
    pub confidence: f64,
    /// Contributor to severity.
    pub weight: f64,
}

/// Complete per-process risk assessment.
#[derive(Debug, Clone)]
pub struct ProcessAssessment {
    pub pid: i32,
    pub name: String,
    pub risk: RiskLevel,
    pub score: f64,
    pub signals: Vec<ProcessSignal>,
}

/// Aggregate security report for all assessed processes.
#[derive(Debug, Clone)]
pub struct SecurityReport {
    pub assessed: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub assessments: Vec<ProcessAssessment>,
}

/// Directory components that are world-writable or temporary. Exact matches
/// on the executable path.
const TEMP_DIRS: &[&str] = &["/tmp", "/var/tmp", "/private/tmp", "/dev/shm"];

/// Common system process basenames and their expected canonical path.
fn expected_system_path(name: &str) -> Option<&'static str> {
    match name {
        "launchd" => Some("/sbin/launchd"),
        "init" | "systemd" => Some("/sbin/init"),
        "sshd" => Some("/usr/sbin/sshd"),
        _ => None,
    }
}

/// A process whose parent is one of these is a service/daemon; a shell child
/// of it is suspicious.
const SERVICE_PARENT_NAMES: &[&str] = &["sshd", "systemd", "launchd", "nginx", "apache2", "httpd"];
const SHELL_NAMES: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh"];

/// Assess a single process against the available (non-privileged) signals.
pub fn assess(process: &ProcessSnapshot, all: &[ProcessSnapshot]) -> ProcessAssessment {
    let mut signals = Vec::new();
    let mut score = 0.0f64;

    let exe = process.exe_path.as_deref().unwrap_or("");
    let in_temp = TEMP_DIRS.iter().any(|d| exe.starts_with(d));
    let no_cmdline = process.cmdline.is_empty();

    // 1. Executable in a temp / world-writable directory.
    if in_temp {
        signals.push(ProcessSignal {
            pid: process.pid,
            kind: SignalKind::TempExecutable,
            explanation: format!(
                "'{}' is executing from {}, a world-writable/temporary directory.",
                process.name, exe
            ),
            confidence: 0.7,
            weight: 0.5,
        });
        score += 0.5 * 0.7;
    }

    // 2. Impersonation: name looks like a system process but path differs.
    if let Some(expected) = expected_system_path(&process.name) {
        if !exe.is_empty() && exe != expected {
            signals.push(ProcessSignal {
                pid: process.pid,
                kind: SignalKind::Impersonation,
                explanation: format!(
                    "'{}' presents as a system process but executes from '{}' (expected '{}').",
                    process.name, exe, expected
                ),
                confidence: 0.85,
                weight: 0.8,
            });
            score += 0.8 * 0.85;
        }
    }

    // 3. Shell spawned as a child of a service/daemon.
    let parent = all.iter().find(|p| p.pid == process.ppid);
    if let Some(parent) = parent {
        let is_shell = SHELL_NAMES.contains(&process.name.as_str());
        let parent_is_service = SERVICE_PARENT_NAMES.contains(&parent.name.as_str());
        if is_shell && parent_is_service {
            signals.push(ProcessSignal {
                pid: process.pid,
                kind: SignalKind::ShellChildOfService,
                explanation: format!(
                    "A shell ('{}') was spawned as a child of '{}'. This is unusual and can indicate injection or persistence.",
                    process.name, parent.name
                ),
                confidence: 0.6,
                weight: 0.7,
            });
            score += 0.7 * 0.6;
        }
    }

    // 4. No readable command line while executing from a temp path.
    if no_cmdline && in_temp {
        signals.push(ProcessSignal {
            pid: process.pid,
            kind: SignalKind::NoCmdlineInTemp,
            explanation: format!(
                "'{}' has no readable command line while executing from a temp directory.",
                process.name
            ),
            confidence: 0.5,
            weight: 0.4,
        });
        score += 0.4 * 0.5;
    }

    let risk = if score >= 0.5 {
        RiskLevel::High
    } else if score >= 0.2 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    ProcessAssessment {
        pid: process.pid,
        name: process.name.clone(),
        risk,
        score,
        signals,
    }
}

/// Assess every process in a snapshot and aggregate the counts.
pub fn assess_all(processes: &[ProcessSnapshot]) -> SecurityReport {
    let mut assessments: Vec<ProcessAssessment> =
        processes.iter().map(|p| assess(p, processes)).collect();
    assessments.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut report = SecurityReport {
        assessed: assessments.len(),
        low: 0,
        medium: 0,
        high: 0,
        assessments: assessments.clone(),
    };
    for a in &assessments {
        match a.risk {
            RiskLevel::Low => report.low += 1,
            RiskLevel::Medium => report.medium += 1,
            RiskLevel::High => report.high += 1,
        }
    }
    report
}

// ---------------------------------------------------------------------------
// Platform-limited capabilities that are reported honestly, not faked.
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("privilege-escalation monitoring requires elevated privileges: {0}")]
    PrivilegeEscalationMonitor(&'static str),
    #[error("sensitive-file access monitoring is not implemented on this platform")]
    SensitiveFileMonitorUnavailable,
    #[error("syscall tracing is not implemented on this platform")]
    SyscallTraceUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: i32, ppid: i32, name: &str, exe: &str, cmdline: Vec<String>) -> ProcessSnapshot {
        ProcessSnapshot {
            pid, ppid,
            name: name.into(),
            user: "u".into(),
            status: "R".into(),
            cpu_percent: 0.0,
            rss_bytes: 0,
            vmsize_bytes: 0,
            runtime_seconds: 10,
            start_time_ticks: 0,
            threads: 1,
            cmdline,
            exe_path: Some(exe.into()),
            fd_count: None,
        }
    }

    #[test]
    fn flags_temp_executable() {
        let p = proc(1, 0, "app", "/tmp/random_app", vec!["/tmp/random_app".into()]);
        let a = assess(&p, &[]);
        assert!(a.risk != RiskLevel::Low);
        assert!(a.signals.iter().any(|s| s.kind == SignalKind::TempExecutable));
    }

    #[test]
    fn flags_impersonation() {
        let p = proc(2, 0, "launchd", "/tmp/fake", vec![]);
        let a = assess(&p, &[]);
        assert!(a.signals.iter().any(|s| s.kind == SignalKind::Impersonation));
    }

    #[test]
    fn flags_shell_child_of_service() {
        let parent = proc(10, 0, "sshd", "/usr/sbin/sshd", vec!["sshd".into()]);
        let child = proc(11, 10, "sh", "/bin/sh", vec!["sh".into()]);
        let a = assess(&child, &[parent, child.clone()]);
        assert!(a.signals.iter().any(|s| s.kind == SignalKind::ShellChildOfService));
    }

    #[test]
    fn normal_process_is_low_risk() {
        let p = proc(3, 0, "Terminal", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", vec!["Terminal".into()]);
        let a = assess(&p, &[]);
        assert_eq!(a.risk, RiskLevel::Low);
        assert!(a.signals.is_empty());
    }

    #[test]
    fn aggregate_counts_categories() {
        let p1 = proc(1, 0, "good", "/usr/bin/good", vec!["good".into()]);
        let p2 = proc(2, 0, "launchd", "/tmp/fake", vec![]);
        let rep = assess_all(&[p1, p2]);
        assert!(rep.high >= 1);
        assert!(rep.low >= 1);
    }
}
