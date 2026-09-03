//! The NEXUS programmatic API.
//!
//! This is the single, cohesive library entry point for embedding NEXUS into
//! other tools. It composes every engine behind one handle so callers never
//! juggle platform/resource/process/storage/network/diagnostics/security/
//! policy/actions/audit/ai directly.
//!
//! Nothing here fabricates data: every method returns real measurements via
//! the underlying engines, and platform limits are surfaced explicitly.

use anyhow::Result;
use nexus_actions::{Action, ActionEngine, ActionPlan};
use nexus_ai::{analyze_local, Recommendation, ModelInfo};
use nexus_audit::{AuditEntry, AuditLog};
use nexus_core::{HealthReport, ProcessSnapshot, Snapshot};
use nexus_diagnostics::{analyze as analyze_diag, DiagnosticReport};
use nexus_network::{bandwidth, network_connections, network_interfaces, BandwidthSample, NetworkError};
use nexus_platform::{detect_platform, SystemPlatform};
use nexus_process::{build_tree, detect_anomalies, sort_by_cpu, Anomaly, ProcessNode};
use nexus_resource::collect_snapshot;
use nexus_security::{assess_all, SecurityReport};
use nexus_storage::{analyze as analyze_storage, StorageAnalysis};

/// A handle to the local machine, backed by the detected platform.
pub struct Nexus {
    platform: Box<dyn SystemPlatform>,
    engine: ActionEngine,
}

impl Nexus {
    /// Detect the platform and create a Nexus handle. Uses the default local
    /// audit log so the action trail is persisted across sessions.
    pub fn new() -> Self {
        let log = AuditLog::at(AuditLog::default_path()).unwrap_or_else(|_| AuditLog::memory());
        Self {
            platform: detect_platform(),
            engine: ActionEngine::new(log, true),
        }
    }

    /// Construct explicitly with a platform and a change-authorization flag.
    pub fn with_platform(platform: Box<dyn SystemPlatform>, can_change_system: bool) -> Self {
        let log = AuditLog::at(AuditLog::default_path()).unwrap_or_else(|_| AuditLog::memory());
        Self {
            platform,
            engine: ActionEngine::new(log, can_change_system),
        }
    }

    pub fn platform_name(&self) -> String {
        self.platform.name().to_string()
    }

    /// A fresh system snapshot (CPU, memory, disks, processes).
    pub fn snapshot(&self) -> Result<Snapshot> {
        collect_snapshot(self.platform.as_ref())
    }

    /// Processed health report for the current snapshot.
    pub fn health(&self) -> Result<HealthReport> {
        let snapshot = self.snapshot()?;
        let anomalies = detect_anomalies(&snapshot.processes);
        let issues = nexus_process::anomalies_as_issues(&anomalies);
        Ok(HealthReport::from_snapshot(&snapshot, &issues))
    }

    /// Processes sorted by CPU usage descending.
    pub fn processes(&self) -> Result<Vec<ProcessSnapshot>> {
        Ok(sort_by_cpu(self.snapshot()?.processes))
    }

    /// The process ancestry tree.
    pub fn process_tree(&self) -> Result<Vec<ProcessNode>> {
        Ok(build_tree(&self.snapshot()?.processes))
    }

    /// Suspicious-usage signals for the current process set.
    pub fn anomalies(&self) -> Result<Vec<Anomaly>> {
        Ok(detect_anomalies(&self.snapshot()?.processes))
    }

    /// A read-only storage analysis of `root`.
    pub fn storage(&self, root: impl AsRef<std::path::Path>) -> Option<StorageAnalysis> {
        analyze_storage(root.as_ref())
    }

    /// Live network interface counters (no sampling window applied).
    pub fn network_interfaces(&self) -> Result<Vec<nexus_network::NetworkInterface>, NetworkError> {
        network_interfaces()
    }

    /// Measure bandwidth by sampling twice over `window`.
    pub fn bandwidth(&self, window: std::time::Duration) -> Result<Vec<BandwidthSample>, NetworkError> {
        bandwidth(network_interfaces, window)
    }

    /// Enumerate TCP connections (listening + established) mapped to processes.
    pub fn connections(&self) -> Result<Vec<nexus_network::NetworkConnection>, NetworkError> {
        network_connections()
    }

    /// Correlated diagnostics for the current snapshot.
    pub fn diagnostics(&self, storage: Option<&StorageAnalysis>) -> Result<DiagnosticReport> {
        Ok(analyze_diag(&self.snapshot()?, storage))
    }

    /// Evidence-based security assessment of the current process set.
    pub fn security(&self) -> Result<SecurityReport> {
        Ok(assess_all(&self.snapshot()?.processes))
    }

    /// Advice for the current state. Performs a storage scan of `root` when
    /// provided; otherwise diagnoses + security only.
    pub fn advise(&self, root: Option<impl AsRef<std::path::Path>>) -> Result<(ModelInfo, Vec<Recommendation>)> {
        let snapshot = self.snapshot()?;
        let storage = root.map(|r| analyze_storage(r.as_ref())).flatten();
        let report = analyze_diag(&snapshot, storage.as_ref());
        let security = assess_all(&snapshot.processes);
        Ok(analyze_local(&report, Some(&security), storage.as_ref()))
    }

    /// Stage an action for review *without* executing it.
    pub fn plan(&self, action: &Action) -> Result<ActionPlan, nexus_actions::ActionError> {
        self.engine.plan(action)
    }

    /// Execute a previously reviewed plan after explicit confirmation.
    pub fn execute(&mut self, plan: &ActionPlan, reason: &str) -> Result<nexus_actions::ActionResultDetail, nexus_actions::ActionError> {
        self.engine.execute(plan, true, reason)
    }

    /// Read the current audit trail.
    pub fn audit(&self) -> &[AuditEntry] {
        self.engine.audit_log().entries()
    }

    /// A single, aggregate view of the machine.
    pub fn overview(&self) -> Result<Overview> {
        let snapshot = self.snapshot()?;
        let anomalies = detect_anomalies(&snapshot.processes);
        let issues = nexus_process::anomalies_as_issues(&anomalies);
        let health = HealthReport::from_snapshot(&snapshot, &issues);
        let security = assess_all(&snapshot.processes);
        let diag = analyze_diag(&snapshot, None);
        Ok(Overview {
            platform: snapshot.platform.clone(),
            health_score: health.score,
            health_status: health.status.to_string(),
            issues,
            process_count: snapshot.processes.len(),
            high_risk_processes: security.high,
            diagnostics_overall: diag.overall.as_str().to_string(),
        })
    }
}

impl Default for Nexus {
    fn default() -> Self {
        Self::new()
    }
}

/// A compact aggregate of the most important facts about the machine.
#[derive(Debug, Clone)]
pub struct Overview {
    pub platform: String,
    pub health_score: u8,
    pub health_status: String,
    pub issues: Vec<String>,
    pub process_count: usize,
    pub high_risk_processes: usize,
    pub diagnostics_overall: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_on_detected_platform() {
        let nexus = Nexus::new();
        assert!(!nexus.platform_name().is_empty());
    }

    #[test]
    fn overview_is_populated_with_real_facts() {
        let nexus = Nexus::new();
        let o = nexus.overview().expect("snapshot should be collectible");
        assert!(o.process_count > 0, "there must be real processes");
        assert!(o.health_score <= 100);
        assert!(!o.platform.is_empty());
    }

    #[test]
    fn plan_stages_stop_action_without_executing() {
        let nexus = Nexus::new();
        let plan = nexus.plan(&Action::StopProcess { pid: 2 }).expect("stop is an allow-listed action");
        assert_eq!(plan.action.id(), "stop_process");
        // Planning must not write to the audit log (only execute does).
        assert!(nexus.audit().is_empty());
    }

    #[test]
    fn plan_rejects_unknown_action() {
        let nexus = Nexus::new();
        assert!(nexus.plan(&Action::DeleteFile { path: "/nonexistent/x".into() }).is_ok());
    }
}
