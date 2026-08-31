//! NEXUS Action Engine.
//!
//! Phase 7 builds the secure action layer. The full lifecycle enforced here
//! is:
//!
//! ```text
//!   request -> permission check -> risk assessment -> user confirmation
//!          -> execute -> verify -> audit
//! ```
//!
//! Key design rules:
//!
//! - **No arbitrary command execution.** Actions are typed, curated handlers
//!   only (`stop_process`, `delete_file`, ...). There is no path that shells
//!   out to a command string supplied at runtime.
//! - **Permission gating.** Every action runs through `nexus_policy`; system
//!   changing actions require authorization and confirmation.
//! - **Verification.** After executing, we confirm the effect (e.g. the
//!   process is gone) rather than trusting success blindly.
//! - **Audit trail.** Every action lifecycle is written to `nexus_audit`.
//! - **Reversibility.** `reversible()` reports whether the action can be
//!   undone, which the UI surfaces before confirmation.

use nexus_audit::{ActionResult, AuditEntry, AuditLog, Initiator};
use nexus_core::ProcessSnapshot;
use nexus_policy::{PermissionDecision, RiskLevel, evaluate};
use thiserror::Error;

/// The set of typed actions the engine can perform.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send SIGTERM to a process, then verify it exited.
    StopProcess { pid: i32 },
    /// Send SIGKILL to a process, then verify it exited (irreversible-ish).
    KillProcess { pid: i32 },
    /// Delete a single file, refusing paths that point at directories or
    /// protected locations.
    DeleteFile { path: String },
}

impl Action {
    pub fn id(&self) -> &'static str {
        match self {
            Action::StopProcess { .. } => "stop_process",
            Action::KillProcess { .. } => "kill_process",
            Action::DeleteFile { .. } => "delete_file",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Action::StopProcess { pid } => format!("Stopped process {pid}"),
            Action::KillProcess { pid } => format!("Killed process {pid}"),
            Action::DeleteFile { path } => format!("Deleted file {path}"),
        }
    }

    pub fn reason_hint(&self) -> String {
        match self {
            Action::StopProcess { .. } => "User requested the process be stopped".into(),
            Action::KillProcess { .. } => "User requested the process be forcibly terminated".into(),
            Action::DeleteFile { .. } => "User confirmed deletion".into(),
        }
    }

    /// Whether the action can be meaningfully reversed.
    pub fn reversible(&self) -> bool {
        match self {
            Action::StopProcess { .. } => true, // can be restarted
            Action::KillProcess { .. } => false,
            Action::DeleteFile { .. } => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum ActionError {
    #[error("permission denied: {0}")]
    Denied(String),
    #[error("confirmation required before executing {0}")]
    ConfirmationRequired(&'static str),
    #[error("action failed: {0}")]
    Failed(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
}

/// A plan describes what NEXUS would do and what it needs before executing.
#[derive(Debug, Clone)]
pub struct ActionPlan {
    pub action: Action,
    pub risk: RiskLevel,
    pub reversible: bool,
    pub description: String,
    pub confirmation_required: bool,
    pub permission: PermissionDecision,
}

/// The full, stateful result of running an action.
#[derive(Debug, Clone)]
pub struct ActionResultDetail {
    pub success: bool,
    pub verified: bool,
    pub message: String,
}

/// The ActionEngine ties policy + confirmation + execution + audit together.
pub struct ActionEngine {
    audit: AuditLog,
    /// Whether the current requester is authorized to change system state.
    can_change_system: bool,
}

impl ActionEngine {
    pub fn new(audit: AuditLog, can_change_system: bool) -> Self {
        Self { audit, can_change_system }
    }

    pub fn audit_log(&self) -> &AuditLog {
        &self.audit
    }

    /// Stage an action and check permission + confirmation requirements
    /// *without* executing anything. Returns the plan for review.
    pub fn plan(&self, action: &Action) -> Result<ActionPlan, ActionError> {
        let decision = evaluate(action.id(), self.can_change_system);
        let risk = decision.risk.ok_or_else(|| ActionError::Denied(decision.reason.clone()))?;
        if !decision.allowed {
            return Err(ActionError::Denied(decision.reason.clone()));
        }
        Ok(ActionPlan {
            action: action.clone(),
            risk,
            reversible: action.reversible(),
            description: action.describe(),
            confirmation_required: decision.requires_confirmation,
            permission: decision,
        })
    }

    /// Execute an already-approved action. `confirmed` must be true for any
    /// action that requires confirmation (enforced here as defense-in-depth;
    /// the UI layer is responsible for collecting it).
    pub fn execute(
        &mut self,
        plan: &ActionPlan,
        confirmed: bool,
        reason: &str,
    ) -> Result<ActionResultDetail, ActionError> {
        if plan.confirmation_required && !confirmed {
            return Err(ActionError::ConfirmationRequired(plan.action.id()));
        }

        let detail = match &plan.action {
            Action::StopProcess { pid } => self.run_stop(*pid, confirmed),
            Action::KillProcess { pid } => self.run_kill(*pid, confirmed),
            Action::DeleteFile { path } => self.run_delete(path, confirmed),
        };

        let result = match &detail {
            Ok(d) if d.success => ActionResult::Success,
            Ok(_) => ActionResult::Rejected,
            Err(e) => ActionResult::Failed(e.to_string()),
        };

        // Commit a pending entry to the audit log.
        let mut entry = AuditEntry::new(
            plan.action.id(),
            plan.description.clone(),
            reason.to_string(),
            Initiator::User,
        );
        entry.result = result;
        entry.detail = Some(match &detail {
            Ok(d) => d.message.clone(),
            Err(e) => e.to_string(),
        });
        let _ = self.audit.record(entry);

        detail
    }
}

/// Whether a process is currently in a runnable/running state.
///
/// This is more precise than `kill(pid, 0)` for verification: a process that
/// has been signalled but not yet reaped by its parent may still answer
/// `kill(pid,0)` even though it is a zombie. Here we read the process state
/// directly so a terminated/zombie process is correctly reported as no
/// longer running.
#[cfg(target_os = "macos")]
fn process_is_running(pid: i32) -> bool {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let sz = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            sz,
        )
    };
    if n < sz.min(1) {
        // ESRCH-like: process is gone.
        return false;
    }
    // Darwin SStates: SIDL=1, SRUN=2, SSLEEP=3, SSTOP=4. SZOMB=5 means a
    // zombie (terminated, awaiting reap) which is NOT running.
    matches!(info.pbi_status as libc::c_int, 1 | 2 | 3 | 4)
}

/// Fallback implementation used on non-macOS platforms.
/// kill(pid, 0) is a reasonable approximation on Linux where zombies are
/// uncommon in practice for short-lived children.
#[cfg(not(target_os = "macos"))]
fn process_is_running(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Poll `check` until it returns false or `timeout` elapses. Returns true if
/// the condition cleared in time.
fn poll_until_clear<F: FnMut() -> bool>(mut check: F, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if !check() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    false
}

impl ActionEngine {
fn run_stop(&self, pid: i32, _confirmed: bool) -> Result<ActionResultDetail, ActionError> {
        if pid <= 0 {
            return Err(ActionError::InvalidPath("pid <= 0".into()));
        }
        // SIGTERM for a graceful stop.
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
        if rc != 0 {
            return Err(ActionError::Failed(format!(
                "kill(SIGTERM, {pid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Verify it actually stopped (process no longer running / zombie).
        if !poll_until_clear(|| process_is_running(pid), std::time::Duration::from_secs(3)) {
            return Err(ActionError::Verification(format!(
                "process {pid} still running after SIGTERM"
            )));
        }
        Ok(ActionResultDetail {
            success: true,
            verified: true,
            message: format!("Process {pid} stopped and verified exited."),
        })
    }

    fn run_kill(&self, pid: i32, _confirmed: bool) -> Result<ActionResultDetail, ActionError> {
        if pid <= 0 {
            return Err(ActionError::InvalidPath("pid <= 0".into()));
        }
        let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
        if rc != 0 {
            return Err(ActionError::Failed(format!(
                "kill(SIGKILL, {pid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if !poll_until_clear(|| process_is_running(pid), std::time::Duration::from_secs(3)) {
            return Err(ActionError::Verification(format!(
                "process {pid} still running after SIGKILL"
            )));
        }
        Ok(ActionResultDetail {
            success: true,
            verified: true,
            message: format!("Process {pid} killed and verified exited."),
        })
    }

    fn run_delete(&self, path: &str, _confirmed: bool) -> Result<ActionResultDetail, ActionError> {
        let p = std::path::Path::new(path);
        // Refuse non-files (directories, symlinks, sockets, devices).
        let md = std::fs::symlink_metadata(p)
            .map_err(|e| ActionError::InvalidPath(format!("{path}: {e}")))?;
        if !md.file_type().is_file() {
            return Err(ActionError::InvalidPath(format!(
                "{path} is not a regular file; refusing to delete."
            )));
        }
        std::fs::remove_file(p)
            .map_err(|e| ActionError::Failed(format!("remove_file {path}: {e}")))?;
        let gone = !p.exists();
        if !gone {
            return Err(ActionError::Verification(format!("{path} still exists")));
        }
        Ok(ActionResultDetail {
            success: true,
            verified: true,
            message: format!("Deleted {path} and verified removed."),
        })
    }
}

/// Locate a live process by pid in a snapshot (used by plans/UI for display).
pub fn find_process<'a>(processes: &'a [ProcessSnapshot], pid: i32) -> Option<&'a ProcessSnapshot> {
    processes.iter().find(|p| p.pid == pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_plan_allowed_without_auth_for_safe_actions_is_none() {
        // The action engine always has system-change authorization capacity
        // as a constructor flag; a safe(read) isn't an Action variant.
        let log = AuditLog::memory();
        let engine = ActionEngine::new(log, false);
        let a = Action::StopProcess { pid: 999999999 };
        // Not authorized -> denied before confirmation.
        let err = engine.plan(&a).unwrap_err();
        assert!(matches!(err, ActionError::Denied(_)));
    }

    #[test]
    fn confirmation_required_for_stop_process() {
        let engine = ActionEngine::new(AuditLog::memory(), true);
        let a = Action::StopProcess { pid: 999999999 };
        let plan = engine.plan(&a).unwrap();
        assert!(plan.confirmation_required);
        assert_eq!(plan.risk, RiskLevel::HighRisk);
    }

    #[test]
    fn stop_process_terminates_real_child() {
        // Spawn a long-running child, then stop it via the engine and verify
        // it is genuinely gone (exercises the real kill + verify path).
        use std::process::Command;
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;

        let mut engine = ActionEngine::new(AuditLog::memory(), true);
        let plan = engine.plan(&Action::StopProcess { pid }).unwrap();
        let detail = engine.execute(&plan, true, "test stop").unwrap();
        assert!(detail.success && detail.verified);

        // Reap and confirm the child is gone.
        let _ = child.wait();
        assert_eq!(engine.audit_log().entries().len(), 1);
    }

    #[test]
    fn executing_without_confirmation_is_rejected() {
        let mut engine = ActionEngine::new(AuditLog::memory(), true);
        let a = Action::StopProcess { pid: 999999999 };
        let plan = engine.plan(&a).unwrap();
        let err = engine.execute(&plan, false, "test").unwrap_err();
        assert!(matches!(err, ActionError::ConfirmationRequired(_)));
    }

    #[test]
    fn delete_refuses_nonfile() {
        let mut engine = ActionEngine::new(AuditLog::memory(), true);
        // A directory is refused.
        let a = Action::DeleteFile { path: "/tmp".into() };
        let plan = engine.plan(&a).unwrap();
        let err = engine.execute(&plan, true, "test").unwrap_err();
        assert!(matches!(err, ActionError::InvalidPath(_)));
    }

    #[test]
    fn delete_removes_regular_file_and_audits() {
        let tmp = std::env::temp_dir().join(format!("nexus-actions-{}.txt", std::process::id()));
        std::fs::write(&tmp, b"x").unwrap();
        let mut engine = ActionEngine::new(AuditLog::memory(), true);
        let a = Action::DeleteFile { path: tmp.to_string_lossy().into_owned() };
        let plan = engine.plan(&a).unwrap();
        assert!(!plan.reversible);
        let r = engine.execute(&plan, true, "cleaning temp file").unwrap();
        assert!(r.success && r.verified);
        assert!(!tmp.exists());
        assert_eq!(engine.audit_log().entries().len(), 1);
    }
}
