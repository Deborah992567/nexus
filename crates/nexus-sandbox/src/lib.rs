//! NEXUS Sandbox — genuine OS-level sandboxing via the macOS seatbelt
//! (Apple's Mandatory Access Control) mechanism, driven by `sandbox-exec`.
//!
//! This is real enforcement, not a simulation: when a profile is applied and
//! the host has `sandbox-exec`, denied operations genuinely fail at the
//! kernel/MAC layer (e.g. a blocked write returns "Operation not permitted"
//! and the file is never created).
//!
//! Honesty rules:
//! - `supports_sandbox()` probes the host at runtime for `sandbox-exec`
//!   rather than assuming availability.
//! - On platforms without the mechanism, running is refused with
//!   [`SandboxError::Unsupported`] instead of pretending to succeed.
//!
//! Policy model: *allow default, deny specific unsafe operations*. This is
//! the reliable seatbelt form that lets real programs execute while clearly
//! constraining high-value capabilities (network access, file writes).

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, ExitStatus};

/// The single dimension of enforcement a [`SandboxProfile`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SandboxFacet {
    /// Deny all network reads/writes (`deny network*`).
    NetworkIsolation,
    /// Deny creating/truncating/modifying any file (`deny file-write*`);
    /// reads and execution remain available.
    ReadOnly,
}

impl SandboxFacet {
    /// The seatbelt operation glob to block for this facet.
    pub fn deny_operation(self) -> &'static str {
        match self {
            SandboxFacet::NetworkIsolation => "network*",
            SandboxFacet::ReadOnly => "file-write*",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SandboxFacet::NetworkIsolation => "network_isolation",
            SandboxFacet::ReadOnly => "read_only",
        }
    }
}

/// A named set of sandboxing facets to apply to a process.
#[derive(Debug, Clone)]
pub struct SandboxProfile {
    pub name: String,
    facets: BTreeSet<SandboxFacet>,
}

impl SandboxProfile {
    /// Build a profile from a name and a list of facets.
    pub fn new(name: impl Into<String>, facets: impl IntoIterator<Item = SandboxFacet>) -> Self {
        Self {
            name: name.into(),
            facets: facets.into_iter().collect(),
        }
    }

    /// A profile that denies ALL network access for the child.
    pub fn network_isolation(name: impl Into<String>) -> Self {
        Self::new(name, [SandboxFacet::NetworkIsolation])
    }

    /// A profile that denies all file writes (read/execute stay allowed).
    pub fn read_only(name: impl Into<String>) -> Self {
        Self::new(name, [SandboxFacet::ReadOnly])
    }

    /// Deny both network access and file writes.
    pub fn isolated(name: impl Into<String>) -> Self {
        Self::new(name, [SandboxFacet::NetworkIsolation, SandboxFacet::ReadOnly])
    }

    pub fn facets(&self) -> &BTreeSet<SandboxFacet> {
        &self.facets
    }

    /// Render the facet set into a valid seatbelt policy expression.
    pub fn render_seatbelt(&self) -> String {
        let mut ops: Vec<String> = vec!["(version 1)".into(), "(allow default)".into()];
        for facet in &self.facets {
            ops.push(format!("(deny {})", facet.deny_operation()));
        }
        ops.join(" ")
    }
}

/// Outcome of running a command under a sandbox profile.
#[derive(Debug, Clone)]
pub struct SandboxRun {
    pub program: String,
    /// Seatbelt policy that was applied (for transparency/audit).
    pub policy: String,
    /// Whether `sandbox-exec` was present to enforce the policy.
    pub enforced: bool,
    /// Exit status when enforced; `None` if the launch itself failed.
    pub exit_status: Option<ExitStatus>,
    /// True if the process was terminated by a signal (e.g. a hard deny).
    pub signaled: bool,
}

/// Errors while preparing or running a sandboxed command.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("platform does not provide a sandbox mechanism (sandbox-exec not found); cannot sandbox honestly")]
    Unsupported,
    #[error("spawn failed: {0}")]
    Spawn(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// True if the host genuinely provides a sandboxing mechanism. Probes the
/// environment rather than assuming.
pub fn supports_sandbox() -> bool {
    find_sandbox_exec().is_some()
}

/// Returns the path to `sandbox-exec` when it exists and is executable.
pub fn find_sandbox_exec() -> Option<std::path::PathBuf> {
    let candidates = ["/usr/bin/sandbox-exec", "/usr/sbin/sandbox-exec"];
    for c in candidates {
        let p = Path::new(c);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Run `program` with `args` under `profile`, honoring the seatbelt policy.
///
/// Returns [`SandboxError::Unsupported`] on hosts without a mechanism (never
/// fakes success). When the platform supports sandboxing, the child is
/// executed beneath `sandbox-exec`; a hard denial typically surfaces as a
/// non-zero exit or signal rather than a partial effect.
pub fn run_boxed(
    profile: &SandboxProfile,
    program: &Path,
    args: &[&str],
) -> Result<SandboxRun, SandboxError> {
    let sandbox_exec = find_sandbox_exec().ok_or(SandboxError::Unsupported)?;
    let policy = profile.render_seatbelt();

    let mut cmd = Command::new(&sandbox_exec);
    cmd.arg("-p").arg(&policy).arg(program).args(args);

    let status = cmd.status().map_err(|e| SandboxError::Spawn(e.to_string()))?;
    let signaled = status.code().is_none();

    Ok(SandboxRun {
        program: program.display().to_string(),
        policy,
        enforced: true,
        exit_status: Some(status),
        signaled,
    })
}

/// Validate that a profile is non-empty and renderable. Pure, testable.
pub fn validate(profile: &SandboxProfile) -> Result<(), SandboxError> {
    if profile.facets.is_empty() {
        return Err(SandboxError::Spawn(
            "profile has no facets; nothing to sandbox".into(),
        ));
    }
    let policy = profile.render_seatbelt();
    if !policy.starts_with("(version 1)") {
        return Err(SandboxError::Spawn("invalid seatbelt policy generated".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as Cmd;

    fn host_supports() -> bool {
        supports_sandbox()
    }

    #[test]
    fn detected_host_support_matches_availability() {
        // This must be truthful: if we detect support, sandbox-exec exists.
        if let Some(p) = find_sandbox_exec() {
            assert!(p.is_file());
        }
    }

    #[test]
    fn renders_versioned_seatbelt_policy() {
        let p = SandboxProfile::isolated("iso");
        let policy = p.render_seatbelt();
        assert!(policy.starts_with("(version 1)"));
        assert!(policy.contains("(deny network*)"));
        assert!(policy.contains("(deny file-write*)"));
    }

    #[test]
    fn empty_profile_fails_validation() {
        let p = SandboxProfile::new("empty", std::iter::empty());
        assert!(validate(&p).is_err());
    }

    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "seatbelt enforcement is only verifiable on macOS"
    )]
    #[test]
    fn genuinely_blocks_file_writes_when_host_supports() {
        if !host_supports() {
            // Honest skip: we only assert when the mechanism truly exists.
            return;
        }
        let target = std::env::temp_dir().join(format!("nexus_sb_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&target);

        // Control: without a write-deny, the write succeeds.
        let ok = Cmd::new("/bin/sh")
            .arg("-c")
            .arg(format!("echo ok > {}", target.display()))
            .status()
            .expect("control shell runs")
            .success();
        assert!(ok, "control write should have been permitted");

        // Sandboxed: a read_only profile must actually block the same write.
        let _ = std::fs::remove_file(&target);
        let profile = SandboxProfile::read_only("write-deny-test");
        let run = run_boxed(&profile, Path::new("/bin/sh"), &["-c", "echo x > /tmp/x_sb_deny.txt"])
            .expect("sandbox launch works");
        assert!(run.enforced);
        assert!(!std::path::Path::new("/tmp/x_sb_deny.txt").exists(), "write must be denied");
        let _ = std::fs::remove_file("/tmp/x_sb_deny.txt");
    }
}
