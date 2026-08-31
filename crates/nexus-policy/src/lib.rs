//! NEXUS Policy & Risk Classification.
//!
//! Phase 7 builds a secure action layer. Every action NEXUS can take is
//! classified into a risk level (SAFE..CRITICAL) and checked against a
//! permission policy. The higher the risk, the stronger the confirmation
//! required before execution. This crate is the source of truth for those
//! levels and for which attestations (e.g. explicit user confirmation) are
//! mandatory for a given action.

use thiserror::Error;

/// Risk classification for an action, mirroring the product spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// No meaningful system impact (e.g. reading metrics, listing).
    Safe = 0,
    /// Minor impact with easy reversal (e.g. clearing a temp file).
    LowRisk = 1,
    /// Meaningful but bounded impact (e.g. suspending a non-critical app).
    MediumRisk = 2,
    /// Potentially disruptive (e.g. killing a process, changing a config).
    HighRisk = 3,
    /// Destructive or security-sensitive (e.g. deleting files, firewall changes).
    Critical = 4,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Safe => "SAFE",
            RiskLevel::LowRisk => "LOW_RISK",
            RiskLevel::MediumRisk => "MEDIUM_RISK",
            RiskLevel::HighRisk => "HIGH_RISK",
            RiskLevel::Critical => "CRITICAL",
        }
    }

    /// Whether explicit user confirmation is required before execution.
    pub fn requires_confirmation(self) -> bool {
        self >= RiskLevel::MediumRisk
    }

    /// A short human explanation of what confirmation is required.
    pub fn confirmation_requirement(self) -> &'static str {
        match self {
            RiskLevel::Safe => "No confirmation required.",
            RiskLevel::LowRisk => "No confirmation required (reversible, trivial impact).",
            RiskLevel::MediumRisk => "Simple confirmation required.",
            RiskLevel::HighRisk => "Explicit confirmation required; user must see the impact.",
            RiskLevel::Critical => "Strong confirmation required: user must acknowledge the risks and reversibility.",
        }
    }
}

/// An error that can occur when deciding permission for an action.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("action '{0}' is not recognized by the policy engine")]
    UnknownAction(String),
    #[error("action '{0}' is not permitted by the current policy")]
    Denied(String),
}

/// The set of known actions and their fixed risk classification.
///
/// This is a closed allow-list: unknown actions are rejected rather than
/// silently assigned a low risk. Actions are grouped and documented.
pub fn classify(action: &str) -> Result<RiskLevel, PolicyError> {
    let level = match action {
        // Read / observe: always safe.
        "status" | "health" | "processes" | "storage" | "network" | "diagnostics" | "security" | "logs" | "audit"
            => RiskLevel::Safe,

        // Minor, reversible cleanups.
        "clean_temp_file" | "clear_cache_entry" => RiskLevel::LowRisk,

        // Suspending an application process.
        "suspend_process" => RiskLevel::MediumRisk,

        // Terminating a process, stopping a service, changing a setting.
        "kill_process" | "stop_service" | "change_setting" => RiskLevel::HighRisk,

        // Destructive / security-sensitive.
        "delete_file" | "delete_directory" | "modify_firewall" | "change_permissions" | "change_network_config" | "change_security_setting"
            => RiskLevel::Critical,

        _ => return Err(PolicyError::UnknownAction(action.to_string())),
    };
    Ok(level)
}

/// A permission decision for attempting an action.
#[derive(Debug, Clone)]
pub struct PermissionDecision {
    pub allowed: bool,
    pub risk: Option<RiskLevel>,
    /// Human-readable reasoning for the decision.
    pub reason: String,
    /// Whether user confirmation must be gathered before execution.
    pub requires_confirmation: bool,
}

/// Evaluate whether an action is permitted to proceed under the policy,
/// given whether the requester (user or NEXUS) is authorized to perform
/// system-changing actions at all.
pub fn evaluate(action: &str, requester_can_change_system: bool) -> PermissionDecision {
    let risk = match classify(action) {
        Ok(risk) => risk,
        Err(e) => {
            return PermissionDecision {
                allowed: false,
                risk: None,
                reason: e.to_string(),
                requires_confirmation: false,
            };
        }
    };

    // System-changing actions require authorization; pure reads always pass.
    let allowed = if risk == RiskLevel::Safe || risk == RiskLevel::LowRisk {
        true
    } else {
        requester_can_change_system
    };

    PermissionDecision {
        allowed,
        risk: Some(risk),
        reason: if allowed {
            format!(
                "Permitted as {} ({}).",
                risk.as_str(),
                risk.confirmation_requirement()
            )
        } else {
            format!("Denied: {} requires system-change authorization.", risk.as_str())
        },
        requires_confirmation: allowed && risk.requires_confirmation(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_actions_are_safe() {
        assert_eq!(classify("status").unwrap(), RiskLevel::Safe);
        assert_eq!(classify("security").unwrap(), RiskLevel::Safe);
    }

    #[test]
    fn destructive_actions_are_critical() {
        assert_eq!(classify("delete_file").unwrap(), RiskLevel::Critical);
        assert_eq!(classify("modify_firewall").unwrap(), RiskLevel::Critical);
        assert_eq!(classify("kill_process").unwrap(), RiskLevel::HighRisk);
        assert_eq!(classify("suspend_process").unwrap(), RiskLevel::MediumRisk);
    }

    #[test]
    fn unknown_action_denied() {
        let d = evaluate("arbitrary_shell", true);
        assert!(!d.allowed);
    }

    #[test]
    fn high_risk_needs_authorization_and_confirmation() {
        let auth = evaluate("kill_process", true);
        assert!(auth.allowed);
        assert!(auth.requires_confirmation);
        let noauth = evaluate("kill_process", false);
        assert!(!noauth.allowed);
    }

    #[test]
    fn safe_action_allowed_without_authorization() {
        let d = evaluate("status", false);
        assert!(d.allowed);
        assert!(!d.requires_confirmation);
    }
}
