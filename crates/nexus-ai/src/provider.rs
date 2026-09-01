//! Provider abstraction for the NEXUS advisory layer.
//!
//! Defines the contract any AI/advisory backend must fulfil, plus the shared
//! data types. Only the deterministic [`crate::LocalAnalyst`] is currently
//! registered as a provider.

use nexus_diagnostics::DiagnosticReport;
use nexus_security::SecurityReport;
use nexus_storage::StorageAnalysis;

/// What kind of recommendation a piece of advice belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendationKind {
    Performance,
    Capacity,
    Security,
    Cleanup,
}

impl RecommendationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecommendationKind::Performance => "performance",
            RecommendationKind::Capacity => "capacity",
            RecommendationKind::Security => "security",
            RecommendationKind::Cleanup => "cleanup",
        }
    }
}

/// A single piece of advice with explicit provenance.
#[derive(Debug, Clone)]
pub struct Recommendation {
    pub kind: RecommendationKind,
    /// The concrete subject, e.g. "pid 4242" or a path.
    pub target: String,
    pub summary: String,
    /// Human-readable reasons, each anchored to facts.
    pub rationale: Vec<String>,
    /// Raw evidence tuples backing each rationale.
    pub evidence: Vec<String>,
    /// A suggested policy-classifiable action name (e.g. "stop_process").
    /// Advisory only — never executed here.
    pub suggested_action: String,
    /// The policy risk of the suggested remedy, if classifiable.
    pub remedy_risk: Option<String>,
    /// Which subsystem produced it ("diagnostics" | "security" | "storage").
    pub source: &'static str,
}

/// Honest description of the advisor in use.
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub model_id: String,
    pub backend: String,
    /// Capabilities this advisor genuinely supports.
    pub caps: Vec<String>,
    pub disclaimer: String,
}

/// Anything that can turn diagnostics+safety signals into advice.
pub trait Advisor {
    fn info(&self) -> ModelInfo;

    fn recommend(
        &self,
        report: &DiagnosticReport,
        security: Option<&SecurityReport>,
        storage: Option<&StorageAnalysis>,
    ) -> Vec<Recommendation>;
}
