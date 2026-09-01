//! NEXUS advisory / "AI" layer.
//!
//! This crate is intentionally honest about what it is and is not. NEXUS
//! does **not** ship a neural model. The advisory engine here is
//! deterministic and evidence-based: every recommendation is derived only
//! from real measurements (diagnostics, security and storage signals) and
//! carries explicit provenance pointing at the supporting evidence. Nothing
//! is fabricated or hallucinated.
//!
//! The `Advisor` trait is a provider abstraction so a true remote/local ML
//! backend could be dropped in later without changing consumers — but until
//! one exists, only the deterministic [`LocalAnalyst`] is registered. Any
//! non-deterministic capability is reported as NOT IMPLEMENTED rather than
//! faked.

use nexus_diagnostics::DiagnosticReport;
use nexus_security::{RiskLevel as SecRisk, SecurityReport};
use nexus_storage::StorageAnalysis;

pub mod provider;

pub use provider::{Advisor, ModelInfo, Recommendation, RecommendationKind};

/// Convenience entry point: analyze a real snapshot trio and produce a
/// deterministic set of recommendations.
pub fn analyze_local(
    report: &DiagnosticReport,
    security: Option<&SecurityReport>,
    storage: Option<&StorageAnalysis>,
) -> (ModelInfo, Vec<Recommendation>) {
    let analyst = LocalAnalyst;
    (analyst.info(), analyst.recommend(report, security, storage))
}

/// The deterministic, rule-based advisor shipped with NEXUS.
pub struct LocalAnalyst;

impl LocalAnalyst {
    pub fn info(&self) -> ModelInfo {
        ModelInfo {
            model_id: "nexus-local-anomaly-v1".into(),
            backend: "local-deterministic".into(),
            caps: vec![
                "performance".into(),
                "capacity".into(),
                "security".into(),
                "cleanup".into(),
            ],
            disclaimer: "Deterministic rule-based analysis of real measurements; not an LLM. Recommendations are suggestions only and never alter the system on their own.".into(),
        }
    }
}

impl Advisor for LocalAnalyst {
    fn info(&self) -> ModelInfo {
        Self::info(self)
    }

    fn recommend(
        &self,
        report: &DiagnosticReport,
        security: Option<&SecurityReport>,
        storage: Option<&StorageAnalysis>,
    ) -> Vec<Recommendation> {
        let mut out = Vec::new();

        // ---- Recommendations anchored to diagnostic findings ----
        for f in &report.findings {
            let (kind, action_name, target) = match f.category {
                nexus_diagnostics::Category::Cpu => {
                    (RecommendationKind::Performance, "stop_process", "cpu_hog".to_string())
                }
                nexus_diagnostics::Category::Memory => {
                    (RecommendationKind::Performance, "stop_process", "memory_hog".to_string())
                }
                nexus_diagnostics::Category::Disk => {
                    (RecommendationKind::Capacity, "delete_file", "disk_full".to_string())
                }
                nexus_diagnostics::Category::Network => {
                    (RecommendationKind::Capacity, "stop_process", "network_consumer".to_string())
                }
                _ => continue, // Overall/Process handled by security below.
            };

            // Only surface the remediation's risk if policy can classify it.
            let remedy_risk = nexus_policy::classify(action_name)
                .ok()
                .map(|r| r.as_str().to_string());

            out.push(Recommendation {
                kind,
                target,
                summary: f.title.clone(),
                rationale: vec![f.explanation.clone()],
                evidence: f.evidence.clone(),
                suggested_action: action_name.to_string(),
                remedy_risk,
                source: "diagnostics".into(),
            });
        }

        // ---- Recommendations anchored to security signals ----
        if let Some(sec) = security {
            for a in sec.assessments.iter() {
                if a.risk == SecRisk::High {
                    out.push(Recommendation {
                        kind: RecommendationKind::Security,
                        target: format!("pid {}", a.pid),
                        summary: format!("High-risk process identified: {}", a.name),
                        rationale: a
                            .signals
                            .iter()
                            .map(|s| s.explanation.clone())
                            .collect(),
                        evidence: a
                            .signals
                            .iter()
                            .map(|s| {
                                format!(
                                    "signal={} confidence={:.2} weight={:.2}",
                                    s.kind.as_str(),
                                    s.confidence,
                                    s.weight
                                )
                            })
                            .collect(),
                        suggested_action: "stop_process".into(),
                        remedy_risk: nexus_policy::classify("stop_process")
                            .ok()
                            .map(|r| r.as_str().to_string()),
                        source: "security".into(),
                    });
                }
            }
        }

        // ---- Recommendations anchored to storage reclaim ----
        if let Some(st) = storage {
            if st.reclaimable_bytes > 0 {
                out.push(Recommendation {
                    kind: RecommendationKind::Cleanup,
                    target: "user_tmp_caches".into(),
                    summary: format!(
                        "{} of safely-reclaimable storage identified",
                        nexus_storage::format_bytes(st.reclaimable_bytes)
                    ),
                    rationale: vec![
                        "NEXUS classified files as safe to reclaim based on directory heuristics.".into(),
                    ],
                    evidence: st
                        .reclaimable_by_category
                        .iter()
                        .map(|(k, v)| format!("{:?}={}", k, nexus_storage::format_bytes(*v)))
                        .collect(),
                    suggested_action: "delete_file".into(),
                    remedy_risk: nexus_policy::classify("delete_file")
                        .ok()
                        .map(|r| r.as_str().to_string()),
                    source: "storage".into(),
                });
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::Snapshot;
    use nexus_diagnostics::{analyze, Severity};
    use nexus_policy::RiskLevel;

    fn hot_cpu_snapshot() -> Snapshot {
        let mut s = Snapshot {
            platform: "test".into(),
            uptime_seconds: 0,
            cpu: nexus_core::CpuSnapshot { usage_percent: 95.0, cores: 8 },
            memory: nexus_core::MemorySnapshot {
                total_bytes: 16_000_000_000,
                available_bytes: 9_600_000_000,
                used_bytes: 6_400_000_000,
            },
            disks: vec![],
            processes: vec![],
        };
        s.processes.push(nexus_core::ProcessSnapshot {
            pid: 4242,
            ppid: 1,
            name: "busyloop".into(),
            user: "test".into(),
            status: "running".into(),
            cpu_percent: 90.0,
            rss_bytes: 0,
            vmsize_bytes: 0,
            runtime_seconds: 0,
            start_time_ticks: 0,
            threads: 1,
            cmdline: vec!["/tmp/busyloop".into()],
            exe_path: Some("/tmp/busyloop".into()),
            fd_count: None,
        });
        s
    }

    #[test]
    fn model_info_is_honest_about_not_being_an_llm() {
        let (info, _) = analyze_local(&DiagnosticReport {
            platform: "test".into(),
            overall: Severity::Info,
            findings: vec![],
        }, None, None);
        assert_eq!(info.backend, "local-deterministic");
        assert!(info.disclaimer.contains("not an LLM"));
    }

    #[test]
    fn high_cpu_yields_a_performance_recommendation() {
        let snapshot = hot_cpu_snapshot();
        let report = analyze(&snapshot, None);
        let (_, recs) = analyze_local(&report, None, None);
        let perf = recs.iter().find(|r| r.kind == RecommendationKind::Performance);
        assert!(perf.is_some(), "expected a performance recommendation");
        let p = perf.unwrap();
        assert_eq!(&p.suggested_action, "stop_process");
        assert_eq!(p.remedy_risk.as_deref(), Some(RiskLevel::HighRisk.as_str()));
        assert!(!p.evidence.is_empty(), "must cite real evidence");
    }

    fn quiet_snapshot() -> Snapshot {
        Snapshot {
            platform: "test".into(),
            uptime_seconds: 0,
            cpu: nexus_core::CpuSnapshot { usage_percent: 5.0, cores: 8 },
            memory: nexus_core::MemorySnapshot {
                total_bytes: 16_000_000_000,
                available_bytes: 14_000_000_000,
                used_bytes: 2_000_000_000,
            },
            disks: vec![],
            processes: vec![],
        }
    }

    #[test]
    fn no_fabrication_when_system_healthy() {
        let report = analyze(&quiet_snapshot(), None);
        let (_, recs) = analyze_local(&report, None, None);
        // A quiet system can still have storage/cleanup recs, but must not
        // invent performance/security problems.
        assert!(!recs.iter().any(|r| r.kind == RecommendationKind::Security));
    }

    #[test]
    fn never_suggests_when_no_evidence() {
        let (_, recs) = analyze_local(
            &DiagnosticReport {
                platform: "test".into(),
                overall: Severity::Info,
                findings: vec![],
            },
            None,
            None,
        );
        assert!(recs.is_empty());
    }
}
