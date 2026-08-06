#[derive(Debug, Clone)]
pub struct CpuSnapshot {
    pub usage_percent: f64,
    pub cores: usize,
}

#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct DiskSnapshot {
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Clone)]
pub struct ProcessSnapshot {
    pub pid: i32,
    pub name: String,
    pub user: String,
    pub status: String,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub platform: String,
    pub uptime_seconds: u64,
    pub cpu: CpuSnapshot,
    pub memory: MemorySnapshot,
    pub disks: Vec<DiskSnapshot>,
    pub processes: Vec<ProcessSnapshot>,
}

#[derive(Debug, Clone)]
pub struct HealthReport {
    pub score: u8,
    pub status: &'static str,
    pub issues: Vec<String>,
}

impl HealthReport {
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        let mut score: i32 = 100;
        let mut issues = Vec::new();

        if snapshot.cpu.usage_percent > 80.0 {
            score -= 20;
            issues.push(format!("CPU is high at {:.1}%", snapshot.cpu.usage_percent));
            if let Some(top) = snapshot.processes.iter().max_by(|a, b| {
                a.cpu_percent
                    .partial_cmp(&b.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }) {
                if matches!(top.name.as_str(), "cargo" | "rustc" | "cc" | "clang" | "make" | "ninja") {
                    issues.push(format!(
                        "High CPU may be expected while {} is active",
                        top.name
                    ));
                }
            }
        }

        let available_ratio = snapshot.memory.available_bytes as f64 / snapshot.memory.total_bytes.max(1) as f64;
        if available_ratio < 0.10 {
            score -= 20;
            issues.push(format!(
                "Memory available is low at {:.1}%",
                available_ratio * 100.0
            ));
        }

        for disk in &snapshot.disks {
            if disk.usage_percent > 90.0 {
                score -= 10;
                issues.push(format!("Disk {} is {:.1}% full", disk.mount_point, disk.usage_percent));
            }
        }

        score = score.clamp(0, 100);
        let status = match score {
            90..=100 => "healthy",
            70..=89 => "degraded",
            _ => "critical",
        };

        Self { score: score as u8, status, issues }
    }

    pub fn summary(&self) -> String {
        format!("NEXUS health: {} (score {})", self.status, self.score)
    }

    pub fn details(&self) -> String {
        if self.issues.is_empty() {
            "No major issues detected.".to_string()
        } else {
            self.issues.iter().map(|s| format!("- {s}")).collect::<Vec<_>>().join("\n")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_flags_high_cpu() {
        let snapshot = Snapshot {
            platform: "linux".into(),
            uptime_seconds: 10,
            cpu: CpuSnapshot { usage_percent: 92.0, cores: 8 },
            memory: MemorySnapshot { total_bytes: 100, available_bytes: 50, used_bytes: 50 },
            disks: vec![],
            processes: vec![],
        };
        let report = HealthReport::from_snapshot(&snapshot);
        assert_eq!(report.status, "degraded");
        assert!(report.issues.iter().any(|s| s.contains("CPU is high")));
    }

    #[test]
    fn health_flags_low_memory_and_disk() {
        let snapshot = Snapshot {
            platform: "linux".into(),
            uptime_seconds: 10,
            cpu: CpuSnapshot { usage_percent: 10.0, cores: 8 },
            memory: MemorySnapshot { total_bytes: 100, available_bytes: 9, used_bytes: 91 },
            disks: vec![DiskSnapshot {
                mount_point: "/".into(),
                fs_type: "ext4".into(),
                total_bytes: 100,
                available_bytes: 5,
                used_bytes: 95,
                usage_percent: 95.0,
            }],
            processes: vec![],
        };
        let report = HealthReport::from_snapshot(&snapshot);
        assert!(report.issues.iter().any(|s| s.contains("Memory available is low")));
        assert!(report.issues.iter().any(|s| s.contains("Disk / is 95.0% full")));
    }
}
