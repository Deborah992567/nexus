use anyhow::Result;
use nexus_core::Snapshot;
use nexus_platform::SystemPlatform;

pub fn collect_snapshot(platform: &dyn SystemPlatform) -> Result<Snapshot> {
    Ok(Snapshot {
        platform: platform.name().to_string(),
        uptime_seconds: platform.uptime()?.as_secs(),
        cpu: platform.cpu_snapshot()?,
        memory: platform.memory_snapshot()?,
        disks: platform.disk_snapshot()?,
        processes: platform.processes()?,
    })
}
