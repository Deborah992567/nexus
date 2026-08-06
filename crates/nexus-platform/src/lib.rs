
use anyhow::Result;
use nexus_core::{CpuSnapshot, DiskSnapshot, MemorySnapshot, ProcessSnapshot};
use std::time::Duration;

pub trait SystemPlatform: Send + Sync {
    fn name(&self) -> &'static str;
    fn cpu_snapshot(&self) -> Result<CpuSnapshot>;
    fn memory_snapshot(&self) -> Result<MemorySnapshot>;
    fn disk_snapshot(&self) -> Result<Vec<DiskSnapshot>>;
    fn uptime(&self) -> Result<Duration>;
    fn processes(&self) -> Result<Vec<ProcessSnapshot>>;
}

pub fn detect_platform() -> Box<dyn SystemPlatform> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::default())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacPlatform::default())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        compile_error!("NEXUS currently supports linux and macos only");
    }
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;
