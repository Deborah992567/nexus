use anyhow::{bail, Result};
use nexus_core::{CpuSnapshot, DiskSnapshot, MemorySnapshot, ProcessSnapshot};
use std::time::Duration;

use super::SystemPlatform;

#[derive(Default)]
pub struct MacPlatform;

impl SystemPlatform for MacPlatform {
    fn name(&self) -> &'static str { "macos" }

    fn cpu_snapshot(&self) -> Result<CpuSnapshot> {
        cpu_snapshot()
    }

    fn memory_snapshot(&self) -> Result<MemorySnapshot> {
        memory_snapshot()
    }

    fn disk_snapshot(&self) -> Result<Vec<DiskSnapshot>> {
        disk_snapshot()
    }

    fn uptime(&self) -> Result<Duration> { uptime() }

    fn processes(&self) -> Result<Vec<ProcessSnapshot>> {
        processes()
    }
}

fn cpu_snapshot() -> Result<CpuSnapshot> {
    let mut load = [0.0f64; 3];
    let rc = unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
    if rc < 1 {
        bail!("getloadavg unavailable");
    }
    Ok(CpuSnapshot { usage_percent: (load[0] / std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64) * 100.0, cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) })
}

fn memory_snapshot() -> Result<MemorySnapshot> {
    unsafe {
        let mut total: u64 = 0;
        let mut size = std::mem::size_of::<u64>();
        let mut mib = [libc::CTL_HW, libc::HW_MEMSIZE];
        if libc::sysctl(mib.as_mut_ptr(), 2, &mut total as *mut _ as *mut _, &mut size, std::ptr::null_mut(), 0) != 0 {
            bail!("sysctl hw.memsize failed");
        }
        let mut vm: libc::vm_statistics64_data_t = std::mem::zeroed();
        let mut count = libc::HOST_VM_INFO64_COUNT;
        let ret = libc::host_statistics64(libc::mach_host_self(), libc::HOST_VM_INFO64, &mut vm as *mut _ as *mut _, &mut count);
        if ret != libc::KERN_SUCCESS {
            bail!("host_statistics64 failed");
        }
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as u64;
        let free = (vm.free_count + vm.inactive_count) as u64 * page_size;
        let used = total.saturating_sub(free);
        Ok(MemorySnapshot { total_bytes: total, available_bytes: free, used_bytes: used })
    }
}

fn disk_snapshot() -> Result<Vec<DiskSnapshot>> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    let mut out = Vec::new();
    let mounts = ["/", "/System/Volumes/Data"];
    for mount in mounts {
        let mut stat = MaybeUninit::<libc::statfs>::uninit();
        let c_mount = CString::new(mount)?;
        if unsafe { libc::statfs(c_mount.as_ptr(), stat.as_mut_ptr()) } != 0 { continue; }
        let stat = unsafe { stat.assume_init() };
        let block_size = stat.f_bsize as u64;
        let total = block_size * stat.f_blocks as u64;
        let available = block_size * stat.f_bavail as u64;
        let used = total.saturating_sub(available);
        out.push(DiskSnapshot {
            mount_point: mount.to_string(),
            fs_type: fsname_to_string(&stat.f_fstypename),
            total_bytes: total,
            available_bytes: available,
            used_bytes: used,
            usage_percent: if total > 0 { used as f64 / total as f64 * 100.0 } else { 0.0 },
        });
    }
    Ok(out)
}

fn fsname_to_string(bytes: &[libc::c_char; 16]) -> String {
    unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr()).to_string_lossy().into_owned() }
}

fn uptime() -> Result<Duration> {
    unsafe {
        let mut bt = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let mut size = std::mem::size_of::<libc::timeval>();
        let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
        if libc::sysctl(mib.as_mut_ptr(), 2, &mut bt as *mut _ as *mut _, &mut size, std::ptr::null_mut(), 0) != 0 {
            bail!("sysctl kern.boottime failed");
        }
        let boot = bt.tv_sec as u64;
        let now = libc::time(std::ptr::null_mut()) as u64;
        Ok(Duration::from_secs(now.saturating_sub(boot)))
    }
}

fn processes() -> Result<Vec<ProcessSnapshot>> {
    bail!("process list not yet implemented on macOS backend; PLATFORM-LIMITED");
}
