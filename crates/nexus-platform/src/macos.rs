use anyhow::{bail, Result};
use nexus_core::{CpuSnapshot, DiskSnapshot, MemorySnapshot, ProcessSnapshot};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::SystemPlatform;

static PID_HINT: AtomicU64 = AtomicU64::new(4096);

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
    let first = sample_processes()?;
    std::thread::sleep(Duration::from_millis(120));
    let second = sample_processes()?;

    let first_map: HashMap<i32, TaskSample> = first.into_iter().map(|p| (p.pid, p)).collect();
    let second_map: HashMap<i32, TaskSample> = second.into_iter().map(|p| (p.pid, p)).collect();

    let num_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let uptime_secs = uptime()?.as_secs_f64();
    let elapsed = 0.120_f64;

    let mut processes = Vec::new();
    for (pid, later) in second_map {
        let earlier = first_map.get(&pid);
        let cpu = match earlier {
            Some(earlier) => {
                let later_cpu = later.cpu_ns;
                let earlier_cpu = earlier.cpu_ns;
                let delta = later_cpu.saturating_sub(earlier_cpu) as f64;
                if elapsed > 0.0 {
                    (delta / 1e9) / elapsed * 100.0 / num_cpus as f64
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        // Runtime based on reported start time when available.
        let runtime = if later.start_secs > 0 {
            (uptime_secs - later.start_secs as f64).max(0.0) as u64
        } else {
            0
        };
        let user = user_from_uid(later.uid).unwrap_or_else(|| later.uid.to_string());
        processes.push(ProcessSnapshot {
            pid,
            ppid: later.ppid,
            name: later.name.clone(),
            user,
            status: later.status.clone(),
            cpu_percent: cpu.clamp(0.0, 10000.0),
            rss_bytes: later.rss_bytes,
            vmsize_bytes: later.vmsize_bytes,
            runtime_seconds: runtime,
            start_time_ticks: later.start_secs,
            threads: later.threads as u32,
            cmdline: later.cmdline.clone(),
            exe_path: later.exe_path.clone(),
            fd_count: None,
        });
    }

    processes.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(processes)
}

#[derive(Clone)]
struct TaskSample {
    pid: i32,
    ppid: i32,
    name: String,
    status: String,
    uid: u32,
    cpu_ns: u64,
    rss_bytes: u64,
    vmsize_bytes: u64,
    threads: i32,
    start_secs: u64,
    cmdline: Vec<String>,
    exe_path: Option<String>,
}

const PROC_ALL_PIDS: u32 = 1;

fn sample_processes() -> Result<Vec<TaskSample>> {
    // Grow the pid buffer until it fits all live pids.
    let mut capacity = PID_HINT.load(Ordering::Relaxed).max(256);
    let pids = loop {
        let mut buf = vec![0i32; capacity as usize];
        let n = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                buf.as_mut_ptr() as *mut libc::c_void,
                (buf.len() * std::mem::size_of::<i32>()) as libc::c_int,
            )
        };
        if n < 0 {
            bail!("proc_listpids failed");
        }
        let count = n as usize / std::mem::size_of::<i32>();
        if count as usize >= buf.len() {
            capacity = (capacity.saturating_mul(2)).max(count as u64 + 64);
            continue;
        }
        buf.truncate(count);
        break buf;
    };

    let mut out = Vec::new();
    for &pid in &pids {
        if pid <= 0 {
            continue;
        }
        if let Ok(sample) = task_sample(pid) {
            out.push(sample);
        }
    }
    PID_HINT.store(pids.len() as u64 + 64, Ordering::Relaxed);
    Ok(out)
}

fn task_sample(pid: i32) -> Result<TaskSample> {
    let mut info: libc::proc_taskallinfo = unsafe { std::mem::zeroed() };
    let sz = std::mem::size_of::<libc::proc_taskallinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKALLINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            sz,
        )
    };
    if n < sz.min(1) {
        anyhow::bail!("proc_pidinfo taskallinfo failed for pid {pid}");
    }

    let pbsd = &info.pbsd;
    let pt = &info.ptinfo;
    let name = cbuf_to_string(&pbsd.pbi_comm, 16);
    let status = match pbsd.pbi_status {
        1 => "S",
        2 => "R",
        4 => "T",
        5 => "Z",
        other => {
            let n = if other == 0 { 0 } else { other >> 8 };
            match n {
                1 => "R",
                2 => "S",
                4 => "T",
                8 => "D",
                _ => "?",
            }
        }
    }
    .to_string();

    let cmdline = read_cmdline(pid);
    let exe_path = read_exe_path(pid);

    Ok(TaskSample {
        pid,
        ppid: pbsd.pbi_ppid as i32,
        name,
        status,
        uid: pbsd.pbi_uid,
        cpu_ns: pt.pti_total_user + pt.pti_total_system,
        rss_bytes: pt.pti_resident_size,
        vmsize_bytes: pt.pti_virtual_size,
        threads: pt.pti_threadnum,
        start_secs: pbsd.pbi_start_tvsec,
        cmdline,
        exe_path,
    })
}

fn read_exe_path(pid: i32) -> Option<String> {
    let mut buf = [0i8; 4096];
    let n = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr() as *mut libc::c_void,
            libc::PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn read_cmdline(pid: i32) -> Vec<String> {
    let mut argmax: libc::c_int = 0;
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut size = std::mem::size_of::<libc::c_int>();
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr() as *mut _,
            2,
            &mut argmax as *mut _ as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Vec::new();
    }
    if argmax <= 0 || argmax > 1 << 22 {
        return Vec::new();
    }

    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut buf = vec![0u8; argmax as usize];
    let mut len = buf.len();
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr() as *mut _,
            3,
            buf.as_mut_ptr() as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Vec::new();
    }
    if len < std::mem::size_of::<libc::c_int>() {
        return Vec::new();
    }
    let argc = i32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    // A reasonable cap keeps malformed data from producing huge output.
    let argc = argc.min(256);
    let rest = &buf[4..len];
    let nuls = rest.memchr(0);
    match nuls {
        Some(first_nul) => {
            let arg0_end = first_nul;
            if arg0_end == 0 {
                return Vec::new();
            }
            let mut args = Vec::new();
            let mut i = arg0_end + 1;
            let mut collected = 0;
            while i < rest.len() && collected < argc {
                if rest[i] != 0 {
                    let start = i;
                    while i < rest.len() && rest[i] != 0 {
                        i += 1;
                    }
                    args.push(String::from_utf8_lossy(&rest[start..i]).into_owned());
                    collected += 1;
                }
                i += 1;
            }
            args
        }
        None => Vec::new(),
    }
}

trait Memchr {
    fn memchr(&self, b: u8) -> Option<usize>;
}

impl Memchr for [u8] {
    fn memchr(&self, b: u8) -> Option<usize> {
        self.iter().position(|&c| c == b)
    }
}

fn cbuf_to_string(bytes: &[libc::c_char], max: usize) -> String {
    let n = bytes
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(bytes.len());
    let n = n.min(max).min(bytes.len());
    let raw = &bytes[..n];
    let chars = raw.iter().map(|&c| c as u8).collect::<Vec<u8>>();
    String::from_utf8_lossy(&chars).into_owned()
}

fn user_from_uid(uid: u32) -> Option<String> {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbuf_to_string_trims_at_nul() {
        let buf = [b'c' as libc::c_char, b'h' as libc::c_char, 0, b'x' as libc::c_char, 0];
        assert_eq!(cbuf_to_string(&buf, 16), "ch");
    }

    #[test]
    fn cbuf_to_string_respects_max() {
        let buf = [b'a' as libc::c_char, b'b' as libc::c_char, b'c' as libc::c_char, 0];
        assert_eq!(cbuf_to_string(&buf, 2), "ab");
    }

    #[test]
    fn memchr_finds_first_nul() {
        let data = [b'a', b'b', 0, 0, b'c'];
        assert_eq!(data.memchr(0), Some(2));
        let none = [b'a', b'b'];
        assert_eq!(none.memchr(0), None);
    }
}
