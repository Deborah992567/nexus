use anyhow::{Context, Result};
use nexus_core::{CpuSnapshot, DiskSnapshot, MemorySnapshot, ProcessSnapshot};
use nexus_process::{anomalies_as_issues, detect_anomalies};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::thread;
use std::time::Duration;

use super::SystemPlatform;

#[derive(Default)]
pub struct LinuxPlatform;

impl SystemPlatform for LinuxPlatform {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn cpu_snapshot(&self) -> Result<CpuSnapshot> {
        cpu_snapshot()
    }

    fn memory_snapshot(&self) -> Result<MemorySnapshot> {
        memory_snapshot()
    }

    fn disk_snapshot(&self) -> Result<Vec<DiskSnapshot>> {
        disk_snapshot()
    }

    fn uptime(&self) -> Result<Duration> {
        uptime()
    }

    fn processes(&self) -> Result<Vec<ProcessSnapshot>> {
        processes()
    }
}

fn read_to_string(path: &str) -> Result<String> {
    Ok(fs::read_to_string(path).with_context(|| format!("read {path}"))?)
}

fn cpu_snapshot() -> Result<CpuSnapshot> {
    let (idle1, total1) = proc_stat()?;
    thread::sleep(Duration::from_millis(120));
    let (idle2, total2) = proc_stat()?;
    let idle = idle2.saturating_sub(idle1) as f64;
    let total = total2.saturating_sub(total1) as f64;
    let usage = if total > 0.0 { (1.0 - idle / total) * 100.0 } else { 0.0 };
    Ok(CpuSnapshot {
        usage_percent: usage.clamp(0.0, 100.0),
        cores: num_cpus(),
    })
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn proc_stat() -> Result<(u64, u64)> {
    let content = read_to_string("/proc/stat")?;
    let line = content.lines().find(|l| l.starts_with("cpu ")).context("cpu line")?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    if fields.len() < 4 {
        anyhow::bail!("unexpected /proc/stat format");
    }
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    let total: u64 = fields.iter().sum();
    Ok((idle, total))
}

fn memory_snapshot() -> Result<MemorySnapshot> {
    let content = read_to_string("/proc/meminfo")?;
    let map: HashMap<_, _> = content
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ':');
            let key = parts.next()?;
            let val = parts.next()?.trim();
            Some((key.to_string(), val.to_string()))
        })
        .collect();
    let total = parse_kb(&map, "MemTotal")?;
    let available = map
        .get("MemAvailable")
        .map(|v| {
            v.split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0)
                * 1024
        })
        .unwrap_or(0);
    let used = total.saturating_sub(available);
    Ok(MemorySnapshot {
        total_bytes: total,
        available_bytes: available,
        used_bytes: used,
    })
}

fn parse_kb(map: &HashMap<String, String>, k: &str) -> Result<u64> {
    let raw = map.get(k).ok_or_else(|| anyhow::anyhow!("missing {k}"))?;
    let n = raw
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing value {k}"))?
        .parse::<u64>()?;
    Ok(n * 1024)
}

fn disk_snapshot() -> Result<Vec<DiskSnapshot>> {
    let mounts = read_mounts()?;
    let mut out = Vec::new();
    for (mount, fs_type) in mounts {
        if let Ok(stat) = statvfs_for(&mount) {
            let total = stat.block_size.saturating_mul(stat.blocks);
            let available = stat.block_size.saturating_mul(stat.blocks_available);
            let used = total.saturating_sub(available);
            let usage = if total > 0 {
                used as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            out.push(DiskSnapshot {
                mount_point: mount,
                fs_type,
                total_bytes: total,
                available_bytes: available,
                used_bytes: used,
                usage_percent: usage,
            });
        }
    }
    Ok(out)
}

#[derive(Clone, Copy)]
struct StatVfsLite {
    block_size: u64,
    blocks: u64,
    blocks_available: u64,
}

fn statvfs_for(path: &str) -> Result<StatVfsLite> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    let c_path = CString::new(path)?;
    let mut s = MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), s.as_mut_ptr()) };
    if rc != 0 {
        anyhow::bail!("statvfs failed for {path}");
    }
    let s = unsafe { s.assume_init() };
    Ok(StatVfsLite {
        block_size: s.f_frsize as u64,
        blocks: s.f_blocks as u64,
        blocks_available: s.f_bavail as u64,
    })
}

fn read_mounts() -> Result<Vec<(String, String)>> {
    let mut mounts = Vec::new();
    let content = read_to_string("/proc/mounts")?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let _source = parts.next();
        let mount = parts.next().unwrap_or("/");
        let fs_type = parts.next().unwrap_or("unknown");
        mounts.push((mount.to_string(), fs_type.to_string()));
    }
    mounts.sort();
    mounts.dedup_by(|a, b| a.0 == b.0);
    Ok(mounts)
}

fn uptime() -> Result<Duration> {
    let content = read_to_string("/proc/uptime")?;
    let secs = content
        .split_whitespace()
        .next()
        .context("uptime")?
        .parse::<f64>()?;
    Ok(Duration::from_secs_f64(secs))
}

fn processes() -> Result<Vec<ProcessSnapshot>> {
    let clk = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let first = sample_processes(clk, page_size)?;
    thread::sleep(Duration::from_millis(120));
    let second = sample_processes(clk, page_size)?;

    let uptime_secs = uptime()?.as_secs_f64();
    let first_map: HashMap<i32, ProcessSample> = first.into_iter().map(|p| (p.pid, p)).collect();
    let second_map: HashMap<i32, ProcessSample> = second.into_iter().map(|p| (p.pid, p)).collect();

    let mut processes = Vec::new();
    for (pid, later) in second_map {
        if let Some(earlier) = first_map.get(&pid) {
            processes.push(to_snapshot(&later, Some(earlier), clk, uptime_secs, page_size));
        }
    }

    let anomalies = anomalies_as_issues(&detect_anomalies(&processes));
    if !anomalies.is_empty() {
        eprintln!("process anomalies detected: {}", anomalies.len());
    }

    processes.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(processes)
}

#[derive(Clone)]
struct ProcessSample {
    pid: i32,
    ppid: i32,
    name: String,
    status: String,
    uid: u32,
    utime: f64,
    stime: f64,
    starttime: f64,
    vmsize_bytes: u64,
    rss_bytes: u64,
    threads: u32,
    cmdline: Vec<String>,
    exe_path: Option<String>,
    fd_count: Option<usize>,
}

fn sample_processes(clk: f64, page_size: u64) -> Result<Vec<ProcessSample>> {
    let mut out = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let pid: i32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(sample) = process_sample(pid, clk, page_size) {
            out.push(sample);
        }
    }
    Ok(out)
}

fn process_sample(pid: i32, _clk: f64, page_size: u64) -> Result<ProcessSample> {
    let stat = read_to_string(&format!("/proc/{pid}/stat"))?;
    let status = read_to_string(&format!("/proc/{pid}/status")).unwrap_or_default();
    let comm_start = stat.find('(').context("stat comm start")?;
    let comm_end = stat.rfind(')').context("stat comm end")?;
    let name = stat[comm_start + 1..comm_end].to_string();
    let rest = stat[comm_end + 2..].split_whitespace().collect::<Vec<_>>();
    let state = rest.get(0).copied().unwrap_or("?").to_string();
    let ppid: i32 = rest.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    let utime: f64 = rest.get(11).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let stime: f64 = rest.get(12).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let num_threads: u32 = rest.get(17).and_then(|v| v.parse().ok()).unwrap_or(0);
    let starttime: f64 = rest.get(19).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let vmsize_bytes: u64 = rest.get(20).and_then(|v| v.parse().ok()).unwrap_or(0);
    let rss_pages: u64 = rest.get(21).and_then(|v| v.parse().ok()).unwrap_or(0);
    let rss_bytes = rss_pages.saturating_mul(page_size);
    let uid = extract_uid(&status).unwrap_or(0);
    let cmdline = read_cmdline(pid).unwrap_or_default();
    let exe_path = read_exe_path(pid);
    let fd_count = count_fds(pid);

    Ok(ProcessSample {
        pid,
        ppid,
        name,
        status: state,
        uid,
        utime,
        stime,
        starttime,
        vmsize_bytes,
        rss_bytes,
        threads: num_threads,
        cmdline,
        exe_path,
        fd_count,
    })
}

fn to_snapshot(
    later: &ProcessSample,
    earlier: Option<&ProcessSample>,
    clk: f64,
    uptime_secs: f64,
    _page_size: u64,
) -> ProcessSnapshot {
    let cpu_percent = if let Some(earlier) = earlier {
        let later_ticks = later.utime + later.stime;
        let earlier_ticks = earlier.utime + earlier.stime;
        let delta_ticks = (later_ticks - earlier_ticks).max(0.0);
        let elapsed_seconds = 0.120_f64;
        if elapsed_seconds > 0.0 {
            (delta_ticks / clk) / elapsed_seconds * 100.0 / num_cpus() as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    let runtime_seconds = (uptime_secs - later.starttime / clk).max(0.0) as u64;
    let user = user_from_uid(later.uid).unwrap_or_else(|| later.uid.to_string());

    ProcessSnapshot {
        pid: later.pid,
        ppid: later.ppid,
        name: later.name.clone(),
        user,
        status: later.status.clone(),
        cpu_percent: cpu_percent.clamp(0.0, 10000.0),
        rss_bytes: later.rss_bytes,
        vmsize_bytes: later.vmsize_bytes,
        runtime_seconds,
        start_time_ticks: later.starttime as u64,
        threads: later.threads,
        cmdline: later.cmdline.clone(),
        exe_path: later.exe_path.clone(),
        fd_count: later.fd_count,
    }
}

fn read_cmdline(pid: i32) -> Result<Vec<String>> {
    let path = format!("/proc/{pid}/cmdline");
    let bytes = fs::read(path)?;
    Ok(bytes
        .split(|b| *b == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect())
}

fn read_exe_path(pid: i32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

fn count_fds(pid: i32) -> Option<usize> {
    fs::read_dir(format!("/proc/{pid}/fd")).ok().map(|iter| iter.count())
}

fn extract_uid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn user_from_uid(uid: u32) -> Option<String> {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        let name = CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned();
        Some(name)
    }
}
