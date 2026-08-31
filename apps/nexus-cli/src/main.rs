use anyhow::Result;
use nexus_core::{HealthReport, Snapshot};
use nexus_platform::detect_platform;
use nexus_process::{anomalies_as_issues, build_tree, detect_anomalies, format_bytes, sort_by_cpu, ProcessNode};
use nexus_resource::collect_snapshot;
use nexus_storage::{analyze, format_bytes as storage_format_bytes};
use nexus_network::{bandwidth, format_rate, network_interfaces};
use nexus_diagnostics::analyze as analyze_diagnostics;
use std::env;
use std::path::Path;
use std::time::Duration;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let platform = detect_platform();
    let snapshot = collect_snapshot(platform.as_ref())?;

    match args.first().map(String::as_str) {
        Some("status") => {
            println!("{}", snapshot_to_json(&snapshot));
        }
        Some("health") => {
            let anomalies = detect_anomalies(&snapshot.processes);
            let report = HealthReport::from_snapshot(&snapshot, &anomalies_as_issues(&anomalies));
            println!("{}", report.summary());
            println!("\n{}", report.details());
        }
        Some("processes") => match args.get(1).map(String::as_str) {
            None => print_processes(&snapshot),
            Some("inspect") => {
                let pid = parse_pid(args.get(2))?;
                print_process_inspect(&snapshot, pid);
            }
            Some("tree") => print_process_tree(&snapshot),
            Some(other) => {
                eprintln!("unknown processes subcommand: {other} (use list omitted, inspect <pid>, tree)");
                std::process::exit(2);
            }
        },
        Some("storage") => {
            let root = args.get(1).cloned().unwrap_or_else(|| home_scan_root());
            print_storage(&root);
        }
        Some("network") => {
            print_network();
        }
        Some("diagnostics") => {
            let report = analyze_diagnostics(&snapshot, None);
            print_diagnostics(&report);
        }
        Some(cmd) => {
            eprintln!("unknown command: {cmd} (use status | health | processes | storage | network | diagnostics)");
            std::process::exit(2);
        }
        None => {
            eprintln!("usage: nexus <status|health|processes|storage|network|diagnostics>");
            std::process::exit(2);
        }
    }

    Ok(())
}

fn parse_pid(value: Option<&String>) -> Result<i32> {
    value
        .ok_or_else(|| anyhow::anyhow!("missing pid"))?
        .parse::<i32>()
        .map_err(Into::into)
}

fn print_processes(snapshot: &Snapshot) {
    let processes = sort_by_cpu(snapshot.processes.clone());
    println!(" PID    NAME                     CPU%   RSS      USER       STATE   RUNTIME   EXE");
    for process in processes.iter().take(30) {
        println!(
            "{:>5}  {:<24} {:>5.1}  {:>7}  {:<9} {:<6} {:>7}s  {}",
            process.pid,
            truncate(&process.name, 24),
            process.cpu_percent,
            format_megabytes(process.rss_bytes),
            truncate(&process.user, 9),
            process.status,
            process.runtime_seconds,
            process.exe_path.as_deref().unwrap_or("<unreadable>")
        );
    }

    let anomalies = detect_anomalies(&snapshot.processes);
    if !anomalies.is_empty() {
        println!("\nAnomalies:");
        for anomaly in anomalies {
            println!("- PID {}: {}", anomaly.pid, anomaly.description);
        }
    }
}

fn print_process_inspect(snapshot: &Snapshot, pid: i32) {
    match snapshot.processes.iter().find(|p| p.pid == pid) {
        Some(process) => {
            println!("Name: {}", process.name);
            println!("PID: {}", process.pid);
            println!("PPID: {}", process.ppid);
            println!("User: {}", process.user);
            println!("Status: {}", process.status);
            println!("CPU%: {:.2}", process.cpu_percent);
            println!("RSS: {}", format_bytes(process.rss_bytes));
            println!("VmSize: {}", format_bytes(process.vmsize_bytes));
            println!("Runtime: {}s", process.runtime_seconds);
            println!("Start time ticks: {}", process.start_time_ticks);
            println!("Threads: {}", process.threads);
            println!("Open FDs: {}", process.fd_count.map(|n| n.to_string()).unwrap_or_else(|| "<unreadable>".into()));
            println!("Executable: {}", process.exe_path.as_deref().unwrap_or("<unreadable>"));
            println!("Cmdline: {}", if process.cmdline.is_empty() { "<unreadable>".into() } else { process.cmdline.join(" ") });
            let children: Vec<i32> = snapshot.processes.iter().filter(|p| p.ppid == pid).map(|p| p.pid).collect();
            println!("Children: {}", if children.is_empty() { "none".into() } else { children.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ") });
            let mut notes = Vec::new();
            if process.cpu_percent > 20.0 {
                notes.push("high CPU");
            }
            if process.rss_bytes > 500 * 1024 * 1024 {
                notes.push("high memory");
            }
            println!("Flags: {}", if notes.is_empty() { "none".into() } else { notes.join(", ") });
        }
        None => {
            eprintln!("process {pid} not found");
            std::process::exit(1);
        }
    }
}

fn print_process_tree(snapshot: &Snapshot) {
    let tree = build_tree(&snapshot.processes);
    for root in tree {
        print_tree_node(&root, 0);
    }
}

fn print_tree_node(node: &ProcessNode, depth: usize) {
    let indent = "  ".repeat(depth);
    println!(
        "{}{} ({})  {:.1}%  {}",
        indent,
        node.name,
        node.pid,
        node.cpu_percent,
        format_megabytes(node.rss_bytes)
    );
    for child in &node.children {
        print_tree_node(child, depth + 1);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out = s.chars().take(max.saturating_sub(1)).collect::<String>();
        out.push('…');
        out
    }
}

fn format_megabytes(bytes: u64) -> String {
    format!("{:.1}MB", bytes as f64 / 1024.0 / 1024.0)
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn home_scan_root() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/Users".to_string())
}

fn print_storage(root: &str) {
    let root_path = Path::new(root);
    if !root_path.is_dir() {
        eprintln!("error: {root} is not a readable directory");
        std::process::exit(1);
    }
    match analyze(root_path) {
        Some(analysis) => {
            println!("STORAGE ANALYSIS — {}", root_path.display());
            println!("Total scanned: {}", storage_format_bytes(analysis.total_bytes));
            println!("Entries scanned: {}", analysis.entries_scanned);
            if analysis.entries_known > analysis.entries_scanned {
                println!("(scan truncated at {} entries)", nexus_storage::MAX_ENTRIES_PER_SCAN);
            }
            println!();

            println!("SAFE-TO-RECLAIM (read-only report; nothing deleted)");
            println!("---------------------------------------");
            for (category, size) in &analysis.reclaimable_by_category {
                println!("  {:<18} {:>12}", category.as_str(), storage_format_bytes(*size));
            }
            println!();

            if !analysis.large_files.is_empty() {
                println!("LARGE FILES");
                println!("----------");
                for item in analysis.large_files.iter().take(15) {
                    let marker = if item.safe_to_reclaim { "reclaimable" } else { "keep" };
                    println!("  {:>10}  [{:<11}] {}", storage_format_bytes(item.size_bytes), marker, item.path.display());
                }
                println!();
            }

            if analysis.reclaimable_bytes > 0 {
                println!("You have approximately {} that may be safely reclaimable across the scanned caches, temporary files, and build artifacts.", storage_format_bytes(analysis.reclaimable_bytes));
            } else {
                println!("No obviously reclaimable space was found in the scanned area.");
            }
            println!("NEXUS is read-only at this stage and will not delete anything. Cleanup actions arrive in a later phase.");
        }
        None => {
            eprintln!("error: could not scan {root}");
            std::process::exit(1);
        }
    }
}

fn print_network() {
    use nexus_network::NetworkError;

    match network_interfaces() {
        Ok(interfaces) => {
            println!("NETWORK INTERFACES");
            println!("------------------");
            println!("  {:<12} {:>12} {:>12}", "interface", "in (cum)", "out (cum)");
            for iface in &interfaces {
                println!(
                    "  {:<12} {:>12} {:>12}",
                    iface.name,
                    format_bytes(iface.cum_in_bytes as u64),
                    format_bytes(iface.cum_out_bytes as u64)
                );
            }
            println!("{} interface(s) enumerated.", interfaces.len());
            println!();

            println!("LIVE BANDWIDTH (2s sample)");
            println!("--------------------------");
            let samples = bandwidth(&mut network_interfaces, Duration::from_secs(2));
            match samples {
                Ok(samples) => {
                    if samples.is_empty() {
                        println!("  (no consistent interfaces observed)");
                    } else {
                        println!("  {:<12} {:>12} {:>12}", "interface", "in", "out");
                        for s in &samples {
                            println!(
                                "  {:<12} {:>12} {:>12}",
                                s.interface,
                                format_rate(s.bytes_in_per_sec),
                                format_rate(s.bytes_out_per_sec)
                            );
                        }
                    }
                }
                Err(NetworkError::PlatformLimited(msg)) => {
                    println!("  PLATFORM-LIMITED: {msg}");
                }
                Err(e) => {
                    println!("  error sampling bandwidth: {e}");
                }
            }
            println!();
            println!("Connection-to-process mapping and listening-port enumeration are PLATFORM-LIMITED on macOS at this stage (not faked).");
        }
        Err(e) => {
            eprintln!("error enumerating network interfaces: {e}");
            std::process::exit(1);
        }
    }
}

fn print_diagnostics(report: &nexus_diagnostics::DiagnosticReport) {
    use nexus_diagnostics::Severity;
    println!("DIAGNOSTICS — {}", report.platform);
    println!("Overall: {}", report.overall.as_str());
    println!();
    for finding in &report.findings {
        let marker = match finding.severity {
            Severity::Critical => "!!",
            Severity::Warning => "! ",
            Severity::Info => "ok",
        };
        println!("[{marker}] {}: {}", finding.severity.as_str(), finding.title);
        println!("      {}", finding.explanation);
        for ev in &finding.evidence {
            println!("      evidence: {ev}");
        }
        println!("      next: {}", finding.suggested_action);
        println!();
    }
}

fn snapshot_to_json(snapshot: &Snapshot) -> String {
    let disks = snapshot
        .disks
        .iter()
        .map(|d| {
            format!(
                "{{\"mount_point\":\"{}\",\"fs_type\":\"{}\",\"total_bytes\":{},\"available_bytes\":{},\"used_bytes\":{},\"usage_percent\":{:.2}}}",
                esc(&d.mount_point),
                esc(&d.fs_type),
                d.total_bytes,
                d.available_bytes,
                d.used_bytes,
                d.usage_percent
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let processes = snapshot
        .processes
        .iter()
        .take(20)
        .map(|p| {
            let cmdline = p.cmdline.iter().map(|s| format!("\"{}\"", esc(s))).collect::<Vec<_>>().join(",");
            format!(
                "{{\"pid\":{},\"ppid\":{},\"name\":\"{}\",\"user\":\"{}\",\"status\":\"{}\",\"cpu_percent\":{:.2},\"rss_bytes\":{},\"vmsize_bytes\":{},\"runtime_seconds\":{},\"start_time_ticks\":{},\"threads\":{},\"cmdline\":[{}],\"exe_path\":{},\"fd_count\":{}}}",
                p.pid,
                p.ppid,
                esc(&p.name),
                esc(&p.user),
                esc(&p.status),
                p.cpu_percent,
                p.rss_bytes,
                p.vmsize_bytes,
                p.runtime_seconds,
                p.start_time_ticks,
                p.threads,
                cmdline,
                p.exe_path.as_ref().map(|v| format!("\"{}\"", esc(v))).unwrap_or_else(|| "null".into()),
                p.fd_count.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"platform\":\"{}\",\"uptime_seconds\":{},\"cpu\":{{\"usage_percent\":{:.2},\"cores\":{}}},\"memory\":{{\"total_bytes\":{},\"available_bytes\":{},\"used_bytes\":{}}},\"disks\":[{}],\"processes\":[{}]}}",
        esc(&snapshot.platform),
        snapshot.uptime_seconds,
        snapshot.cpu.usage_percent,
        snapshot.cpu.cores,
        snapshot.memory.total_bytes,
        snapshot.memory.available_bytes,
        snapshot.memory.used_bytes,
        disks,
        processes
    )
}
