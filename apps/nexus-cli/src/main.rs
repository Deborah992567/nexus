use anyhow::Result;
use nexus_core::{HealthReport, Snapshot};
use nexus_platform::detect_platform;
use nexus_process::{anomalies_as_issues, build_tree, detect_anomalies, format_bytes, sort_by_cpu, ProcessNode};
use nexus_resource::collect_snapshot;
use nexus_storage::{analyze, format_bytes as storage_format_bytes};
use nexus_network::{bandwidth, format_rate, network_interfaces};
use nexus_diagnostics::analyze as analyze_diagnostics;
use nexus_security::assess_all;
use nexus_actions::ActionEngine;
use nexus_audit::AuditLog;
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
        Some("security") => {
            let report = assess_all(&snapshot.processes);
            print_security(&report);
        }
        Some("audit") => {
            print_audit();
        }
        Some("act") => {
            act(&args[1..]);
        }
        Some("advice") => {
            let storage = analyze(Path::new(&home_scan_root()));
            let report = analyze_diagnostics(&snapshot, storage.as_ref());
            let security = assess_all(&snapshot.processes);
            print_advice(&report, &security, storage.as_ref());
        }
        Some("sandbox") => {
            sandbox(args.get(1).map(String::as_str));
        }
        Some("mode") => {
            mode_cmd(args.get(1).map(String::as_str));
        }
        Some("config") => {
            config_cmd();
        }
        Some(cmd) => {
            eprintln!("unknown command: {cmd} (use status | health | processes | storage | network | diagnostics | security | audit | act | advice | sandbox | mode | config)");
            std::process::exit(2);
        }
        None => {
            match nexus_config::ConfigStore::load().mode() {
                nexus_config::Mode::Simple => simple_overview(&snapshot),
                nexus_config::Mode::Developer => {
                    print_usage();
                }
            }
        }
    }

    Ok(())
}

/// Developer-mode: show the full command reference.
fn print_usage() {
    println!("NEXUS — system observability (current mode: developer)");
    println!();
    println!("commands:");
    println!("  status        JSON snapshot (CPU/mem/disk/processes)");
    println!("  health        summary + issues");
    println!("  processes     top processes (list | inspect <pid> | tree)");
    println!("  storage       storage analysis of a path (default: home)");
    println!("  network       interface counters + live bandwidth");
    println!("  diagnostics   correlated diagnosis of the current snapshot");
    println!("  security      evidence-based process risk assessment");
    println!("  advice        advisory recommendations with evidence");
    println!("  audit         the persisted action journal");
    println!("  act           plan/execute a policy-checked action");
    println!("  sandbox       OS-level sandboxing status + demo");
    println!("  mode          show or change UI mode (simple | developer)");
    println!("  config        show persisted configuration");
    println!();
    println!("run 'nexus <command> --help' style hints; try: nexus mode simple");
}

/// Simple-mode: a friendly plain-language overview with no raw internals.
fn simple_overview(snapshot: &Snapshot) {
    use nexus_process::format_bytes;
    println!("NEXUS (Simple Mode)");
    println!("--------------------");
    let anomalies = detect_anomalies(&snapshot.processes);
    let health = HealthReport::from_snapshot(snapshot, &anomalies_as_issues(&anomalies));
    println!("Overall status: {}", health.status);
    println!("Health score:   {}/100", health.score);
    println!("CPU usage:      {:.1}%", snapshot.cpu.usage_percent);
    println!(
        "Memory:         {} used of {}",
        format_bytes(snapshot.memory.used_bytes),
        format_bytes(snapshot.memory.total_bytes)
    );
    println!("Processes:      {}", snapshot.processes.len());
    if !health.issues.is_empty() {
        println!();
        println!("Things to look at:");
        for issue in &health.issues {
            println!("  - {issue}");
        }
    } else {
        println!();
        println!("Nothing looks out of the ordinary right now.");
    }
    println!();
    println!("For full control, switch to Developer mode: nexus mode developer");
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

fn print_security(report: &nexus_security::SecurityReport) {
    use nexus_security::RiskLevel;

    println!("SECURITY ASSESSMENT");
    println!("-------------------");
    println!(
        "Assessed {} process(es): {} low, {} medium, {} high.",
        report.assessed, report.low, report.medium, report.high
    );

    let flagged: Vec<_> = report.assessments.iter().filter(|a| !a.signals.is_empty()).collect();
    if flagged.is_empty() {
        println!("No suspicious signals detected in the sampled processes.");
    } else {
        println!();
        for a in flagged {
            let marker = match a.risk {
                RiskLevel::High => "!!",
                RiskLevel::Medium => "! ",
                RiskLevel::Low => "  ",
            };
            println!("[{marker}] {} (pid {}) — {} risk, score {:.2}", a.name, a.pid, a.risk.as_str(), a.score);
            for s in &a.signals {
                println!("     - [{}] conf {:.2}: {}", s.kind.as_str(), s.confidence, s.explanation);
            }
            println!();
        }
    }

    println!("NOTE: These are evidence-based signals from process telemetry. NEXUS does not claim any process is malware without real evidence. Deeper monitoring (privilege escalation, file-access, syscalls) requires elevated privileges and is PLATFORM-LIMITED at this stage.");
}

fn print_audit() {
    let path = AuditLog::default_path();
    println!("AUDIT LOG — {}", path.display());
    println!("------------------");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            println!("No audit file found yet. Actions performed with 'nexus act' will appear here.");
            return;
        }
    };
    // The audit file is append-only JSONL. Print each record, numbered.
    let mut count = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        count += 1;
        println!("#{count}: {line}");
    }
    if count == 0 {
        println!("No actions recorded yet. Actions performed with 'nexus act' will appear here.");
    }
}

fn persistent_engine() -> ActionEngine {
    // The CLI runner is authorized to change system state only when an
    // action is explicitly confirmed (see act()). Reads/writes the default
    // local audit log.
    let log = AuditLog::at(AuditLog::default_path()).unwrap_or_else(|_| AuditLog::memory());
    ActionEngine::new(log, true)
}

fn resolve_action(action: &str, target: &str) -> Option<nexus_actions::Action> {
    match action {
        "stop" => target.parse::<i32>().ok().map(|pid| nexus_actions::Action::StopProcess { pid }),
        "kill" => target.parse::<i32>().ok().map(|pid| nexus_actions::Action::KillProcess { pid }),
        "delete" => Some(nexus_actions::Action::DeleteFile { path: target.to_string() }),
        _ => None,
    }
}

fn sandbox(sub: Option<&str>) {
    use std::path::Path;

    let supported = nexus_sandbox::supports_sandbox();
    match sub {
        None => {
            println!("NEXUS SANDBOX");
            println!("-------------");
            match nexus_sandbox::find_sandbox_exec() {
                Some(p) => println!("mechanism: {} (seatbelt MAC)", p.display()),
                None => println!("mechanism: NONE — OS-level sandboxing not available on this host"),
            }
            println!("supported: {}", if supported { "yes" } else { "no" });
            println!();
            println!("subcommands:");
            println!("  nexus sandbox status        show mechanism + available profiles");
            println!("  nexus sandbox demo          run a genuine write-deny demonstration");
            if !supported {
                println!();
                println!("This host provides no sandbox mechanism; NEXUS will not fake enforcement.");
            }
        }
        Some("status") => {
            let profiles = [
                ("network_isolation", "denies all network access"),
                ("read_only", "denies all file writes (reads/exec allowed)"),
                ("isolated", "denies network + file writes"),
            ];
            println!("MECHANISM: {}", if supported { "seatbelt (sandbox-exec)" } else { "unavailable" });
            if supported {
                println!("AVAILABLE PROFILES:");
                for (name, desc) in profiles {
                    println!("  {:<18} {desc}", name);
                }
            } else {
                println!("No sandbox mechanism detected. No profile can be enforced honestly.");
            }
        }
        Some("demo") => {
            if !supported {
                eprintln!("Cannot demonstrate: this host has no sandbox mechanism.");
                std::process::exit(1);
            }
            // Control: a write is permitted outside the sandbox.
            let target = std::env::temp_dir().join(format!("nexus_demo_{}.txt", std::process::id()));
            let _ = std::fs::remove_file(&target);
            std::fs::write(&target, "control").expect("control write");
            println!("control: wrote {}", target.display());
            // Sandboxed: the same write is denied.
            let _ = std::fs::remove_file(&target);
            let profile =
                nexus_sandbox::SandboxProfile::read_only("cli-demo");
            let run = nexus_sandbox::run_boxed(
                &profile,
                Path::new("/bin/sh"),
                &["-c", &format!("echo x > {}", target.display())],
            );
            match run {
                Ok(r) => {
                    println!("sandboxed write attempted -> enforced={}", r.enforced);
                    let exists = target.exists();
                    println!("file created: {} (must be false for enforcement)", exists);
                    if exists {
                        println!("WARNING: write was NOT blocked!");
                        std::process::exit(1);
                    }
                    println!("policy applied: {}", r.policy);
                    println!("RESULT: write genuinely denied by seatbelt.");
                }
                Err(e) => {
                    eprintln!("sandbox error: {e}");
                    std::process::exit(1);
                }
            }
            let _ = std::fs::remove_file(&target);
        }
        Some(other) => {
            eprintln!("unknown sandbox subcommand: {other} (use status | demo)");
            std::process::exit(2);
        }
    }
}

fn mode_cmd(mode: Option<&str>) {
    use nexus_config::{ConfigStore, Mode};
    let mut store = ConfigStore::load();
    match mode {
        None => {
            println!("NEXUS UI MODE");
            println!("-------------");
            println!("current:     {}", store.mode().as_str());
            println!("confirmation: {}", store.config().confirmation.as_str());
            println!("sandbox_auto_ok: {}", store.config().sandbox_auto_ok);
            println!("scan_limit:  {}", store.config().scan_limit);
            println!();
            println!("change with: nexus mode simple | nexus mode developer");
        }
        Some(m) => match Mode::from_str(m) {
            Some(target) => {
                match store.set_mode(target) {
                    Ok(_) => println!("Mode set to '{}' and saved to {}.", target.as_str(), store.path().display()),
                    Err(e) => {
                        eprintln!("failed to save config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            None => {
                eprintln!("unknown mode: {m} (use simple | developer)");
                std::process::exit(2);
            }
        },
    }
}

fn config_cmd() {
    use nexus_config::ConfigStore;
    let store = ConfigStore::load();
    println!("NEXUS CONFIG — {}", store.path().display());
    println!("----------------------");
    let c = store.config();
    println!("mode            = {}", c.mode.as_str());
    println!("confirmation    = {}", c.confirmation.as_str());
    println!("sandbox_auto_ok = {}", c.sandbox_auto_ok);
    println!("scan_limit      = {}", c.scan_limit);
}

fn act(args: &[String]) {
    let command = match args.first() {
        Some(v) => v.as_str(),
        None => {
            eprintln!("usage: nexus act <plan|stop|kill|delete> <target> [--yes]");
            std::process::exit(2);
        }
    };
    let confirmed = args.iter().any(|a| a == "--yes");

    match command {
        "plan" => {
            let action_name = args.get(1).map(String::as_str).unwrap_or("");
            let target_val = args.get(2).map(String::as_str).unwrap_or("");
            let action = match resolve_action(action_name, target_val) {
                Some(a) => a,
                None => {
                    eprintln!("unknown/unsupported action for plan. Use e.g. 'nexus act plan stop 123'.");
                    std::process::exit(2);
                }
            };
            let engine = persistent_engine();
            match engine.plan(&action) {
                Ok(plan) => {
                    println!("ACTION PLAN");
                    println!("-----------");
                    println!("action:     {}", plan.action.describe());
                    println!("risk:       {}", plan.risk.as_str());
                    println!("reversible: {}", plan.reversible);
                    println!("confirm:    {}", if plan.confirmation_required { "REQUIRED" } else { "not required" });
                    println!("{}", plan.permission.reason);
                    println!();
                    println!("To execute (a real, verified system change):");
                    println!("  nexus act {action_name} {target_val} --yes");
                }
                Err(e) => {
                    eprintln!("cannot plan action: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            let action = match args.get(1).and_then(|a| {
                let name = command;
                let target = a.as_str();
                resolve_action(name, target)
            }) {
                Some(a) => a,
                None => {
                    eprintln!("unknown action '{command}' or missing target");
                    std::process::exit(2);
                }
            };
            let mut engine = persistent_engine();
            let plan = match engine.plan(&action) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cannot plan: {e}");
                    std::process::exit(1);
                }
            };
            if !confirmed {
                eprintln!(
                    "Refusing to execute without --yes. This is a {}-risk, reversible={} action.",
                    plan.risk.as_str(),
                    plan.reversible
                );
                eprintln!("Review the plan first: nexus act plan {command} {}", args.get(1).map(String::as_str).unwrap_or(""));
                std::process::exit(2);
            }
            match engine.execute(&plan, true, "User requested via CLI") {
                Ok(detail) if detail.success => {
                    println!("SUCCESS: {}", detail.message);
                    println!("(recorded in audit log)");
                }
                Ok(detail) => {
                    eprintln!("NOT EXECUTED: {}", detail.message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("ACTION FAILED: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn print_advice(
    report: &nexus_diagnostics::DiagnosticReport,
    security: &nexus_security::SecurityReport,
    storage: Option<&nexus_storage::StorageAnalysis>,
) {
    use nexus_ai::analyze_local;

    println!("NEXUS ADVISOR");
    println!("-------------");
    let (info, recs) = analyze_local(&report, Some(security), storage);
    println!("model: {} ({})", info.model_id, info.backend);
    println!("disclaimer: {}", info.disclaimer);
    println!();

    if recs.is_empty() {
        println!("No actionable recommendations right now. NEXUS only advises on real, evidence-backed findings.");
        return;
    }
    for (i, r) in recs.iter().enumerate() {
        println!(
            "{} {:<12} [{}] {}",
            i + 1,
            r.kind.as_str(),
            r.remedy_risk.as_deref().unwrap_or("n/a"),
            r.summary
        );
        println!("     target: {}", r.target);
        for reason in &r.rationale {
            println!("     because: {reason}");
        }
        for ev in &r.evidence {
            println!("     evidence: {ev}");
        }
        println!("     proposed action: {} (advisory only; review before running)", r.suggested_action);
        println!("     via: `nexus act plan {} <target> --yes`", r.suggested_action);
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
