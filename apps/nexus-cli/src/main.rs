use anyhow::Result;
use nexus_core::{HealthReport, Snapshot};
use nexus_platform::detect_platform;
use nexus_resource::collect_snapshot;
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let platform = detect_platform();
    let snapshot = collect_snapshot(platform.as_ref())?;

    match args.first().map(String::as_str) {
        Some("status") => {
            println!("{}", snapshot_to_json(&snapshot));
        }
        Some("health") => {
            let report = HealthReport::from_snapshot(&snapshot);
            println!("{}", report.summary());
            println!("\n{}", report.details());
        }
        Some(cmd) => {
            eprintln!("unknown command: {cmd} (use status | health)");
            std::process::exit(2);
        }
        None => {
            eprintln!("usage: nexus <status|health>");
            std::process::exit(2);
        }
    }

    Ok(())
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
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
            format!(
                "{{\"pid\":{},\"name\":\"{}\",\"user\":\"{}\",\"status\":\"{}\",\"cpu_percent\":{:.2},\"memory_bytes\":{}}}",
                p.pid,
                esc(&p.name),
                esc(&p.user),
                esc(&p.status),
                p.cpu_percent,
                p.memory_bytes
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
