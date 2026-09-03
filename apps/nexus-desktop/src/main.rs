//! NEXUS Desktop terminal UI entry point.
//!
//! A genuine, non-interactive dashboard that renders real system data
//! collected via `nexus-api`. It supports:
//!   - default: live refresh loop (clear + redraw each tick)
//!   - `once`: render a single frame to stdout and exit
//!   - `version`: print version marker
//!
//! The dashboard honors the persisted UI mode (Simple vs Developer) from
//! `nexus-config`: Simple renders a concise frame, Developer the richer set.
//! A `--simple` / `--developer` flag overrides the saved mode for a run.
//!
//! No data is faked: each frame re-reads the system through the API.

use nexus_api::Nexus;
use nexus_config::{ConfigStore, Mode};
use nexus_desktop::{render_frame, render_full_frame};
use std::time::Duration;

const REFRESH_MS: u64 = 1500;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // Honor an explicit mode override for this run.
    let override_mode = if args.iter().any(|a| a == "--developer") {
        Some(Mode::Developer)
    } else if args.iter().any(|a| a == "--simple") {
        Some(Mode::Simple)
    } else {
        None
    };
    args.retain(|a| a != "--developer" && a != "--simple");

    let mode = override_mode.unwrap_or_else(|| ConfigStore::load().mode());
    let nexus = Nexus::new();

    match args.first().map(String::as_str) {
        Some("version") => {
            println!("nexus-desktop {} (NEXUS TUI)", env!("CARGO_PKG_VERSION"));
        }
        Some("mode") => {
            println!("dashboard mode: {} (persisted: config.conf)", mode.as_str());
        }
        Some("health") => match nexus.health() {
            Ok(h) => {
                println!("health: {}/100 ({})", h.score, h.status);
                for issue in &h.issues {
                    println!("  - {issue}");
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        Some("once") => match render_one(&nexus, mode) {
            Ok(frame) => println!("{frame}"),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        Some(other) => {
            eprintln!("unknown argument: {other} (use 'once' | 'mode' | 'version', or nothing for live mode; add --simple/--developer)");
            std::process::exit(2);
        }
        None => live_loop(&nexus, mode),
    }
}

/// Fetch snapshot (+ bandwidth/security in Developer) and render a frame.
fn render_one(nexus: &Nexus, mode: Mode) -> Result<String, String> {
    let snap = nexus.snapshot().map_err(|e| e.to_string())?;
    match mode {
        Mode::Simple => Ok(render_frame(&snap)),
        Mode::Developer => {
            let bw = nexus.bandwidth(Duration::from_millis(700)).unwrap_or_default();
            let sec = nexus.security().unwrap_or_else(|_| nexus_security::assess_all(&[]));
            Ok(render_full_frame(&snap, &bw, &sec))
        }
    }
}

/// Live dashboard loop until interrupted; uses ANSI clear for a smooth redraw.
fn live_loop(nexus: &Nexus, mode: Mode) {
    let ok = is_tty();
    eprintln!("NEXUS Desktop — live dashboard ({}) (Ctrl-C to exit)", mode.as_str());
    loop {
        match render_one(nexus, mode) {
            Ok(frame) => {
                if ok {
                    print!("\x1b[2J\x1b[H"); // clear + home
                }
                println!("{frame}");
            }
            Err(e) => {
                eprintln!("[error: {e}]");
            }
        }
        std::thread::sleep(Duration::from_millis(REFRESH_MS));
    }
}

fn is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}
