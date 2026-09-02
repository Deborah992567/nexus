//! NEXUS Desktop terminal UI entry point.
//!
//! A genuine, non-interactive dashboard that renders real system data
//! collected via `nexus-api`. It supports:
//!   - default: live refresh loop (clear + redraw each tick)
//!   - `nexus-desktop once`: render a single frame to stdout and exit
//!   - `nexus-desktop version`: print version marker
//!
//! No data is faked: each frame re-reads the system through the API.

use nexus_api::Nexus;
use nexus_desktop::render_full_frame;
use std::time::Duration;

const REFRESH_MS: u64 = 1500;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let nexus = Nexus::new();

    match args.first().map(String::as_str) {
        Some("version") => {
            println!("nexus-desktop {} (NEXUS TUI)", env!("CARGO_PKG_VERSION"));
        }
        Some("once") => match render_one(&nexus) {
            Ok(frame) => println!("{frame}"),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        Some(other) => {
            eprintln!("unknown argument: {other} (use 'once' or 'version', or nothing for live mode)");
            std::process::exit(2);
        }
        None => live_loop(&nexus),
    }
}

/// Fetch a snapshot + bandwidth + security and compose a full frame.
fn render_one(nexus: &Nexus) -> Result<String, String> {
    let snap = nexus.snapshot().map_err(|e| e.to_string())?;
    let bw = nexus.bandwidth(Duration::from_millis(700)).unwrap_or_default();
    let sec = nexus.security().unwrap_or_else(|_| nexus_security::assess_all(&[]));
    Ok(render_full_frame(&snap, &bw, &sec))
}

/// Live dashboard loop until interrupted; uses ANSI clear for a smooth redraw.
fn live_loop(nexus: &Nexus) {
    let ok = is_tty();
    eprintln!("NEXUS Desktop — live dashboard (Ctrl-C to exit)");
    loop {
        match render_one(nexus) {
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
