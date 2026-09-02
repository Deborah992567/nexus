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
use nexus_desktop::render_frame;

const REFRESH_MS: u64 = 1500;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let nexus = Nexus::new();

    match args.first().map(String::as_str) {
        Some("version") => {
            println!("nexus-desktop {} (NEXUS TUI)", env!("CARGO_PKG_VERSION"));
        }
        Some("once") => {
            match Nexus::new().snapshot() {
                Ok(snap) => {
                    println!("{}", render_frame(&snap));
                }
                Err(e) => {
                    eprintln!("error collecting snapshot: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(other) => {
            eprintln!("unknown argument: {other} (use 'once' or 'version', or nothing for live mode)");
            std::process::exit(2);
        }
        None => live_loop(&nexus),
    }
}

/// Live dashboard loop until interrupted; uses ANSI clear for a smooth redraw.
fn live_loop(nexus: &Nexus) {
    let ok = is_tty();
    eprintln!("NEXUS Desktop — live dashboard (Ctrl-C to exit)");
    loop {
        match nexus.snapshot() {
            Ok(snap) => {
                if ok {
                    print!("\x1b[2J\x1b[H"); // clear + home
                }
                println!("{}", render_frame(&snap));
            }
            Err(e) => {
                eprintln!("[error collecting snapshot: {e}]");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(REFRESH_MS));
    }
}

fn is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}
