//! NEXUS Network Intelligence.
//!
//! Phase 4 of the roadmap. This crate reports real network information from
//! the operating system. It currently implements:
//!
//! - per-interface byte counters via the sysctl route/interface table
//!   (`NET_RT_IFLIST2` / `if_msghdr2`), which yield real cumulative inbound
//!   and outbound bytes; two samples produce a live bandwidth rate.
//!
//! Connection-to-process mapping and listening-port enumeration are real on
//! macOS only through the (privileged) `libproc` socket FD introspection, and
//! on Linux through `/proc/net/tcp`. Those are intentionally marked as
//! `PLATFORM-LIMITED` rather than faked.
//!
//! Design principle: metrics come from OS sources. Nothing is simulated.

use std::ffi::CStr;
use std::time::Duration;
use thiserror::Error;

/// A physical/virtual network interface with its cumulative byte counters.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub cum_in_bytes: u64,
    pub cum_out_bytes: u64,
}

/// Bandwidth observed over a sampling window for one interface.
#[derive(Debug, Clone)]
pub struct BandwidthSample {
    pub interface: String,
    pub window: Duration,
    pub bytes_in_per_sec: f64,
    pub bytes_out_per_sec: f64,
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network interface enumeration failed: {0}")]
    Enumeration(String),
    #[error("interfaces changed between samples")]
    Changed,
    #[error("feature not supported on this platform: {0}")]
    PlatformLimited(&'static str),
}

/// Darwin's `NET_RT_IFLIST2`, not exposed by the `libc` crate.
const NET_RT_IFLIST2: libc::c_int = 6;
const RTM_IFINFO2: libc::c_int = 0x12;

/// Enumerate network interfaces and their cumulative byte counters using the
/// sysctl route interface table. Only implemented for `target_os = "macos"`.
#[cfg(target_os = "macos")]
pub fn network_interfaces() -> Result<Vec<NetworkInterface>, NetworkError> {
    let mut mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        0,
        NET_RT_IFLIST2,
        0,
    ];

    // First call sizes the buffer.
    let mut needed: libc::size_t = 0;
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || needed == 0 {
        return Err(NetworkError::Enumeration(
            "sysctl sizing NET_RT_IFLIST2 failed".into(),
        ));
    }

    // Allocate a buffer aligned sufficiently for the message structs.
    let mut buf = Vec::<u8>::with_capacity(needed);
    buf.resize(needed, 0);
    let mut len = needed;
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(NetworkError::Enumeration(
            "sysctl NET_RT_IFLIST2 failed".into(),
        ));
    }

    Ok(parse_if_msgs(&buf, len))
}

#[cfg(not(target_os = "macos"))]
pub fn network_interfaces() -> Result<Vec<NetworkInterface>, NetworkError> {
    Err(NetworkError::PlatformLimited("interface enumeration"))
}

#[cfg(target_os = "macos")]
fn parse_if_msgs(buf: &[u8], len: usize) -> Vec<NetworkInterface> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let min_hdr = std::mem::size_of::<libc::if_msghdr2>();
    while offset + 4 <= len {
        // if_msghdr2 is packed(4). Prefix layout: u16 msglen, u8 version,
        // u8 type. The type byte is therefore at offset +3.
        let msglen = read_u16(buf, offset) as usize;
        if msglen == 0 || msglen < 4 {
            break;
        }
        if offset + msglen > len {
            break;
        }
        let msgtype = buf[offset + 3];
        if msgtype as libc::c_int == RTM_IFINFO2 && msglen >= min_hdr {
            // The sysctl buffer is not guaranteed to be aligned to the struct
            // alignment, so use read_unaligned (valid for repr(packed(4))).
            let msg: libc::if_msghdr2 =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const libc::if_msghdr2) };
            let name = ifname_for_index(msg.ifm_index);
            out.push(NetworkInterface {
                name: name.clone(),
                index: msg.ifm_index as u32,
                cum_in_bytes: msg.ifm_data.ifi_ibytes,
                cum_out_bytes: msg.ifm_data.ifi_obytes,
            });
        }
        offset += msglen;
    }
    out
}

#[cfg(target_os = "macos")]
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    if offset + 2 <= buf.len() {
        u16::from_ne_bytes([buf[offset], buf[offset + 1]])
    } else {
        0
    }
}

#[cfg(target_os = "macos")]
fn ifname_for_index(index: u16) -> String {
    // A fixed-size name buffer works for typical interface names; the
    // if_nameindex interface would be more robust but requires iterating a
    // linked list of names.
    let mut name = [0u8; 64];
    let len = unsafe {
        libc::if_indextoname(
            index as libc::c_uint,
            name.as_mut_ptr() as *mut libc::c_char,
        )
    };
    if len.is_null() {
        format!("if{index}")
    } else {
        unsafe { CStr::from_ptr(name.as_ptr() as *const libc::c_char) }
            .to_string_lossy()
            .into_owned()
    }
}

/// Compute per-interface bandwidth by sampling cumulative counters twice and
/// dividing the delta by the window duration. Consistent interfaces (matched
/// by name) are reported; interfaces that appear or disappear are skipped.
pub fn bandwidth<F>(
    mut sampler: F,
    window: Duration,
) -> Result<Vec<BandwidthSample>, NetworkError>
where
    F: FnMut() -> Result<Vec<NetworkInterface>, NetworkError>,
{
    let first = sampler()?;
    std::thread::sleep(window);
    let second = sampler()?;
    let window_secs = window.as_secs_f64().max(1e-6);

    let mut out = Vec::new();
    for a in &first {
        if let Some(b) = second.iter().find(|b| b.name == a.name && b.index == a.index) {
            let in_rate = b.cum_in_bytes.saturating_sub(a.cum_in_bytes) as f64 / window_secs;
            let out_rate = b.cum_out_bytes.saturating_sub(a.cum_out_bytes) as f64 / window_secs;
            out.push(BandwidthSample {
                interface: a.name.clone(),
                window,
                bytes_in_per_sec: in_rate,
                bytes_out_per_sec: out_rate,
            });
        }
    }
    Ok(out)
}

/// Format a bytes-per-second rate into a human-friendly string.
pub fn format_rate(bps: f64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    const KIB: f64 = 1024.0;
    if bps >= MIB {
        format!("{:.2} MiB/s", bps / MIB)
    } else if bps >= KIB {
        format!("{:.1} KiB/s", bps / KIB)
    } else {
        format!("{:.0} B/s", bps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_rate_is_human_readable() {
        assert_eq!(format_rate(0.0), "0 B/s");
        assert_eq!(format_rate(500.0), "500 B/s");
        assert_eq!(format_rate(2048.0), "2.0 KiB/s");
        assert_eq!(format_rate(5.0 * 1024.0 * 1024.0), "5.00 MiB/s");
    }

    #[test]
    fn parse_if_msgs_tolerates_short_buffer() {
        // Empty / incomplete buffers must not panic and return nothing.
        let parsed = parse_if_msgs(&[], 0);
        assert!(parsed.is_empty());
        let parsed = parse_if_msgs(&[0, 0, 0, 0], 4);
        assert!(parsed.is_empty());
    }
}
