//! NEXUS Audit Log.
//!
//! Every system-changing action that NEXUS performs must be recorded. This
//! crate provides an append-only, JSONL-backed audit log so users can inspect
//! what NEXUS has done, when, at whose request, and with what result.
//!
//! Privacy-first: the log is stored locally (default `~/.nexus/audit.jsonl`)
//! and is never uploaded anywhere.
//!
//! Note on safety: audit entries are informational records. Nothing here
//! executes or changes system state; it only *describes* actions.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// How an action was requested.
#[derive(Debug, Clone)]
pub enum Initiator {
    User,
    Nexus,
    Unknown,
}

impl Initiator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Initiator::User => "user",
            Initiator::Nexus => "nexus",
            Initiator::Unknown => "unknown",
        }
    }
}

/// The outcome of attempting an action.
#[derive(Debug, Clone)]
pub enum ActionResult {
    Success,
    Failed(String),
    Rejected,
    Pending,
}

/// One audit log entry describing a single action lifecycle.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// A short, stable action id (e.g. "stop_process").
    pub action: String,
    /// Free-form details (e.g. "Stopped process 4812").
    pub description: String,
    /// Why NEXUS performed or proposed it.
    pub reason: String,
    /// Who initiated it.
    pub initiated_by: Initiator,
    pub result: ActionResult,
    /// Optional structured detail captured after the action.
    pub detail: Option<String>,
}

impl AuditEntry {
    pub fn new(
        action: impl Into<String>,
        description: impl Into<String>,
        reason: impl Into<String>,
        initiated_by: Initiator,
    ) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            action: action.into(),
            description: description.into(),
            reason: reason.into(),
            initiated_by,
            result: ActionResult::Pending,
            detail: None,
        }
    }

    /// Render the entry as a single JSON line.
    pub fn to_json_line(&self) -> String {
        let result = match &self.result {
            ActionResult::Success => "success".to_string(),
            ActionResult::Failed(e) => format!("failed:{}", json_escape(e)),
            ActionResult::Rejected => "rejected".to_string(),
            ActionResult::Pending => "pending".to_string(),
        };
        let detail = self.detail.as_deref().unwrap_or("").to_string();
        format!(
            "{{\"ts\":{},\"action\":\"{}\",\"description\":\"{}\",\"reason\":\"{}\",\"initiator\":\"{}\",\"result\":\"{}\",\"detail\":\"{}\"}}",
            self.timestamp,
            json_escape(&self.action),
            json_escape(&self.description),
            json_escape(&self.reason),
            self.initiated_by.as_str(),
            result,
            json_escape(&detail),
        )
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// An append-only audit log persisted as JSONL.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Create an in-memory-only audit log (no persistence).
    pub fn memory() -> Self {
        Self {
            path: PathBuf::new(),
            entries: Vec::new(),
        }
    }

    /// Create an audit log that persists to `path` (creating parent dirs).
    pub fn at(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self { path, entries: Vec::new() })
    }

    /// Create the default audit log at `~/.nexus/audit.jsonl`.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".nexus").join("audit.jsonl")
    }

    /// Append an entry to the log. In-memory always succeeds; the file
    /// append failure is returned so the caller can surface it if needed.
    pub fn record(&mut self, entry: AuditEntry) -> std::io::Result<()> {
        self.entries.push(entry.clone());
        if !self.path.as_os_str().is_empty() {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writeln!(f, "{}", entry.to_json_line())?;
        }
        Ok(())
    }

    /// All recorded entries (most recent last).
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrips_in_memory() {
        let mut log = AuditLog::memory();
        log.record(AuditEntry::new(
            "stop_process",
            "Stopped process 4812",
            "User requested memory optimization",
            Initiator::User,
        ))
        .unwrap();
        assert_eq!(log.entries().len(), 1);
        assert_eq!(log.entries()[0].action, "stop_process");
    }

    #[test]
    fn json_line_is_valid() {
        let e = AuditEntry::new("x", "desc \"quoted\"", "reason", Initiator::Nexus);
        let line = e.to_json_line();
        assert!(line.contains("\"action\":\"x\""));
        assert!(line.contains("\\\"quoted\\\""));
        assert!(line.contains("\"initiator\":\"nexus\""));
        assert!(line.contains("\"result\":\"pending\""));
    }

    #[test]
    fn persists_to_temp_file() {
        let tmp = std::env::temp_dir().join(format!("nexus-audit-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&tmp);
        let mut log = AuditLog::at(&tmp).unwrap();
        log.record(AuditEntry::new("a", "desc", "reason", Initiator::User)).unwrap();
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("\"action\":\"a\""));
        let _ = fs::remove_file(&tmp);
    }
}
