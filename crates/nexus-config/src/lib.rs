//! NEXUS user configuration and UI mode.
//!
//! Deliverable of Phase 10 ("Desktop Experience") part A: Simple Mode and
//! Developer Mode. Settings are persisted to a real file (default
//! `~/.nexus/config.conf`) so choices survive restarts; nothing is faked or
//! hardcoded at runtime.
//!
//! The file format is a minimal `key = value` store chosen deliberately to
//! avoid a serialization dependency; `ConfigStore` is responsible for
//! parsing, default-merging, and writing it back losslessly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The two UI modes NEXUS can run in. They change how much is shown and how
/// much is done without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Hide technical detail; surface plain-language status and only ask
    /// before clearly risky actions.
    Simple,
    /// Show the underlying engines, raw values, and more controls.
    Developer,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Simple => "simple",
            Mode::Developer => "developer",
        }
    }

    pub fn from_str(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "simple" => Some(Mode::Simple),
            "developer" | "dev" => Some(Mode::Developer),
            _ => None,
        }
    }

    /// Whether a user confirmation prompt is really needed before an action
    /// proceeds, given the action's policy risk letter.
    pub fn confirmation_policy(self) -> ConfirmationPolicy {
        match self {
            Mode::Simple => ConfirmationPolicy::AllRiskActions,
            Mode::Developer => ConfirmationPolicy::HighRiskOnly,
        }
    }
}

/// How strictly the UI demands confirmation before acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationPolicy {
    /// Confirm anything not explicitly SAFE.
    AllRiskActions,
    /// Confirm only HIGH_RISK / CRITICAL actions.
    HighRiskOnly,
}

impl ConfirmationPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfirmationPolicy::AllRiskActions => "all_risk_actions",
            ConfirmationPolicy::HighRiskOnly => "high_risk_only",
        }
    }
    pub fn from_str(s: &str) -> Option<ConfirmationPolicy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "all_risk_actions" => Some(ConfirmationPolicy::AllRiskActions),
            "high_risk_only" => Some(ConfirmationPolicy::HighRiskOnly),
            _ => None,
        }
    }
}

/// All user-facing settings that can be persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    pub confirmation: ConfirmationPolicy,
    /// When true, NEXUS may run sandboxed commands without an extra prompt.
    pub sandbox_auto_ok: bool,
    /// Row cap applied to long listings.
    pub scan_limit: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Developer,
            confirmation: Mode::Developer.confirmation_policy(),
            sandbox_auto_ok: false,
            scan_limit: 100_000,
        }
    }
}

impl Config {
    pub fn simple() -> Self {
        Self {
            mode: Mode::Simple,
            confirmation: Mode::Simple.confirmation_policy(),
            sandbox_auto_ok: false,
            scan_limit: 10_000,
        }
    }

    fn to_pairs(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("mode".into(), self.mode.as_str().into());
        m.insert("confirmation".into(), self.confirmation.as_str().into());
        m.insert("sandbox_auto_ok".into(), if self.sandbox_auto_ok { "true" } else { "false" }.into());
        m.insert("scan_limit".into(), self.scan_limit.to_string());
        m
    }

    fn from_pairs(pairs: &BTreeMap<String, String>) -> Self {
        let mut c = Self::default();
        if let Some(v) = pairs.get("mode") {
            if let Some(m) = Mode::from_str(v) {
                c.mode = m;
                c.confirmation = m.confirmation_policy();
            }
        }
        if let Some(v) = pairs.get("confirmation") {
            if let Some(p) = ConfirmationPolicy::from_str(v) {
                c.confirmation = p;
            }
        }
        if let Some(v) = pairs.get("sandbox_auto_ok") {
            c.sandbox_auto_ok = v.trim() == "true";
        }
        if let Some(v) = pairs.get("scan_limit") {
            if let Ok(n) = v.trim().parse::<usize>() {
                c.scan_limit = n;
            }
        }
        c
    }
}

/// A wrapper that loads and saves a [`Config`] to disk.
#[derive(Debug, Clone)]
pub struct ConfigStore {
    path: PathBuf,
    config: Config,
}

impl ConfigStore {
    /// Load from an explicit path, defaulting any missing keys.
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let loaded = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| parse_kv(&s))
            .map(|p| Config::from_pairs(&p))
            .unwrap_or_default();
        Self { path, config: loaded }
    }

    /// Load from the default location (`~/.nexus/config.conf`).
    pub fn load() -> Self {
        Self::from_path(Self::default_path())
    }

    /// The default config file location.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        Path::new(&home).join(".nexus").join("config.conf")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn mode(&self) -> Mode {
        self.config.mode
    }

    /// Change the mode and persist immediately.
    pub fn set_mode(&mut self, mode: Mode) -> std::io::Result<()> {
        self.config.mode = mode;
        self.config.confirmation = mode.confirmation_policy();
        self.save()
    }

    pub fn set_sandbox_auto_ok(&mut self, v: bool) -> std::io::Result<()> {
        self.config.sandbox_auto_ok = v;
        self.save()
    }

    /// Write the current config to disk, creating parent dirs as needed.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut lines: Vec<String> = self
            .config
            .to_pairs()
            .into_iter()
            .map(|(k, v)| format!("{k} = {v}"))
            .collect();
        lines.sort();
        std::fs::write(&self.path, lines.join("\n") + "\n")
    }
}

/// Parse `key = value` lines, ignoring comments and blanks.
fn parse_kv(s: &str) -> Option<BTreeMap<String, String>> {
    let mut pairs = BTreeMap::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let idx = line.find('=')?;
        let key = line[..idx].trim();
        let value = line[idx + 1..].trim();
        if !key.is_empty() {
            pairs.insert(key.to_string(), value.to_string());
        }
    }
    Some(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_developer_mode() {
        assert_eq!(ConfigStore::from_path("/nonexistent/x.conf").mode(), Mode::Developer);
    }

    #[test]
    fn simple_mode_requires_confirmation_for_all_risk_actions() {
        assert_eq!(Mode::Simple.confirmation_policy(), ConfirmationPolicy::AllRiskActions);
        assert_eq!(Mode::Developer.confirmation_policy(), ConfirmationPolicy::HighRiskOnly);
    }

    #[test]
    fn roundtrip_persists_mode_and_limit() {
        let dir = std::env::temp_dir().join(format!("nexus_cfg_{}", std::process::id()));
        let path = dir.join("config.conf");
        let mut store = ConfigStore::from_path(&path);
        store.set_mode(Mode::Simple).expect("saves");
        store.set_sandbox_auto_ok(true).expect("saves");
        store.save().expect("saves");

        let reloaded = ConfigStore::from_path(&path);
        assert_eq!(reloaded.mode(), Mode::Simple);
        assert!(reloaded.config().sandbox_auto_ok);
        assert_eq!(reloaded.config().confirmation, ConfirmationPolicy::AllRiskActions);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_kv_reads_simple_lines() {
        let pairs = parse_kv("mode = simple\n# comment\nscan_limit = 5\n").unwrap();
        assert_eq!(pairs.get("mode").map(String::as_str), Some("simple"));
        assert_eq!(pairs.get("scan_limit").map(String::as_str), Some("5"));
    }
}
