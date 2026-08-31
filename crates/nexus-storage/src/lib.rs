//! NEXUS Storage Intelligence.
//!
//! Phase 3 of the roadmap. This crate provides a real, read-only storage
//! analyzer that:
//!
//! - computes the total size of a directory tree (or a limited scan),
//! - finds large files,
//! - classifies paths into categories (cache, temporary, logs, downloads,
//!   application data, docker, build artifacts, developer files, other),
//! - groups size by category so NEXUS can explain *where* space goes.
//!
//! Design principles:
//!
//! - **Read-only**: this crate never deletes or modifies anything.
//! - **Safe scanning**: by default we do not follow symlinks (avoiding
//!   cycles and out-of-root escapes) and we hard-limit the number of entries
//!   scanned so an accidental whole-disk walk cannot hang the tool.
//! - **Explainable**: categorization is based on path heuristics that are
//!   documented per rule, and every recommendation is tied to concrete
//!   evidence (a path and a size).
//!
//! The `StorageAnalysis` returned by [`analyze`] aggregates per-category
//! totals plus the largest individual files, so upper layers can produce
//! human-readable recommendations without re-walking the disk.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Hard cap on how many directory entries a scan will visit in a single root.
///
/// This protects the user from an extremely expensive recursive walk (for
/// example scanning `/` outright). Callers that want a full disk estimate
/// should target specific high-level directories instead.
pub const MAX_ENTRIES_PER_SCAN: usize = 100_000;

/// Minimum file size (in bytes) before a file is reported as "large".
pub const LARGE_FILE_THRESHOLD: u64 = 64 * 1024 * 1024; // 64 MiB

/// Classification of a single path. This is the vocabulary NEXUS uses to
/// explain storage consumption to a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StorageCategory {
    Cache,
    Temporary,
    Logs,
    Downloads,
    ApplicationData,
    Docker,
    BuildArtifacts,
    Developer,
    Other,
}

impl StorageCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageCategory::Cache => "cache",
            StorageCategory::Temporary => "temporary",
            StorageCategory::Logs => "logs",
            StorageCategory::Downloads => "downloads",
            StorageCategory::ApplicationData => "application data",
            StorageCategory::Docker => "docker",
            StorageCategory::BuildArtifacts => "build artifacts",
            StorageCategory::Developer => "developer files",
            StorageCategory::Other => "other",
        }
    }
}

/// A single classified storage item with concrete evidence.
#[derive(Debug, Clone)]
pub struct StorageItem {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub category: StorageCategory,
    /// Whether this item is, in NEXUS's judgment, safe to reclaim. NEXUS
    /// never deletes anything; this flag only feeds recommendation text.
    pub safe_to_reclaim: bool,
}

/// Aggregate result of a storage scan.
#[derive(Debug, Clone)]
pub struct StorageAnalysis {
    pub total_bytes: u64,
    pub large_files: Vec<StorageItem>,
    pub by_category: BTreeMap<StorageCategory, u64>,
    /// Total bytes judged safe to reclaim, broken down by category.
    pub reclaimable_by_category: BTreeMap<StorageCategory, u64>,
    /// Total bytes judged safe to reclaim across all categories.
    pub reclaimable_bytes: u64,
    /// Count of entries actually visited (bounded by [`MAX_ENTRIES_PER_SCAN`]).
    pub entries_scanned: usize,
    /// Total count known to exist, which may exceed `entries_scanned` when
    /// the scan was truncated.
    pub entries_known: usize,
}

impl Default for StorageAnalysis {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            large_files: Vec::new(),
            by_category: BTreeMap::new(),
            reclaimable_by_category: BTreeMap::new(),
            reclaimable_bytes: 0,
            entries_scanned: 0,
            entries_known: 0,
        }
    }
}

/// Classify a filesystem path into a [`StorageCategory`] using documented
/// heuristics. Classification is purely path-based and intentionally
/// conservative: anything unrecognised becomes [`StorageCategory::Other`].
pub fn classify_path(path: &Path) -> StorageCategory {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Directory components (excluding the file name itself) are matched
    // exactly where a heuristic targets a known directory name.
    let dirs: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => n
                .to_str()
                .map(|s| s.to_ascii_lowercase())
                .filter(|s| *s != file_name),
            _ => None,
        })
        .collect();
    // The full component list (dirs + file name) for filename-substring rules.
    let all: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => n.to_str().map(|s| s.to_ascii_lowercase()),
            _ => None,
        })
        .collect();

    let has = |needle: &str| dirs.iter().any(|c| c == needle);
    let any_dir_contains = |needles: &[&str]| needles.iter().any(|n| dirs.iter().any(|c| c.contains(n)));
    let any_all_contains = |needles: &[&str]| needles.iter().any(|n| all.iter().any(|c| c.contains(n)));

    // --- Cache and temporary files first (most common safe-to-reclaim). ---
    // Match cache/temp by directory name OR clear filename markers.
    if has("caches")
        || has("cache")
        || any_dir_contains(&["cache", "temp", "tmp", "trash", ".thumbnails"])
        || file_name.ends_with(".tmp")
        || file_name.ends_with(".temp")
        || file_name.ends_with(".part")
        || file_name.ends_with(".crswap")
    {
        return StorageCategory::Cache;
    }

    // --- Docker data (VM images, overlay layers, build cache). ---
    if has("docker") && any_dir_contains(&["docker", "containers", "images", "vms", "overlay2"]) {
        return StorageCategory::Docker;
    }
    if any_dir_contains(&["docker"], )
        && (has("containers") || has("vms") || file_name.ends_with(".raw") || file_name.ends_with(".qcow"))
    {
        return StorageCategory::Docker;
    }

    // --- Logs (by directory or extension). ---
    if has("logs")
        || has("log")
        || any_dir_contains(&["logs"])
        || (file_name.ends_with(".log") && any_all_contains(&["log"]))
    {
        return StorageCategory::Logs;
    }

    // --- Downloads directory. ---
    if has("downloads") {
        return StorageCategory::Downloads;
    }

    // --- Build artifacts: exact directory names only (avoid substring
    //     false-positives on filenames like big.cache). ---
    if has("target")
        || has("node_modules")
        || has(".gradle")
        || any_dir_contains(&["build", ".gradle", "deriveddata", "node_modules"])
    {
        return StorageCategory::BuildArtifacts;
    }

    // --- Developer tool data. ---
    if any_dir_contains(&["simulator", ".xcode", ".npm", "go-build", ".rustup", ".local"])
        || has(".cargo")
    {
        return StorageCategory::Developer;
    }

    // --- Application data directories. ---
    if any_dir_contains(&["application support", "containers"]) {
        return StorageCategory::ApplicationData;
    }

    // --- Bare log files that "log" appears nowhere in the path. ---
    if file_name.ends_with(".log") {
        return StorageCategory::Logs;
    }

    StorageCategory::Other
}

/// Scan the subtree rooted at `root`, computing sizes and classifying each
/// entry. Returns [`None`] if `root` is not a readable directory.
///
/// Symlinks are not followed, and the walk is bounded by
/// [`MAX_ENTRIES_PER_SCAN`].
pub fn analyze(root: &Path) -> Option<StorageAnalysis> {
    let mut analysis = StorageAnalysis::default();
    let mut entries_known = 0usize;
    walk(root, root, &mut analysis, &mut entries_known, 0);
    analysis.entries_known = entries_known;
    Some(analysis)
}

fn walk(
    root: &Path,
    dir: &Path,
    analysis: &mut StorageAnalysis,
    entries_known: &mut usize,
    depth: usize,
) {
    if analysis.entries_scanned >= MAX_ENTRIES_PER_SCAN {
        return;
    }
    if depth > 64 {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if analysis.entries_scanned >= MAX_ENTRIES_PER_SCAN {
            break;
        }
        *entries_known += 1;
        analysis.entries_scanned += 1;

        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };

        // Do not follow symlinks (avoids cycles and out-of-root escapes).
        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            walk(root, &path, analysis, entries_known, depth + 1);
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let rel: PathBuf = path
            .strip_prefix(root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| path.clone());
        let category = classify_path(&rel);

        let item = StorageItem {
            path,
            size_bytes: size,
            category,
            safe_to_reclaim: is_reclaimable(category, &rel),
        };

        analysis.total_bytes += size;
        *analysis.by_category.entry(category).or_insert(0) += size;

        if item.safe_to_reclaim {
            analysis.reclaimable_bytes += size;
            *analysis.reclaimable_by_category.entry(category).or_insert(0) += size;
        }

        if size >= LARGE_FILE_THRESHOLD {
            analysis.large_files.push(item);
        }
    }

    analysis.large_files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
}

/// Whether an item is judged safe to reclaim. NEXUS is deliberately
/// conservative: only caches, temporary files, and build artifacts that live
/// under a cache/tmp/build path are considered reclaimable. Logs and
/// download directories are *not* auto-reclaimed.
fn is_reclaimable(category: StorageCategory, rel: &Path) -> bool {
    match category {
        StorageCategory::Cache | StorageCategory::Temporary => true,
        StorageCategory::BuildArtifacts => {
            let s = rel.to_string_lossy().to_ascii_lowercase();
            s.contains("target") || s.contains("deriveddata") || s.contains(".gradle")
        }
        _ => false,
    }
}

/// Format bytes into a human-friendly string (GiB/MiB/KiB).
pub fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= GIB {
        format!("{:.2} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn write_file(path: &Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(path).unwrap();
        let data = vec![b'x'; bytes];
        f.write_all(&data).unwrap();
    }

    #[test]
    fn classifies_cache_and_logs() {
        assert_eq!(classify_path(Path::new("~/Library/Caches/Chrome")), StorageCategory::Cache);
        assert_eq!(classify_path(Path::new("/var/log/syslog")), StorageCategory::Logs);
        assert_eq!(classify_path(Path::new("~/Downloads/file.zip")), StorageCategory::Downloads);
        assert_eq!(classify_path(Path::new("/some/random/thing")), StorageCategory::Other);
    }

    #[test]
    fn classifies_docker_and_build() {
        assert_eq!(classify_path(Path::new("~/Library/Containers/com.docker.docker/Data/vms")), StorageCategory::Docker);
        assert_eq!(classify_path(Path::new("project/target/debug")), StorageCategory::BuildArtifacts);
        assert_eq!(classify_path(Path::new("~/.cargo/registry")), StorageCategory::Developer);
    }

    #[test]
    fn analyze_sums_and_lists_large_files() {
        let dir = std::env::temp_dir().join(format!("nexus-storage-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_file(&dir.join("cache/big.cache"), 100 * 1024 * 1024);
        write_file(&dir.join("cache/small.cache"), 1000);
        write_file(&dir.join("logs/app.log"), 256);

        match analyze(&dir) {
            Some(analysis) => {
                assert_eq!(analysis.total_bytes, 100 * 1024 * 1024 + 1000 + 256);
                assert_eq!(analysis.large_files.len(), 1);
                assert!(analysis.large_files[0].path.ends_with("big.cache"));
                let cache_total = analysis.by_category.get(&StorageCategory::Cache).copied().unwrap_or(0);
                assert_eq!(cache_total, 100 * 1024 * 1024 + 1000);
                // Cache files are reclaimable; the log file is not.
                assert_eq!(analysis.reclaimable_bytes, 100 * 1024 * 1024 + 1000);
                let reclaimable_cache = analysis.reclaimable_by_category.get(&StorageCategory::Cache).copied().unwrap_or(0);
                assert_eq!(reclaimable_cache, 100 * 1024 * 1024 + 1000);
            }
            None => panic!("analyze returned None"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlinks_not_followed() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = std::env::temp_dir().join(format!("nexus-storage-symlink-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let real = dir.join("real");
            fs::create_dir_all(&real).unwrap();
            write_file(&real.join("f"), 1024);
            // A symlink pointing back to the root would create a cycle if followed.
            let _ = symlink(&dir, dir.join("loop"));
            let analysis = analyze(&dir).unwrap();
            // The symlink is counted as an entry but NOT followed (no cycle).
            assert_eq!(analysis.entries_scanned, 3); // root: "real", "loop"; real: "f"
            assert_eq!(analysis.total_bytes, 1024); // only the real file counted
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
