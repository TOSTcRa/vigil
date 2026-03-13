use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::crypto::sha256_hex;
use crate::timestamp::now_local_fmt;
use crate::toml_parser::parse_config;

pub use crate::toml_parser::Config;

pub struct CheatEntry {
    pub hash: String,
    pub name: String,
    pub category: String,
    pub description: String,
}

pub enum LogLevel {
    Alert,
    Cheat,
    Net,
    Inotify,
    Info,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Alert => write!(f, "[ALERT]"),
            LogLevel::Cheat => write!(f, "[CHEAT]"),
            LogLevel::Net => write!(f, "[NET]"),
            LogLevel::Inotify => write!(f, "[INOTIFY]"),
            LogLevel::Info => write!(f, "[INFO]"),
        }
    }
}

pub fn get_config() -> Result<Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string("/etc/vigil/config.toml")?;
    parse_config(&content).map_err(|e| e.into())
}

pub fn log(level: LogLevel, message: &str, path: &str) -> std::io::Result<()> {
    let time = now_local_fmt();
    let line = format!("{} {} {}", time, level, message);
    println!("{}", line);

    let mut f = OpenOptions::new().append(true).create(true).open(path)?;
    writeln!(f, "{}", line)?;

    Ok(())
}

// loads trusted path patterns from /etc/vigil/whitelist.txt
// each line is a pattern (like "/usr/lib/", ".config/", "libmozsandbox.so")
// used by get_map and check_preload to skip known-safe libraries
// if file doesnt exist -> unwrap_or_default() in main gives empty vec (no whitelist)
pub fn get_whitelist() -> std::io::Result<Vec<String>> {
    let content = std::fs::read_to_string("/etc/vigil/whitelist.txt")?;
    let mut res: Vec<String> = vec![];
    for line in content.lines() {
        res.push(line.to_string());
    }
    Ok(res)
}

// loads known cheat signatures from /etc/vigil/cheat_hashes.txt
// format: hash:name:category:description (4 fields separated by :)
// hash can be "name_only" for name-based detection or a real sha256 hash
// if file doesnt exist -> unwrap_or_default() in main gives empty vec
pub fn get_cheat_db() -> std::io::Result<Vec<CheatEntry>> {
    let content = std::fs::read_to_string("/etc/vigil/cheat_hashes.txt")?;
    let mut res = vec![];

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() == 4 {
            res.push(CheatEntry {
                hash: parts[0].to_string(),
                name: parts[1].to_string(),
                category: parts[2].to_string(),
                description: parts[3].to_string(),
            });
        }
    }

    Ok(res)
}

// checks a running process against the cheat signature database
// two-layer detection:
// 1. fast name check - reads /proc/PID/exe symlink, compares filename against "name_only" entries
// 2. sha256 hash check - only runs if database has real hash entries (not just name_only)
//    reads the full binary and computes sha256, compares against known hashes
// name check runs first to avoid expensive disk reads for every process
// returns (name, category, description) of matched cheat or None
pub fn check_hash(
    pid: u64,
    cheat_db: &[CheatEntry],
) -> std::io::Result<Option<(String, String, String)>> {
    let exe_path = format!("/proc/{}/exe", pid);
    let real_path = std::fs::read_link(&exe_path)?;

    let exe_name = real_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    for entry in cheat_db {
        if entry.hash == "name_only" && exe_name == entry.name {
            return Ok(Some((
                entry.name.clone(),
                entry.category.clone(),
                entry.description.clone(),
            )));
        }
    }

    let has_hash_entries = cheat_db.iter().any(|e| e.hash != "name_only");

    if has_hash_entries {
        let binary = std::fs::read(&real_path)?;
        let hash = sha256_hex(&binary);

        for entry in cheat_db {
            if entry.hash != "name_only" && hash == entry.hash {
                return Ok(Some((
                    entry.name.clone(),
                    entry.category.clone(),
                    entry.description.clone(),
                )));
            }
        }
    }

    Ok(None)
}

pub struct FileChanges {
    pub modified: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl FileChanges {
    pub fn total(&self) -> usize {
        self.modified.len() + self.added.len() + self.removed.len()
    }

    pub fn is_suspicious(&self) -> bool {
        self.total() > 0 && self.total() <= 2
    }
}

pub fn get_game_dir() -> std::io::Result<String> {
    let content = std::fs::read_to_string("/etc/vigil/game_dir.txt")?;
    Ok(content.trim().to_string())
}

pub fn scan_game_dir(dir: &str) -> std::io::Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    scan_dir_recursive(Path::new(dir), &mut result)?;
    Ok(result)
}

fn scan_dir_recursive(dir: &Path, result: &mut HashMap<String, String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            scan_dir_recursive(&path, result)?;
        } else {
            let bytes = std::fs::read(&path)?;
            let hash = sha256_hex(&bytes);
            result.insert(path.to_string_lossy().to_string(), hash);
        }
    }
    Ok(())
}

pub fn load_baseline(path: &str) -> std::io::Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(path)?;
    let mut result = HashMap::new();
    for line in content.lines() {
        if let Some((hash, file_path)) = line.split_once(':') {
            result.insert(file_path.to_string(), hash.to_string());
        }
    }
    Ok(result)
}

pub fn save_baseline(path: &str, hashes: &HashMap<String, String>) -> std::io::Result<()> {
    let mut content = String::new();
    for (file_path, hash) in hashes {
        content.push_str(&format!("{}:{}\n", hash, file_path));
    }
    std::fs::write(path, content)
}

pub fn compare_hashes(
    baseline: &HashMap<String, String>,
    current: &HashMap<String, String>,
) -> FileChanges {
    let mut modified = vec![];
    let mut added = vec![];
    let mut removed = vec![];

    for (path, hash) in current {
        match baseline.get(path) {
            Some(old_hash) if old_hash != hash => modified.push(path.clone()),
            None => added.push(path.clone()),
            _ => {}
        }
    }

    for path in baseline.keys() {
        if !current.contains_key(path) {
            removed.push(path.clone());
        }
    }

    FileChanges {
        modified,
        added,
        removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_hashes_no_changes() {
        let mut baseline = HashMap::new();
        baseline.insert("/game/a.dll".to_string(), "abc123".to_string());
        baseline.insert("/game/b.dll".to_string(), "def456".to_string());

        let current = baseline.clone();
        let changes = compare_hashes(&baseline, &current);
        assert_eq!(changes.total(), 0);
        assert!(!changes.is_suspicious());
    }

    #[test]
    fn compare_hashes_modified() {
        let mut baseline = HashMap::new();
        baseline.insert("/game/a.dll".to_string(), "abc123".to_string());

        let mut current = HashMap::new();
        current.insert("/game/a.dll".to_string(), "CHANGED".to_string());

        let changes = compare_hashes(&baseline, &current);
        assert_eq!(changes.modified.len(), 1);
        assert_eq!(changes.added.len(), 0);
        assert_eq!(changes.removed.len(), 0);
        assert_eq!(changes.total(), 1);
        assert!(changes.is_suspicious()); // 1 change = suspicious
    }

    #[test]
    fn compare_hashes_added() {
        let baseline = HashMap::new();
        let mut current = HashMap::new();
        current.insert("/game/new.dll".to_string(), "aaa".to_string());

        let changes = compare_hashes(&baseline, &current);
        assert_eq!(changes.added.len(), 1);
        assert_eq!(changes.modified.len(), 0);
        assert_eq!(changes.removed.len(), 0);
    }

    #[test]
    fn compare_hashes_removed() {
        let mut baseline = HashMap::new();
        baseline.insert("/game/old.dll".to_string(), "bbb".to_string());

        let current = HashMap::new();
        let changes = compare_hashes(&baseline, &current);
        assert_eq!(changes.removed.len(), 1);
        assert_eq!(changes.added.len(), 0);
    }

    #[test]
    fn compare_hashes_many_changes_not_suspicious() {
        let mut baseline = HashMap::new();
        for i in 0..10 {
            baseline.insert(format!("/game/{}.dll", i), format!("old{}", i));
        }
        let mut current = HashMap::new();
        for i in 0..10 {
            current.insert(format!("/game/{}.dll", i), format!("new{}", i));
        }

        let changes = compare_hashes(&baseline, &current);
        assert_eq!(changes.total(), 10);
        assert!(!changes.is_suspicious()); // >2 changes = not suspicious (likely update)
    }

    #[test]
    fn file_changes_total() {
        let fc = FileChanges {
            modified: vec!["a".to_string()],
            added: vec!["b".to_string(), "c".to_string()],
            removed: vec![],
        };
        assert_eq!(fc.total(), 3);
    }

    #[test]
    fn load_baseline_roundtrip() {
        let dir = std::env::temp_dir().join("vigil_test_baseline");
        let path = dir.to_str().unwrap();

        let mut hashes = HashMap::new();
        hashes.insert("/game/test.dll".to_string(), "aabbcc".to_string());
        hashes.insert("/game/lib.so".to_string(), "ddeeff".to_string());

        save_baseline(path, &hashes).unwrap();
        let loaded = load_baseline(path).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get("/game/test.dll").unwrap(), "aabbcc");
        assert_eq!(loaded.get("/game/lib.so").unwrap(), "ddeeff");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn log_level_display() {
        assert_eq!(format!("{}", LogLevel::Alert), "[ALERT]");
        assert_eq!(format!("{}", LogLevel::Cheat), "[CHEAT]");
        assert_eq!(format!("{}", LogLevel::Net), "[NET]");
        assert_eq!(format!("{}", LogLevel::Inotify), "[INOTIFY]");
        assert_eq!(format!("{}", LogLevel::Info), "[INFO]");
    }
}
