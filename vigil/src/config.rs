use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

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

#[derive(Deserialize)]
pub struct Config {
    pub game: GameConfig,
    pub logging: LogConfig,
    pub server: Option<ServerConfig>,
}

#[derive(Deserialize)]
pub struct GameConfig {
    pub path: String,
}

#[derive(Deserialize)]
pub struct LogConfig {
    pub path: String,
}

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub url: String,
    pub player_id: String,
}

pub fn get_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_path = std::fs::read_to_string("/etc/vigil/config.toml")?;

    Ok(toml::from_str(&config_path)?)
}

pub fn log(level: LogLevel, message: &str, path: &str) -> std::io::Result<()> {
    let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let line = format!("{} {} {}", time, level, message);
    println!("{}", line);

    let mut config_file = OpenOptions::new().append(true).create(true).open(path)?;

    writeln!(config_file, "{}", line)?;

    Ok(())
}

// loads trusted path patterns from /etc/vigil/whitelist.txt
// each line is a pattern (like "/usr/lib/", ".config/", "libmozsandbox.so")
// used by get_map and check_preload to skip known-safe libraries
// if file doesnt exist -> unwrap_or_default() in main gives empty vec (no whitelist)
pub fn get_whitelist() -> std::io::Result<Vec<String>> {
    let path = "/etc/vigil/whitelist.txt";
    let content = std::fs::read_to_string(path)?;
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
    let path = "/etc/vigil/cheat_hashes.txt";
    let content = std::fs::read_to_string(path)?;
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
// 1. fast name check — reads /proc/PID/exe symlink, compares filename against "name_only" entries
// 2. sha256 hash check — only runs if database has real hash entries (not just name_only)
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
        let mut hasher = Sha256::new();
        hasher.update(&binary);
        let hash = format!("{:x}", hasher.finalize());

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
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash = format!("{:x}", hasher.finalize());
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
