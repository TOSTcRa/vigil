use sha2::{Digest, Sha256};

pub struct CheatEntry {
    pub hash: String,
    pub name: String,
    pub category: String,
    pub description: String,
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
