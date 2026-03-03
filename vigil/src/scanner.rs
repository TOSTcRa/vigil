use crate::process::{Proc, ProcessStatus};
use sha2::{Digest, Sha256};

pub struct CheatEntry {
    pub hash: String,
    pub name: String,
    pub category: String,
    pub description: String,
}

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

pub fn check_hash(
    pid: u64,
    cheat_db: &[CheatEntry],
) -> std::io::Result<Option<(String, String, String)>> {
    let exe_path = format!("/proc/{}/exe", pid);
    let real_path = std::fs::read_link(&exe_path)?;

    let exe_name = real_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

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

// reads /proc directory and collects all numeric folder names (those are PIDs)
// non-numeric entries (like /proc/cpuinfo, /proc/net) are skipped
// returns vec of pids or io error if /proc cant be read
pub fn scan_processes() -> std::io::Result<Vec<u64>> {
    let mut res = vec![];
    for entry in std::fs::read_dir("/proc/")? {
        let entry = entry?;
        let os_name = entry.file_name();
        let name = os_name.to_str();

        if let Some(val) = name
            && let Ok(pid) = val.parse::<u64>()
        {
            res.push(pid);
        }
    }

    Ok(res)
}

// builds a full Proc struct from multiple /proc/PID/* files:
// 1. /proc/PID/status -> Name, State (R/S/T/Z etc), TracerPid
// 2. /proc/PID/environ -> LD_PRELOAD detection (via check_preload)
// 3. /proc/PID/cmdline -> launch arguments (via get_cmdline)
// whitelist is passed through to check_preload for filtering trusted preloads
// if any /proc file cant be read (process died mid-scan) -> returns io error
// state mapping: R=running, S/D/I=sleeping, T/t=stopped, Z=zombie, anything else=suspicious
pub fn get_process(pid: u64, whitelist: &[String]) -> std::io::Result<Proc> {
    let mut name = String::new();
    let mut tracer_pid: u64 = 0;
    let mut ppid: u64 = 0;
    let mut status = ProcessStatus::Suspicious(String::from("Status not found"));

    let path = format!("/proc/{}/status", pid);
    let content = std::fs::read_to_string(path)?;

    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();

            match key {
                "Name" => name = value.to_string(),
                "State" => {
                    status = match value.chars().next() {
                        Some('R') => ProcessStatus::Running,
                        Some('S') | Some('D') | Some('I') => ProcessStatus::Sleeping,
                        Some('T') | Some('t') => ProcessStatus::Stopped,
                        Some('Z') => ProcessStatus::Zombie,
                        _ => ProcessStatus::Suspicious(value.to_string()),
                    }
                }
                "TracerPid" => {
                    if let Ok(num) = value.parse::<u64>() {
                        tracer_pid = num;
                    }
                }
                "PPid" => {
                    if let Ok(num) = value.parse::<u64>() {
                        ppid = num;
                    }
                }
                _ => {}
            }
        }
    }

    let preload_path = check_preload(pid, whitelist)?;
    let cmdline = get_cmdline(pid)?;
    let exe_path = get_exe(pid, whitelist)?;

    Ok(Proc::new(
        name,
        pid,
        status,
        tracer_pid,
        preload_path,
        cmdline,
        exe_path,
        ppid,
    ))
}

// parses /proc/PID/maps and checks loaded .so libraries for suspicious stuff
// returns only suspicious findings as (path, reason) tuples
// two checks:
// 1. library has both write and execute permissions (w+x) -> possible code injection
// 2. library loaded from unusual dir (/tmp, /home, /dev/shm) -> possible LD_PRELOAD cheat
// uses HashSet to avoid reporting same library twice
pub fn get_map(
    pid: u64,
    found_maps: &mut std::collections::HashSet<String>,
    whitelist: &[String],
) -> std::io::Result<Vec<(String, String)>> {
    let mut res: Vec<(String, String)> = vec![];
    let path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(path)?;
    for line in content.lines() {
        if !line.contains(".so") {
            continue;
        }
        let splited: Vec<&str> = line.split_whitespace().collect();
        if let Some(path) = splited.last()
            && !found_maps.contains(*path)
        {
            if whitelist
                .iter()
                .any(|whitelist_item| path.contains(whitelist_item))
            {
                found_maps.insert(path.to_string());
                continue;
            }
            if splited[1].contains("w") && splited[1].contains("x") {
                res.push((
                    path.to_string(),
                    String::from("Proces has w and x rights at the same time"),
                ));
            }
            if path.contains("/home/") || path.contains("/tmp/") || path.contains("/dev/shm/") {
                res.push((
                    path.to_string(),
                    String::from("Proces was launched from non standart dir"),
                ));
            }
            found_maps.insert(path.to_string());
        }
    }

    Ok(res)
}

// checks /proc/PID/environ for LD_PRELOAD variable
// env vars are separated by null bytes (\0), each one is KEY=VALUE
// if LD_PRELOAD found and path is NOT in whitelist -> returns Some(path)
// if no LD_PRELOAD or its whitelisted -> returns None
// called from get_process() so preload info is part of every Proc
pub fn check_preload(pid: u64, whitelist: &[String]) -> std::io::Result<Option<String>> {
    let path = format!("/proc/{}/environ", pid);
    let content = std::fs::read_to_string(path)?;
    let splited: Vec<&str> = content.split('\0').collect();
    for line in splited {
        if let Some((key, value)) = line.split_once("=")
            && key == "LD_PRELOAD"
        {
            let is_whitelisted = whitelist
                .iter()
                .any(|whitelist_item| value.contains(whitelist_item));

            if !is_whitelisted {
                return Ok(Some(value.to_string()));
            }
        }
    }

    Ok(None)
}

// reads /proc/PID/cmdline — the full command that launched the process
// args are separated by null bytes, we replace them with spaces for readability
// used in is_suspicious() to detect debugger tools (gdb, strace, ltrace)
pub fn get_cmdline(pid: u64) -> std::io::Result<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let content = std::fs::read_to_string(path)?;
    Ok(content.replace('\0', " "))
}

// loads trusted path patterns from /etc/vigil/whitelist.txt
// each line is a pattern (like "/usr/lib/", ".config/", "libmozsandbox.so")
// used by get_map and check_preload to skip known-safe libraries
// if file doesnt exist -> unwrap_or_default() in main gives empty vec (no whitelist)
pub fn get_whitelist() -> std::io::Result<Vec<String>> {
    let mut res: Vec<String> = vec![];
    let path = "/etc/vigil/whitelist.txt";
    let content = std::fs::read_to_string(path)?;
    for line in content.lines() {
        res.push(line.to_string());
    }

    Ok(res)
}

// reads /proc/PID/exe symlink — points to the real binary path
// read_link returns PathBuf, to_string_lossy converts to String
// checks: if path is NOT whitelisted AND in suspicious dir (/home, /tmp, /dev/shm) -> Some(path)
// otherwise returns None (safe binary)
// exe shows real binary path even if process was renamed — cheater cant hide
pub fn get_exe(pid: u64, whitelist: &[String]) -> std::io::Result<Option<String>> {
    let path = format!("/proc/{}/exe", pid);
    let content = std::fs::read_link(path)?;
    let res = content.to_string_lossy().to_string();
    let is_whitelisted = whitelist
        .iter()
        .any(|whitelist_item| res.contains(whitelist_item));

    if !is_whitelisted
        && (res.contains("/home/") || res.contains("/tmp/") || res.contains("/dev/shm/"))
    {
        return Ok(Some(res));
    }

    Ok(None)
}

// reads /proc/PID/fd directory — each entry is a symlink to an open file
// checks if any symlink points to /proc/*/mem (another process memory)
// filters self-reads (num != pid) — process reading its own mem is normal
// returns vec of victim PIDs whose memory is being read
// needs root to read other processes fd dirs
pub fn get_fd(pid: u64) -> std::io::Result<Vec<u64>> {
    let path = format!("/proc/{}/fd", pid);
    let dir = std::fs::read_dir(path)?;
    let mut res: Vec<u64> = vec![];
    for entry in dir {
        let entry = entry?;
        let content = std::fs::read_link(entry.path())?;
        let symlink = content.to_string_lossy();

        if symlink.starts_with("/proc/") && symlink.ends_with("/mem") {
            for item in symlink.split('/') {
                if item.is_empty() {
                    continue;
                }

                if let Ok(num) = item.parse::<u64>()
                    && num != pid
                {
                    res.push(num);
                }
            }
        }
    }
    Ok(res)
}

pub fn get_modules() -> std::io::Result<Vec<String>> {
    let content = std::fs::read_to_string("/proc/modules")?;
    let mut res: Vec<String> = vec![];

    for line in content.lines() {
        let splited: Vec<&str> = line.split_whitespace().collect();

        res.push(splited[0].to_string());
    }

    Ok(res)
}

pub fn get_cross_traces(
    procs: &[Proc],
) -> std::io::Result<std::collections::HashMap<u64, Vec<u64>>> {
    let mut res: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();

    for p in procs {
        let tracer_pid: u64 = *p.get_tracer_pid();
        let pid: u64 = *p.get_pid();

        if tracer_pid != 0 {
            res.entry(tracer_pid).or_default().push(pid);
        }
    }

    Ok(res)
}
