use std::collections::HashSet;

use crate::process::{Proc, ProcessStatus};

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

// parses /proc/PID/status file and builds a Proc struct from it
// grabs: Name (process name), State (R/S/T/Z etc), TracerPid (0 = nobody tracing)
// if status file cant be read (process died between scan and read) -> returns io error
// state mapping: R=running, S/D/I=sleeping, T/t=stopped, Z=zombie, anything else=suspicious
pub fn get_process(pid: u64) -> std::io::Result<Proc> {
    let mut name = String::new();
    let mut tracer_pid: u64 = 0;
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
                _ => {}
            }
        }
    }

    let preload_path = check_preload(pid)?;

    Ok(Proc::new(name, pid, status, tracer_pid, preload_path))
}

// parses /proc/PID/maps and checks loaded .so libraries for suspicious stuff
// returns only suspicious findings as (path, reason) tuples
// two checks:
// 1. library has both write and execute permissions (w+x) -> possible code injection
// 2. library loaded from unusual dir (/tmp, /home, /dev/shm) -> possible LD_PRELOAD cheat
// uses HashSet to avoid reporting same library twice
pub fn get_map(
    pid: u64,
    found_maps: &mut HashSet<String>,
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

pub fn check_preload(pid: u64) -> std::io::Result<Option<String>> {
    let path = format!("/proc/{}/environ", pid);
    let content = std::fs::read_to_string(path)?;
    let splited: Vec<&str> = content.split('\0').collect();
    for line in splited {
        if let Some((key, value)) = line.split_once("=")
            && key == "LD_PRELOAD"
        {
            return Ok(Some(value.to_string()));
        }
    }

    Ok(None)
}
