use crate::process::{Proc, ProcessStatus};

pub fn scan_processes() -> std::io::Result<Vec<u64>> {
    let mut res = vec![];
    for entry in std::fs::read_dir("/proc/")? {
        let entry = entry?;
        let os_name = entry.file_name();
        let name = os_name.to_str();

        match name {
            Some(val) => match val.parse::<u64>() {
                Ok(pid) => res.push(pid),
                Err(_) => {}
            },
            None => {}
        }
    }

    Ok(res)
}

pub fn get_process(pid: u64) -> std::io::Result<Proc> {
    let mut name = String::new();
    let mut tracer_pid: u64 = 0;
    let mut status = ProcessStatus::Suspicious(String::from("Status not found"));
    let path = format!("/proc/{}/status", pid);
    let content = std::fs::read_to_string(path)?;
    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();

            if key == "Name" {
                name = value.to_string();
            } else if key == "State" {
                status = match value.chars().next() {
                    Some('R') => ProcessStatus::Running,
                    Some('S') | Some('D') | Some('I') => ProcessStatus::Sleeping,
                    Some('T') | Some('t') => ProcessStatus::Stopped,
                    Some('Z') => ProcessStatus::Zombie,
                    _ => ProcessStatus::Suspicious(value.to_string()),
                };
            } else if key == "TracerPid" {
                match value.parse::<u64>() {
                    Ok(num) => tracer_pid = num,
                    Err(_) => {}
                };
            }
        }
    }

    let res = Proc::new(name, pid, status, tracer_pid);

    Ok(res)
}
