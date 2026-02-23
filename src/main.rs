use std::{collections::HashSet, thread, time::Duration};

use crate::{
    process::Suspicious,
    scanner::{get_fd, get_map, get_process, get_whitelist, scan_processes},
};

mod process;
mod scanner;

// main monitoring loop — vigil anti-cheat core
// scans all running processes every 5 sec via /proc
// 5 detection methods: TracerPid, maps (w+x / suspicious dirs), LD_PRELOAD, cmdline debuggers, name check
// found = already alerted pids (dedup), found_maps = already checked .so paths (dedup)
// whitelist = trusted path patterns from ~/.config/vigil/whitelist.txt
// if process was suspicious but now its fine -> auto-remove from found (cleanup)
//
// how to test:
// 1. sleep 1000 &        <- starts a dummy process, returns pid
// 2. sudo strace -p PID  <- attaches debugger to it (sets TracerPid)
// 3. cargo run            <- vigil should catch and print the sleep process
// 4. ctrl+c strace        <- TracerPid goes back to 0, vigil removes it from found
fn main() {
    let mut history: HashSet<u64> = HashSet::new();
    let mut found: HashSet<u64> = HashSet::new();
    let mut found_maps: HashSet<String> = HashSet::new();

    let whitelist = get_whitelist().unwrap_or_default();

    let mut first_run = true;

    loop {
        if let Ok(vec) = scan_processes() {
            for &pid in &vec {
                if let Ok(proc) = get_process(pid, &whitelist) {
                    if let Ok(val) = get_map(pid, &mut found_maps, &whitelist)
                        && !val.is_empty()
                    {
                        println!("{:?}", val);
                    }

                    if let Ok(val) = get_fd(pid)
                        && !val.is_empty()
                    {
                        println!("Process {}, reading other process memory: {:?}", pid, val);
                    }

                    if found.contains(&pid) && !proc.is_suspicious() {
                        found.remove(&pid);
                    }

                    if proc.is_suspicious() && !found.contains(&pid) {
                        println!("{:?}", proc);
                        found.insert(pid);
                    }

                    if !history.contains(&pid) && !first_run {
                        println!("A new process was born: \n{:?}", proc);
                    }
                }
            }

            history = vec.into_iter().collect();
            first_run = false;
        }

        thread::sleep(Duration::from_secs(5));
    }
}
