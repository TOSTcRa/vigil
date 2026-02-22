use std::{
    collections::{self, HashSet},
    thread, time,
};

use crate::{
    process::Suspicious,
    scanner::{get_map, get_process, get_whitelist, scan_processes},
};

mod process;
mod scanner;

// main monitoring loop
// scans all running processes every 5 sec via /proc
// if process is suspicious (traced, weird status, name contains "cheat") -> print it
// found set = already printed pids, so we dont spam same alert
// if process was suspicious but now its fine -> remove from found (auto cleanup)
//
// how to test:
// 1. sleep 1000 &        <- starts a dummy process, returns pid
// 2. sudo strace -p PID  <- attaches debugger to it (sets TracerPid)
// 3. cargo run            <- vigil should catch and print the sleep process
// 4. ctrl+c strace        <- TracerPid goes back to 0, vigil removes it from found
fn main() {
    let mut found: HashSet<u64> = collections::HashSet::new();
    let mut found_maps: HashSet<String> = collections::HashSet::new();
    let whitelist = get_whitelist().unwrap_or_default();
    loop {
        if let Ok(vec) = scan_processes() {
            for pid in vec {
                if let Ok(proc) = get_process(pid, &whitelist) {
                    if let Ok(val) = get_map(pid, &mut found_maps, &whitelist)
                        && !val.is_empty()
                    {
                        println!("{:?}", val);
                    }

                    if found.contains(&pid) && !proc.is_suspicious() {
                        found.remove(&pid);
                    }

                    if proc.is_suspicious() && !found.contains(&pid) {
                        println!("{:?}", proc);
                        found.insert(pid);
                    }
                }
            }
        }

        thread::sleep(time::Duration::from_secs(5));
    }
}
