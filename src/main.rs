use std::{
    collections::{self, HashSet},
    thread, time,
};

use crate::{
    process::Suspicious,
    scanner::{get_map, get_process, scan_processes},
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
    loop {
        match scan_processes() {
            Ok(vec) => {
                for pid in vec {
                    match get_process(pid) {
                        Ok(proc) => {
                            match get_map(pid, &mut found_maps) {
                                Ok(val) => {
                                    if !val.is_empty() {
                                        println!("{:?}", val)
                                    }
                                }
                                Err(_) => {}
                            };

                            if found.contains(&pid) && !proc.is_suspicious() {
                                found.remove(&pid);
                            }
                            if proc.is_suspicious() && !found.contains(&pid) {
                                println!("{:?}", proc);
                                found.insert(pid);
                            }
                        }
                        Err(_) => {}
                    };
                }
            }
            Err(_) => {}
        }
        thread::sleep(time::Duration::from_secs(5));
    }
}
