use std::{
    collections::{self, HashSet},
    thread, time,
};

use crate::{
    process::Suspicious,
    scanner::{get_process, scan_processes},
};

mod process;
mod scanner;
// main loop here
// scans processes and prints suspicious
// doesnt print anything twice if found
// for tests:
// sleep 1000 & -> returns pid
// sudo strace -p returned_pid
// cargo run must print sleep process
fn main() {
    let mut found: HashSet<u64> = collections::HashSet::new();
    loop {
        match scan_processes() {
            Ok(vec) => {
                for pid in vec {
                    match get_process(pid) {
                        Ok(proc) => {
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
