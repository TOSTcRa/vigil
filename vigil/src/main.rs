use crate::{
    ebpf::{get_events, read_events, start_ebpf},
    process::Suspicious,
    scanner::{get_fd, get_map, get_process, get_whitelist, scan_processes},
};

mod ebpf;
mod process;
mod scanner;

// vigil anti-cheat — two detection layers running in parallel:
// 1. eBPF tracepoint — kernel-level hook catches every process_vm_readv call in real time
//    loaded at startup via start_ebpf(), events read async via tokio::spawn per CPU
// 2. /proc scanner — polls every 5 sec, 7 detection methods:
//    TracerPid, maps (w+x / suspicious dirs), LD_PRELOAD, cmdline debuggers, exe path, fd, name
// found = already alerted pids (dedup), found_maps = already checked .so paths (dedup)
// whitelist = trusted path patterns from /etc/vigil/whitelist.txt
// history = previous scan pids for birth tracking (first_run skips initial alerts)
// _active_ebpf = keeps Ebpf alive so BPF stays loaded in kernel (dropped = unloaded)
//
// how to test:
// 1. cargo +nightly build -p vigil-ebpf --target bpfel-unknown-none -Z build-std=core --release
// 2. cargo build -p vigil && sudo ./target/debug/vigil
// 3. from another terminal: python3 -c "import ctypes; libc = ctypes.CDLL('libc.so.6'); libc.process_vm_readv(1, 0, 0, 0, 0, 0)"
// 4. vigil should print SyscallEvent { pid_caller: ..., pid_target: 1 }

#[tokio::main]
async fn main() {
    let mut history: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut found: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut found_maps: std::collections::HashSet<String> = std::collections::HashSet::new();

    let whitelist = get_whitelist().unwrap_or_default();
    let mut first_run = true;

    let mut _active_ebpf = None;

    match start_ebpf() {
        Ok(mut ebpf) => {
            match get_events(&mut ebpf) {
                Ok(mut perf_array) => {
                    if let Err(e) = read_events(&mut perf_array).await {
                        println!("Error reading events: {:?}", e);
                    } else {
                        println!("eBPF loaded and listening in the background!");
                    }
                }
                Err(err) => println!("Error getting events: {:?}", err),
            }

            _active_ebpf = Some(ebpf);
        }
        Err(e) => println!("Ebpf err: {:?}", e),
    }

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

        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
