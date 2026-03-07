use std::collections::HashSet;

use std::collections::HashMap;

use crate::{
    config::{
        check_hash, compare_hashes, get_cheat_db, get_game_dir, get_whitelist, load_baseline,
        save_baseline, scan_game_dir,
    },
    ebpf::{get_events, read_events, start_ebpf},
    network::{get_connections, get_inode},
    process::{Proc, Suspicious},
    scanner::{
        get_cross_traces, get_fd, get_map, get_modules, get_process, scan_processes,
    },
};

mod config;
mod ebpf;
mod network;
mod process;
mod scanner;
mod kernel_log;
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
    let mut history: HashSet<u64> = HashSet::new();
    let mut module_history: HashSet<String> = HashSet::new();
    let mut found: HashSet<u64> = HashSet::new();
    let mut found_maps: HashSet<String> = HashSet::new();
    let mut procs: Vec<Proc> = vec![];

    let whitelist = get_whitelist().unwrap_or_default();
    let cheat_db = get_cheat_db().unwrap_or_default();
    let mut first_run = true;

    let mut _active_ebpf = None;

    let baseline_path = "/etc/vigil/game_baseline.txt";
    let mut game_baseline: HashMap<String, String> = HashMap::new();
    let mut game_dir: Option<String> = None;
    let mut integrity_counter: u32 = 0;

    if let Ok(dir) = get_game_dir() {
        match load_baseline(baseline_path) {
            Ok(bl) => {
                println!("[INTEGRITY] Baseline loaded ({} files)", bl.len());
                game_baseline = bl;
            }
            Err(_) => {
                println!("[INTEGRITY] No baseline found, creating...");
                if let Ok(hashes) = scan_game_dir(&dir) {
                    println!("[INTEGRITY] Baseline created ({} files)", hashes.len());
                    let _ = save_baseline(baseline_path, &hashes);
                    game_baseline = hashes;
                }
            }
        }
        game_dir = Some(dir);
    }

    println!(
        r#"


VVVVVVVV           VVVVVVVV iiii                        iiii  lllllll
V::::::V           V::::::Vi::::i                      i::::i l:::::l
V::::::V           V::::::V iiii                        iiii  l:::::l
V::::::V           V::::::V                                   l:::::l
 V:::::V           V:::::Viiiiiii    ggggggggg   gggggiiiiiii  l::::l
  V:::::V         V:::::V i:::::i   g:::::::::ggg::::gi:::::i  l::::l
   V:::::V       V:::::V   i::::i  g:::::::::::::::::g i::::i  l::::l
    V:::::V     V:::::V    i::::i g::::::ggggg::::::gg i::::i  l::::l
     V:::::V   V:::::V     i::::i g:::::g     g:::::g  i::::i  l::::l
      V:::::V V:::::V      i::::i g:::::g     g:::::g  i::::i  l::::l
       V:::::V:::::V       i::::i g:::::g     g:::::g  i::::i  l::::l
        V:::::::::V        i::::i g::::::g    g:::::g  i::::i  l::::l
         V:::::::V        i::::::ig:::::::ggggg:::::g i::::::il::::::l
          V:::::V         i::::::i g::::::::::::::::g i::::::il::::::l
           V:::V          i::::::i  gg::::::::::::::g i::::::il::::::l
            VVV           iiiiiiii    gggggggg::::::g iiiiiiiillllllll
                                              g:::::g
                                  gggggg      g:::::g
                                  g:::::gg   gg:::::g
                                   g::::::ggg:::::::g
                                    gg:::::::::::::g
                                      ggg::::::ggg
                                         gggggg
      "#
    );
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
        procs.clear();
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

                    if let Ok(inodes) = get_inode(pid)
                        && !inodes.is_empty()
                    {
                        if let Ok(connections) = get_connections(&inodes) {
                            for conn in &connections {
                                println!("[NET] pid {} has connection: {}", pid, conn);
                            }
                        }
                    }

                    if let Ok(Some((name, category, desc))) = check_hash(pid, &cheat_db) {
                        println!(
                            "[CHEAT] pid {} matched: {} [{}] — {}",
                            pid, name, category, desc
                        );
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

                    procs.push(proc);
                }
            }

            let cross_traced = get_cross_traces(&procs);
            for (tracer, targets) in &cross_traced {
                if targets.len() > 1 {
                    println!(
                        "There is some tracer with pid: {:?} that traces more than 1 process: {:?}",
                        tracer, targets
                    );
                }
            }

            history = vec.into_iter().collect();
        }

        if let Ok(modules) = get_modules() {
            let current_modules: HashSet<String> = modules.into_iter().collect();

            if !first_run {
                for new_mod in current_modules.difference(&module_history) {
                    println!("[ALERT] A new kernel module was loaded: {}", new_mod);
                }

                for dead_mod in module_history.difference(&current_modules) {
                    println!("[INFO] A kernel module was unloaded: {}", dead_mod);
                }
            }

            module_history = current_modules;
        }

        if let Some(ref dir) = game_dir {
            integrity_counter += 1;
            if integrity_counter >= 12 {
                integrity_counter = 0;
                if let Ok(current) = scan_game_dir(dir) {
                    let changes = compare_hashes(&game_baseline, &current);
                    if changes.total() > 0 {
                        for f in &changes.modified {
                            println!("[INTEGRITY] Modified: {}", f);
                        }
                        for f in &changes.added {
                            println!("[INTEGRITY] Added: {}", f);
                        }
                        for f in &changes.removed {
                            println!("[INTEGRITY] Removed: {}", f);
                        }

                        if changes.is_suspicious() {
                            println!(
                                "[INTEGRITY] SUSPICIOUS — only {} file(s) changed",
                                changes.total()
                            );
                        } else {
                            println!(
                                "[INTEGRITY] {} files changed — likely a game update, resaving baseline",
                                changes.total()
                            );
                            let _ = save_baseline(baseline_path, &current);
                            game_baseline = current;
                        }
                    }
                }
            }
        }

        first_run = false;
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
