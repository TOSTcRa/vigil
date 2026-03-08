use std::collections::HashSet;

use std::collections::HashMap;

use clap::Parser;

use crate::cli::{Cli, Commands, cmd_check, cmd_init, cmd_scan, cmd_status};
use crate::kernel_log::{get_kernel_logs, parse_kernel_log};
use crate::scanner::check_sandbox;
use crate::{
    config::{
        LogLevel, check_hash, compare_hashes, get_cheat_db, get_config, get_game_dir,
        get_whitelist, load_baseline, log, save_baseline, scan_game_dir,
    },
    ebpf::{get_events, read_events, start_ebpf},
    network::{get_connections, get_inode},
    process::{Proc, Suspicious},
    scanner::{get_cross_traces, get_fd, get_map, get_modules, get_process, scan_processes},
};

mod cli;
mod config;
mod ebpf;
mod kernel_log;
mod network;
mod notify;
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
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan) => cmd_scan(),
        Some(Commands::Check) => cmd_check(),
        Some(Commands::Status) => cmd_status(),
        Some(Commands::Init) => cmd_init(),
        None => run_daemon().await,
    }
}

// vigil (no args) — full daemon: eBPF + /proc loop + inotify + kernel log monitor
async fn run_daemon() {
    let mut history: HashSet<u64> = HashSet::new();
    let mut module_history: HashSet<String> = HashSet::new();
    let mut found: HashSet<u64> = HashSet::new();
    let mut found_maps: HashSet<String> = HashSet::new();
    let mut procs: Vec<Proc> = vec![];

    let whitelist = get_whitelist().unwrap_or_default();
    let cheat_db = get_cheat_db().unwrap_or_default();
    let mut first_run = true;

    let mut _active_ebpf = None;

    let config = match get_config() {
        Ok(c) => {
            println!("[CONFIG] Loaded /etc/vigil/config.toml");
            Some(c)
        }
        Err(e) => {
            eprintln!("[CONFIG] Failed to load config: {} — using defaults", e);
            None
        }
    };

    let log_path = config
        .as_ref()
        .map(|c| c.logging.path.clone())
        .unwrap_or_else(|| String::from("/var/log/vigil.log"));

    let game_path_from_config = config.as_ref().map(|c| c.game.path.clone());

    let baseline_path = "/etc/vigil/game_baseline.txt";
    let mut game_baseline: HashMap<String, String> = HashMap::new();
    let mut game_dir: Option<String> = None;

    let dir_result = game_path_from_config
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no config"))
        .or_else(|_| get_game_dir());

    if let Ok(dir) = dir_result {
        match load_baseline(baseline_path) {
            Ok(bl) => {
                let _ = log(
                    LogLevel::Info,
                    &format!("Baseline loaded ({} files)", bl.len()),
                    &log_path,
                );
                game_baseline = bl;
            }
            Err(_) => {
                let _ = log(LogLevel::Info, "No baseline found, creating...", &log_path);
                if let Ok(hashes) = scan_game_dir(&dir) {
                    let _ = log(
                        LogLevel::Info,
                        &format!("Baseline created ({} files)", hashes.len()),
                        &log_path,
                    );
                    let _ = save_baseline(baseline_path, &hashes);
                    game_baseline = hashes;
                }
            }
        }

        if let Ok(current) = scan_game_dir(&dir) {
            let changes = compare_hashes(&game_baseline, &current);
            if changes.total() > 0 {
                for f in &changes.modified {
                    let _ = log(
                        LogLevel::Alert,
                        &format!("Game file MODIFIED: {}", f),
                        &log_path,
                    );
                }
                for f in &changes.added {
                    let _ = log(
                        LogLevel::Alert,
                        &format!("Game file ADDED: {}", f),
                        &log_path,
                    );
                }
                for f in &changes.removed {
                    let _ = log(
                        LogLevel::Alert,
                        &format!("Game file REMOVED: {}", f),
                        &log_path,
                    );
                }
                if changes.is_suspicious() {
                    let _ = log(
                        LogLevel::Cheat,
                        "Small targeted file change detected — possible cheat injection",
                        &log_path,
                    );
                }
            } else {
                let _ = log(
                    LogLevel::Info,
                    "Game integrity OK — no changes since baseline",
                    &log_path,
                );
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

    if let Some(ref dir) = game_dir {
        let dir = dir.clone();
        let baseline = game_baseline.clone();
        let inotify_log_path = log_path.clone();
        tokio::spawn(async move {
            let _ = log(
                LogLevel::Inotify,
                &format!("Starting watcher for {}", dir),
                &inotify_log_path,
            );
            if let Err(e) = notify::watch_game_dir(dir, baseline).await {
                let _ = log(
                    LogLevel::Inotify,
                    &format!("Watcher error: {}", e),
                    &inotify_log_path,
                );
            }
        });
    }

    std::thread::spawn(|| {
        if let Err(e) = get_kernel_logs(|log| parse_kernel_log(&log)) {
            eprintln!("[KLOG] Failed to read /dev/kmsg: {}", e);
        }
    });

    if let Ok(reasons) = check_sandbox()
        && !reasons.is_empty()
    {
        let _ = log(
            LogLevel::Alert,
            &format!("Sandbox environment detected: {:?}", reasons),
            &log_path,
        );
    }

    tokio::select! {
        _ = async {
            loop {
                procs.clear();
                if let Ok(vec) = scan_processes() {
                    for &pid in &vec {
                        if let Ok(proc) = get_process(pid, &whitelist) {
                            if let Ok(val) = get_map(pid, &mut found_maps, &whitelist)
                                && !val.is_empty()
                            {
                                let _ = log(LogLevel::Alert, &format!("{:?}", val), &log_path);
                            }

                            if let Ok(val) = get_fd(pid)
                                && !val.is_empty()
                            {
                                let _ = log(
                                    LogLevel::Alert,
                                    &format!("Process {}, reading other process memory: {:?}", pid, val),
                                    &log_path,
                                );
                            }

                            if let Ok(inodes) = get_inode(pid)
                                && !inodes.is_empty()
                                && let Ok(connections) = get_connections(&inodes)
                            {
                                for conn in &connections {
                                    let _ = log(
                                        LogLevel::Net,
                                        &format!("pid {} has connection: {}", pid, conn),
                                        &log_path,
                                    );
                                }
                            }

                            if let Ok(Some((name, category, desc))) = check_hash(pid, &cheat_db) {
                                let _ = log(
                                    LogLevel::Cheat,
                                    &format!("pid {} matched: {} [{}] — {}", pid, name, category, desc),
                                    &log_path,
                                );
                            }

                            if found.contains(&pid) && !proc.is_suspicious() {
                                found.remove(&pid);
                            }

                            if proc.is_suspicious() && !found.contains(&pid) {
                                let _ = log(LogLevel::Alert, &format!("{:?}", proc), &log_path);
                                found.insert(pid);
                            }

                            if !history.contains(&pid) && !first_run {
                                let _ = log(
                                    LogLevel::Info,
                                    &format!("A new process was born: \n{:?}", proc),
                                    &log_path,
                                );
                            }

                            procs.push(proc);
                        }
                    }

                    let cross_traced = get_cross_traces(&procs);
                    for (tracer, targets) in &cross_traced {
                        if targets.len() > 1 {
                            let _ = log(
                                LogLevel::Alert,
                                &format!(
                                    "Tracer pid {} traces multiple processes: {:?}",
                                    tracer, targets
                                ),
                                &log_path,
                            );
                        }
                    }

                    history = vec.into_iter().collect();
                }

                if let Ok(modules) = get_modules() {
                    let current_modules: HashSet<String> = modules.into_iter().collect();

                    if !first_run {
                        for new_mod in current_modules.difference(&module_history) {
                            let _ = log(
                                LogLevel::Alert,
                                &format!("New kernel module loaded: {}", new_mod),
                                &log_path,
                            );
                        }

                        for dead_mod in module_history.difference(&current_modules) {
                            let _ = log(
                                LogLevel::Info,
                                &format!("Kernel module unloaded: {}", dead_mod),
                                &log_path,
                            );
                        }
                    }

                    module_history = current_modules;
                }

                first_run = false;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {
            let _ = log(LogLevel::Info, "Vigil stopped (SIGINT)", &log_path);
        }
    }
}
