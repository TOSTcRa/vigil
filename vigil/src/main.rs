use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::cli::{Commands, cmd_check, cmd_init, cmd_scan, cmd_status, parse_args};
use crate::kernel_log::{get_kernel_logs, parse_kernel_log};
use crate::report::{
    CheatMatch, CrossTrace, FileIntegrity, ModuleChange, NetworkConnection, SuspiciousProcess,
    build_report,
};
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

mod bpf;
mod cli;
mod client;
mod config;
mod crypto;
mod ebpf;
mod http_client;
mod json;
mod kernel_log;
mod network;
mod notify;
mod process;
mod report;
mod runtime;
mod scanner;
mod sys;
mod timestamp;
mod toml_parser;

static RUNNING: AtomicBool = AtomicBool::new(true);

unsafe extern "C" fn handle_sigint(_sig: i32) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn main() {
    // install signal handler for ctrl+c
    libc_signal(2, handle_sigint as *const () as usize); // SIGINT = 2

    match parse_args() {
        Some(Commands::Scan) => cmd_scan(),
        Some(Commands::Check) => cmd_check(),
        Some(Commands::Status) => cmd_status(),
        Some(Commands::Init) => cmd_init(),
        None => run_daemon(),
    }
}

unsafe extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
}

fn libc_signal(sig: i32, handler: usize) {
    unsafe {
        signal(sig, handler);
    }
}

fn run_daemon() {
    let mut history: HashSet<u64> = HashSet::new();
    let mut module_history: HashSet<String> = HashSet::new();
    let mut found: HashSet<u64> = HashSet::new();
    let mut found_maps: HashSet<String> = HashSet::new();
    let mut procs: Vec<Proc> = vec![];

    let whitelist = get_whitelist().unwrap_or_default();
    let cheat_db = get_cheat_db().unwrap_or_default();
    let mut first_run = true;

    let mut _active_ebpf = None;
    let mut ebpf_active = false;

    let config = match get_config() {
        Ok(c) => {
            println!("[CONFIG] Loaded /etc/vigil/config.toml");
            Some(c)
        }
        Err(e) => {
            eprintln!("[CONFIG] Failed to load config: {} - using defaults", e);
            None
        }
    };

    let log_path = config
        .as_ref()
        .map(|c| c.logging.path.clone())
        .unwrap_or_else(|| String::from("/var/log/vigil.log"));

    let game_path_from_config = config.as_ref().map(|c| c.game.path.clone());

    // Server reporting config
    let server_url = config
        .as_ref()
        .and_then(|c| c.server.as_ref())
        .map(|s| s.url.clone());
    let player_id = config
        .as_ref()
        .and_then(|c| c.server.as_ref())
        .map(|s| s.player_id.clone())
        .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string());

    if server_url.is_some() {
        let _ = log(
            LogLevel::Info,
            &format!("Server reporting enabled, player_id: {}", player_id),
            &log_path,
        );
    }

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
                        "Small targeted file change detected - possible cheat injection",
                        &log_path,
                    );
                }
            } else {
                let _ = log(
                    LogLevel::Info,
                    "Game integrity OK - no changes since baseline",
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
                Ok(_event_fds) => {
                    if let Err(e) = read_events(&mut ebpf) {
                        println!("Error reading events: {:?}", e);
                    } else {
                        println!("eBPF loaded and listening in the background!");
                        ebpf_active = true;
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
        std::thread::spawn(move || {
            let _ = log(
                LogLevel::Inotify,
                &format!("Starting watcher for {}", dir),
                &inotify_log_path,
            );
            if let Err(e) = notify::watch_game_dir(dir, baseline) {
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

    let sandbox_reasons = check_sandbox().unwrap_or_default();
    if !sandbox_reasons.is_empty() {
        let _ = log(
            LogLevel::Alert,
            &format!("Sandbox environment detected: {:?}", sandbox_reasons),
            &log_path,
        );
    }

    runtime::block_on(async {
    while RUNNING.load(Ordering::SeqCst) {
        procs.clear();

        // Report data collectors
        let mut report_suspicious: Vec<SuspiciousProcess> = vec![];
        let mut report_cheats: Vec<CheatMatch> = vec![];
        let mut report_connections: Vec<NetworkConnection> = vec![];
        let mut report_modules: Vec<ModuleChange> = vec![];

        if let Ok(vec) = scan_processes() {
            for &pid in &vec {
                if let Ok(proc) = get_process(pid, &whitelist) {
                    if let Ok(val) = get_map(pid, &mut found_maps, &whitelist)
                        && !val.is_empty()
                    {
                        let _ = log(LogLevel::Alert, &format!("{:?}", val), &log_path);
                        for (path, reason) in &val {
                            report_suspicious.push(SuspiciousProcess {
                                pid,
                                name: path.clone(),
                                reason: reason.clone(),
                            });
                        }
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
                            report_connections.push(NetworkConnection {
                                pid,
                                address: conn.clone(),
                            });
                        }
                    }

                    if let Ok(Some((name, category, desc))) = check_hash(pid, &cheat_db) {
                        let _ = log(
                            LogLevel::Cheat,
                            &format!("pid {} matched: {} [{}] - {}", pid, name, category, desc),
                            &log_path,
                        );
                        report_cheats.push(CheatMatch {
                            pid,
                            name: name.clone(),
                            category: category.clone(),
                            description: desc.clone(),
                        });
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
            let report_traces: Vec<CrossTrace> = cross_traced
                .iter()
                .filter(|(_, targets)| targets.len() > 1)
                .map(|(tracer, targets)| {
                    let _ = log(
                        LogLevel::Alert,
                        &format!(
                            "Tracer pid {} traces multiple processes: {:?}",
                            tracer, targets
                        ),
                        &log_path,
                    );
                    CrossTrace {
                        tracer_pid: *tracer,
                        targets: targets.clone(),
                    }
                })
                .collect();

            history = vec.into_iter().collect();

            // Module tracking
            if let Ok(modules) = get_modules() {
                let current_modules: HashSet<String> = modules.into_iter().collect();

                if !first_run {
                    for new_mod in current_modules.difference(&module_history) {
                        let _ = log(
                            LogLevel::Alert,
                            &format!("New kernel module loaded: {}", new_mod),
                            &log_path,
                        );
                        report_modules.push(ModuleChange {
                            name: new_mod.clone(),
                            action: "loaded".to_string(),
                        });
                    }

                    for dead_mod in module_history.difference(&current_modules) {
                        let _ = log(
                            LogLevel::Info,
                            &format!("Kernel module unloaded: {}", dead_mod),
                            &log_path,
                        );
                        report_modules.push(ModuleChange {
                            name: dead_mod.clone(),
                            action: "unloaded".to_string(),
                        });
                    }
                }

                module_history = current_modules;
            }

            // Build and send report to server
            if let Some(ref url) = server_url {
                let integrity = if let Some(ref dir) = game_dir {
                    if let Ok(current) = scan_game_dir(dir) {
                        let changes = compare_hashes(&game_baseline, &current);
                        FileIntegrity {
                            status: if changes.total() == 0 {
                                "ok".to_string()
                            } else {
                                "modified".to_string()
                            },
                            modified: changes.modified,
                            added: changes.added,
                            removed: changes.removed,
                        }
                    } else {
                        FileIntegrity {
                            status: "unknown".to_string(),
                            modified: vec![],
                            added: vec![],
                            removed: vec![],
                        }
                    }
                } else {
                    FileIntegrity {
                        status: "unconfigured".to_string(),
                        modified: vec![],
                        added: vec![],
                        removed: vec![],
                    }
                };

                let scan_report = build_report(
                    &player_id,
                    ebpf_active,
                    &sandbox_reasons,
                    report_suspicious,
                    report_cheats,
                    report_traces,
                    report_connections,
                    report_modules,
                    integrity,
                );

                if let Err(e) = client::send_report(url, &scan_report, None) {
                    let _ = log(
                        LogLevel::Info,
                        &format!("Failed to send report: {}", e),
                        &log_path,
                    );
                }
            }
        }

        first_run = false;
        runtime::sleep(Duration::from_secs(5)).await;
    }
    }); // block_on

    let _ = log(LogLevel::Info, "Vigil stopped (SIGINT)", &log_path);
}
