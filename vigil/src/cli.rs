use std::collections::HashSet;

use crate::config::{
    check_hash, compare_hashes, get_cheat_db, get_config, get_game_dir, get_whitelist,
    load_baseline, save_baseline, scan_game_dir,
};
use crate::network::{get_connections, get_inode};
use crate::process::{Proc, Suspicious};
use crate::scanner::{
    check_sandbox, get_cross_traces, get_fd, get_map, get_modules, get_process, scan_processes,
};

pub enum Commands {
    Scan,
    Check,
    Status,
    Init,
}

pub fn parse_args() -> Option<Commands> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None; // no subcommand = run daemon
    }
    match args[1].as_str() {
        "scan" => Some(Commands::Scan),
        "check" => Some(Commands::Check),
        "status" => Some(Commands::Status),
        "init" => Some(Commands::Init),
        "--help" | "-h" => {
            println!("vigil - linux anti-cheat system\n");
            println!("usage: vigil [command]\n");
            println!("commands:");
            println!("  scan    one-time /proc scan");
            println!("  check   compare game files against baseline");
            println!("  status  show configuration and system readiness");
            println!("  init    create /etc/vigil/ with default configs");
            println!("\nno command = run as daemon");
            std::process::exit(0);
        }
        other => {
            eprintln!("unknown command: {}", other);
            eprintln!("run 'vigil --help' for usage");
            std::process::exit(1);
        }
    }
}

// vigil scan - one-time /proc scan without loop, eBPF, or inotify
pub fn cmd_scan() {
    let whitelist = get_whitelist().unwrap_or_default();
    let cheat_db = get_cheat_db().unwrap_or_default();
    let mut found_maps: HashSet<String> = HashSet::new();

    if let Ok(reasons) = check_sandbox()
        && !reasons.is_empty()
    {
        println!("[ALERT] Sandbox environment detected: {:?}", reasons);
    }

    let pids = match scan_processes() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to scan /proc: {}", e);
            return;
        }
    };

    let mut procs: Vec<Proc> = vec![];

    for &pid in &pids {
        if let Ok(proc) = get_process(pid, &whitelist) {
            if let Ok(val) = get_map(pid, &mut found_maps, &whitelist)
                && !val.is_empty()
            {
                println!("[ALERT] {:?}", val);
            }

            if let Ok(val) = get_fd(pid)
                && !val.is_empty()
            {
                println!(
                    "[ALERT] Process {}, reading other process memory: {:?}",
                    pid, val
                );
            }

            if let Ok(inodes) = get_inode(pid)
                && !inodes.is_empty()
                && let Ok(connections) = get_connections(&inodes)
            {
                for conn in &connections {
                    println!("[NET] pid {} has connection: {}", pid, conn);
                }
            }

            if let Ok(Some((name, category, desc))) = check_hash(pid, &cheat_db) {
                println!(
                    "[CHEAT] pid {} matched: {} [{}] - {}",
                    pid, name, category, desc
                );
            }

            if proc.is_suspicious() {
                println!("[ALERT] {:?}", proc);
            }

            procs.push(proc);
        }
    }

    let cross_traced = get_cross_traces(&procs);
    for (tracer, targets) in &cross_traced {
        if targets.len() > 1 {
            println!(
                "[ALERT] Tracer pid {} traces multiple processes: {:?}",
                tracer, targets
            );
        }
    }

    if let Ok(modules) = get_modules() {
        for m in &modules {
            println!("[MODULE] {}", m);
        }
    }

    println!("[SCAN] Done. Scanned {} processes.", pids.len());
}

// vigil check - compare current game files against baseline
pub fn cmd_check() {
    let config = get_config().ok();
    let game_path = config
        .as_ref()
        .map(|c| c.game.path.clone())
        .or_else(|| get_game_dir().ok());

    let dir = match game_path {
        Some(d) => d,
        None => {
            eprintln!("No game directory configured (config.toml or game_dir.txt)");
            return;
        }
    };

    let baseline_path = "/etc/vigil/game_baseline.txt";

    let baseline = match load_baseline(baseline_path) {
        Ok(bl) => {
            println!("[CHECK] Baseline loaded ({} files)", bl.len());
            bl
        }
        Err(_) => {
            println!("[CHECK] No baseline found, creating...");
            match scan_game_dir(&dir) {
                Ok(hashes) => {
                    let _ = save_baseline(baseline_path, &hashes);
                    println!("[CHECK] Baseline created ({} files)", hashes.len());
                    println!("[CHECK] Run again to compare against this baseline.");
                    return;
                }
                Err(e) => {
                    eprintln!("[CHECK] Failed to scan game dir: {}", e);
                    return;
                }
            }
        }
    };

    let current = match scan_game_dir(&dir) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[CHECK] Failed to scan game dir: {}", e);
            return;
        }
    };

    let changes = compare_hashes(&baseline, &current);
    if changes.total() == 0 {
        println!("[CHECK] Game integrity OK - no changes since baseline.");
        return;
    }

    for f in &changes.modified {
        println!("[CHECK] MODIFIED: {}", f);
    }
    for f in &changes.added {
        println!("[CHECK] ADDED: {}", f);
    }
    for f in &changes.removed {
        println!("[CHECK] REMOVED: {}", f);
    }
    if changes.is_suspicious() {
        println!("[CHECK] Small targeted change - possible cheat injection.");
    }
    println!(
        "[CHECK] Total changes: {} modified, {} added, {} removed",
        changes.modified.len(),
        changes.added.len(),
        changes.removed.len()
    );
}

// vigil status - show current configuration and system readiness
pub fn cmd_status() {
    println!("=== Vigil Status ===\n");

    let config = get_config().ok();

    match &config {
        Some(c) => {
            println!("[CONFIG] /etc/vigil/config.toml - OK");
            println!("  game path:  {}", c.game.path);
            println!("  log path:   {}", c.logging.path);
        }
        None => println!("[CONFIG] /etc/vigil/config.toml - not found"),
    }

    match get_whitelist() {
        Ok(w) => println!("[WHITELIST] {} entries loaded", w.len()),
        Err(_) => println!("[WHITELIST] not found (/etc/vigil/whitelist.txt)"),
    }

    match get_cheat_db() {
        Ok(db) => println!("[CHEAT DB] {} signatures loaded", db.len()),
        Err(_) => println!("[CHEAT DB] not found (/etc/vigil/cheat_hashes.txt)"),
    }

    let game_path = config.map(|c| c.game.path).or_else(|| get_game_dir().ok());

    match game_path {
        Some(dir) => {
            println!("[GAME DIR] {}", dir);
            if std::path::Path::new(&dir).is_dir() {
                println!("  directory exists: yes");
            } else {
                println!("  directory exists: no");
            }
        }
        None => println!("[GAME DIR] not configured"),
    }

    let baseline_path = "/etc/vigil/game_baseline.txt";
    match load_baseline(baseline_path) {
        Ok(bl) => println!("[BASELINE] {} files tracked", bl.len()),
        Err(_) => println!("[BASELINE] not found (run `vigil check` to create)"),
    }

    let ebpf_path = "./target/bpfel-unknown-none/release/vigil";
    if std::path::Path::new(ebpf_path).exists() {
        println!("[eBPF] bytecode found");
    } else {
        println!("[eBPF] bytecode not found (build with cargo +nightly)");
    }

    match check_sandbox() {
        Ok(reasons) if !reasons.is_empty() => {
            println!("[SANDBOX] detected: {:?}", reasons);
        }
        Ok(_) => println!("[SANDBOX] not detected"),
        Err(e) => println!("[SANDBOX] check failed: {}", e),
    }

    println!("\n=== Done ===");
}

// vigil init - create /etc/vigil/ directory and config files with defaults
pub fn cmd_init() {
    let vigil_dir = "/etc/vigil";

    if let Err(e) = std::fs::create_dir_all(vigil_dir) {
        eprintln!(
            "[INIT] Failed to create {}: {} (run with sudo)",
            vigil_dir, e
        );
        return;
    }
    println!("[INIT] {} - OK", vigil_dir);

    let config_path = format!("{}/config.toml", vigil_dir);
    if !std::path::Path::new(&config_path).exists() {
        let config_content = r#"[game]
path = "/home/user/.steam/steam/steamapps/common/GameName"

[logging]
path = "/var/log/vigil.log"

# Uncomment to enable server reporting
# [server]
# url = "http://localhost:3000"
# player_id = "00000000-0000-0000-0000-000000000000"
"#;
        match std::fs::write(&config_path, config_content) {
            Ok(_) => println!("[INIT] {} - created (edit game path!)", config_path),
            Err(e) => eprintln!("[INIT] {} - failed: {}", config_path, e),
        }
    } else {
        println!("[INIT] {} - already exists", config_path);
    }

    let whitelist_path = format!("{}/whitelist.txt", vigil_dir);
    if !std::path::Path::new(&whitelist_path).exists() {
        let whitelist_content = "/usr/lib/
/usr/lib64/
/lib/
/lib64/
libmozsandbox.so
libgamemodeauto.so
libsteam_api.so
libmangoapp.so
libmangohud.so
";
        match std::fs::write(&whitelist_path, whitelist_content) {
            Ok(_) => println!("[INIT] {} - created", whitelist_path),
            Err(e) => eprintln!("[INIT] {} - failed: {}", whitelist_path, e),
        }
    } else {
        println!("[INIT] {} - already exists", whitelist_path);
    }

    let cheat_path = format!("{}/cheat_hashes.txt", vigil_dir);
    if !std::path::Path::new(&cheat_path).exists() {
        let cheat_content = "name_only:aimbot:cheat:Generic aimbot process
name_only:wallhack:cheat:Generic wallhack process
name_only:csgo_cheat:cheat:CS cheat process
name_only:memwrite:injection:Memory writer tool
";
        match std::fs::write(&cheat_path, cheat_content) {
            Ok(_) => println!("[INIT] {} - created", cheat_path),
            Err(e) => eprintln!("[INIT] {} - failed: {}", cheat_path, e),
        }
    } else {
        println!("[INIT] {} - already exists", cheat_path);
    }

    let log_path = "/var/log/vigil.log";
    if !std::path::Path::new(log_path).exists() {
        match std::fs::write(log_path, "") {
            Ok(_) => println!("[INIT] {} - created", log_path),
            Err(e) => eprintln!("[INIT] {} - failed: {}", log_path, e),
        }
    } else {
        println!("[INIT] {} - already exists", log_path);
    }

    println!("\n[INIT] Done. Edit {} to set your game path.", config_path);
}
