use crate::{
    ebpf::{get_events, read_events, start_ebpf},
    process::{Proc, Suspicious},
    scanner::{
        check_hash, get_cheat_db, get_connections, get_cross_traces, get_fd, get_inode, get_map,
        get_modules, get_process, get_whitelist, scan_processes,
    },
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
    let mut module_history: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut found: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut found_maps: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut procs: Vec<Proc> = vec![];

    let whitelist = get_whitelist().unwrap_or_default();
    let cheat_db = get_cheat_db().unwrap_or_default();
    let mut first_run = true;

    let mut _active_ebpf = None;

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

            if let Ok(cross_traced) = get_cross_traces(&procs) {
                for (tracer, targets) in &cross_traced {
                    if targets.len() > 1 {
                        println!(
                            "There is some tracer with pid: {:?} that traces more than 1 process: {:?}",
                            tracer, targets
                        );
                    }
                }
            }

            history = vec.into_iter().collect();
        }

        if let Ok(modules) = get_modules() {
            let current_modules: std::collections::HashSet<String> = modules.into_iter().collect();

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

        first_run = false;
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
