# VIGIL Anti-Cheat System

Linux-native anti-cheat for competitive gaming (CS2 and others). Written in Rust.

Not a FACEIT competitor — an independent anti-cheat platform focused on Linux.

## Current Status

**Phase 2 IN PROGRESS.** Working process scanner with continuous monitoring, 6 detection methods, whitelist system, process birth tracking, fd monitoring, and eBPF kernel-level syscall interception. All tested live.

### What works now:
- Scan all running processes via `/proc`
- Parse `/proc/{PID}/status` (name, state, TracerPid)
- Detect processes being traced/debugged (TracerPid != 0)
- Continuous monitoring loop (every 5 sec, deduplication, auto-cleanup)
- Parse `/proc/{PID}/maps` — detect suspicious .so libraries (w+x permissions, unusual paths)
- Parse `/proc/{PID}/environ` — detect LD_PRELOAD injection
- Parse `/proc/{PID}/cmdline` — detect debugger tools (gdb, strace, ltrace)
- Parse `/proc/{PID}/exe` — detect binaries from suspicious dirs (symlink check + whitelist)
- Monitor `/proc/{PID}/fd` — detect processes reading other processes memory via /proc/*/mem
- Whitelist system (`/etc/vigil/whitelist.txt`) — filter trusted paths in maps, LD_PRELOAD, and exe
- Process birth tracking — detect new processes appearing mid-game
- eBPF tracepoints — kernel-level interception of `process_vm_readv` and `process_vm_writev` in real time
- Async event reading via tokio — BPF events processed in background, /proc scan in main loop

## Roadmap

### Phase 1: Process Monitoring (current)
- [x] Scan `/proc` for all running PIDs
- [x] Parse `/proc/{PID}/status` — name, state, TracerPid
- [x] Basic suspicion detection (name, status, TracerPid)
- [x] Live TracerPid detection test (attach debugger, verify Vigil catches it)
- [x] Continuous monitoring loop (scan every 5 seconds, dedup alerts, auto-cleanup)
- [x] Parse `/proc/{PID}/maps` — detect injected/suspicious shared libraries
- [x] Detect LD_PRELOAD injection via `/proc/{PID}/environ`
- [x] Parse `/proc/{PID}/cmdline` — detect suspicious launch arguments (gdb, strace, ltrace)
- [x] Parse `/proc/{PID}/exe` — verify executable path legitimacy (symlink check + whitelist)
- [x] Whitelist for trusted paths (~/.config/vigil/whitelist.txt — filters maps + LD_PRELOAD)
- [x] Process birth/death tracking (detect new processes appearing mid-game)

### Phase 2: Deep Process Inspection
- [x] Monitor `/proc/{PID}/fd` — detect processes reading other processes memory
- [x] Detect `process_vm_readv` usage via eBPF tracepoint (kernel-level, real-time)
- [x] Detect `process_vm_writev` usage via eBPF tracepoint (kernel-level, real-time)
- [x] Parent process tracking (PPid) — parsed from /proc/PID/status, suspicious tree detection TBD
- [x] `/proc/modules` scanning — detect new/unloaded kernel modules (birth/death tracking)
- [x] Detect `ptrace` usage via eBPF tracepoint (`sys_enter_ptrace`) — catch PTRACE_PEEKDATA memory reads in real time
- [ ] Detect `memfd_create` usage via eBPF tracepoint — catch anonymous file creation for code injection
- [ ] Detect `/proc/PID/mem` writes via eBPF tracepoint — catch direct memory injection
- [ ] Detect kernel module loading in real time via eBPF kprobe on `do_init_module` (replaces /proc/modules polling)
- [ ] Detect known cheat signatures (hash database)
- [ ] Detect ptrace-based memory reading by scanning all processes for TracerPid pointing to same target

### Phase 3: System-Level Detection
- [ ] dmesg log monitoring for suspicious kernel activity
- [ ] Network traffic analysis — detect cheat communication with external servers
- [ ] Game file hash verification (detect modified game files)
- [ ] Sandboxing detection (is the game running in a compromised environment?)
- [ ] inotify watching for suspicious file changes in game directories

### Phase 4: Daemon & Service
- [ ] Run Vigil as a systemd service/daemon
- [ ] Configuration file (what game to protect, scan interval, rules)
- [ ] Logging system (write scan results to files, timestamps)
- [ ] CLI interface (start/stop monitoring, show status, show suspicious processes)
- [ ] Signal handling (graceful shutdown)

### Phase 5: Reporting & Backend
- [ ] Local report generation (JSON/structured output)
- [ ] Server communication — send scan results to backend
- [ ] REST API backend (Rust with Actix/Axum)
- [ ] Player verification system (is this player running Vigil?)
- [ ] Match integrity reports

### Phase 6: Frontend & Platform
- [ ] Web dashboard — view scan reports, player status
- [ ] Admin panel — manage rules, review flagged players
- [ ] Player-facing client UI (system tray or terminal UI)
- [ ] Account system and authentication

### Phase 7: Advanced (long-term)
- [ ] Custom kernel module for deeper monitoring (requires unsafe Rust / C)
- [ ] Machine learning for behavior analysis (mouse patterns, aim patterns)
- [ ] Community rule database (crowdsourced cheat signatures)
- [ ] Game developer SDK/API integration
- [ ] Windows port (maybe, for fun)

## Tech Stack

- **Language:** Rust
- **Target OS:** Linux (primary), Windows (future maybe)
- **Detection methods:** `/proc` filesystem, ptrace monitoring, library injection, LD_PRELOAD, eBPF syscall tracing
- **Async runtime:** tokio (for eBPF event reading)
- **eBPF:** aya + aya-ebpf (Rust-native BPF framework)
- **Backend:** TBD (Rust with Actix/Axum)
- **Frontend:** TBD (pure Rust with egui)

## Project Structure

```
vigil/                 — userspace binary (cargo workspace)
  src/
    main.rs            — entry point, async main, eBPF init + /proc monitoring loop
    process.rs         — Proc struct, ProcessStatus enum, Suspicious trait
    scanner.rs         — scan_processes(), get_process(), get_map(), check_preload(), get_cmdline(), get_exe(), get_fd(), get_whitelist()
    ebpf.rs            — start_ebpf(), get_events(), read_events() — BPF loading + async event reading
vigil-ebpf/            — BPF kernel program (compiled for bpfel-unknown-none)
  src/
    main.rs            — tracepoint for process_vm_readv, PerfEventArray for sending events
vigil-common/          — shared types between kernel and userspace
  src/
    lib.rs             — SyscallEvent struct (#[repr(C)], no_std)
```

## How cheats work on Linux (research notes)

- **Memory reading:** Cheats use ptrace or /proc/PID/mem to read game memory (player positions, health). Detected via TracerPid.
- **Library injection:** LD_PRELOAD or dlopen to inject code into game process. Detected via /proc/PID/maps and /proc/PID/environ.
- **Memory manipulation:** process_vm_readv/writev to read/write memory without ptrace. Harder to detect.
- **File modification:** Replacing game textures/shaders for wallhack. Detected via file hash verification.
- **Kernel modules:** Rootkit-style cheats that hide from userspace. Detected via /proc/modules monitoring.

## Building

```
# build BPF program (needs nightly + bpf-linker)
cargo +nightly build -p vigil-ebpf --target bpfel-unknown-none -Z build-std=core --release

# build userspace
cargo build -p vigil

# run (needs sudo for eBPF + /proc/PID/fd access)
sudo ./target/debug/vigil
```

Requires Linux. eBPF tracepoints require root. `/proc/PID/fd` monitoring requires elevated permissions.
