<div align="center">

```
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
```

**Linux-native anti-cheat for competitive gaming.**

Written in Rust. Powered by eBPF.

[![Linux](https://img.shields.io/badge/platform-Linux-yellow?logo=linux&logoColor=white)](#)
[![Rust](https://img.shields.io/badge/language-Rust-orange?logo=rust)](#)
[![eBPF](https://img.shields.io/badge/kernel-eBPF-red)](#)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](#)
[![Status](https://img.shields.io/badge/status-Phase%202-brightgreen)](#)

---

*No corporate backing. No Windows port. No compromises.*
*Built for Linux gamers, by a Linux gamer.*

</div>

## What is Vigil?

Vigil is a kernel-level anti-cheat system built from the ground up for Linux. It combines real-time eBPF syscall interception with deep `/proc` filesystem analysis to detect cheats, memory injectors, debugger attachments, and rootkit-style kernel modules.

There is no production-ready, open-source, Linux-native anti-cheat. FACEIT doesn't support Linux. ESEA doesn't support Linux. Riot Vanguard blocks Linux entirely. EAC and BattlEye offer degraded usermode-only support through Proton as an opt-in afterthought.

Vigil fills that gap.

## How It Works

Vigil runs two detection layers in parallel:

```
                    +--------------------------+
                    |       VIGIL CORE         |
                    +--------------------------+
                           /          \
                          /            \
            +----------------+    +------------------+
            |  eBPF LAYER    |    |  /proc SCANNER   |
            |  (kernel-level)|    |  (userspace)     |
            +----------------+    +------------------+
            | Tracepoints:   |    | 7 detection      |
            | - vm_readv     |    | methods, polling |
            | - vm_writev    |    | every 5 seconds  |
            | - ptrace       |    | with dedup and   |
            | - memfd_create |    | whitelist        |
            +-------+--------+    +--------+---------+
                    |                      |
                    v                      v
            +------------------------------------------+
            |          PerfEventArray (per-CPU)         |
            |       async tokio event processing        |
            +------------------------------------------+
                               |
                               v
                      [ ALERT / LOG ]
```

### Layer 1: eBPF Kernel Interception

Tracepoints hooked directly into the kernel. Fires on every matching syscall in real time. No cheat can dodge this from userspace.

| Tracepoint | Catches |
|---|---|
| `sys_enter_process_vm_readv` | Cross-process memory reads (external cheats reading game memory) |
| `sys_enter_process_vm_writev` | Cross-process memory writes (injecting code/data into game) |
| `sys_enter_ptrace` | Debugger attachment (PEEKDATA memory reads, breakpoints) |
| `sys_enter_memfd_create` | Anonymous file creation (fileless code injection) |

Events flow through a shared `PerfEventArray` map — one async reader per CPU core via tokio.

### Layer 2: /proc Filesystem Scanner

Polls every 5 seconds with deduplication. Seven independent detection methods:

| Method | Source | Detects |
|---|---|---|
| TracerPid | `/proc/PID/status` | Process being debugged or traced |
| Memory maps | `/proc/PID/maps` | Injected .so libraries, w+x permissions |
| LD_PRELOAD | `/proc/PID/environ` | Library injection via environment variable |
| Cmdline | `/proc/PID/cmdline` | Debugger tools (gdb, strace, ltrace) |
| Exe path | `/proc/PID/exe` | Binaries running from suspicious dirs (/tmp, /dev/shm) |
| File descriptors | `/proc/PID/fd` | Processes reading other processes' memory |
| Kernel modules | `/proc/modules` | New/unloaded kernel modules (rootkit detection) |

Plus: process birth/death tracking, parent PID analysis, and a configurable whitelist system (`/etc/vigil/whitelist.txt`).

## Project Structure

```
vigil/                      Cargo workspace root
|
+-- vigil/                  Userspace binary
|   +-- src/
|       +-- main.rs         Entry point, async main, eBPF init + monitoring loop
|       +-- process.rs      Proc struct, ProcessStatus enum, Suspicious trait
|       +-- scanner.rs      /proc parsing: maps, environ, cmdline, exe, fd, modules
|       +-- ebpf.rs         BPF loading, PerfEventArray, async event reading
|
+-- vigil-ebpf/             BPF kernel program (bpfel-unknown-none target)
|   +-- src/
|       +-- main.rs         Tracepoints: vm_readv, vm_writev, ptrace, memfd_create
|
+-- vigil-common/           Shared types (kernel <-> userspace)
    +-- src/
        +-- lib.rs          SyscallEvent (#[repr(C)], no_std)
```

## Building

```bash
# Build the BPF kernel program (requires nightly + bpf-linker)
cargo +nightly build -p vigil-ebpf --target bpfel-unknown-none -Z build-std=core --release

# Build userspace
cargo build -p vigil

# Run (requires root for eBPF + /proc/PID/fd access)
sudo ./target/debug/vigil
```

**Requirements:** Linux, root privileges, Rust nightly (for BPF compilation).

## Quick Test

Start Vigil, then from another terminal:

```bash
# Trigger process_vm_readv — Vigil should catch it instantly
python3 -c "import ctypes; libc = ctypes.CDLL('libc.so.6'); libc.process_vm_readv(1, 0, 0, 0, 0, 0)"

# Attach a debugger to any process — Vigil detects TracerPid change
sudo strace -p $(pidof sleep) &
```

## Tech Stack

| Component | Technology |
|---|---|
| Language | Rust |
| Platform | Linux (native) |
| Kernel layer | eBPF via [aya](https://github.com/aya-rs/aya) + aya-ebpf |
| Async runtime | tokio |
| Backend (planned) | Rust with Actix or Axum |
| Frontend (planned) | egui |

## How Linux Cheats Work

Understanding the enemy:

- **Memory reading** — `ptrace` or `/proc/PID/mem` to read game memory (player positions, health, weapon data). External cheats like [deadlocked](https://github.com/avitran0/deadlocked) use this approach.
- **Library injection** — `LD_PRELOAD` or `dlopen` to inject code directly into the game process. Shows up in `/proc/PID/maps` and `/proc/PID/environ`.
- **Cross-process memory access** — `process_vm_readv`/`writev` syscalls to read/write memory without ptrace. Harder to detect without kernel-level hooks.
- **File modification** — Replacing game textures or shaders for wallhacks. Detected via file hash verification.
- **Kernel modules** — Rootkit-style `.ko` modules that hide cheat processes from userspace entirely. Detected via `/proc/modules` monitoring.

---

## Roadmap

### Phase 1: Process Monitoring
- [x] Scan `/proc` for all running PIDs
- [x] Parse `/proc/{PID}/status` — name, state, TracerPid
- [x] Basic suspicion detection (name, status, TracerPid)
- [x] Live TracerPid detection test (attach debugger, verify Vigil catches it)
- [x] Continuous monitoring loop (scan every 5 seconds, dedup alerts, auto-cleanup)
- [x] Parse `/proc/{PID}/maps` — detect injected/suspicious shared libraries
- [x] Detect LD_PRELOAD injection via `/proc/{PID}/environ`
- [x] Parse `/proc/{PID}/cmdline` — detect suspicious launch arguments (gdb, strace, ltrace)
- [x] Parse `/proc/{PID}/exe` — verify executable path legitimacy (symlink check + whitelist)
- [x] Whitelist for trusted paths (`/etc/vigil/whitelist.txt` — filters maps + LD_PRELOAD)
- [x] Process birth/death tracking (detect new processes appearing mid-game)

### Phase 2: Deep Process Inspection *(in progress)*
- [x] Monitor `/proc/{PID}/fd` — detect processes reading other processes memory
- [x] Detect `process_vm_readv` usage via eBPF tracepoint (kernel-level, real-time)
- [x] Detect `process_vm_writev` usage via eBPF tracepoint (kernel-level, real-time)
- [x] Parent process tracking (PPid) — parsed from /proc/PID/status
- [x] `/proc/modules` scanning — detect new/unloaded kernel modules (birth/death tracking)
- [x] Detect `ptrace` usage via eBPF tracepoint (`sys_enter_ptrace`)
- [x] Detect `memfd_create` usage via eBPF tracepoint — catch anonymous file creation
- [ ] Detect `/proc/PID/mem` writes via eBPF tracepoint — catch direct memory injection
- [ ] Detect kernel module loading in real time via eBPF kprobe on `do_init_module`
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

### Phase 7: Advanced
- [ ] Custom kernel module for deeper monitoring
- [ ] Machine learning for behavior analysis (mouse patterns, aim patterns)
- [ ] Community rule database (crowdsourced cheat signatures)
- [ ] Game developer SDK/API integration
- [ ] Windows port (maybe, for fun)

---

<div align="center">

*Vigil watches. Cheaters lose.*

</div>
