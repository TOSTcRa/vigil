# VIGIL Anti-Cheat System

Linux-native anti-cheat for competitive gaming (CS2 and others). Written in Rust.

Not a FACEIT competitor — an independent anti-cheat platform focused on Linux.

## Current Status

**Phase 1 in progress.** Working process scanner that reads `/proc`, parses process data (name, state, TracerPid), and detects suspicious activity.

### What works now:
- Scan all running processes via `/proc`
- Parse `/proc/{PID}/status` (name, state, TracerPid)
- Detect processes being traced/debugged (TracerPid != 0)
- Suspicious process detection by name patterns and status

## Roadmap

### Phase 1: Process Monitoring (current)
- [x] Scan `/proc` for all running PIDs
- [x] Parse `/proc/{PID}/status` — name, state, TracerPid
- [x] Basic suspicion detection (name, status, TracerPid)
- [ ] Live TracerPid detection test (attach debugger, verify Vigil catches it)
- [ ] Parse `/proc/{PID}/maps` — detect injected/suspicious shared libraries
- [ ] Parse `/proc/{PID}/cmdline` — detect suspicious launch arguments
- [ ] Parse `/proc/{PID}/exe` — verify executable path legitimacy
- [ ] Continuous monitoring loop (scan every N seconds, detect changes)
- [ ] Process birth/death tracking (detect new processes appearing mid-game)

### Phase 2: Memory & File Integrity
- [ ] Monitor `/proc/{PID}/mem` access patterns
- [ ] Game file hash verification (detect modified game files)
- [ ] Detect LD_PRELOAD injection (common cheat technique on Linux)
- [ ] Detect ptrace-based memory reading
- [ ] Monitor `/proc/{PID}/fd` — detect suspicious file descriptors

### Phase 3: System-Level Detection
- [ ] Kernel module detection (`/proc/modules`) — detect rootkit-style cheats
- [ ] dmesg log monitoring for suspicious kernel activity
- [ ] Network traffic analysis — detect cheat communication with external servers
- [ ] Detect known cheat signatures (hash database)
- [ ] Sandboxing detection (is the game running in a compromised environment?)

### Phase 4: Daemon & Service
- [ ] Run Vigil as a systemd service/daemon
- [ ] Configuration file (what game to protect, scan interval, rules)
- [ ] Logging system (write scan results to files, timestamps)
- [ ] CLI interface (start/stop monitoring, show status, show suspicious processes)
- [ ] Signal handling (graceful shutdown)

### Phase 5: Reporting & Backend
- [ ] Local report generation (JSON/structured output)
- [ ] Server communication — send scan results to backend
- [ ] REST API backend (Rust or separate service)
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
- **Detection methods:** `/proc` filesystem, ptrace monitoring, file integrity, memory analysis
- **Backend:** TBD (Rust with Actix/Axum or separate service)
- **Frontend:** TBD (React/Next.js likely)

## Project Structure

```
src/
  main.rs        — entry point, scan orchestration
  process.rs     — Proc struct, ProcessStatus enum, Suspicious trait
  scanner.rs     — scan_processes(), get_process() — reads /proc
```

## How cheats work on Linux (research notes)

- **Memory reading:** Cheats use ptrace or /proc/PID/mem to read game memory (player positions, health). Detected via TracerPid.
- **Library injection:** LD_PRELOAD or dlopen to inject code into game process. Detected via /proc/PID/maps.
- **File modification:** Replacing game textures/shaders for wallhack. Detected via file hash verification.
- **Kernel modules:** Rootkit-style cheats that hide from userspace. Detected via /proc/modules monitoring.

## Building

```
cargo build
cargo run
```

Requires Linux. Reads `/proc` filesystem — some process info may require elevated permissions.
