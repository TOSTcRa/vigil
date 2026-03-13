// BPF program loader - loads compiled ELF, creates maps, attaches programs

use std::collections::HashMap;
use std::error::Error;
use std::os::fd::RawFd;

use crate::bpf::elf::ElfFile;
use crate::sys;

const BPF_PSEUDO_MAP_FD: u8 = 1;

pub struct BpfLoader {
    pub prog_fds: Vec<RawFd>,
    pub map_fds: HashMap<String, RawFd>,
    pub event_fds: Vec<RawFd>,
}

impl BpfLoader {
    // load BPF programs from an ELF file
    pub fn load(path: &str) -> Result<Self, Box<dyn Error>> {
        let data = std::fs::read(path)?;
        let elf = ElfFile::parse(&data)?;

        let mut map_fds: HashMap<String, RawFd> = HashMap::new();

        // create maps - find the "maps" section or .maps
        // the EVENTS map is a PerfEventArray: key_size=4, value_size=4, max_entries=nr_cpus
        let nr_cpus = sys::nr_cpus() as u32;

        // find map symbols - in aya-compiled ELF, maps are in a section called "maps"
        // each symbol in that section is a map
        if let Some(maps_sec) = elf.section_by_name("maps").or_else(|| elf.section_by_name(".maps")) {
            for sym in &elf.symbols {
                if sym.section_idx as usize == maps_sec.idx && !sym.name.is_empty() {
                    // create a PerfEventArray map for each map symbol
                    let fd = sys::bpf_map_create(
                        sys::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                        4, // key_size (u32 = cpu index)
                        4, // value_size (u32 = fd)
                        nr_cpus,
                    )?;
                    map_fds.insert(sym.name.clone(), fd);
                }
            }
        }

        // load programs
        let mut prog_fds = Vec::new();
        let license = b"GPL\0";

        for (sec, _attach_point) in elf.program_sections() {
            // determine program type from section name
            let prog_type = if sec.name.starts_with("tracepoint/") {
                sys::BPF_PROG_TYPE_TRACEPOINT
            } else if sec.name.starts_with("kprobe/") {
                sys::BPF_PROG_TYPE_KPROBE
            } else {
                continue;
            };

            // apply relocations - patch map fds into BPF instructions
            let mut insns = sec.data.to_vec();
            let relocs = elf.relocations_for(sec.idx);

            for reloc in &relocs {
                let sym = &elf.symbols[reloc.sym_idx as usize];
                // find which map this symbol refers to
                if let Some(&map_fd) = map_fds.get(&sym.name) {
                    let off = reloc.offset as usize;
                    if off + 8 <= insns.len() {
                        // BPF instruction format: 8 bytes
                        // byte 0: opcode
                        // byte 1: dst_reg:4 | src_reg:4
                        // byte 2-3: offset (i16)
                        // byte 4-7: imm (i32)
                        // for map fd references: set src_reg = BPF_PSEUDO_MAP_FD (1), imm = map_fd
                        insns[off + 1] = (insns[off + 1] & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
                        insns[off + 4..off + 8].copy_from_slice(&(map_fd as i32).to_le_bytes());
                    }
                }
            }

            let mut log_buf = vec![0u8; 4096];
            match sys::bpf_prog_load(prog_type, &insns, license, &mut log_buf) {
                Ok(fd) => prog_fds.push(fd),
                Err(e) => {
                    let log_str = String::from_utf8_lossy(&log_buf);
                    let log_str = log_str.trim_end_matches('\0');
                    return Err(format!(
                        "failed to load BPF program {}: {} (verifier: {})",
                        sec.name, e, log_str
                    ).into());
                }
            }
        }

        Ok(BpfLoader {
            prog_fds,
            map_fds,
            event_fds: Vec::new(),
        })
    }

    // attach all loaded programs to their tracepoints/kprobes
    pub fn attach_all(&mut self, elf_path: &str) -> Result<(), Box<dyn Error>> {
        let data = std::fs::read(elf_path)?;
        let elf = ElfFile::parse(&data)?;

        let programs = elf.program_sections();

        for (i, (sec, attach_point)) in programs.iter().enumerate() {
            if i >= self.prog_fds.len() {
                break;
            }
            let prog_fd = self.prog_fds[i];

            if sec.name.starts_with("tracepoint/") {
                // attach_point = "syscalls/sys_enter_ptrace"
                let event_fd = attach_tracepoint(prog_fd, attach_point)?;
                self.event_fds.push(event_fd);
            } else if sec.name.starts_with("kprobe/") {
                // attach_point = "do_init_module"
                let event_fd = attach_kprobe(prog_fd, attach_point)?;
                self.event_fds.push(event_fd);
            }
        }

        Ok(())
    }

    pub fn get_map_fd(&self, name: &str) -> Option<RawFd> {
        self.map_fds.get(name).copied()
    }
}

impl Drop for BpfLoader {
    fn drop(&mut self) {
        for &fd in &self.event_fds {
            let _ = sys::sys_ioctl(fd, sys::PERF_EVENT_IOC_DISABLE, 0);
            sys::sys_close(fd);
        }
        for &fd in &self.prog_fds {
            sys::sys_close(fd);
        }
        for (_, &fd) in &self.map_fds {
            sys::sys_close(fd);
        }
    }
}

// attach a BPF program to a tracepoint
fn attach_tracepoint(prog_fd: RawFd, attach_point: &str) -> Result<RawFd, Box<dyn Error>> {
    // attach_point format: "syscalls/sys_enter_ptrace"
    let parts: Vec<&str> = attach_point.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid tracepoint: {}", attach_point).into());
    }
    let category = parts[0];
    let name = parts[1];

    // read tracepoint id from /sys/kernel/tracing/events/{category}/{name}/id
    // also try /sys/kernel/debug/tracing/ as fallback
    let id = read_tracepoint_id(category, name)?;

    // open perf event
    let attr = sys::PerfEventAttr {
        pe_type: sys::PERF_TYPE_TRACEPOINT,
        size: std::mem::size_of::<sys::PerfEventAttr>() as u32,
        config: id,
        sample_period_or_freq: 0,
        sample_type: 0,
        read_format: 0,
        flags: 0,
        wakeup_events_or_watermark: 0,
        bp_type: 0,
        config1: 0,
        config2: 0,
        branch_sample_type: 0,
        sample_regs_user: 0,
        sample_stack_user: 0,
        clockid: 0,
        sample_regs_intr: 0,
        aux_watermark: 0,
        sample_max_stack: 0,
        reserved: 0,
    };

    let event_fd = sys::sys_perf_event_open(&attr, -1, 0, -1, sys::PERF_FLAG_FD_CLOEXEC)?;

    // attach BPF program to perf event
    sys::sys_ioctl(event_fd, sys::PERF_EVENT_IOC_SET_BPF, prog_fd as u64)?;
    sys::sys_ioctl(event_fd, sys::PERF_EVENT_IOC_ENABLE, 0)?;

    Ok(event_fd)
}

// attach a BPF program to a kprobe
fn attach_kprobe(prog_fd: RawFd, func_name: &str) -> Result<RawFd, Box<dyn Error>> {
    let event_name = format!("vigil_{}", func_name);

    // register kprobe via /sys/kernel/tracing/kprobe_events (or debug variant)
    let probe_def = format!("p:kprobes/{} {}", event_name, func_name);

    let kprobe_path = if std::path::Path::new("/sys/kernel/tracing/kprobe_events").exists() {
        "/sys/kernel/tracing/kprobe_events"
    } else {
        "/sys/kernel/debug/tracing/kprobe_events"
    };

    std::fs::write(kprobe_path, &probe_def)?;

    // read the event id
    let id_path = format!(
        "{}/events/kprobes/{}/id",
        if kprobe_path.contains("debug") {
            "/sys/kernel/debug/tracing"
        } else {
            "/sys/kernel/tracing"
        },
        event_name
    );

    let id: u64 = std::fs::read_to_string(&id_path)?
        .trim()
        .parse()
        .map_err(|_| format!("bad kprobe id in {}", id_path))?;

    // open perf event and attach
    let attr = sys::PerfEventAttr {
        pe_type: sys::PERF_TYPE_TRACEPOINT,
        size: std::mem::size_of::<sys::PerfEventAttr>() as u32,
        config: id,
        sample_period_or_freq: 0,
        sample_type: 0,
        read_format: 0,
        flags: 0,
        wakeup_events_or_watermark: 0,
        bp_type: 0,
        config1: 0,
        config2: 0,
        branch_sample_type: 0,
        sample_regs_user: 0,
        sample_stack_user: 0,
        clockid: 0,
        sample_regs_intr: 0,
        aux_watermark: 0,
        sample_max_stack: 0,
        reserved: 0,
    };

    let event_fd = sys::sys_perf_event_open(&attr, -1, 0, -1, sys::PERF_FLAG_FD_CLOEXEC)?;

    sys::sys_ioctl(event_fd, sys::PERF_EVENT_IOC_SET_BPF, prog_fd as u64)?;
    sys::sys_ioctl(event_fd, sys::PERF_EVENT_IOC_ENABLE, 0)?;

    Ok(event_fd)
}

fn read_tracepoint_id(category: &str, name: &str) -> Result<u64, Box<dyn Error>> {
    let paths = [
        format!("/sys/kernel/tracing/events/{}/{}/id", category, name),
        format!(
            "/sys/kernel/debug/tracing/events/{}/{}/id",
            category, name
        ),
    ];

    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(id) = content.trim().parse::<u64>() {
                return Ok(id);
            }
        }
    }

    Err(format!("tracepoint {}/{} not found", category, name).into())
}
