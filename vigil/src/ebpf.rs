// real bpf loader - loads compiled ELF, attaches tracepoints/kprobes, reads perf events
// uses bpf::loader for ELF parsing + program loading, bpf::perf for ring buffer reading

use std::os::fd::RawFd;
use std::sync::atomic::Ordering;

use crate::bpf::loader::BpfLoader;
use crate::bpf::perf::PerfBuffer;
use crate::config::{LogLevel, log};
use crate::sys;
use crate::RUNNING;

const BPF_ELF_PATH: &str = "/etc/vigil/vigil-ebpf";

pub struct EbpfState {
    loader: BpfLoader,
    perf: Option<PerfBuffer>,
}

// load and attach BPF programs from compiled ELF
pub fn start_ebpf() -> Result<EbpfState, Box<dyn std::error::Error>> {
    let mut loader = BpfLoader::load(BPF_ELF_PATH)?;
    loader.attach_all(BPF_ELF_PATH)?;
    Ok(EbpfState {
        loader,
        perf: None,
    })
}

// open perf ring buffers on the EVENTS map, return fds for monitoring
pub fn get_events(state: &mut EbpfState) -> Result<Vec<RawFd>, Box<dyn std::error::Error>> {
    let map_fd = state
        .loader
        .get_map_fd("EVENTS")
        .ok_or("EVENTS map not found in BPF ELF")?;
    let perf = PerfBuffer::open(map_fd)?;
    let fds = perf.fds().to_vec();
    state.perf = Some(perf);
    Ok(fds)
}

// spawn a background thread that polls perf ring buffers and logs BPF events
pub fn read_events(state: &mut EbpfState) -> Result<(), Box<dyn std::error::Error>> {
    let perf = state
        .perf
        .take()
        .ok_or("perf buffers not initialized - call get_events first")?;

    std::thread::spawn(move || {
        let log_path = "/var/log/vigil.log".to_string();

        // set up epoll to watch all perf fds
        let epfd = match sys::sys_epoll_create() {
            Ok(fd) => fd,
            Err(e) => {
                let _ = log(
                    LogLevel::Alert,
                    &format!("eBPF epoll_create failed: {}", e),
                    &log_path,
                );
                return;
            }
        };

        let perf_fds = perf.fds().to_vec();
        for &fd in &perf_fds {
            let _ = sys::sys_epoll_ctl(epfd, sys::EPOLL_CTL_ADD, fd, sys::EPOLLIN);
        }

        let mut events = [sys::EpollEvent { events: 0, data: 0 }; 32];

        while RUNNING.load(Ordering::SeqCst) {
            let n = match sys::sys_epoll_wait(epfd, &mut events, 200) {
                Ok(n) => n,
                Err(_) => continue,
            };

            for i in 0..n {
                let ready_fd = events[i].data as RawFd;

                // find which CPU this fd belongs to and read its events
                for (cpu, &pfd) in perf_fds.iter().enumerate() {
                    if pfd == ready_fd {
                        perf.read_events(cpu, |data| {
                            // data is a raw SyscallEvent from the BPF program
                            if data.len() >= 12 {
                                // SyscallEvent: pid_caller(u32) + pid_target(u32) + syscall_type(u32)
                                let caller = u32::from_ne_bytes([
                                    data[0], data[1], data[2], data[3],
                                ]);
                                let target = u32::from_ne_bytes([
                                    data[4], data[5], data[6], data[7],
                                ]);
                                let syscall = u32::from_ne_bytes([
                                    data[8], data[9], data[10], data[11],
                                ]);
                                let _ = log(
                                    LogLevel::Alert,
                                    &format!(
                                        "[eBPF] syscall={} caller={} target={}",
                                        syscall, caller, target
                                    ),
                                    &log_path,
                                );
                            }
                        });
                    }
                }
            }
        }

        sys::sys_close(epfd);
    });

    Ok(())
}
