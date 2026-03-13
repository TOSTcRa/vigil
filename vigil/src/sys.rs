// thin wrappers around linux syscalls needed by the async runtime and bpf loader
// uses libc FFI - we already link libc for signal()

use std::io;
use std::os::fd::RawFd;

// ---- epoll (async reactor) ----

pub const EPOLLIN: u32 = 0x001;
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

unsafe extern "C" {
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
    fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32;
}

pub fn sys_epoll_create() -> io::Result<RawFd> {
    let fd = unsafe { epoll_create1(0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn sys_epoll_ctl(epfd: RawFd, op: i32, fd: RawFd, events: u32) -> io::Result<()> {
    let mut ev = EpollEvent {
        events,
        data: fd as u64,
    };
    let ret = unsafe { epoll_ctl(epfd, op, fd, &mut ev) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn sys_epoll_wait(epfd: RawFd, buf: &mut [EpollEvent], timeout_ms: i32) -> io::Result<usize> {
    let ret = unsafe { epoll_wait(epfd, buf.as_mut_ptr(), buf.len() as i32, timeout_ms) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

// ---- timerfd (async sleep) ----

pub const CLOCK_MONOTONIC: i32 = 1;
pub const TFD_NONBLOCK: i32 = 0o4000;
pub const TFD_CLOEXEC: i32 = 0o2000000;

#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
pub struct ItimerSpec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

unsafe extern "C" {
    fn timerfd_create(clockid: i32, flags: i32) -> i32;
    fn timerfd_settime(fd: i32, flags: i32, new: *const ItimerSpec, old: *mut ItimerSpec) -> i32;
}

pub fn sys_timerfd_create() -> io::Result<RawFd> {
    let fd = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn sys_timerfd_settime(fd: RawFd, secs: u64, nanos: u64) -> io::Result<()> {
    let spec = ItimerSpec {
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: Timespec {
            tv_sec: secs as i64,
            tv_nsec: nanos as i64,
        },
    };
    let ret = unsafe { timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ---- close / read (shared) ----

unsafe extern "C" {
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
}

pub fn sys_close(fd: RawFd) {
    unsafe {
        close(fd);
    }
}

pub fn sys_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let ret = unsafe { read(fd, buf.as_mut_ptr(), buf.len()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

// ---- bpf syscall ----

pub const SYS_BPF: i64 = 321; // x86_64

pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;

pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;

// bpf() syscall - we use raw syscall since libc doesn't wrap it
unsafe extern "C" {
    fn syscall(num: i64, ...) -> i64;
}

pub fn sys_bpf(cmd: u32, attr: &[u8]) -> io::Result<i64> {
    let ret = unsafe { syscall(SYS_BPF, cmd as i64, attr.as_ptr() as i64, attr.len() as i64) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

// helper: create a BPF map
pub fn bpf_map_create(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> io::Result<RawFd> {
    // BPF_MAP_CREATE attr layout (first 20 bytes)
    let mut attr = [0u8; 64];
    attr[0..4].copy_from_slice(&map_type.to_ne_bytes());
    attr[4..8].copy_from_slice(&key_size.to_ne_bytes());
    attr[8..12].copy_from_slice(&value_size.to_ne_bytes());
    attr[12..16].copy_from_slice(&max_entries.to_ne_bytes());
    sys_bpf(BPF_MAP_CREATE, &attr).map(|fd| fd as RawFd)
}

// helper: load a BPF program
pub fn bpf_prog_load(
    prog_type: u32,
    insns: &[u8],
    license: &[u8],
    log_buf: &mut [u8],
) -> io::Result<RawFd> {
    let insn_cnt = (insns.len() / 8) as u32;
    // BPF_PROG_LOAD attr layout
    let mut attr = [0u8; 128];
    attr[0..4].copy_from_slice(&prog_type.to_ne_bytes()); // prog_type
    attr[4..8].copy_from_slice(&insn_cnt.to_ne_bytes()); // insn_cnt
    attr[8..16].copy_from_slice(&(insns.as_ptr() as u64).to_ne_bytes()); // insns
    attr[16..24].copy_from_slice(&(license.as_ptr() as u64).to_ne_bytes()); // license
    // log_level at offset 24, log_size at offset 28
    if !log_buf.is_empty() {
        attr[24..28].copy_from_slice(&1u32.to_ne_bytes()); // log_level = 1
    }
    attr[28..32].copy_from_slice(&(log_buf.len() as u32).to_ne_bytes()); // log_size
    attr[32..40].copy_from_slice(&(log_buf.as_mut_ptr() as u64).to_ne_bytes()); // log_buf

    sys_bpf(BPF_PROG_LOAD, &attr).map(|fd| fd as RawFd)
}

// helper: update a map element
pub fn bpf_map_update_elem(map_fd: RawFd, key: &[u8], value: &[u8]) -> io::Result<()> {
    let mut attr = [0u8; 64];
    attr[0..4].copy_from_slice(&(map_fd as u32).to_ne_bytes()); // map_fd
    attr[8..16].copy_from_slice(&(key.as_ptr() as u64).to_ne_bytes()); // key
    attr[16..24].copy_from_slice(&(value.as_ptr() as u64).to_ne_bytes()); // value
    // flags = 0 (BPF_ANY)
    sys_bpf(BPF_MAP_UPDATE_ELEM, &attr)?;
    Ok(())
}

// ---- perf_event_open ----

pub const SYS_PERF_EVENT_OPEN: i64 = 298; // x86_64

pub const PERF_TYPE_TRACEPOINT: u32 = 2;
pub const PERF_TYPE_SOFTWARE: u32 = 1;
pub const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;
pub const PERF_SAMPLE_RAW: u64 = 1 << 10;
pub const PERF_FLAG_FD_CLOEXEC: u64 = 8;

// perf_event_attr struct (simplified - only fields we use)
#[repr(C)]
pub struct PerfEventAttr {
    pub pe_type: u32,
    pub size: u32,
    pub config: u64,
    pub sample_period_or_freq: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64, // bitfield: disabled, inherit, etc
    pub wakeup_events_or_watermark: u32,
    pub bp_type: u32,
    pub config1: u64,
    pub config2: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub reserved: u16,
}

pub fn sys_perf_event_open(
    attr: &PerfEventAttr,
    pid: i32,
    cpu: i32,
    group_fd: i32,
    flags: u64,
) -> io::Result<RawFd> {
    let ret = unsafe {
        syscall(
            SYS_PERF_EVENT_OPEN,
            attr as *const PerfEventAttr as i64,
            pid as i64,
            cpu as i64,
            group_fd as i64,
            flags as i64,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as RawFd)
    }
}

// ---- ioctl ----

pub const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
pub const PERF_EVENT_IOC_SET_BPF: u64 = 0x40042408;
pub const PERF_EVENT_IOC_DISABLE: u64 = 0x2401;

unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

pub fn sys_ioctl(fd: RawFd, request: u64, arg: u64) -> io::Result<()> {
    let ret = unsafe { ioctl(fd, request, arg as i64) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ---- mmap / munmap (perf ring buffer) ----

pub const PROT_READ: i32 = 1;
pub const PROT_WRITE: i32 = 2;
pub const MAP_SHARED: i32 = 1;

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}

pub fn sys_mmap(fd: RawFd, len: usize) -> io::Result<*mut u8> {
    let ptr = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) };
    if ptr == usize::MAX as *mut u8 {
        // MAP_FAILED = (void*)-1
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

pub fn sys_munmap(ptr: *mut u8, len: usize) -> io::Result<()> {
    let ret = unsafe { munmap(ptr, len) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ---- utility ----

pub fn nr_cpus() -> usize {
    std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .ok()
        .and_then(|s| {
            // format: "0-N" or "0"
            let s = s.trim();
            if let Some((_start, end)) = s.split_once('-') {
                end.parse::<usize>().ok().map(|n| n + 1)
            } else {
                s.parse::<usize>().ok().map(|n| n + 1)
            }
        })
        .unwrap_or(1)
}

pub fn page_size() -> usize {
    4096 // standard on x86_64
}
