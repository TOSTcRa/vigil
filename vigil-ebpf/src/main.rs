#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use vigil_common::SyscallEvent;
// BPF program — lives inside the kernel, loaded by vigil/src/ebpf.rs
// no_std = no standard library (kernel doesnt have it)
// no_main = no normal main function (kernel loads this differently)
// compiles to bpfel-unknown-none target with nightly + build-std=core --release
// two tracepoints: sys_enter_process_vm_readv (310) and sys_enter_process_vm_writev (311)
// catches EVERY call in real time — unlike /proc polling which checks every 5 sec
// sends (pid_caller, pid_target, syscall_type) to userspace via shared PerfEventArray EVENTS map
// syscall_type: 0 = readv, 1 = writev

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[tracepoint(name = "sys_enter_process_vm_readv", category = "syscalls")]
fn trace_read(ctx: TracePointContext) -> u32 {
    let pid_caller = (bpf_get_current_pid_tgid() >> 32) as i32;
    if let Ok(pid_target) = unsafe { ctx.read_at::<i32>(16) } {
        let event = SyscallEvent {
            pid_caller,
            pid_target,
            syscall_type: 0,
        };
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[tracepoint(name = "sys_enter_process_vm_writev", category = "syscalls")]
fn trace_write(ctx: TracePointContext) -> u32 {
    let pid_caller = (bpf_get_current_pid_tgid() >> 32) as i32;
    if let Ok(pid_target) = unsafe { ctx.read_at::<i32>(16) } {
        let event = SyscallEvent {
            pid_caller,
            pid_target,
            syscall_type: 1,
        };
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[tracepoint(name = "sys_enter_ptrace", category = "syscalls")]
fn trace_ptrace(ctx: TracePointContext) -> u32 {
    let pid_caller = (bpf_get_current_pid_tgid() >> 32) as i32;
    if let Ok(pid_target) = unsafe { ctx.read_at::<i32>(24) } {
        let event = SyscallEvent {
            pid_caller,
            pid_target,
            syscall_type: 2,
        };
        EVENTS.output(&ctx, &event, 0);
    }

    0
}

#[tracepoint(name = "sys_enter_memfd_create", category = "syscalls")]
fn trace_memfd(ctx: TracePointContext) -> u32 {
    let pid_caller = (bpf_get_current_pid_tgid() >> 32) as i32;
    let event = SyscallEvent {
        pid_caller,
        pid_target: 0,
        syscall_type: 3,
    };
    EVENTS.output(&ctx, &event, 0);

    0
}
