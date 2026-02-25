#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use vigil_common::SyscallEvent;
// BPF program — lives inside the kernel
// no_std = no standard library (kernel doesnt have it)
// no_main = no normal main function (kernel loads this differently)

// TODO: tracepoint hook for process_vm_readv syscall (310 on x86_64)

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[tracepoint(name = "sys_enter_process_vm_readv", category = "syscalls")]
fn get_syscall(ctx: TracePointContext) -> u32 {
    let pid_caller = (bpf_get_current_pid_tgid() >> 32) as i32;
    if let Ok(pid_target) = unsafe { ctx.read_at::<i32>(16) } {
        let event = SyscallEvent {
            pid_caller,
            pid_target,
        };
        EVENTS.output(&ctx, &event, 0);
    }

    0
}
