#![no_std]

// shared between BPF kernel program and userspace vigil
// repr(C) = C-compatible memory layout so bytes can be safely cast between BPF and Rust
// no_std required because BPF target has no standard library
// Clone + Copy for BPF (stack values), Debug for println in userspace
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallEvent {
    pub pid_caller: i32,
    pub pid_target: i32,
    pub syscall_type: u8,
}
