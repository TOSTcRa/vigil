#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallEvent {
    pub pid_caller: i32,
    pub pid_target: i32,
}
