// raw BPF loader - no aya, only std + linux syscalls
// parses compiled ELF, creates maps, loads programs, attaches to tracepoints/kprobes

pub mod elf;
pub mod loader;
pub mod perf;
