use aya::Ebpf;
use aya::maps::{AsyncPerfEventArray, MapData};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use bytes::BytesMut;
use vigil_common::SyscallEvent;

// loads compiled BPF bytecode from target dir, attaches two tracepoints:
// trace_read -> sys_enter_process_vm_readv, trace_write -> sys_enter_process_vm_writev
// returns Ebpf object — MUST be kept alive in main, otherwise BPF unloads from kernel (ownership)
// needs sudo — loading BPF into kernel requires root
// BPF must be compiled with --release (dev profile produces invalid bytecode for kernel verifier)
pub fn start_ebpf() -> Result<Ebpf, Box<dyn std::error::Error>> {
    let bytes = std::fs::read("./target/bpfel-unknown-none/release/vigil")?;
    let mut ebpf = Ebpf::load(&bytes)?;

    let tp_read = ebpf.program_mut("trace_read").ok_or("program not found")?;
    let read: &mut TracePoint = tp_read.try_into()?;
    read.load()?;
    read.attach("syscalls", "sys_enter_process_vm_readv")?;

    let tp_write = ebpf.program_mut("trace_write").ok_or("program not found")?;
    let write: &mut TracePoint = tp_write.try_into()?;
    write.load()?;
    write.attach("syscalls", "sys_enter_process_vm_writev")?;

    let tp_ptrace = ebpf
        .program_mut("trace_ptrace")
        .ok_or("program not found")?;
    let ptrace: &mut TracePoint = tp_ptrace.try_into()?;
    ptrace.load()?;
    ptrace.attach("syscalls", "sys_enter_ptrace")?;

    let tp_memfd = ebpf.program_mut("trace_memfd").ok_or("program not found")?;
    let memfd: &mut TracePoint = tp_memfd.try_into()?;
    memfd.load()?;
    memfd.attach("syscalls", "sys_enter_memfd_create")?;

    Ok(ebpf)
}

// extracts EVENTS PerfEventArray map from loaded BPF program
// take_map = removes map from Ebpf (ownership transfer), try_into casts to AsyncPerfEventArray
// async version needed for tokio-based event reading
pub fn get_events(
    ebpf: &mut Ebpf,
) -> Result<AsyncPerfEventArray<MapData>, Box<dyn std::error::Error>> {
    let map = ebpf.take_map("EVENTS").ok_or("map not found")?;
    let map_data: AsyncPerfEventArray<MapData> = map.try_into()?;

    Ok(map_data)
}

// reads BPF events in background — one tokio::spawn per CPU for parallel reading
// each CPU has its own perf buffer, events arrive independently
// inside each spawn: infinite loop reading events, parsing raw bytes to SyscallEvent
// bytes_buff = vec of 10 BytesMut buffers (multiple events can arrive at once)
// ev.read = how many events were read this batch
// unsafe read_unaligned: raw bytes -> SyscallEvent via pointer cast (repr(C) guarantees layout)
// runs in background — returns Ok(()) immediately, spawned tasks keep reading
pub async fn read_events(
    perf_array: &mut AsyncPerfEventArray<MapData>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cpus = online_cpus().map_err(|(msg, e)| format!("{}:{}", msg, e))?;
    let mut buffers = vec![];
    for cpu in cpus {
        let buffer = perf_array.open(cpu, None)?;

        buffers.push(buffer);
    }

    for mut buf in buffers {
        tokio::spawn(async move {
            loop {
                let mut bytes_buff: Vec<BytesMut> = vec![BytesMut::with_capacity(1024); 10];
                if let Ok(ev) = buf.read_events(&mut bytes_buff[..]).await {
                    for i in 0..ev.read {
                        let ptr = bytes_buff[i].as_ptr() as *const SyscallEvent;
                        let syscall = unsafe { std::ptr::read_unaligned(ptr) };
                        println!("{:?}", syscall);
                    }
                }
            }
        });
    }

    Ok(())
}
