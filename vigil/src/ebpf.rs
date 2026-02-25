use aya::Ebpf;
use aya::maps::{AsyncPerfEventArray, MapData};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use bytes::BytesMut;
use vigil_common::SyscallEvent;
pub fn start_ebpf() -> Result<Ebpf, Box<dyn std::error::Error>> {
    let bytes = std::fs::read("./target/bpfel-unknown-none/release/vigil")?;
    let mut ebpf = Ebpf::load(&bytes)?;
    let tracepoint = ebpf.program_mut("get_syscall").ok_or("program not found")?;
    let tp: &mut TracePoint = tracepoint.try_into()?;
    tp.load()?;
    tp.attach("syscalls", "sys_enter_process_vm_readv")?;

    Ok(ebpf)
}

pub fn get_events(
    ebpf: &mut Ebpf,
) -> Result<AsyncPerfEventArray<MapData>, Box<dyn std::error::Error>> {
    let map = ebpf.take_map("EVENTS").ok_or("map not found")?;
    let map_data: AsyncPerfEventArray<MapData> = map.try_into()?;

    Ok(map_data)
}

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
