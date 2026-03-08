use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug)]
pub struct Log {
    priority: u8,
    number: u32,
    timestamp: u64,
    message: String,
}

impl Log {
    pub fn new(priority: u8, number: u32, timestamp: u64, message: String) -> Self {
        Self {
            priority,
            number,
            timestamp,
            message,
        }
    }

    pub fn get_priority(&self) -> &u8 {
        &self.priority
    }

    pub fn get_number(&self) -> &u32 {
        &self.number
    }

    pub fn get_timestamp(&self) -> &u64 {
        &self.timestamp
    }

    pub fn get_message(&self) -> &String {
        &self.message
    }
}

// reads /dev/kmsg — the kernel log ring buffer (like dmesg but as a stream)
// format per line: "priority,sequence,timestamp;message"
// filters for priority 3 (KERN_ERR) and 4 (KERN_WARNING)
// uses callback pattern so caller decides what to do with each log entry
// blocks on read when no new messages — runs forever as a listener
// needs root (or CAP_SYSLOG) to open /dev/kmsg
pub fn get_kernel_logs(callback: impl Fn(Log)) -> std::io::Result<()> {
    let f = File::open("/dev/kmsg")?;
    let reader = BufReader::new(f);

    for line in reader.lines() {
        let line = line?;
        let semi_split = line.split(';').collect::<Vec<&str>>();
        let comma_split = semi_split[0].split(',').collect::<Vec<&str>>();

        if comma_split[0].parse::<u8>().unwrap() == 3 || comma_split[0].parse::<u32>().unwrap() == 4
        {
            let log = Log::new(
                comma_split[0].parse().unwrap(),
                comma_split[1].parse().unwrap(),
                comma_split[2].parse().unwrap(),
                semi_split[1].into(),
            );
            callback(log);
        }
    }

    Ok(())
}

// analyzes a single kernel log entry for anti-cheat relevant events
// checks message text against known suspicious kernel patterns:
// unsigned/out-of-tree modules, kernel taint, segfaults, /dev/mem access,
// DMA/IOMMU errors, USB device events, livepatch, ptrace LSM denials
pub fn parse_kernel_log(log: &Log) {
    let msg = log.get_message();
    let ts = log.get_timestamp();

    if msg.contains("loading out-of-tree module") || msg.contains("module verification failed") {
        println!(
            "[KLOG ts={}] Unsigned/out-of-tree module loaded: {}",
            ts,
            msg.trim()
        );
    }

    if msg.contains("Tainted:") || msg.contains("tainting kernel") {
        println!("[KLOG ts={}] Kernel taint changed: {}", ts, msg.trim());
    }

    if msg.contains("segfault at") || msg.contains("general protection fault") {
        println!(
            "[KLOG ts={}] Memory fault (possible injection failure): {}",
            ts,
            msg.trim()
        );
    }

    if msg.contains("BUG: unable to handle page fault") || msg.contains("page_fault") {
        println!("[KLOG ts={}] Kernel page fault: {}", ts, msg.trim());
    }

    if msg.contains("/dev/mem") || msg.contains("/dev/kmem") {
        println!(
            "[KLOG ts={}] Physical memory device access: {}",
            ts,
            msg.trim()
        );
    }

    if msg.contains("DMAR:") || msg.contains("IOMMU") || msg.contains("DMA") {
        println!("[KLOG ts={}] DMA/IOMMU event: {}", ts, msg.trim());
    }

    if msg.contains("new USB device") || msg.contains("usb") && msg.contains("new") {
        println!("[KLOG ts={}] USB device event: {}", ts, msg.trim());
    }

    if msg.contains("livepatch:") {
        println!("[KLOG ts={}] Kernel livepatch detected: {}", ts, msg.trim());
    }

    if (msg.contains("apparmor=") || msg.contains("avc:")) && msg.contains("ptrace") {
        println!("[KLOG ts={}] LSM denied ptrace: {}", ts, msg.trim());
    }
}
