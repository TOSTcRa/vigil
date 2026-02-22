// trait for checking if something is suspicious
// any struct that implements this can be checked in the main loop
pub trait Suspicious {
    fn is_suspicious(&self) -> bool;
}

// represents a linux process parsed from /proc/PID/status
// fields are private on purpose — use getters to read, cant modify from outside
// name = process name (like "sleep", "cs2", "strace")
// pid = process id number
// status = running/sleeping/stopped/zombie/suspicious
// tracer_pid = if not 0 -> someone is debugging/tracing this process (cheats do this)
#[derive(Debug)]
pub struct Proc {
    name: String,
    pid: u64,
    status: ProcessStatus,
    tracer_pid: u64,
    preload_path: Option<String>,
    cmdline: String,
}

// possible states from /proc/PID/status "State" field
// Suspicious holds a string with the raw value when state is unknown
// mapped from: R=Running, S/D/I=Sleeping, T/t=Stopped, Z=Zombie
#[derive(Debug)]
pub enum ProcessStatus {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Suspicious(String),
}

impl Proc {
    pub fn new(
        name: String,
        pid: u64,
        status: ProcessStatus,
        tracer_pid: u64,
        preload_path: Option<String>,
        cmdline: String,
    ) -> Self {
        Self {
            name,
            pid,
            status,
            tracer_pid,
            preload_path,
            cmdline,
        }
    }

    pub fn rename(&mut self, new_name: &str) {
        self.name = String::from(new_name);
    }

    pub fn get_status(&self) -> &ProcessStatus {
        &self.status
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }
}

// a process is suspicious if:
// 1. name contains "cheat" (basic name check, will improve later)
// 2. status is unknown/weird (Suspicious variant)
// 3. tracer_pid != 0 (someone is debugging it — main detection method rn)
// 4. has some LD_PRELOAD
impl Suspicious for Proc {
    fn is_suspicious(&self) -> bool {
        self.name.contains("cheat")
            || self.tracer_pid != 0
            || self.preload_path.is_some()
            || self.cmdline.contains("gdb")
            || self.cmdline.contains("strace")
            || self.cmdline.contains("ltrace")
            || matches!(self.status, ProcessStatus::Suspicious(_))
    }
}
