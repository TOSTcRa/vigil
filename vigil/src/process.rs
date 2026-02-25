// trait for checking if something is suspicious
// any struct that implements this can be checked in the main loop
pub trait Suspicious {
    fn is_suspicious(&self) -> bool;
}

// represents a linux process built from multiple /proc/PID/* files
// built by get_process() in scanner.rs from: status, environ, cmdline, exe, fd
// fields are private — use getters to read, cant modify from outside
// name = process name (like "sleep", "cs2", "strace")
// pid = process id number
// status = running/sleeping/stopped/zombie/suspicious
// tracer_pid = if not 0 -> someone is debugging/tracing this process (cheats do this)
// preload_path = Some(path) if process has LD_PRELOAD set (library injection)
// cmdline = full command line args (for detecting debugger tools)
// exe_path = Some(path) if binary runs from suspicious dir (/tmp, /home, /dev/shm) and not whitelisted
#[derive(Debug)]
pub struct Proc {
    name: String,
    pid: u64,
    status: ProcessStatus,
    tracer_pid: u64,
    preload_path: Option<String>,
    cmdline: String,
    exe_path: Option<String>,
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
        exe_path: Option<String>,
    ) -> Self {
        Self {
            name,
            pid,
            status,
            tracer_pid,
            preload_path,
            cmdline,
            exe_path,
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

// a process is suspicious if any of these is true:
// 1. name contains "cheat" (basic name check, will improve later)
// 2. tracer_pid != 0 (someone is debugging/tracing it)
// 3. has LD_PRELOAD set (preload_path.is_some() = library injection)
// 4. cmdline contains gdb/strace/ltrace (debugger tools attached)
// 5. exe_path is Some = binary runs from suspicious dir and not whitelisted
// 6. status is unknown/weird (Suspicious variant from /proc parsing)
impl Suspicious for Proc {
    fn is_suspicious(&self) -> bool {
        self.name.contains("cheat")
            || self.tracer_pid != 0
            || self.preload_path.is_some()
            || self.cmdline.contains("gdb")
            || self.cmdline.contains("strace")
            || self.cmdline.contains("ltrace")
            || self.exe_path.is_some()
            || matches!(self.status, ProcessStatus::Suspicious(_))
    }
}
