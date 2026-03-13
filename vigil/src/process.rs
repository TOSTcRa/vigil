// trait for checking if something is suspicious
// any struct that implements this can be checked in the main loop
pub trait Suspicious {
    fn is_suspicious(&self) -> bool;
}

// represents a linux process built from multiple /proc/PID/* files
// built by get_process() in scanner.rs from: status, environ, cmdline, exe, fd
// fields are private - use getters to read, cant modify from outside
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
    ppid: u64,
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
    #[allow(dead_code)]
    Suspicious(String),
}

impl Proc {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        pid: u64,
        status: ProcessStatus,
        tracer_pid: u64,
        preload_path: Option<String>,
        cmdline: String,
        exe_path: Option<String>,
        ppid: u64,
    ) -> Self {
        Self {
            name,
            pid,
            status,
            tracer_pid,
            preload_path,
            cmdline,
            exe_path,
            ppid,
        }
    }

    pub fn get_tracer_pid(&self) -> &u64 {
        &self.tracer_pid
    }

    pub fn get_pid(&self) -> &u64 {
        &self.pid
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(
        name: &str,
        tracer_pid: u64,
        preload: Option<&str>,
        cmdline: &str,
        exe_path: Option<&str>,
        status: ProcessStatus,
    ) -> Proc {
        Proc::new(
            name.to_string(),
            1234,
            status,
            tracer_pid,
            preload.map(|s| s.to_string()),
            cmdline.to_string(),
            exe_path.map(|s| s.to_string()),
            1,
        )
    }

    #[test]
    fn clean_process_not_suspicious() {
        let p = make_proc("bash", 0, None, "/bin/bash", None, ProcessStatus::Running);
        assert!(!p.is_suspicious());
    }

    #[test]
    fn cheat_name_is_suspicious() {
        let p = make_proc("mycheat", 0, None, "./mycheat", None, ProcessStatus::Running);
        assert!(p.is_suspicious());
    }

    #[test]
    fn tracer_pid_is_suspicious() {
        let p = make_proc("game", 999, None, "/opt/game", None, ProcessStatus::Running);
        assert!(p.is_suspicious());
    }

    #[test]
    fn preload_is_suspicious() {
        let p = make_proc(
            "game",
            0,
            Some("/tmp/hack.so"),
            "/opt/game",
            None,
            ProcessStatus::Running,
        );
        assert!(p.is_suspicious());
    }

    #[test]
    fn gdb_cmdline_is_suspicious() {
        let p = make_proc("gdb", 0, None, "gdb -p 1234", None, ProcessStatus::Running);
        assert!(p.is_suspicious());
    }

    #[test]
    fn strace_cmdline_is_suspicious() {
        let p = make_proc("strace", 0, None, "strace -p 1234", None, ProcessStatus::Running);
        assert!(p.is_suspicious());
    }

    #[test]
    fn exe_from_tmp_is_suspicious() {
        let p = make_proc(
            "hack",
            0,
            None,
            "./hack",
            Some("/tmp/hack"),
            ProcessStatus::Running,
        );
        assert!(p.is_suspicious());
    }

    #[test]
    fn suspicious_status_is_suspicious() {
        let p = make_proc(
            "thing",
            0,
            None,
            "./thing",
            None,
            ProcessStatus::Suspicious("X (unknown)".to_string()),
        );
        assert!(p.is_suspicious());
    }

    #[test]
    fn sleeping_process_not_suspicious() {
        let p = make_proc("sleep", 0, None, "sleep 60", None, ProcessStatus::Sleeping);
        assert!(!p.is_suspicious());
    }

    #[test]
    fn getters_work() {
        let p = make_proc("test", 42, None, "test", None, ProcessStatus::Running);
        assert_eq!(*p.get_pid(), 1234);
        assert_eq!(*p.get_tracer_pid(), 42);
    }
}
