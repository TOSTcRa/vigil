pub trait Suspicious {
    fn is_suspicious(&self) -> bool;
}

#[derive(Debug)]
pub struct Proc {
    name: String,
    pid: u64,
    status: ProcessStatus,
    tracer_pid: u64,
}

#[derive(Debug)]
pub enum ProcessStatus {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Suspicious(String),
}

impl Proc {
    pub fn new(name: String, pid: u64, status: ProcessStatus, tracer_pid: u64) -> Self {
        Self {
            name,
            pid,
            status,
            tracer_pid,
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

impl Suspicious for Proc {
    fn is_suspicious(&self) -> bool {
        self.name.contains("cheat")
            || match self.status {
                ProcessStatus::Suspicious(_) => true,
                _ => false,
            }
            || self.tracer_pid != 0
    }
}
