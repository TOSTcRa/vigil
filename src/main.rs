struct Proc {
    name: String,
    pid: u64,
    time_created: String,
    time_alive: String,
    status: ProcessStatus,
}

enum ProcessStatus {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Suspicious(String),
}

impl Proc {
    fn new(
        name: String,
        pid: u64,
        time_created: String,
        time_alive: String,
        status: ProcessStatus,
    ) -> Self {
        Self {
            name,
            pid,
            time_created,
            time_alive,
            status,
        }
    }

    fn is_sneaky(&self) -> bool {
        self.name.contains("cheat")
    }

    fn rename(&mut self, new_name: &str) {
        self.name = String::from(new_name);
    }
}

fn main() {
    let mut process = Proc::new(
        String::from("Super sneaky cheat"),
        191239,
        String::from("HH-mm-DD"),
        String::from("HH-mm"),
        ProcessStatus::Suspicious(String::from("Sneaky name")),
    );

    match process.status {
        ProcessStatus::Running => println!("Process is running"),
        ProcessStatus::Sleeping => println!("Process is asleep"),
        ProcessStatus::Stopped => println!("Process was stopped"),
        ProcessStatus::Zombie => println!("A zombie!"),
        ProcessStatus::Suspicious(reason) => println!("{}", reason),
    }
}
