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