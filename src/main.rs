use crate::{
    process::Suspicious,
    scanner::{get_process, scan_processes},
};

mod process;
mod scanner;
// main loop here
// just scans processes right now
// also prints how many active processes are working right now
fn main() {
    match scan_processes() {
        Ok(vec) => {
            println!("{}", vec.len());
            for pid in vec {
                match get_process(pid) {
                    Ok(proc) => {
                        if proc.is_suspicious() {
                            println!("{:?}", proc);
                        }
                    }
                    Err(_) => {}
                };
            }
        }
        Err(_) => {}
    }
}
