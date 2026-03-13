// minimal single-threaded async runtime
// only what vigil needs: block_on, spawn, sleep, readable(fd)
// built on epoll - zero external deps

pub mod executor;
pub mod io;
pub mod reactor;
pub mod time;
pub mod waker;

pub use executor::{block_on, spawn};
pub use io::readable;
pub use time::sleep;
