// epoll-based reactor - watches fds and wakes tasks when data is ready

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::task::Waker;

use crate::sys::{self, EpollEvent, EPOLLIN, EPOLL_CTL_ADD, EPOLL_CTL_DEL};

pub struct Reactor {
    epoll_fd: RawFd,
    interests: HashMap<RawFd, Waker>,
}

impl Reactor {
    pub fn new() -> std::io::Result<Self> {
        let epoll_fd = sys::sys_epoll_create()?;
        Ok(Reactor {
            epoll_fd,
            interests: HashMap::new(),
        })
    }

    // register interest in a fd becoming readable
    pub fn register(&mut self, fd: RawFd, waker: Waker) {
        if !self.interests.contains_key(&fd) {
            let _ = sys::sys_epoll_ctl(self.epoll_fd, EPOLL_CTL_ADD, fd, EPOLLIN);
        }
        self.interests.insert(fd, waker);
    }

    // remove interest in a fd
    pub fn deregister(&mut self, fd: RawFd) {
        if self.interests.remove(&fd).is_some() {
            let _ = sys::sys_epoll_ctl(self.epoll_fd, EPOLL_CTL_DEL, fd, 0);
        }
    }

    // poll for ready fds, wake corresponding tasks
    // returns number of events processed
    pub fn poll(&mut self, timeout_ms: i32) -> usize {
        let mut events = [EpollEvent { events: 0, data: 0 }; 32];
        let n = match sys::sys_epoll_wait(self.epoll_fd, &mut events, timeout_ms) {
            Ok(n) => n,
            Err(_) => return 0,
        };

        for i in 0..n {
            let fd = events[i].data as RawFd;
            if let Some(waker) = self.interests.get(&fd) {
                waker.wake_by_ref();
            }
        }

        n
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        sys::sys_close(self.epoll_fd);
    }
}
