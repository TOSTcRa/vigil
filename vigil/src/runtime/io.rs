// async fd readability - waits for a fd to become readable via epoll

use std::future::Future;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::runtime::executor::with_reactor;

struct Readable {
    fd: RawFd,
    registered: bool,
}

impl Future for Readable {
    type Output = std::io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.registered {
            // second poll - fd was ready, deregister and return
            with_reactor(|r| r.deregister(self.fd));
            Poll::Ready(Ok(()))
        } else {
            // first poll - register with reactor, return pending
            self.registered = true;
            with_reactor(|r| r.register(self.fd, cx.waker().clone()));
            Poll::Pending
        }
    }
}

impl Drop for Readable {
    fn drop(&mut self) {
        if self.registered {
            with_reactor(|r| r.deregister(self.fd));
        }
    }
}

// wait until fd has data to read
pub fn readable(fd: RawFd) -> impl Future<Output = std::io::Result<()>> {
    Readable {
        fd,
        registered: false,
    }
}
