// async sleep - creates a timerfd, arms it, waits for it to fire via epoll

use std::time::Duration;

use crate::runtime::io::readable;
use crate::sys;

// sleep for the given duration using timerfd + epoll
pub async fn sleep(duration: Duration) {
    let fd = match sys::sys_timerfd_create() {
        Ok(fd) => fd,
        Err(_) => {
            // fallback: blocking sleep if timerfd fails
            std::thread::sleep(duration);
            return;
        }
    };

    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos() as u64;

    if sys::sys_timerfd_settime(fd, secs, nanos).is_err() {
        sys::sys_close(fd);
        std::thread::sleep(duration);
        return;
    }

    // wait for the timer to fire
    let _ = readable(fd).await;

    // drain the timerfd (read the expiration count)
    let mut buf = [0u8; 8];
    let _ = sys::sys_read(fd, &mut buf);

    sys::sys_close(fd);
}
