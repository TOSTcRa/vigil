// custom Waker implementation backed by Arc<AtomicBool>
// when woken, sets the flag to true so the executor knows to re-poll this task

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{RawWaker, RawWakerVTable, Waker};

const VTABLE: RawWakerVTable = RawWakerVTable::new(clone_fn, wake_fn, wake_by_ref_fn, drop_fn);

pub fn create_waker(ready: &Arc<AtomicBool>) -> Waker {
    let ptr = Arc::into_raw(ready.clone()) as *const ();
    unsafe { Waker::from_raw(RawWaker::new(ptr, &VTABLE)) }
}

unsafe fn clone_fn(ptr: *const ()) -> RawWaker {
    let arc = unsafe { Arc::from_raw(ptr as *const AtomicBool) };
    let cloned = arc.clone();
    // don't drop the original - we still hold it
    std::mem::forget(arc);
    RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
}

unsafe fn wake_fn(ptr: *const ()) {
    let arc = unsafe { Arc::from_raw(ptr as *const AtomicBool) };
    arc.store(true, Ordering::SeqCst);
    // drop the Arc (consumed by wake)
}

unsafe fn wake_by_ref_fn(ptr: *const ()) {
    let arc = unsafe { Arc::from_raw(ptr as *const AtomicBool) };
    arc.store(true, Ordering::SeqCst);
    // don't drop - wake_by_ref borrows
    std::mem::forget(arc);
}

unsafe fn drop_fn(ptr: *const ()) {
    unsafe {
        drop(Arc::from_raw(ptr as *const AtomicBool));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waker_sets_flag_on_wake() {
        let flag = Arc::new(AtomicBool::new(false));
        let waker = create_waker(&flag);
        waker.wake_by_ref();
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn waker_clone_works() {
        let flag = Arc::new(AtomicBool::new(false));
        let waker = create_waker(&flag);
        let cloned = waker.clone();
        drop(waker);
        cloned.wake();
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn waker_wake_consumes() {
        let flag = Arc::new(AtomicBool::new(false));
        let waker = create_waker(&flag);
        waker.wake(); // consumes the waker
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn waker_multiple_wakes() {
        let flag = Arc::new(AtomicBool::new(false));
        let waker = create_waker(&flag);
        waker.wake_by_ref();
        assert!(flag.load(Ordering::SeqCst));
        flag.store(false, Ordering::SeqCst);
        waker.wake_by_ref();
        assert!(flag.load(Ordering::SeqCst));
    }
}
