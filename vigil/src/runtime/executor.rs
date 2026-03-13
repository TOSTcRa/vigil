// single-threaded async executor
// main future is polled directly (no 'static requirement)
// spawned tasks go into a task vec and need 'static

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::runtime::reactor::Reactor;
use crate::runtime::waker::create_waker;

struct Task {
    future: Pin<Box<dyn Future<Output = ()>>>,
    ready: Arc<AtomicBool>,
}

struct Runtime {
    tasks: Vec<Option<Task>>,
    reactor: Reactor,
}

thread_local! {
    static RT: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

// access the reactor from inside a future (used by io::readable, time::sleep)
pub(crate) fn with_reactor<F, R>(f: F) -> R
where
    F: FnOnce(&mut Reactor) -> R,
{
    RT.with(|rt| {
        let mut borrow = rt.borrow_mut();
        let runtime = borrow.as_mut().expect("no runtime active");
        f(&mut runtime.reactor)
    })
}

// spawn a new task onto the executor
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + 'static,
{
    let ready = Arc::new(AtomicBool::new(true)); // poll immediately
    let task = Task {
        future: Box::pin(future),
        ready,
    };
    RT.with(|rt| {
        let mut borrow = rt.borrow_mut();
        let runtime = borrow.as_mut().expect("no runtime active");
        runtime.tasks.push(Some(task));
    });
}

// run the main future and all spawned tasks to completion
// main future does NOT need 'static - it's polled directly, not stored in the task vec
pub fn block_on<F>(main: F)
where
    F: Future<Output = ()>,
{
    let reactor = Reactor::new().expect("failed to create epoll reactor");

    RT.with(|rt| {
        *rt.borrow_mut() = Some(Runtime {
            tasks: vec![],
            reactor,
        });
    });

    let main_ready = Arc::new(AtomicBool::new(true));
    let mut main_future = Box::pin(main);
    let mut main_done = false;

    loop {
        let mut made_progress = false;
        let mut all_done = true;

        // poll main future
        if !main_done {
            if main_ready.load(Ordering::SeqCst) {
                main_ready.store(false, Ordering::SeqCst);
                let waker = create_waker(&main_ready);
                let mut cx = Context::from_waker(&waker);

                match main_future.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => {
                        main_done = true;
                        made_progress = true;
                    }
                    Poll::Pending => {
                        made_progress = true;
                    }
                }
            }

            if !main_done {
                all_done = false;
            }
        }

        // poll spawned tasks
        let task_count = RT.with(|rt| {
            rt.borrow().as_ref().map(|r| r.tasks.len()).unwrap_or(0)
        });

        for i in 0..task_count {
            let is_ready = RT.with(|rt| {
                let borrow = rt.borrow();
                let runtime = borrow.as_ref().unwrap();
                if let Some(Some(task)) = runtime.tasks.get(i) {
                    task.ready.load(Ordering::SeqCst)
                } else {
                    false
                }
            });

            if !is_ready {
                let has_task = RT.with(|rt| {
                    let borrow = rt.borrow();
                    let runtime = borrow.as_ref().unwrap();
                    runtime.tasks.get(i).map(|t| t.is_some()).unwrap_or(false)
                });
                if has_task {
                    all_done = false;
                }
                continue;
            }

            // take the task out so we can poll it without holding the borrow
            let mut task = RT.with(|rt| {
                let mut borrow = rt.borrow_mut();
                let runtime = borrow.as_mut().unwrap();
                runtime.tasks[i].take()
            });

            if let Some(ref mut t) = task {
                t.ready.store(false, Ordering::SeqCst);
                let waker = create_waker(&t.ready);
                let mut cx = Context::from_waker(&waker);

                match t.future.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => {
                        made_progress = true;
                        continue; // task done, leave slot as None
                    }
                    Poll::Pending => {
                        made_progress = true;
                        all_done = false;
                    }
                }
            }

            // put the task back
            RT.with(|rt| {
                let mut borrow = rt.borrow_mut();
                let runtime = borrow.as_mut().unwrap();
                while runtime.tasks.len() <= i {
                    runtime.tasks.push(None);
                }
                runtime.tasks[i] = task;
            });
        }

        if all_done {
            break;
        }

        if !made_progress {
            // no task was ready - wait on epoll for IO events (up to 100ms)
            RT.with(|rt| {
                let mut borrow = rt.borrow_mut();
                let runtime = borrow.as_mut().unwrap();
                runtime.reactor.poll(100);
            });
        }
    }

    // cleanup
    RT.with(|rt| {
        *rt.borrow_mut() = None;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn block_on_immediate_ready() {
        let ran = Rc::new(Cell::new(false));
        let ran2 = ran.clone();
        block_on(async move {
            ran2.set(true);
        });
        assert!(ran.get());
    }

    #[test]
    fn block_on_with_yield() {
        // future that returns Pending once, then Ready
        struct YieldOnce(bool);
        impl Future for YieldOnce {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.0 {
                    Poll::Ready(())
                } else {
                    self.0 = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        let done = Rc::new(Cell::new(false));
        let done2 = done.clone();
        block_on(async move {
            YieldOnce(false).await;
            done2.set(true);
        });
        assert!(done.get());
    }

    #[test]
    fn block_on_borrows_locals() {
        // key feature: block_on does NOT require 'static
        let mut counter = 0u32;
        block_on(async {
            counter += 1;
        });
        assert_eq!(counter, 1);
    }

    #[test]
    fn spawn_runs_tasks() {
        let flag = Rc::new(Cell::new(false));
        let flag2 = flag.clone();
        block_on(async move {
            spawn(async move {
                flag2.set(true);
            });
        });
        assert!(flag.get());
    }
}
