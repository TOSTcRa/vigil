// perf ring buffer reader - mmap'd shared memory between kernel and userspace
// one ring buffer per CPU, events written by BPF programs via EVENTS.output()

use std::os::fd::RawFd;

use crate::sys;

// perf_event_mmap_page header (at start of mmap'd region)
// we only need data_head and data_tail for reading
const DATA_HEAD_OFFSET: usize = 0x40; // offset of data_head in perf_event_mmap_page
const DATA_TAIL_OFFSET: usize = 0x48; // offset of data_tail

// perf event header in the ring buffer
#[repr(C)]
struct PerfEventHeader {
    pe_type: u32,
    misc: u16,
    size: u16,
}

const PERF_RECORD_SAMPLE: u32 = 9;
const PERF_RECORD_LOST: u32 = 2;

pub struct PerfBuffer {
    fds: Vec<RawFd>,
    mmaps: Vec<*mut u8>,
    mmap_size: usize,
    data_size: usize,
}

// SAFETY: PerfBuffer is only accessed from one thread at a time
// the mmap pointers are valid for the lifetime of the fds
unsafe impl Send for PerfBuffer {}

impl PerfBuffer {
    // open perf ring buffers for all CPUs, wire them into the BPF map
    pub fn open(map_fd: RawFd) -> Result<Self, Box<dyn std::error::Error>> {
        let nr_cpus = sys::nr_cpus();
        let page_size = sys::page_size();
        let nr_pages = 16; // 16 data pages = 64KB per CPU
        let mmap_size = (1 + nr_pages) * page_size; // 1 metadata page + data pages
        let data_size = nr_pages * page_size;

        let mut fds = Vec::with_capacity(nr_cpus);
        let mut mmaps = Vec::with_capacity(nr_cpus);

        for cpu in 0..nr_cpus {
            // create a perf event for BPF output on this CPU
            let attr = sys::PerfEventAttr {
                pe_type: 1, // PERF_TYPE_SOFTWARE
                size: std::mem::size_of::<sys::PerfEventAttr>() as u32,
                config: sys::PERF_COUNT_SW_BPF_OUTPUT,
                sample_period_or_freq: 1,
                sample_type: sys::PERF_SAMPLE_RAW,
                read_format: 0,
                flags: 0, // will be set by kernel
                wakeup_events_or_watermark: 1,
                bp_type: 0,
                config1: 0,
                config2: 0,
                branch_sample_type: 0,
                sample_regs_user: 0,
                sample_stack_user: 0,
                clockid: 0,
                sample_regs_intr: 0,
                aux_watermark: 0,
                sample_max_stack: 0,
                reserved: 0,
            };

            let fd = sys::sys_perf_event_open(
                &attr,
                -1,          // pid = -1 (all processes)
                cpu as i32,  // cpu
                -1,          // group_fd
                sys::PERF_FLAG_FD_CLOEXEC,
            )?;

            // mmap the ring buffer
            let ptr = sys::sys_mmap(fd, mmap_size)?;

            // enable the perf event
            sys::sys_ioctl(fd, sys::PERF_EVENT_IOC_ENABLE, 0)?;

            // store the fd in the BPF map so programs can output to it
            let key = (cpu as u32).to_ne_bytes();
            let val = (fd as u32).to_ne_bytes();
            sys::bpf_map_update_elem(map_fd, &key, &val)?;

            fds.push(fd);
            mmaps.push(ptr);
        }

        Ok(PerfBuffer {
            fds,
            mmaps,
            mmap_size,
            data_size,
        })
    }

    // get the perf event fds (for epoll registration)
    pub fn fds(&self) -> &[RawFd] {
        &self.fds
    }

    // read all available events from one CPU's ring buffer
    pub fn read_events<F>(&self, cpu: usize, mut callback: F)
    where
        F: FnMut(&[u8]),
    {
        if cpu >= self.mmaps.len() {
            return;
        }

        let base = self.mmaps[cpu];
        let page_size = sys::page_size();

        // data_head: written by kernel (how far it has written)
        // data_tail: written by us (how far we have read)
        let data_head = unsafe {
            let ptr = base.add(DATA_HEAD_OFFSET) as *const u64;
            std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
            ptr.read_volatile()
        };

        let data_tail = unsafe {
            let ptr = base.add(DATA_TAIL_OFFSET) as *const u64;
            ptr.read_volatile()
        };

        if data_head == data_tail {
            return; // no new events
        }

        let data_start = base.wrapping_add(page_size);
        let mut tail = data_tail;

        while tail < data_head {
            let offset = (tail as usize) % self.data_size;

            // read event header
            let header = unsafe {
                let ptr = data_start.add(offset) as *const PerfEventHeader;
                ptr.read_unaligned()
            };

            if header.size == 0 {
                break;
            }

            if header.pe_type == PERF_RECORD_SAMPLE {
                // sample format: header(8) + size(u32) + data(size bytes)
                let sample_offset = (offset + std::mem::size_of::<PerfEventHeader>()) % self.data_size;
                let sample_size = unsafe {
                    let ptr = data_start.add(sample_offset) as *const u32;
                    ptr.read_unaligned() as usize
                };

                let data_offset = (sample_offset + 4) % self.data_size;

                // read sample data (may wrap around ring buffer)
                if data_offset + sample_size <= self.data_size {
                    // no wrap
                    let slice = unsafe {
                        std::slice::from_raw_parts(data_start.add(data_offset), sample_size)
                    };
                    callback(slice);
                } else {
                    // wraps around - copy into temp buffer
                    let mut buf = vec![0u8; sample_size];
                    let first = self.data_size - data_offset;
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            data_start.add(data_offset),
                            buf.as_mut_ptr(),
                            first,
                        );
                        std::ptr::copy_nonoverlapping(
                            data_start,
                            buf.as_mut_ptr().add(first),
                            sample_size - first,
                        );
                    }
                    callback(&buf);
                }
            }

            tail += header.size as u64;
        }

        // update data_tail so kernel knows we consumed the events
        unsafe {
            let ptr = base.add(DATA_TAIL_OFFSET) as *mut u64;
            ptr.write_volatile(data_head);
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        }
    }
}

impl Drop for PerfBuffer {
    fn drop(&mut self) {
        for &ptr in &self.mmaps {
            let _ = sys::sys_munmap(ptr, self.mmap_size);
        }
        for &fd in &self.fds {
            let _ = sys::sys_ioctl(fd, sys::PERF_EVENT_IOC_DISABLE, 0);
            sys::sys_close(fd);
        }
    }
}
