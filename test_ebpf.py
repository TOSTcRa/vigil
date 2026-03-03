#!/usr/bin/env python3
"""Test script for Vigil eBPF detections. Run with sudo."""

import ctypes
import time
import os

libc = ctypes.CDLL("libc.so.6")

def test_readv():
    print("[TEST] process_vm_readv (syscall_type: 0)")
    libc.process_vm_readv(1, 0, 0, 0, 0, 0)
    print("  -> sent\n")

def test_writev():
    print("[TEST] process_vm_writev (syscall_type: 1)")
    libc.process_vm_writev(1, 0, 0, 0, 0, 0)
    print("  -> sent\n")

def test_ptrace():
    print("[TEST] ptrace PTRACE_PEEKDATA (syscall_type: 2)")
    libc.ptrace(2, 1, 0, 0)
    print("  -> sent\n")

def test_memfd():
    print("[TEST] memfd_create (syscall_type: 3)")
    libc.syscall(319, b"test", 0)  # 319 = memfd_create on x86_64
    print("  -> sent\n")

def test_mem_write():
    print("[TEST] /proc/PID/mem write (syscall_type: 4)")
    try:
        f = open("/proc/1/mem", "wb")
        f.seek(0)
        f.write(b"\x00")
    except Exception as e:
        print(f"  (expected error: {e})")
    print("  -> sent\n")

if __name__ == "__main__":
    print("=== Vigil eBPF Test Suite ===\n")
    print(f"Test PID: {os.getpid()}")
    print(f"Target PID: 1 (init)\n")

    tests = [test_readv, test_writev, test_ptrace, test_memfd, test_mem_write]

    for test in tests:
        test()
        time.sleep(0.5)

    print("=== All tests sent! Check Vigil output. ===")
