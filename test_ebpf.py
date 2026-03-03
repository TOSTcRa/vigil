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

def test_init_module():
    print("[TEST] do_init_module kprobe (syscall_type: 5)")
    print("  Run manually: sudo modprobe dummy && sudo modprobe -r dummy")
    print("  (cannot trigger from python)\n")

def test_cheat_signature():
    print("[TEST] Cheat signature detection (name_only match)")
    import subprocess, stat
    # Compile a tiny C binary named "scanmem" so /proc/PID/exe points to it
    tmpdir = os.path.join("/tmp", f"vigil_test_{os.getpid()}")
    os.makedirs(tmpdir, exist_ok=True)
    src = os.path.join(tmpdir, "fakecheat.c")
    fake = os.path.join(tmpdir, "scanmem")
    with open(src, "w") as f:
        f.write('#include <unistd.h>\nint main() { sleep(30); return 0; }\n')
    os.system(f"cc {src} -o {fake}")
    os.remove(src)
    p = subprocess.Popen([fake])
    print(f"  launched fake scanmem binary with pid {p.pid}")
    print("  -> waiting 10s for Vigil to detect cheat signature...")
    time.sleep(10)
    p.kill()
    p.wait()
    os.remove(fake)
    os.rmdir(tmpdir)
    print("  -> done\n")

def test_cross_trace():
    print("[TEST] TracerPid cross-reference (one tracer -> multiple targets)")
    import subprocess, signal
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    targets = []
    try:
        for i in range(3):
            p = subprocess.Popen(["sleep", "60"])
            targets.append(p)
        time.sleep(0.5)
        for p in targets:
            libc.ptrace(PTRACE_ATTACH, p.pid, 0, 0)
            print(f"  attached to pid {p.pid}")
        print("  -> waiting 10s for Vigil to detect cross-trace...")
        time.sleep(10)
    finally:
        for p in targets:
            libc.ptrace(PTRACE_DETACH, p.pid, 0, 0)
            p.kill()
            p.wait()
    print("  -> done\n")

if __name__ == "__main__":
    print("=== Vigil eBPF Test Suite ===\n")
    print(f"Test PID: {os.getpid()}")
    print(f"Target PID: 1 (init)\n")

    tests = [test_readv, test_writev, test_ptrace, test_memfd, test_mem_write, test_init_module, test_cheat_signature, test_cross_trace]

    for test in tests:
        test()
        time.sleep(0.5)

    print("=== All tests sent! Check Vigil output. ===")
