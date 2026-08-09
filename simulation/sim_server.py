#!/usr/bin/env python3
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


SIM_DIR = Path(__file__).resolve().parent
SIM_BIN = SIM_DIR / "obj_dir" / "Vsim_top"
READY_FILE = SIM_DIR / "obj_dir" / ".sim_server_ready"
TAP_NAME = os.environ.get("SIM_TAP", "udptap")
HOST_IP = os.environ.get("SIM_HOST_IP", "192.168.15.1")
POLL_INTERVAL_S = 0.25
BINARY_STABLE_S = 0.75
TAP_STABLE_S = 0.5


def binary_signature():
    try:
        stat = SIM_BIN.stat()
    except FileNotFoundError:
        return None
    if stat.st_size == 0:
        return None
    return stat.st_mtime_ns, stat.st_size


def clear_ready_file():
    try:
        READY_FILE.unlink()
    except FileNotFoundError:
        pass


def wait_tap_ready(proc: subprocess.Popen, timeout_s: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_s
    ready_since = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        status = subprocess.run(
            ["ip", "addr", "show", "dev", TAP_NAME],
            text=True,
            capture_output=True,
        )
        if status.returncode == 0 and HOST_IP in status.stdout:
            now = time.monotonic()
            if ready_since is None:
                ready_since = now
            elif now - ready_since >= TAP_STABLE_S:
                return True
        else:
            ready_since = None
        time.sleep(0.1)
    return False


def start_simulator(signature) -> subprocess.Popen:
    print(f"[server] starting simulator build={signature[0]} size={signature[1]}", flush=True)
    proc = subprocess.Popen([str(SIM_BIN), TAP_NAME], cwd=SIM_DIR)
    if wait_tap_ready(proc):
        READY_FILE.write_text(f"{signature[0]} {signature[1]}\n", encoding="ascii")
        print(f"[server] TAP {TAP_NAME} ready; loaded build matches Vsim_top", flush=True)
    else:
        print(f"[server] simulator failed to make TAP {TAP_NAME} ready", flush=True)
    return proc


def stop_simulator(proc: subprocess.Popen):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=1.0)


def main() -> int:
    if os.geteuid() != 0:
        print("[error] TAP creation requires root privileges")
        print("[hint] run: sudo python3 sim_server.py")
        return 2
    signature = binary_signature()
    if signature is None:
        print(f"[error] simulator binary not found: {SIM_BIN}")
        print("[hint] run make as the normal WSL user first")
        return 2

    os.chdir(SIM_DIR)
    shutdown = threading.Event()

    def request_shutdown(_signum, _frame):
        shutdown.set()

    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)

    print(
        f"[server] persistent supervisor started on TAP {TAP_NAME}; "
        "Vsim_top changes are reloaded automatically; press Ctrl+C to stop",
        flush=True,
    )
    clear_ready_file()
    proc = start_simulator(signature)
    active_signature = signature
    candidate_signature = signature
    candidate_since = time.monotonic()

    try:
        while not shutdown.wait(POLL_INTERVAL_S):
            current_signature = binary_signature()
            now = time.monotonic()

            if current_signature != candidate_signature:
                candidate_signature = current_signature
                candidate_since = now

            if proc.poll() is not None:
                clear_ready_file()
                print(f"[server] simulator exited with code {proc.returncode}; restarting", flush=True)
                if current_signature is None:
                    continue
                time.sleep(0.5)
                proc = start_simulator(current_signature)
                active_signature = current_signature
                candidate_signature = current_signature
                candidate_since = time.monotonic()
                continue

            if (
                candidate_signature is not None
                and candidate_signature != active_signature
                and now - candidate_since >= BINARY_STABLE_S
            ):
                print("[server] new stable Vsim_top detected; reloading RTL model", flush=True)
                clear_ready_file()
                stop_simulator(proc)
                proc = start_simulator(candidate_signature)
                active_signature = candidate_signature
    finally:
        clear_ready_file()
        stop_simulator(proc)
        print("[server] stopped", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
