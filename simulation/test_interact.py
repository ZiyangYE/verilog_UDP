#!/usr/bin/env python3
import os
import signal
import socket
import subprocess
import sys
import time
import select
from pathlib import Path

SIM_DIR = Path(__file__).resolve().parent
SIM_BIN = SIM_DIR / "obj_dir" / "Vsim_top"
TAP_NAME = os.environ.get("SIM_TAP", "udptap")
HOST_IP = os.environ.get("SIM_HOST_IP", "192.168.15.1")
DUT_IP = os.environ.get("SIM_DUT_IP", "192.168.15.14")
DUT_PORT = int(os.environ.get("SIM_DUT_PORT", "11451"))
SRC_PORT = int(os.environ.get("SIM_SRC_PORT", "12345"))
RECV_PORT = SRC_PORT + 1
PAYLOAD = os.environ.get("SIM_PAYLOAD", "hello-from-test-script").encode()


def run_cmd(cmd, check=False):
    p = subprocess.run(cmd, text=True, capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{p.stdout}\n{p.stderr}")
    return p


def wait_tap_up(name: str, timeout_s: float = 10.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        p = run_cmd(["ip", "addr", "show", "dev", name])
        if p.returncode == 0 and HOST_IP in p.stdout:
            return True
        time.sleep(0.2)
    return False


def start_sim() -> subprocess.Popen:
    if not SIM_BIN.exists():
        raise FileNotFoundError(f"simulation binary not found: {SIM_BIN}")

    if os.geteuid() == 0:
        cmd = [str(SIM_BIN), TAP_NAME]
    else:
        cmd = ["sudo", str(SIM_BIN), TAP_NAME]

    return subprocess.Popen(
        cmd,
        cwd=str(SIM_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def stop_sim(proc: subprocess.Popen):
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def ensure_sudo_ticket() -> bool:
    if os.geteuid() == 0:
        return True
    print("[step] requesting one-time sudo authorization (sudo -v)...")
    p = subprocess.run(["sudo", "-v"])
    return p.returncode == 0


def drain_output(proc: subprocess.Popen, max_lines: int = 80, timeout_s: float = 0.25):
    lines = []
    if proc.stdout is None:
        return lines
    fd = proc.stdout.fileno()
    deadline = time.time() + timeout_s
    while len(lines) < max_lines and time.time() < deadline:
        wait_s = max(0.0, deadline - time.time())
        rlist, _, _ = select.select([fd], [], [], wait_s)
        if not rlist:
            break
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.rstrip())
    return lines


def udp_roundtrip() -> bool:
    recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        recv.settimeout(1.0)
        recv.bind((HOST_IP, RECV_PORT))
        send.bind((HOST_IP, SRC_PORT))

        # First few packets may be lost while ARP settles, so retry.
        for i in range(12):
            send.sendto(PAYLOAD, (DUT_IP, DUT_PORT))
            try:
                data, addr = recv.recvfrom(2048)
                print(f"[ok] recv {len(data)} bytes from {addr}: {data!r}")
                return data == PAYLOAD
            except socket.timeout:
                print(f"[info] retry {i + 1}/12: no UDP response yet")
                time.sleep(0.2)
        return False
    finally:
        recv.close()
        send.close()


def main() -> int:
    if not ensure_sudo_ticket():
        print("[error] sudo authorization failed")
        return 2

    print("[step] starting simulator...")
    try:
        sim = start_sim()
    except Exception as e:
        print(f"[error] failed to start simulator: {e}")
        print("[hint] run once with sudo privileges or set NOPASSWD for this binary")
        return 2

    try:
        time.sleep(0.3)
        if sim.poll() is not None:
            for line in drain_output(sim):
                print(line)
            print("[error] simulator exited early (likely sudo permission issue)")
            return 2

        if not wait_tap_up(TAP_NAME, timeout_s=10.0):
            print("[error] TAP interface did not come up in time")
            for line in drain_output(sim):
                print(line)
            return 3

        print(f"[step] TAP ready on {TAP_NAME}, host ip {HOST_IP}")
        ok = udp_roundtrip()

        for line in drain_output(sim, max_lines=40):
            print(line)

        if ok:
            print("[pass] UDP interaction passed")
            return 0

        print("[fail] did not receive expected UDP echo")
        return 1
    finally:
        stop_sim(sim)


if __name__ == "__main__":
    sys.exit(main())
