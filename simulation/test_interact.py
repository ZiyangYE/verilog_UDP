#!/usr/bin/env python3
import os
import random
import select
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

SIM_DIR = Path(__file__).resolve().parent
SIM_BIN = SIM_DIR / "obj_dir" / "Vsim_top"

TAP_NAME = os.environ.get("SIM_TAP", "udptap")
HOST_IP = os.environ.get("SIM_HOST_IP", "192.168.15.1")
DUT_IP = os.environ.get("SIM_DUT_IP", "192.168.15.14")
DUT_MAC = os.environ.get("SIM_DUT_MAC", "06:00:aa:bb:0c:dd").lower()

DUT_PORT = int(os.environ.get("SIM_DUT_PORT", "11451"))
BASE_SRC_PORT = int(os.environ.get("SIM_SRC_PORT", "12345"))

_udp_matrix_env = os.environ.get("SIM_UDP_MATRIX", "2,4,8,16,32,64,128")
UDP_MATRIX = [int(x) for x in _udp_matrix_env.split(",") if x.strip()]
UDP_STRESS_COUNT = int(os.environ.get("SIM_UDP_STRESS", "40"))
PING_SIZE = int(os.environ.get("SIM_PING_SIZE", "0"))
STRICT_MODE = os.environ.get("SIM_STRICT", "1") == "1"


@dataclass
class CheckResult:
    name: str
    ok: bool
    details: str


def run_cmd(cmd, check=False, timeout=None):
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{p.stdout}\n{p.stderr}")
    return p


def stop_sim(proc: subprocess.Popen):
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


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

    cmd = [str(SIM_BIN), TAP_NAME] if os.geteuid() == 0 else ["sudo", str(SIM_BIN), TAP_NAME]
    return subprocess.Popen(
        cmd,
        cwd=str(SIM_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def get_iface_mac(ifname: str) -> str:
    mac_path = Path(f"/sys/class/net/{ifname}/address")
    return mac_path.read_text(encoding="utf-8").strip().lower()


def ones_complement_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_ipv4(frame: bytes):
    if len(frame) < 14 + 20:
        return None
    dst_mac = ":".join(f"{b:02x}" for b in frame[0:6])
    src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
    eth_type = struct.unpack("!H", frame[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip = frame[14:]
    version_ihl = ip[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(ip) < ihl or ihl < 20:
        return None

    total_length = struct.unpack("!H", ip[2:4])[0]
    if len(ip) < total_length:
        return None

    proto = ip[9]
    src_ip = socket.inet_ntoa(ip[12:16])
    dst_ip = socket.inet_ntoa(ip[16:20])
    ip_hdr = ip[:ihl]
    ip_payload = ip[ihl:total_length]
    ip_csum_field = struct.unpack("!H", ip[10:12])[0]

    ip_hdr_zero = bytearray(ip_hdr)
    ip_hdr_zero[10] = 0
    ip_hdr_zero[11] = 0
    ip_csum_calc = ones_complement_checksum(bytes(ip_hdr_zero))

    return {
        "dst_mac": dst_mac,
        "src_mac": src_mac,
        "eth_type": eth_type,
        "ip_proto": proto,
        "ip_ttl": ip[8],
        "ip_src": src_ip,
        "ip_dst": dst_ip,
        "ip_id": struct.unpack("!H", ip[4:6])[0],
        "ip_total_length": total_length,
        "ip_header_checksum": ip_csum_field,
        "ip_header_checksum_calc": ip_csum_calc,
        "payload": ip_payload,
    }


def parse_icmp(pkt: dict):
    payload = pkt["payload"]
    if len(payload) < 8:
        return None
    icmp_type = payload[0]
    icmp_code = payload[1]
    icmp_checksum = struct.unpack("!H", payload[2:4])[0]
    icmp_ident = struct.unpack("!H", payload[4:6])[0]
    icmp_seq = struct.unpack("!H", payload[6:8])[0]
    icmp_calc = ones_complement_checksum(payload)
    return {
        "type": icmp_type,
        "code": icmp_code,
        "checksum": icmp_checksum,
        "checksum_ok": icmp_calc == 0,
        "ident": icmp_ident,
        "seq": icmp_seq,
        "data": payload[8:],
    }


def parse_udp(pkt: dict):
    payload = pkt["payload"]
    if len(payload) < 8:
        return None
    src_port, dst_port, udp_len, udp_sum = struct.unpack("!HHHH", payload[:8])
    udp_payload = payload[8:udp_len]
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(pkt["ip_src"]),
        socket.inet_aton(pkt["ip_dst"]),
        0,
        17,
        udp_len,
    )
    checksum_data = pseudo + payload[:udp_len]
    udp_ok = ones_complement_checksum(checksum_data) == 0
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": udp_len,
        "checksum": udp_sum,
        "checksum_ok": udp_ok,
        "data": udp_payload,
    }


def sniff_until(
    predicate: Callable[[bytes], Optional[dict]],
    trigger: Callable[[], object],
    timeout_s: float,
):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((TAP_NAME, 0))
    s.settimeout(0.2)
    trigger_obj = None
    try:
        trigger_obj = trigger()
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            try:
                frame = s.recv(4096)
            except socket.timeout:
                continue
            parsed = predicate(frame)
            if parsed is not None:
                return parsed
        return None
    finally:
        if isinstance(trigger_obj, subprocess.Popen):
            try:
                trigger_obj.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                trigger_obj.kill()
        s.close()


def arp_resolve_check() -> CheckResult:
    run_cmd(["ip", "neigh", "del", DUT_IP, "dev", TAP_NAME])

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((HOST_IP, BASE_SRC_PORT + 100))
        probe.sendto(b"arp-probe", (DUT_IP, DUT_PORT))
    finally:
        probe.close()

    t0 = time.time()
    while time.time() - t0 < 3.0:
        p = run_cmd(["ip", "neigh", "show", "to", DUT_IP, "dev", TAP_NAME])
        line = p.stdout.strip().lower()
        if "lladdr" in line and "incomplete" not in line and "failed" not in line:
            ok = DUT_MAC in line
            if ok:
                return CheckResult("arp.resolve", True, line)
            return CheckResult("arp.resolve", False, f"resolved but mac mismatch: {line}")
        time.sleep(0.2)
    return CheckResult("arp.resolve", False, "arp entry did not resolve")


def icmp_echo_wire_check() -> CheckResult:
    host_mac = get_iface_mac(TAP_NAME)
    req_pkt = {"v": None}
    rep_pkt = {"v": None}
    req_ident = {"v": None}

    def pred(frame: bytes):
        pkt = parse_ipv4(frame)
        if pkt is None or pkt["ip_proto"] != 1:
            return None
        if pkt["ip_src"] == HOST_IP and pkt["ip_dst"] == DUT_IP:
            ic = parse_icmp(pkt)
            if ic and ic["type"] == 8:
                req_pkt["v"] = (pkt, ic)
                req_ident["v"] = ic["ident"]
                return None
        if pkt["ip_src"] == DUT_IP and pkt["ip_dst"] == HOST_IP:
            ic = parse_icmp(pkt)
            if ic and ic["type"] == 0:
                if req_ident["v"] is None or ic["ident"] != req_ident["v"]:
                    return None
                rep_pkt["v"] = (pkt, ic)
                if req_pkt["v"] is not None:
                    return {"req": req_pkt["v"], "rep": rep_pkt["v"]}
        return None

    def trigger():
        return subprocess.Popen(
            [
                "ping",
                "-c",
                "1",
                "-W",
                "2",
                "-s",
                str(PING_SIZE),
                "-I",
                HOST_IP,
                DUT_IP,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    pair = sniff_until(pred, trigger, timeout_s=3.0)
    if pair is None:
        return CheckResult("icmp.wire", False, "did not capture icmp request/reply pair")

    req_ip, req_icmp = pair["req"]
    rep_ip, rep_icmp = pair["rep"]

    checks = []
    checks.append((rep_ip["src_mac"] == DUT_MAC, f"src_mac={rep_ip['src_mac']} expect={DUT_MAC}"))
    checks.append((rep_ip["dst_mac"] == host_mac, f"dst_mac={rep_ip['dst_mac']} expect={host_mac}"))
    checks.append((rep_ip["ip_ttl"] == 0x80, f"ttl={rep_ip['ip_ttl']} expect=128"))
    checks.append((rep_ip["ip_header_checksum"] == rep_ip["ip_header_checksum_calc"], "ip checksum mismatch"))
    checks.append((rep_icmp["checksum_ok"], "icmp checksum invalid"))
    checks.append((rep_icmp["code"] == 0, f"icmp code={rep_icmp['code']}"))
    checks.append(
        (
            rep_icmp["ident"] == req_icmp["ident"],
            f"icmp ident mismatch req={req_icmp['ident']} rep={rep_icmp['ident']}",
        )
    )
    checks.append(
        (
            rep_icmp["seq"] == req_icmp["seq"],
            f"icmp seq mismatch req={req_icmp['seq']} rep={rep_icmp['seq']}",
        )
    )
    checks.append((rep_icmp["data"] == req_icmp["data"], "icmp payload mismatch"))

    failed = [msg for ok, msg in checks if not ok]
    if failed:
        return CheckResult(
            "icmp.wire",
            False,
            "; ".join(failed)
            + f"; rep_cksum=0x{rep_icmp['checksum']:04x} rep_data_len={len(rep_icmp['data'])}",
        )
    return CheckResult(
        "icmp.wire",
        True,
        f"id={rep_icmp['ident']} seq={rep_icmp['seq']} ttl={rep_ip['ip_ttl']} payload={len(rep_icmp['data'])}",
    )


def ping_basic_check() -> CheckResult:
    p = run_cmd(
        [
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "-s",
            str(PING_SIZE),
            "-I",
            HOST_IP,
            DUT_IP,
        ]
    )
    if p.returncode == 0:
        return CheckResult("icmp.basic", True, "ping command succeeded")
    details = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    return CheckResult("icmp.basic", False, details.strip() or "ping command failed")


def udp_single_roundtrip(payload: bytes, src_port: int, timeout_s: float = 1.2):
    recv_port = src_port + 1
    recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        recv.settimeout(timeout_s)
        recv.bind((HOST_IP, recv_port))
        send.bind((HOST_IP, src_port))
        send.sendto(payload, (DUT_IP, DUT_PORT))
        data, addr = recv.recvfrom(4096)
        return data, addr
    finally:
        recv.close()
        send.close()


def udp_matrix_check() -> CheckResult:
    random.seed(20260319)
    for i, sz in enumerate(UDP_MATRIX):
        payload = bytes(random.getrandbits(8) for _ in range(sz))
        src_port = BASE_SRC_PORT + 200 + i * 2
        for retry in range(3):
            try:
                data, addr = udp_single_roundtrip(payload, src_port)
                if data != payload:
                    return CheckResult(
                        "udp.matrix",
                        False,
                        (
                            f"size={sz} payload mismatch len={len(data)} src_port={src_port} "
                            f"exp={payload.hex()} got={data.hex()}"
                        ),
                    )
                if addr[0] != DUT_IP or addr[1] != DUT_PORT:
                    return CheckResult("udp.matrix", False, f"size={sz} unexpected addr={addr}")
                break
            except socket.timeout:
                if retry == 2:
                    return CheckResult("udp.matrix", False, f"size={sz} timeout")
                time.sleep(0.15)
    return CheckResult("udp.matrix", True, f"validated {len(UDP_MATRIX)} payload sizes")


def udp_basic_check() -> CheckResult:
    payload = b"hello-from-test-script"
    src_port = BASE_SRC_PORT + 50
    for i in range(12):
        try:
            data, addr = udp_single_roundtrip(payload, src_port, timeout_s=1.0)
            if data != payload:
                return CheckResult("udp.basic", False, f"payload mismatch got={data!r}")
            if addr[0] != DUT_IP or addr[1] != DUT_PORT:
                return CheckResult("udp.basic", False, f"unexpected source addr={addr}")
            return CheckResult("udp.basic", True, f"received {len(data)} bytes")
        except socket.timeout:
            time.sleep(0.2)
            if i == 11:
                return CheckResult("udp.basic", False, "timeout waiting for echo")
    return CheckResult("udp.basic", False, "internal unexpected path")


def udp_wire_header_check() -> CheckResult:
    payload = b"wire-check-udp"
    src_port = BASE_SRC_PORT + 500
    recv_port = src_port + 1
    host_mac = get_iface_mac(TAP_NAME)

    def pred(frame: bytes):
        pkt = parse_ipv4(frame)
        if pkt is None or pkt["ip_proto"] != 17:
            return None
        if pkt["ip_src"] != DUT_IP or pkt["ip_dst"] != HOST_IP:
            return None
        udp = parse_udp(pkt)
        if udp is None:
            return None
        if udp["dst_port"] != recv_port:
            return None
        if udp["data"] != payload:
            return None
        return {"ip": pkt, "udp": udp}

    def trigger():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((HOST_IP, src_port))
            s.sendto(payload, (DUT_IP, DUT_PORT))
        finally:
            s.close()
        return None

    got = sniff_until(pred, trigger, timeout_s=2.5)
    if got is None:
        return CheckResult("udp.wire", False, "wire packet not captured")

    ip_pkt = got["ip"]
    udp_pkt = got["udp"]
    checks = []
    checks.append((ip_pkt["src_mac"] == DUT_MAC, f"src_mac={ip_pkt['src_mac']} expect={DUT_MAC}"))
    checks.append((ip_pkt["dst_mac"] == host_mac, f"dst_mac={ip_pkt['dst_mac']} expect={host_mac}"))
    checks.append((ip_pkt["ip_header_checksum"] == ip_pkt["ip_header_checksum_calc"], "ip checksum mismatch"))
    checks.append((udp_pkt["src_port"] == DUT_PORT, f"udp src_port={udp_pkt['src_port']} expect={DUT_PORT}"))
    checks.append((udp_pkt["length"] == 8 + len(payload), f"udp length={udp_pkt['length']} expect={8 + len(payload)}"))
    checks.append((udp_pkt["checksum_ok"], "udp checksum invalid"))

    failed = [msg for ok, msg in checks if not ok]
    if failed:
        return CheckResult("udp.wire", False, "; ".join(failed))
    return CheckResult("udp.wire", True, f"len={udp_pkt['length']} dst_port={udp_pkt['dst_port']}")


def udp_negative_wrong_port() -> CheckResult:
    recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    src_port = BASE_SRC_PORT + 700
    recv_port = src_port + 1
    try:
        recv.settimeout(0.6)
        recv.bind((HOST_IP, recv_port))
        send.bind((HOST_IP, src_port))
        send.sendto(b"wrong-port", (DUT_IP, DUT_PORT + 9))
        try:
            data, _ = recv.recvfrom(2048)
            if data == b"wrong-port":
                return CheckResult("udp.negative", True, "reply observed on non-default port (expected echo-any-port behavior)")
            return CheckResult("udp.negative", False, "received reply but payload mismatch")
        except socket.timeout:
            return CheckResult("udp.negative", False, "no reply on non-default port")
    finally:
        recv.close()
        send.close()


def udp_stress_check() -> CheckResult:
    recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    src_port = BASE_SRC_PORT + 900
    recv_port = src_port + 1
    try:
        recv.settimeout(1.5)
        recv.bind((HOST_IP, recv_port))
        send.bind((HOST_IP, src_port))

        expected = set()
        for i in range(UDP_STRESS_COUNT):
            msg = f"stress-{i:04d}".encode()
            expected.add(msg)
            send.sendto(msg, (DUT_IP, DUT_PORT))
            time.sleep(0.003)

        got = set()
        deadline = time.time() + 3.5
        while time.time() < deadline and len(got) < len(expected):
            try:
                data, _ = recv.recvfrom(2048)
                if data in expected:
                    got.add(data)
            except socket.timeout:
                break

        if got != expected:
            return CheckResult("udp.stress", False, f"received {len(got)}/{len(expected)}")
        return CheckResult("udp.stress", True, f"received {len(got)}/{len(expected)}")
    finally:
        recv.close()
        send.close()


def run_suite() -> tuple[list[CheckResult], list[CheckResult]]:
    core_results = []
    ext_results = []

    core_tests = [
        arp_resolve_check,
        ping_basic_check,
        udp_basic_check,
    ]

    ext_tests = [
        icmp_echo_wire_check,
        udp_matrix_check,
        udp_wire_header_check,
        udp_negative_wrong_port,
        udp_stress_check,
    ]

    for test in core_tests:
        name = test.__name__
        t0 = time.time()
        try:
            res = test()
        except Exception as e:
            res = CheckResult(name, False, f"exception: {e}")
        dt_ms = int((time.time() - t0) * 1000)
        status = "ok" if res.ok else "fail"
        print(f"[{status}] {res.name} ({dt_ms} ms): {res.details}")
        core_results.append(res)

    for test in ext_tests:
        name = test.__name__
        t0 = time.time()
        try:
            res = test()
        except Exception as e:
            res = CheckResult(name, False, f"exception: {e}")
        dt_ms = int((time.time() - t0) * 1000)
        status = "ok" if res.ok else "warn"
        print(f"[{status}] {res.name} ({dt_ms} ms): {res.details}")
        ext_results.append(res)

    return core_results, ext_results


def main() -> int:
    print("[step] starting simulator...")
    try:
        sim = start_sim()
    except Exception as e:
        print(f"[error] failed to start simulator: {e}")
        return 2

    try:
        time.sleep(0.3)
        if sim.poll() is not None:
            for line in drain_output(sim):
                print(line)
            print("[error] simulator exited early")
            return 2

        if not wait_tap_up(TAP_NAME, timeout_s=10.0):
            print("[error] TAP interface did not come up in time")
            for line in drain_output(sim):
                print(line)
            return 3

        print(f"[step] TAP ready on {TAP_NAME}, host ip {HOST_IP}, dut ip {DUT_IP}")
        core_results, ext_results = run_suite()

        for line in drain_output(sim, max_lines=50):
            print(line)

        core_failed = [r for r in core_results if not r.ok]
        ext_failed = [r for r in ext_results if not r.ok]

        if core_failed:
            print("[fail] core regression has failing checks:")
            for r in core_failed:
                print(f"  - {r.name}: {r.details}")
            return 1

        if ext_failed and STRICT_MODE:
            print("[fail] strict mode enabled; extended checks failed:")
            for r in ext_failed:
                print(f"  - {r.name}: {r.details}")
            return 1

        if ext_failed:
            print("[pass] core regression passed; extended diagnostics found issues:")
            for r in ext_failed:
                print(f"  - {r.name}: {r.details}")
            print("[hint] set SIM_STRICT=1 to gate on extended diagnostics")
            return 0

        print("[pass] core + extended ARP/ICMP/UDP regression passed")
        return 0
    finally:
        stop_sim(sim)


if __name__ == "__main__":
    sys.exit(main())
