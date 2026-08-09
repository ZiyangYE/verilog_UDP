#!/usr/bin/env python3
import argparse
import os
import random
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

SIM_DIR = Path(__file__).resolve().parent
SIM_BIN = SIM_DIR / "obj_dir" / "Vsim_top"
SERVER_READY_FILE = SIM_DIR / "obj_dir" / ".sim_server_ready"

TAP_NAME = os.environ.get("SIM_TAP", "udptap")
HOST_IP = os.environ.get("SIM_HOST_IP", "192.168.15.1")
DUT_IP = os.environ.get("SIM_DUT_IP", "192.168.15.14")
DUT_MAC = os.environ.get("SIM_DUT_MAC", "06:00:aa:bb:0c:dd").lower()

DUT_PORT = int(os.environ.get("SIM_DUT_PORT", "11451"))
BASE_SRC_PORT = int(os.environ.get("SIM_SRC_PORT", "12345"))

_udp_matrix_env = os.environ.get("SIM_UDP_MATRIX", "1,2,3,4,5,6,7,8,15,16,17,18,31,32,33,34,63,64,65,66,127,128,129,130")
UDP_MATRIX = [int(x) for x in _udp_matrix_env.split(",") if x.strip()]
UDP_STRESS_COUNT = int(os.environ.get("SIM_UDP_STRESS", "40"))
UDP_BURST_COUNT = int(os.environ.get("SIM_UDP_BURST", "100"))
UDP_BURST_MAX_SIZE = int(os.environ.get("SIM_UDP_BURST_MAX_SIZE", "1400"))
UDP_BURST_TIMEOUT_S = float(os.environ.get("SIM_UDP_BURST_TIMEOUT", "3.0"))
PING_SIZE = int(os.environ.get("SIM_PING_SIZE", "32"))
STRICT_MODE = os.environ.get("SIM_STRICT", "1") == "1"

BURST_MAGIC = b"SIMBURST"
BURST_HEADER_SIZE = len(BURST_MAGIC) + 6


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


def wait_tap_up(name: str, timeout_s: float = 10.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        p = run_cmd(["ip", "addr", "show", "dev", name])
        if p.returncode == 0 and HOST_IP in p.stdout:
            return True
        time.sleep(0.2)
    return False


def simulator_binary_signature():
    try:
        stat = SIM_BIN.stat()
    except FileNotFoundError:
        return None
    return stat.st_mtime_ns, stat.st_size


def loaded_simulator_signature():
    try:
        parts = SERVER_READY_FILE.read_text(encoding="ascii").split()
        return int(parts[0]), int(parts[1])
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return None


def wait_simulator_ready(timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        binary_signature = simulator_binary_signature()
        if binary_signature is not None and loaded_simulator_signature() == binary_signature:
            if wait_tap_up(TAP_NAME, timeout_s=0.2):
                return True
        time.sleep(0.1)
    return False


def raw_packet_access_available() -> bool:
    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        return False
    else:
        probe.close()
        return True


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
    deadline = time.monotonic() + 8.0
    next_probe = 0.0
    probe_count = 0
    last_send_error = ""
    try:
        probe.bind((HOST_IP, BASE_SRC_PORT + 100))
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_probe:
                try:
                    probe.sendto(b"arp-probe", (DUT_IP, DUT_PORT))
                    probe_count += 1
                    last_send_error = ""
                except OSError as exc:
                    last_send_error = str(exc)
                next_probe = now + 0.25

            p = run_cmd(["ip", "neigh", "show", "to", DUT_IP, "dev", TAP_NAME])
            line = p.stdout.strip().lower()
            if "lladdr" in line and "incomplete" not in line and "failed" not in line:
                if DUT_MAC in line:
                    return CheckResult("arp.resolve", True, line)
                return CheckResult("arp.resolve", False, f"resolved but mac mismatch: {line}")
            time.sleep(0.1)
    finally:
        probe.close()

    detail = f"arp entry did not resolve after {probe_count} probes"
    if last_send_error:
        detail += f"; last send error: {last_send_error}"
    return CheckResult("arp.resolve", False, detail)


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


def udp_burst_check() -> CheckResult:
    if UDP_BURST_COUNT <= 0:
        return CheckResult("udp.burst", True, "disabled")
    if UDP_BURST_MAX_SIZE < BURST_HEADER_SIZE:
        return CheckResult(
            "udp.burst",
            False,
            f"SIM_UDP_BURST_MAX_SIZE must be >= {BURST_HEADER_SIZE}",
        )

    rng = random.Random(20260319)
    payloads = []
    for sequence in range(UDP_BURST_COUNT):
        size = rng.randint(BURST_HEADER_SIZE, UDP_BURST_MAX_SIZE)
        header = BURST_MAGIC + sequence.to_bytes(4, "big") + size.to_bytes(2, "big")
        payloads.append(header + bytes(rng.getrandbits(8) for _ in range(size - len(header))))

    recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    src_port = BASE_SRC_PORT + 1100
    recv_port = src_port + 1

    packets = []
    receiver_errors = []
    receiver_ready = threading.Event()
    send_done = threading.Event()
    stop_receiver = threading.Event()
    receive_deadline = [float("inf")]

    def receive_worker():
        seen_sequences = set()
        quiet_deadline = float("inf")
        recv.settimeout(0.02)
        receiver_ready.set()

        while not stop_receiver.is_set():
            now = time.perf_counter()
            if send_done.is_set():
                if len(seen_sequences) == UDP_BURST_COUNT and quiet_deadline == float("inf"):
                    quiet_deadline = now + 0.02
                if now >= receive_deadline[0] or now >= quiet_deadline:
                    break

            try:
                data, addr = recv.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if not stop_receiver.is_set():
                    receiver_errors.append(str(e))
                break

            packets.append((data, addr))
            if len(data) >= BURST_HEADER_SIZE and data.startswith(BURST_MAGIC):
                sequence = int.from_bytes(data[len(BURST_MAGIC) : len(BURST_MAGIC) + 4], "big")
                if sequence < UDP_BURST_COUNT:
                    seen_sequences.add(sequence)
                    if send_done.is_set() and len(seen_sequences) == UDP_BURST_COUNT:
                        quiet_deadline = time.perf_counter() + 0.02

    try:
        recv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        send.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        recv.bind((HOST_IP, recv_port))
        send.bind((HOST_IP, src_port))

        receiver = threading.Thread(target=receive_worker, name="sim-udp-burst-rx", daemon=True)
        receiver.start()
        if not receiver_ready.wait(1.0):
            stop_receiver.set()
            receiver.join(0.1)
            return CheckResult("udp.burst", False, "receiver thread did not start")

        sent = 0
        send_errors = []
        for sequence, payload in enumerate(payloads):
            try:
                send.sendto(payload, (DUT_IP, DUT_PORT))
                sent += 1
            except OSError as e:
                send_errors.append(f"seq={sequence}: {e}")

        receive_deadline[0] = time.perf_counter() + UDP_BURST_TIMEOUT_S
        send_done.set()
        receiver.join(UDP_BURST_TIMEOUT_S + 0.5)
        if receiver.is_alive():
            stop_receiver.set()
            receiver.join(0.1)
    finally:
        stop_receiver.set()
        recv.close()
        send.close()

    matched = set()
    duplicates = 0
    unexpected = 0
    mismatched = 0
    out_of_order = 0
    highest_sequence = -1

    for data, addr in packets:
        if addr[0] != DUT_IP or addr[1] != DUT_PORT:
            unexpected += 1
            continue
        if len(data) < BURST_HEADER_SIZE or not data.startswith(BURST_MAGIC):
            unexpected += 1
            continue

        sequence = int.from_bytes(data[len(BURST_MAGIC) : len(BURST_MAGIC) + 4], "big")
        if sequence >= UDP_BURST_COUNT:
            unexpected += 1
            continue
        if sequence in matched:
            duplicates += 1
            continue
        if data != payloads[sequence]:
            mismatched += 1
            continue

        if sequence < highest_sequence:
            out_of_order += 1
        highest_sequence = max(highest_sequence, sequence)
        matched.add(sequence)

    missing_sequences = [sequence for sequence in range(UDP_BURST_COUNT) if sequence not in matched]
    ok = (
        sent == UDP_BURST_COUNT
        and len(matched) == UDP_BURST_COUNT
        and duplicates == 0
        and unexpected == 0
        and mismatched == 0
        and out_of_order == 0
        and not receiver_errors
        and not send_errors
    )
    details = (
        f"sent={sent} received={len(packets)} matched={len(matched)} "
        f"missing={len(missing_sequences)} duplicates={duplicates} "
        f"unexpected={unexpected} mismatched={mismatched} out_of_order={out_of_order}"
    )
    if missing_sequences:
        details += f" missing_samples={missing_sequences[:8]}"
    if receiver_errors:
        details += f" receiver_error={receiver_errors[0]}"
    if send_errors:
        details += f" send_error={send_errors[0]}"
    return CheckResult("udp.burst", ok, details)


def udp_stress_check() -> CheckResult:
    recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    src_port = BASE_SRC_PORT + 900
    recv_port = src_port + 1
    try:
        recv.bind((HOST_IP, recv_port))
        send.bind((HOST_IP, src_port))

        expected = {f"stress-{i:04d}".encode() for i in range(UDP_STRESS_COUNT)}
        got = set()
        unexpected = []

        # Interleave tx/rx with short recv timeout to keep throughput high.
        recv.settimeout(0.02)
        for i in range(UDP_STRESS_COUNT):
            msg = f"stress-{i:04d}".encode()
            send.sendto(msg, (DUT_IP, DUT_PORT))

            for _ in range(2):
                try:
                    data, _ = recv.recvfrom(2048)
                    if data in expected:
                        got.add(data)
                    elif len(unexpected) < 3:
                        unexpected.append(data.hex())
                except socket.timeout:
                    break

            time.sleep(0.001)

        # Drain remaining echoes with a longer timeout.
        recv.settimeout(0.5)
        deadline = time.time() + max(3.0, UDP_STRESS_COUNT * 0.01)
        while time.time() < deadline and len(got) < len(expected):
            try:
                data, _ = recv.recvfrom(2048)
                if data in expected:
                    got.add(data)
                elif len(unexpected) < 3:
                    unexpected.append(data.hex())
            except socket.timeout:
                continue

        if got != expected:
            missing = len(expected) - len(got)
            detail = f"received {len(got)}/{len(expected)} missing={missing}"
            if unexpected:
                detail += f" unexpected_samples={unexpected}"
            return CheckResult("udp.stress", False, detail)
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

    ext_tests = []
    raw_available = raw_packet_access_available()
    if raw_available:
        ext_tests.append(icmp_echo_wire_check)
    else:
        print("[skip] icmp.wire and udp.wire: raw packet access is unavailable")

    ext_tests.append(udp_matrix_check)
    if raw_available:
        ext_tests.append(udp_wire_header_check)
    ext_tests.extend(
        [
            udp_negative_wrong_port,
            udp_burst_check,
            udp_stress_check,
        ]
    )

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


def run_burst_only() -> int:
    checks = [arp_resolve_check, udp_basic_check, udp_burst_check]
    results = []
    for test in checks:
        t0 = time.time()
        try:
            result = test()
        except Exception as e:
            result = CheckResult(test.__name__, False, f"exception: {e}")
        dt_ms = int((time.time() - t0) * 1000)
        status = "ok" if result.ok else "fail"
        print(f"[{status}] {result.name} ({dt_ms} ms): {result.details}")
        results.append(result)
        if not result.ok and test is not udp_burst_check:
            break
    return 1 if any(not result.ok for result in results) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Unprivileged client for the persistent UDP simulator")
    parser.add_argument("--burst-only", action="store_true", help="run ARP/UDP preflight and the burst check only")
    args = parser.parse_args()

    if not wait_simulator_ready(timeout_s=10.0):
        print(f"[error] simulator on TAP {TAP_NAME!r} is not ready with the current Vsim_top build")
        print("[hint] start or restart the supervisor with: sudo python3 sim_server.py")
        return 3

    print(f"[step] using persistent TAP {TAP_NAME}, host ip {HOST_IP}, dut ip {DUT_IP}")
    if args.burst_only:
        return run_burst_only()

    core_results, ext_results = run_suite()
    core_failed = [r for r in core_results if not r.ok]
    ext_failed = [r for r in ext_results if not r.ok]

    if core_failed:
        print("[fail] core regression has failing checks:")
        for result in core_failed:
            print(f"  - {result.name}: {result.details}")
        return 1

    if ext_failed and STRICT_MODE:
        print("[fail] strict mode enabled; extended checks failed:")
        for result in ext_failed:
            print(f"  - {result.name}: {result.details}")
        return 1

    if ext_failed:
        print("[pass] core regression passed; extended diagnostics found issues:")
        for result in ext_failed:
            print(f"  - {result.name}: {result.details}")
        print("[hint] set SIM_STRICT=1 to gate on extended diagnostics")
        return 0

    print("[pass] available unprivileged ARP/ICMP/UDP regression passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
