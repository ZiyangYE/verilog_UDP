#!/usr/bin/env python3
import argparse
import platform
import random
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass


@dataclass
class CaseResult:
    ok: bool
    reason: str
    tx_len: int
    rx_len: int
    src_port: int
    recv_port: int
    latency_ms: float
    skipped: bool = False


def parse_sizes(text: str) -> list[int]:
    values = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        size = int(token)
        if size < 0:
            raise ValueError(f"size must be >= 0, got {size}")
        values.append(size)
    if not values:
        raise ValueError("size list cannot be empty")
    return values


def payload_with_len(rng: random.Random, size: int) -> bytes:
    # Prefix pattern helps fast visual comparison in packet captures.
    if size == 0:
        return b""
    head = b"UDPTEST"
    raw = bytes(rng.getrandbits(8) for _ in range(size))
    data = (head + raw)[:size]
    if len(data) < size:
        data += bytes(rng.getrandbits(8) for _ in range(size - len(data)))
    return data


def rotate_port(port: int, min_port: int, max_port: int) -> int:
    width = max_port - min_port + 1
    # Keep src/recv adjacent and odd/even relationship stable.
    nxt = port + 2
    while nxt > max_port - 1:
        nxt -= width
    if nxt < min_port:
        nxt = min_port
    return nxt


def discover_usable_ports(host_ip: str, min_port: int, max_port: int, limit: int) -> list[int]:
    usable = []
    for port in range(min_port, max_port, 2):
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            recv_sock.bind((host_ip, port + 1))
            send_sock.bind((host_ip, port))
            usable.append(port)
            if len(usable) >= limit:
                break
        except OSError:
            pass
        finally:
            recv_sock.close()
            send_sock.close()
    return usable


def icmp_check(dut_ip: str, host_ip: str, ping_size: int, timeout_ms: int) -> tuple[bool, str]:
    sys_name = platform.system().lower()
    if "windows" in sys_name:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), "-l", str(ping_size), dut_ip]
    else:
        # -I source address is useful for multi-NIC Linux hosts.
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), "-s", str(ping_size), "-I", host_ip, dut_ip]

    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode == 0:
        return True, "icmp ok"
    details = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    return False, details.strip() or "icmp failed"


def arp_check(dut_ip: str, host_ip: str, dut_port: int) -> tuple[bool, str]:
    # Trigger ARP resolution with a tiny UDP probe.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((host_ip, 22345))
        s.sendto(b"arp-probe", (dut_ip, dut_port))
    except OSError:
        # If bind is unavailable, still continue to ARP table check.
        pass
    finally:
        s.close()

    sys_name = platform.system().lower()
    if "windows" in sys_name:
        cmd = ["arp", "-a"]
    else:
        cmd = ["ip", "neigh", "show", "to", dut_ip]

    for _ in range(20):
        p = subprocess.run(cmd, text=True, capture_output=True)
        out = (p.stdout or "").lower()
        if dut_ip in out and ("incomplete" not in out and "failed" not in out):
            return True, "arp resolved"
        time.sleep(0.1)

    return False, "arp unresolved"


def run_one_case(
    host_ip: str,
    dut_ip: str,
    dut_port: int,
    src_port: int,
    payload: bytes,
    timeout_s: float,
    retries: int,
    expect_dut_src_port: int,
    min_port: int,
    max_port: int,
    bind_hop_limit: int,
) -> CaseResult:
    cur_port = src_port
    for _ in range(retries):
        bind_ok = False
        bind_err = "bind failed"
        recv_port = cur_port + 1
        recv_sock = None
        send_sock = None
        try:
            # Some Windows environments reserve large port ranges; hop ports automatically.
            for _ in range(bind_hop_limit):
                recv_port = cur_port + 1
                recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                recv_sock.settimeout(timeout_s)
                try:
                    recv_sock.bind((host_ip, recv_port))
                    send_sock.bind((host_ip, cur_port))
                    bind_ok = True
                    break
                except OSError as e:
                    bind_err = str(e)
                    recv_sock.close()
                    send_sock.close()
                    recv_sock = None
                    send_sock = None
                    cur_port = rotate_port(cur_port, min_port, max_port)

            if not bind_ok:
                return CaseResult(False, f"bind-unavailable: {bind_err}", len(payload), 0, cur_port, recv_port, -1.0, True)

            t0 = time.perf_counter()
            send_sock.sendto(payload, (dut_ip, dut_port))

            try:
                data, addr = recv_sock.recvfrom(max(2048, len(payload) + 64))
            except socket.timeout:
                continue

            latency_ms = (time.perf_counter() - t0) * 1000.0

            if addr[0] != dut_ip:
                return CaseResult(
                    False,
                    f"unexpected source ip {addr[0]}",
                    len(payload),
                    len(data),
                    cur_port,
                    recv_port,
                    latency_ms,
                )

            if expect_dut_src_port >= 0 and addr[1] != expect_dut_src_port:
                return CaseResult(
                    False,
                    f"unexpected source port {addr[1]} (expect {expect_dut_src_port})",
                    len(payload),
                    len(data),
                    cur_port,
                    recv_port,
                    latency_ms,
                )

            if data != payload:
                return CaseResult(
                    False,
                    "payload mismatch",
                    len(payload),
                    len(data),
                    cur_port,
                    recv_port,
                    latency_ms,
                )

            return CaseResult(
                True,
                "ok",
                len(payload),
                len(data),
                cur_port,
                recv_port,
                latency_ms,
            )
        finally:
            if recv_sock is not None:
                recv_sock.close()
            if send_sock is not None:
                send_sock.close()

    return CaseResult(False, "timeout", len(payload), 0, cur_port, recv_port, -1.0)


def print_summary(total: int, fails: list[CaseResult], latencies: list[float], elapsed_s: float, skipped: int):
    passed = total - len(fails)
    print("\n=== Summary ===")
    print(f"total={total}, passed={passed}, failed={len(fails)}, skipped={skipped}, elapsed={elapsed_s:.2f}s")
    if latencies:
        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=100)[94] if len(latencies) >= 20 else max(latencies)
        print(
            "latency_ms: "
            f"min={min(latencies):.3f}, p50={p50:.3f}, p95={p95:.3f}, max={max(latencies):.3f}, avg={statistics.mean(latencies):.3f}"
        )
    if fails:
        print("\nTop failed samples:")
        for i, case in enumerate(fails[:8], start=1):
            print(
                f"[{i}] reason={case.reason}, tx_len={case.tx_len}, rx_len={case.rx_len}, "
                f"src_port={case.src_port}, recv_port={case.recv_port}, latency_ms={case.latency_ms:.3f}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Comprehensive UDP board test")
    parser.add_argument("--dut-ip", default="192.168.15.14")
    parser.add_argument("--host-ip", default="192.168.15.15")
    parser.add_argument("--dut-port", type=int, default=11451)
    parser.add_argument("--expect-dut-src-port", type=int, default=-1, help="-1 means do not check")

    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--matrix-sizes", default="0,1,2,4,8,16,32,64,128,256,512,1024,1400")
    parser.add_argument("--random-count", type=int, default=1000)
    parser.add_argument("--max-random-size", type=int, default=1400)
    parser.add_argument("--min-port", type=int, default=5500)
    parser.add_argument("--max-port", type=int, default=60000)

    parser.add_argument("--timeout-ms", type=int, default=800)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--interval-ms", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=20260319)
    parser.add_argument("--ping-size", type=int, default=32)
    parser.add_argument("--with-icmp", action="store_true", default=True)
    parser.add_argument("--without-icmp", action="store_true")
    parser.add_argument("--with-arp", action="store_true", default=True)
    parser.add_argument("--without-arp", action="store_true")
    parser.add_argument("--bind-hop-limit", type=int, default=256)
    parser.add_argument("--port-pool-size", type=int, default=4096)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    timeout_s = args.timeout_ms / 1000.0
    interval_s = args.interval_ms / 1000.0
    matrix = parse_sizes(args.matrix_sizes)

    if args.min_port < 1024 or args.max_port > 65534 or args.min_port >= args.max_port:
        print("invalid port range")
        return 2

    print("=== UDP Comprehensive Test ===")
    print(
        f"dut={args.dut_ip}:{args.dut_port}, host={args.host_ip}, "
        f"warmup={args.warmup}, matrix={len(matrix)}, random={args.random_count}, seed={args.seed}"
    )

    if args.without_icmp:
        args.with_icmp = False
    if args.without_arp:
        args.with_arp = False

    total = 0
    fails: list[CaseResult] = []
    latencies: list[float] = []
    skipped = 0
    t_all = time.perf_counter()

    usable_ports = discover_usable_ports(args.host_ip, args.min_port, args.max_port, args.port_pool_size)
    if not usable_ports:
        print("no usable UDP port pairs found in the selected range")
        return 2
    print(f"usable_port_pairs={len(usable_ports)}")

    if args.with_arp:
        total += 1
        ok, detail = arp_check(args.dut_ip, args.host_ip, args.dut_port)
        if not ok:
            fails.append(CaseResult(False, f"arp: {detail}", 0, 0, 0, 0, -1.0))
            print(f"[fail] arp: {detail}")
        else:
            print("[ok] arp")

    if args.with_icmp:
        total += 1
        ok, detail = icmp_check(args.dut_ip, args.host_ip, args.ping_size, args.timeout_ms)
        if not ok:
            fails.append(CaseResult(False, f"icmp: {detail}", 0, 0, 0, 0, -1.0))
            print(f"[fail] icmp: {detail}")
        else:
            print("[ok] icmp")

    # Warmup stabilizes ARP and transient socket/timing states.
    warmup_port = max(args.min_port, 20023)
    for _ in range(args.warmup):
        warmup_port = usable_ports[_ % len(usable_ports)]
        payload = payload_with_len(rng, 32)
        case = run_one_case(
            args.host_ip,
            args.dut_ip,
            args.dut_port,
            warmup_port,
            payload,
            timeout_s,
            args.retries,
            args.expect_dut_src_port,
            args.min_port,
            args.max_port,
            args.bind_hop_limit,
        )
        total += 1
        if case.skipped:
            skipped += 1
        elif not case.ok:
            fails.append(case)
        else:
            latencies.append(case.latency_ms)
        time.sleep(interval_s)

    # Matrix tests fixed payload sizes for boundary coverage.
    for i, size in enumerate(matrix):
        src_port = usable_ports[i % len(usable_ports)]
        payload = payload_with_len(rng, size)
        case = run_one_case(
            args.host_ip,
            args.dut_ip,
            args.dut_port,
            src_port,
            payload,
            timeout_s,
            args.retries,
            args.expect_dut_src_port,
            args.min_port,
            args.max_port,
            args.bind_hop_limit,
        )
        total += 1
        if case.skipped:
            skipped += 1
        elif not case.ok:
            fails.append(case)
        else:
            latencies.append(case.latency_ms)
        time.sleep(interval_s)

    # Random soak tests random ports and random payload lengths.
    for i in range(args.random_count):
        src_port = usable_ports[rng.randint(0, len(usable_ports) - 1)]
        size = rng.randint(0, args.max_random_size)
        payload = payload_with_len(rng, size)
        case = run_one_case(
            args.host_ip,
            args.dut_ip,
            args.dut_port,
            src_port,
            payload,
            timeout_s,
            args.retries,
            args.expect_dut_src_port,
            args.min_port,
            args.max_port,
            args.bind_hop_limit,
        )
        total += 1
        if case.skipped:
            skipped += 1
        elif not case.ok:
            fails.append(case)
            print(
                f"[fail] i={i}, reason={case.reason}, tx_len={case.tx_len}, "
                f"src_port={case.src_port}, recv_port={case.recv_port}"
            )
            # Continue collecting failures for richer diagnostics.
        else:
            latencies.append(case.latency_ms)

        if (i + 1) % 200 == 0:
            print(f"[progress] random_cases={i + 1}/{args.random_count}, fails={len(fails)}")
        time.sleep(interval_s)

    elapsed_s = time.perf_counter() - t_all
    print_summary(total, fails, latencies, elapsed_s, skipped)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())