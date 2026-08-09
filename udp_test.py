#!/usr/bin/env python3
import argparse
import platform
import random
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass


BURST_MAGIC = b"UDPBURST"
BURST_HEADER_SIZE = len(BURST_MAGIC) + 6


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


@dataclass
class BurstResult:
    cases: list[CaseResult]
    extra_failures: list[CaseResult]
    sent: int
    received: int
    matched: int
    duplicates: int
    unexpected: int
    out_of_order: int
    elapsed_ms: float
    src_port: int
    recv_port: int


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


def burst_payload(rng: random.Random, sequence: int, size: int) -> bytes:
    header = BURST_MAGIC + sequence.to_bytes(4, "big") + size.to_bytes(2, "big")
    return header + bytes(rng.getrandbits(8) for _ in range(size - len(header)))


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


def run_burst_case(
    host_ip: str,
    dut_ip: str,
    dut_port: int,
    src_port: int,
    payloads: list[bytes],
    timeout_s: float,
    expect_dut_src_port: int,
    min_port: int,
    max_port: int,
    bind_hop_limit: int,
) -> BurstResult:
    cur_port = src_port
    recv_port = cur_port + 1
    recv_sock = None
    send_sock = None
    bind_err = "bind failed"

    for _ in range(bind_hop_limit):
        recv_port = cur_port + 1
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            recv_sock.bind((host_ip, recv_port))
            send_sock.bind((host_ip, cur_port))
            break
        except OSError as e:
            bind_err = str(e)
            recv_sock.close()
            send_sock.close()
            recv_sock = None
            send_sock = None
            cur_port = rotate_port(cur_port, min_port, max_port)

    if recv_sock is None or send_sock is None:
        skipped_case = CaseResult(
            False,
            f"burst bind-unavailable: {bind_err}",
            0,
            0,
            cur_port,
            recv_port,
            -1.0,
            True,
        )
        return BurstResult([skipped_case], [], 0, 0, 0, 0, 0, 0, 0.0, cur_port, recv_port)

    received_packets: list[tuple[bytes, tuple[str, int], float]] = []
    receiver_errors: list[str] = []
    receiver_ready = threading.Event()
    send_done = threading.Event()
    stop_receiver = threading.Event()
    receive_deadline = [float("inf")]
    expected_count = len(payloads)

    def receive_worker():
        seen_sequences: set[int] = set()
        quiet_deadline = float("inf")
        recv_sock.settimeout(0.02)
        receiver_ready.set()

        while not stop_receiver.is_set():
            now = time.perf_counter()
            if send_done.is_set():
                if len(seen_sequences) == expected_count and quiet_deadline == float("inf"):
                    quiet_deadline = now + 0.02
                if now >= receive_deadline[0] or now >= quiet_deadline:
                    break

            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if not stop_receiver.is_set():
                    receiver_errors.append(str(e))
                break

            received_at = time.perf_counter()
            received_packets.append((data, addr, received_at))

            if len(data) >= BURST_HEADER_SIZE and data.startswith(BURST_MAGIC):
                sequence = int.from_bytes(data[len(BURST_MAGIC) : len(BURST_MAGIC) + 4], "big")
                if 0 <= sequence < expected_count:
                    seen_sequences.add(sequence)

            if send_done.is_set() and len(seen_sequences) == expected_count:
                # Keep receiving briefly so duplicate replies are also detected.
                quiet_deadline = received_at + 0.02

    receiver_thread = threading.Thread(target=receive_worker, name="udp-burst-receiver", daemon=True)
    send_times = [-1.0] * expected_count
    send_errors: dict[int, str] = {}
    t0 = time.perf_counter()

    try:
        receiver_thread.start()
        if not receiver_ready.wait(1.0):
            stop_receiver.set()
            receiver_thread.join(0.1)
            failure = CaseResult(False, "burst receiver did not start", 0, 0, cur_port, recv_port, -1.0)
            return BurstResult([failure], [], 0, 0, 0, 0, 0, 0, 0.0, cur_port, recv_port)

        sent = 0
        for sequence, payload in enumerate(payloads):
            send_times[sequence] = time.perf_counter()
            try:
                send_sock.sendto(payload, (dut_ip, dut_port))
                sent += 1
            except OSError as e:
                send_errors[sequence] = str(e)

        receive_deadline[0] = time.perf_counter() + timeout_s
        send_done.set()
        receiver_thread.join(timeout_s + 0.5)
        if receiver_thread.is_alive():
            stop_receiver.set()
            receiver_thread.join(0.1)
    finally:
        stop_receiver.set()
        recv_sock.close()
        send_sock.close()

    cases_by_sequence: dict[int, CaseResult] = {}
    extra_failures: list[CaseResult] = []
    duplicates = 0
    unexpected = 0
    out_of_order = 0
    highest_sequence = -1

    for data, addr, received_at in received_packets:
        if addr[0] != dut_ip:
            unexpected += 1
            extra_failures.append(
                CaseResult(False, f"burst unexpected source ip {addr[0]}", 0, len(data), cur_port, recv_port, -1.0)
            )
            continue

        if expect_dut_src_port >= 0 and addr[1] != expect_dut_src_port:
            unexpected += 1
            extra_failures.append(
                CaseResult(
                    False,
                    f"burst unexpected source port {addr[1]} (expect {expect_dut_src_port})",
                    0,
                    len(data),
                    cur_port,
                    recv_port,
                    -1.0,
                )
            )
            continue

        if len(data) < BURST_HEADER_SIZE or not data.startswith(BURST_MAGIC):
            unexpected += 1
            extra_failures.append(
                CaseResult(False, "burst malformed or unexpected payload", 0, len(data), cur_port, recv_port, -1.0)
            )
            continue

        sequence = int.from_bytes(data[len(BURST_MAGIC) : len(BURST_MAGIC) + 4], "big")
        declared_size = int.from_bytes(data[len(BURST_MAGIC) + 4 : BURST_HEADER_SIZE], "big")
        if sequence >= expected_count:
            unexpected += 1
            extra_failures.append(
                CaseResult(False, f"burst unexpected sequence {sequence}", 0, len(data), cur_port, recv_port, -1.0)
            )
            continue

        if sequence in cases_by_sequence:
            duplicates += 1
            extra_failures.append(
                CaseResult(
                    False,
                    f"burst duplicate sequence {sequence}",
                    len(payloads[sequence]),
                    len(data),
                    cur_port,
                    recv_port,
                    -1.0,
                )
            )
            continue

        if sequence < highest_sequence:
            out_of_order += 1
        highest_sequence = max(highest_sequence, sequence)

        latency_ms = (received_at - send_times[sequence]) * 1000.0
        if declared_size != len(data) or data != payloads[sequence]:
            cases_by_sequence[sequence] = CaseResult(
                False,
                f"burst payload mismatch sequence {sequence}",
                len(payloads[sequence]),
                len(data),
                cur_port,
                recv_port,
                latency_ms,
            )
        else:
            cases_by_sequence[sequence] = CaseResult(
                True,
                "ok",
                len(payloads[sequence]),
                len(data),
                cur_port,
                recv_port,
                latency_ms,
            )

    cases = []
    for sequence, payload in enumerate(payloads):
        if sequence in cases_by_sequence:
            cases.append(cases_by_sequence[sequence])
        elif sequence in send_errors:
            cases.append(
                CaseResult(
                    False,
                    f"burst send failed sequence {sequence}: {send_errors[sequence]}",
                    len(payload),
                    0,
                    cur_port,
                    recv_port,
                    -1.0,
                )
            )
        else:
            cases.append(
                CaseResult(
                    False,
                    f"burst timeout sequence {sequence}",
                    len(payload),
                    0,
                    cur_port,
                    recv_port,
                    -1.0,
                )
            )

    if receiver_errors:
        extra_failures.append(
            CaseResult(
                False,
                f"burst receiver error: {receiver_errors[0]}",
                0,
                0,
                cur_port,
                recv_port,
                -1.0,
            )
        )
    if out_of_order:
        extra_failures.append(
            CaseResult(
                False,
                f"burst out-of-order packets={out_of_order}",
                0,
                0,
                cur_port,
                recv_port,
                -1.0,
            )
        )

    matched = sum(case.ok for case in cases)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return BurstResult(
        cases,
        extra_failures,
        sent,
        len(received_packets),
        matched,
        duplicates,
        unexpected,
        out_of_order,
        elapsed_ms,
        cur_port,
        recv_port,
    )


def print_summary(total: int, fails: list[CaseResult], latencies: list[float], elapsed_s: float, skipped: int):
    passed = total - len(fails) - skipped
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
    parser.add_argument("--burst-count", type=int, default=100)
    parser.add_argument("--burst-timeout-ms", type=int, default=3000)
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
    if args.warmup < 0 or args.burst_count < 0 or args.random_count < 0:
        print("warmup, burst-count and random-count must be >= 0")
        return 2
    if args.max_random_size > 65507 or (
        (args.random_count > 0 and args.max_random_size < 0)
        or (args.burst_count > 0 and args.max_random_size < BURST_HEADER_SIZE)
    ):
        print(f"max-random-size must be {BURST_HEADER_SIZE}..65507 when burst is enabled")
        return 2
    if args.burst_timeout_ms <= 0:
        print("burst-timeout-ms must be > 0")
        return 2

    print("=== UDP Comprehensive Test ===")
    print(
        f"dut={args.dut_ip}:{args.dut_port}, host={args.host_ip}, "
        f"warmup={args.warmup}, matrix={len(matrix)}, burst={args.burst_count}, "
        f"random={args.random_count}, seed={args.seed}"
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

    print("\n=== Stage: preflight ===")
    if args.with_arp:
        total += 1
        ok, detail = arp_check(args.dut_ip, args.host_ip, args.dut_port)
        if not ok:
            fails.append(CaseResult(False, f"arp: {detail}", 0, 0, 0, 0, -1.0))
            print(f"[fail] arp: {detail}")
        else:
            print("[ok] arp")
    else:
        print("[skip] arp")

    if args.with_icmp:
        total += 1
        ok, detail = icmp_check(args.dut_ip, args.host_ip, args.ping_size, args.timeout_ms)
        if not ok:
            fails.append(CaseResult(False, f"icmp: {detail}", 0, 0, 0, 0, -1.0))
            print(f"[fail] icmp: {detail}")
        else:
            print("[ok] icmp")
    else:
        print("[skip] icmp")

    # Warmup stabilizes ARP and transient socket/timing states.
    print(f"\n=== Stage: warmup ({args.warmup} packets) ===")
    stage_fail_start = len(fails)
    stage_skip_start = skipped
    stage_start = time.perf_counter()
    for i in range(args.warmup):
        warmup_port = usable_ports[i % len(usable_ports)]
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
            print(f"[skip] warmup i={i}, reason={case.reason}")
        elif not case.ok:
            fails.append(case)
            print(f"[fail] warmup i={i}, reason={case.reason}")
        else:
            latencies.append(case.latency_ms)
        time.sleep(interval_s)
    stage_failed = len(fails) - stage_fail_start
    stage_skipped = skipped - stage_skip_start
    print(
        f"[done] warmup: passed={args.warmup - stage_failed - stage_skipped}, "
        f"failed={stage_failed}, skipped={stage_skipped}, elapsed={time.perf_counter() - stage_start:.2f}s"
    )

    # Matrix tests fixed payload sizes for boundary coverage.
    print(f"\n=== Stage: matrix ({len(matrix)} packets) ===")
    stage_fail_start = len(fails)
    stage_skip_start = skipped
    stage_start = time.perf_counter()
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
            print(f"[skip] matrix i={i}, len={size}, reason={case.reason}")
        elif not case.ok:
            fails.append(case)
            print(f"[fail] matrix i={i}, len={size}, reason={case.reason}")
        else:
            latencies.append(case.latency_ms)
            print(f"[ok] matrix i={i}, len={size}, latency_ms={case.latency_ms:.3f}")
        time.sleep(interval_s)
    stage_failed = len(fails) - stage_fail_start
    stage_skipped = skipped - stage_skip_start
    print(
        f"[done] matrix: passed={len(matrix) - stage_failed - stage_skipped}, "
        f"failed={stage_failed}, skipped={stage_skipped}, elapsed={time.perf_counter() - stage_start:.2f}s"
    )

    # Pre-generate the whole burst, start receiving, then send without an interval.
    print(f"\n=== Stage: burst ({args.burst_count} packets) ===")
    if args.burst_count:
        burst_rng = random.Random(args.seed ^ 0x42555253)
        burst_payloads = [
            burst_payload(
                burst_rng,
                sequence,
                burst_rng.randint(BURST_HEADER_SIZE, args.max_random_size),
            )
            for sequence in range(args.burst_count)
        ]
        burst_port = usable_ports[(args.warmup + len(matrix)) % len(usable_ports)]
        burst_result = run_burst_case(
            args.host_ip,
            args.dut_ip,
            args.dut_port,
            burst_port,
            burst_payloads,
            args.burst_timeout_ms / 1000.0,
            args.expect_dut_src_port,
            args.min_port,
            args.max_port,
            args.bind_hop_limit,
        )
        burst_cases = burst_result.cases + burst_result.extra_failures
        burst_failed_cases = []
        burst_skipped = 0
        for case in burst_cases:
            total += 1
            if case.skipped:
                skipped += 1
                burst_skipped += 1
            elif not case.ok:
                fails.append(case)
                burst_failed_cases.append(case)
            else:
                latencies.append(case.latency_ms)

        status = "ok" if not burst_failed_cases and not burst_skipped else "fail"
        missing = sum(case.reason.startswith("burst timeout") for case in burst_result.cases)
        print(
            f"[{status}] burst: sent={burst_result.sent}, received={burst_result.received}, "
            f"matched={burst_result.matched}, missing={missing}, failed={len(burst_failed_cases)}, "
            f"duplicates={burst_result.duplicates}, unexpected={burst_result.unexpected}, "
            f"out_of_order={burst_result.out_of_order}, elapsed={burst_result.elapsed_ms:.2f}ms"
        )
        for case in burst_failed_cases[:5]:
            print(f"[fail] {case.reason}, tx_len={case.tx_len}, rx_len={case.rx_len}")
        if burst_skipped:
            print(f"[skip] {burst_result.cases[0].reason}")
    else:
        print("[skip] burst disabled")

    # Random soak tests random ports and random payload lengths.
    print(f"\n=== Stage: random ({args.random_count} packets) ===")
    stage_fail_start = len(fails)
    stage_skip_start = skipped
    stage_start = time.perf_counter()
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
                f"[fail] random i={i}, reason={case.reason}, tx_len={case.tx_len}, "
                f"src_port={case.src_port}, recv_port={case.recv_port}"
            )
            # Continue collecting failures for richer diagnostics.
        else:
            latencies.append(case.latency_ms)

        if (i + 1) % 200 == 0:
            print(
                f"[progress] random_cases={i + 1}/{args.random_count}, "
                f"fails={len(fails) - stage_fail_start}"
            )
        time.sleep(interval_s)
    stage_failed = len(fails) - stage_fail_start
    stage_skipped = skipped - stage_skip_start
    print(
        f"[done] random: passed={args.random_count - stage_failed - stage_skipped}, "
        f"failed={stage_failed}, skipped={stage_skipped}, elapsed={time.perf_counter() - stage_start:.2f}s"
    )

    elapsed_s = time.perf_counter() - t_all
    print_summary(total, fails, latencies, elapsed_s, skipped)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
