// sim_main.cpp
// Verilator testbench: bridges a Linux TAP device to the simulated RMII MAC.
//
// Usage (must run as root or with CAP_NET_ADMIN):
//   sudo ./sim_main [tap_name]          e.g.  sudo ./sim_main udptap
//
// The testbench:
//   - Creates (or reuses) a TAP interface named "udptap" (or argv[1])
//   - Drives rmii_clk50m / rmii_rxd / rmii_rx_crs from TAP → DUT
//   - Collects rmii_txd / rmii_txen from DUT → TAP
//   - Relies on force() in sim_top.sv to bypass PHY init in simulation
//
// Ethernet framing on RMII:
//   TX (DUT→TAP): detect txen, collect dibit stream, reassemble bytes,
//                 strip preamble+SFD+CRC, write to TAP.
//   RX (TAP→DUT): read TAP frame, prepend preamble+SFD, inject via
//                 crs+rxd dibits, append CRC.

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fcntl.h>
// Use only linux/if.h; include linux/if_tun.h after it.
// Do NOT include net/if.h — it conflicts with linux/if.h on modern kernels.
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include "Vsim_top.h"
#include "verilated.h"

// ─────────────────────────── TAP helpers ────────────────────────────────────

static int tap_fd = -1;

static int tap_open(const char *name)
{
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF"); close(fd); return -1;
    }
    printf("[tap] interface '%s' opened (fd=%d)\n", ifr.ifr_name, fd);
    return fd;
}

// Bring the TAP interface up and assign an IP address via netlink/ip commands.
// We call out to 'ip' since we don't want to link libmnl.
static void tap_ifup(const char *name, const char *ip_cidr)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s up", name);
    if (system(cmd) != 0)
        fprintf(stderr, "[warn] '%s' failed\n", cmd);
    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s 2>/dev/null || true", ip_cidr, name);
    system(cmd);
    printf("[tap] %s up with %s\n", name, ip_cidr);
}

// ─────────────────────────── CRC-32 (Ethernet) ──────────────────────────────

static uint32_t crc32_table[256];

static void crc32_init()
{
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
}

static uint32_t crc32_byte(uint32_t crc, uint8_t b)
{
    return crc32_table[(crc ^ b) & 0xFF] ^ (crc >> 8);
}

static uint32_t crc32_buf(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
        crc = crc32_byte(crc, buf[i]);
    return ~crc;
}

// ─────────────────────────── RMII TX collector ──────────────────────────────
// Monitors txen/txd from DUT.  When txen goes low after a frame,
// strips preamble+SFD+CRC and writes the payload to the TAP fd.

struct RmiiRxCollector {
    bool        active  = false;
    std::vector<uint8_t> raw;   // raw dibits reassembled to bytes
    uint8_t     cur_byte = 0;
    int         bit_pos  = 0;

    void feed(uint8_t txen, uint8_t txd)
    {
        if (!active) {
            if (txen) { active = true; raw.clear(); bit_pos = 0; }
            else return;
        }
        if (!txen) {
            // end of frame
            flush_frame();
            active = false;
            return;
        }
        cur_byte |= (txd & 3) << bit_pos;
        bit_pos += 2;
        if (bit_pos == 8) {
            raw.push_back(cur_byte);
            cur_byte = 0;
            bit_pos  = 0;
        }
    }

    void flush_frame()
    {
        // Find SFD (0xD5) after preamble bytes (0x55)
        size_t sfd_pos = SIZE_MAX;
        for (size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == 0xD5) { sfd_pos = i; break; }
        }
        if (sfd_pos == SIZE_MAX) {
            fprintf(stderr, "[tx_col] no SFD found (%zu bytes), dropping\n", raw.size());
            return;
        }
        size_t payload_start = sfd_pos + 1;
        if (raw.size() < payload_start + 4) {
            fprintf(stderr, "[tx_col] frame too short after SFD\n");
            return;
        }
        size_t payload_len = raw.size() - payload_start - 4; // strip CRC
        const uint8_t *payload = raw.data() + payload_start;

        // Verify CRC
        uint32_t calc = crc32_buf(payload, payload_len);
        uint32_t frame_crc =
            (uint32_t)raw[raw.size()-4]       |
            (uint32_t)raw[raw.size()-3] << 8  |
            (uint32_t)raw[raw.size()-2] << 16 |
            (uint32_t)raw[raw.size()-1] << 24;
        if (calc != frame_crc)
            fprintf(stderr, "[tx_col] CRC mismatch: calc=%08X frame=%08X\n", calc, frame_crc);

        // Write to TAP
        ssize_t wr = write(tap_fd, payload, payload_len);
        if (wr < 0) perror("[tx_col] write TAP");
        else printf("[tx_col] wrote %zd bytes to TAP\n", wr);
    }
};

// ─────────────────────────── RMII RX injector ───────────────────────────────
// Converts a TAP frame into a stream of (crs,rxd) dibit pairs to feed the DUT.
// The frame is preceded by 7 preamble bytes (0x55) + SFD (0xD5) and followed
// by a CRC32.  One byte = 4 half-clock toggles of the 50 MHz clock → at sim
// speed we simply present one dibit per rising edge of rmii_clk50m.

struct RmiiTxInjector {
    std::deque<uint8_t> bit_stream; // one entry = one dibit (2 bits)
    bool crs = false;

    void queue_frame(const uint8_t *buf, size_t len)
    {
        std::vector<uint8_t> frame;

        // preamble (7 bytes 0x55) + SFD (0xD5)
        for (int i = 0; i < 7; ++i) frame.push_back(0x55);
        frame.push_back(0xD5);

        // payload
        for (size_t i = 0; i < len; ++i) frame.push_back(buf[i]);

        // CRC
        uint32_t crc = crc32_buf(buf, len);
        frame.push_back(crc & 0xFF);
        frame.push_back((crc >> 8)  & 0xFF);
        frame.push_back((crc >> 16) & 0xFF);
        frame.push_back((crc >> 24) & 0xFF);

        // convert to dibits (LSB first)
        for (uint8_t byte : frame) {
            bit_stream.push_back((byte >> 0) & 3);
            bit_stream.push_back((byte >> 2) & 3);
            bit_stream.push_back((byte >> 4) & 3);
            bit_stream.push_back((byte >> 6) & 3);
        }

        // guard: a few idle dibits after frame so crs can drop
        for (int i = 0; i < 8; ++i) bit_stream.push_back(0xFE); // sentinel = end

        printf("[rx_inj] queued %zu bytes (%zu dibits)\n", len, bit_stream.size());
    }

    // Call once per rising rmii_clk50m edge.
    // Updates crs and rxd in-place.
    void tick(uint8_t &o_crs, uint8_t &o_rxd)
    {
        if (bit_stream.empty()) {
            o_crs = 0; o_rxd = 0;
            crs   = false;
            return;
        }
        uint8_t d = bit_stream.front();
        if (d == 0xFE) {
            // end sentinel
            bit_stream.pop_front();
            o_crs = 0; o_rxd = 0;
            crs   = false;
            return;
        }
        bit_stream.pop_front();
        o_crs = 1;
        o_rxd = d & 3;
        crs   = true;
    }
};

// ─────────────────────────── main ───────────────────────────────────────────

int main(int argc, char **argv)
{
    crc32_init();

    const char *tap_name   = (argc > 1) ? argv[1] : "udptap";
    // Host side: 192.168.15.1/24  DUT: 192.168.15.14
    const char *host_ip    = "192.168.15.1/24";

    tap_fd = tap_open(tap_name);
    if (tap_fd < 0) return 1;
    tap_ifup(tap_name, host_ip);

    VerilatedContext *ctx = new VerilatedContext;
    ctx->commandArgs(argc, argv);
    Vsim_top *dut = new Vsim_top(ctx);

    RmiiRxCollector rx_col;
    RmiiTxInjector  tx_inj;

    // Reset sequence
    dut->clk         = 0;
    dut->rst         = 0;
    dut->rmii_clk50m = 0;
    dut->rmii_rx_crs = 0;
    dut->rmii_rxd    = 0;
    dut->eval();

    auto half_clk = [&]() {
        dut->clk = !dut->clk;
        dut->eval();
        ctx->timeInc(1);
    };

    // Hold reset for 20 cycles
    for (int i = 0; i < 40; ++i) half_clk();
    dut->rst = 1;

    // ─── main simulation loop ────────────────────────────────────────────────
    // We run 50 MHz RMII clock in lock-step with the 27 MHz "board" clock.
    // For simulation purposes we just toggle both every half-step.
    // Ratio doesn't need to be exact — functional correctness only needs
    // the 50 MHz domain to have a separate signal.

    uint64_t cycle = 0;
    // RMII clock period: we toggle rmii_clk50m every iteration
    // Board clock is 27 MHz; we toggle it every 2 iterations (slower).

    bool rmii_phase = false; // track rmii half-cycle

    while (!ctx->gotFinish()) {
        // ── Toggle RMII clock ────────────────────────────────────────────
        dut->rmii_clk50m = !dut->rmii_clk50m;
        rmii_phase = dut->rmii_clk50m;

        // ── Board clock: every 2 rmii half-cycles ────────────────────────
        if (cycle % 2 == 0) dut->clk = !dut->clk;

        // ── On rising edge of RMII clock: inject RX dibits ───────────────
        if (rmii_phase) {
            uint8_t o_crs = 0, o_rxd = 0;
            tx_inj.tick(o_crs, o_rxd);
            dut->rmii_rx_crs = o_crs;
            dut->rmii_rxd    = o_rxd;
        }

        dut->eval();
        ctx->timeInc(1);

        // ── On rising edge: collect TX dibits ────────────────────────────
        if (rmii_phase) {
            rx_col.feed(dut->rmii_txen, dut->rmii_txd);
        }

        ++cycle;

        // ── Poll TAP for incoming frames (every 200 cycles) ──────────────
        if (cycle % 200 == 0 && tx_inj.bit_stream.empty()) {
            uint8_t buf[2048];
            struct timeval tv{0, 0};
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(tap_fd, &rfds);
            int sel = select(tap_fd + 1, &rfds, nullptr, nullptr, &tv);
            if (sel > 0) {
                ssize_t n = read(tap_fd, buf, sizeof(buf));
                if (n > 0) {
                    printf("[main] TAP→DUT %zd bytes\n", n);
                    tx_inj.queue_frame(buf, (size_t)n);
                }
            }
        }

        // ── Stop after 10 billion half-cycles (~100 seconds sim time) ────
        if (cycle > 10000000000ULL) break;
    }

    dut->final();
    printf("[main] simulation ended at cycle %llu\n", (unsigned long long)cycle);

    delete dut;
    delete ctx;
    close(tap_fd);
    return 0;
}
