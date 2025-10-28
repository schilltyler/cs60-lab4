#!/usr/bin/env python3
"""
key_exchange_fixed_v2.py -- Secret key generation by rapid RSSI exchange (robust version)

Usage:
  sudo python3 key_exchange_fixed_v2.py --iface wlan0 --n 300 --listen 2 --per-index-timeout 0.05

Changes vs your version:
 - Filters out self-sent packets (by MAC)
 - Deduplicates per-index prints to prevent multiple prints for the same index
 - Adds clear debug logs for initiator/responder activity
"""

import argparse
import json
import threading
import time
import hashlib
import statistics
from queue import Queue, Empty
from random import randint
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sniff, sendp, get_if_hwaddr
import re
import subprocess

# ---------- Constants ----------
IDX_ELT_ID = 221
IDX_LIST_ELT_ID = 222
COMMIT_ELT_ID = 223
ACK_ELT_ID = 224

SSID_READY_BEGIN = b"Ready to Begin"
SSID_READY_EXCHANGE = b"Ready to Exchange"

# ---------- Globals ----------
args = None
stop_event = threading.Event()
tx_queue = Queue()

observed_by_initiator = {}
observed_by_responder = {}

responder_flag = threading.Event()
initiator_ready = threading.Event()

received_index_lists = []
received_commits = set()

# ---------- Helpers ----------
def safe_get_iface_mac(iface: str) -> str:
    """Try multiple methods to obtain the interface's real MAC address, even in monitor mode."""
    # 1. Try Scapy's built-in function
    try:
        from scapy.arch import get_if_hwaddr
        mac = get_if_hwaddr(iface)
        if mac and re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac.lower()):
            return mac
    except Exception:
        pass

    # 2. Try reading from `ip link`
    try:
        result = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass

    # 3. Try `ifconfig`
    try:
        result = subprocess.run(["ifconfig", iface], capture_output=True, text=True)
        m = re.search(r"ether\s+([0-9a-f:]{17})", result.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass

    # 4. Final fallback: random locally-administered MAC
    rand_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(randint(0, 255) for _ in range(5))
    print(f"[warn] Could not get MAC for {iface}, using random {rand_mac}")
    return rand_mac

def build_beacon_frame(iface_mac, ssid_bytes, index=None, extra_elt=None):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=iface_mac, addr3=iface_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID=0, info=ssid_bytes)
    frame = RadioTap() / dot11 / beacon / essid
    if index is not None:
        frame = frame / Dot11Elt(ID=IDX_ELT_ID, info=str(index).encode())
    if extra_elt:
        eid, info = extra_elt
        frame = frame / Dot11Elt(ID=eid, info=info)
    return frame

def get_dot11elt_by_id(packet, eid):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if getattr(elt, "ID", None) == eid:
            return elt
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def get_ssid_from_packet(packet):
    elt = get_dot11elt_by_id(packet, 0)
    return elt.info if elt else None

def get_index_from_packet(packet):
    elt = get_dot11elt_by_id(packet, IDX_ELT_ID)
    if elt and elt.info:
        try:
            return int(elt.info.decode(errors="ignore"))
        except Exception:
            return None
    return None

def get_rssi(packet):
    if hasattr(packet, "dBm_AntSignal") and packet.dBm_AntSignal is not None:
        try:
            return int(packet.dBm_AntSignal)
        except Exception:
            pass
    try:
        rt = packet.getlayer(RadioTap)
        if rt:
            val = getattr(rt, "dBm_AntSignal", None)
            if val is not None:
                return int(val)
    except Exception:
        pass
    return None

# ---------- Filters ----------
def is_self_packet(packet, local_mac):
    """Return True if the frame was transmitted by us."""
    dot11 = packet.getlayer(Dot11)
    if not dot11:
        return False
    src = getattr(dot11, "addr2", "")
    return src.lower() == local_mac.lower()

# ---------- Handlers ----------
def negotiation_handler(packet):
    ssid = get_ssid_from_packet(packet)
    if not ssid:
        return
    if ssid == SSID_READY_BEGIN:
        if not responder_flag.is_set():
            responder_flag.set()
            iface_mac = safe_get_iface_mac(args.iface)
            ack = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE)
            tx_queue.put(ack)
            print("[role] Detected peer 'Ready to Begin'. Acting as responder.")
    elif ssid == SSID_READY_EXCHANGE:
        if not initiator_ready.is_set():
            initiator_ready.set()
            print("[role] Detected peer 'Ready to Exchange'. Acting as initiator.")

# track printed indices to avoid duplicates
printed_responder_indices = set()
printed_initiator_indices = set()

def responder_handler(packet):
    local_mac = safe_get_iface_mac(args.iface)
    if is_self_packet(packet, local_mac):
        return
    idx = get_index_from_packet(packet)
    if idx is None:
        return
    if idx in printed_responder_indices:
        return
    printed_responder_indices.add(idx)
    rssi = get_rssi(packet)
    observed_by_responder[idx] = rssi
    print(f"[responder] idx={idx}, rssi={rssi}")
    reply = build_beacon_frame(local_mac, SSID_READY_EXCHANGE, index=idx)
    tx_queue.put(reply)

def initiator_reply_handler(packet):
    local_mac = safe_get_iface_mac(args.iface)
    if is_self_packet(packet, local_mac):
        return
    ssid = get_ssid_from_packet(packet)
    if ssid != SSID_READY_EXCHANGE:
        return
    idx = get_index_from_packet(packet)
    if idx is None or idx in printed_initiator_indices:
        return
    printed_initiator_indices.add(idx)
    rssi = get_rssi(packet)
    observed_by_initiator[idx] = rssi
    print(f"[initiator] idx={idx}, rssi={rssi}")

# ---------- TX Worker ----------
def tx_worker():
    while not stop_event.is_set():
        try:
            frame = tx_queue.get(timeout=0.2)
        except Empty:
            continue
        try:
            sendp(frame, iface=args.iface, inter=0, verbose=False)
        except Exception as e:
            print(f"[tx_worker] sendp error: {e}")
        finally:
            tx_queue.task_done()

# ---------- Role negotiation ----------
def negotiate_role(listen_time=2.0):
    iface_mac = safe_get_iface_mac(args.iface)
    sniff_thread = threading.Thread(target=lambda: sniff(iface=args.iface, prn=negotiation_handler, store=False, timeout=listen_time), daemon=True)
    sniff_thread.start()
    time.sleep(listen_time)
    if not responder_flag.is_set():
        print("[role] No peer detected -> acting as initiator.")
        frame = build_beacon_frame(iface_mac, SSID_READY_BEGIN)
        start = time.time()
        while not initiator_ready.is_set() and time.time() - start < 10:
            tx_queue.put(frame)
            time.sleep(0.1)
        return "initiator"
    else:
        print("[role] Peer indicated Ready -> acting as responder.")
        return "responder"

# ---------- Exchange logic ----------
def run_responder(n_frames, per_index_timeout):
    print("[responder] Waiting for initiator frames...")
    sniff_thread = threading.Thread(target=lambda: sniff(iface=args.iface, prn=responder_handler, store=False,
                             timeout=n_frames * per_index_timeout + 20), daemon=True)
    sniff_thread.start()
    sniff_thread.join(timeout=n_frames * per_index_timeout + 25)
    print(f"[responder] Collected {len(observed_by_responder)} samples.")
    stop_event.set()

def run_initiator(n_frames, per_index_timeout):
    print("[initiator] Sending frames...")
    iface_mac = safe_get_iface_mac(args.iface)
    sniff_thread = threading.Thread(target=lambda: sniff(iface=args.iface, prn=initiator_reply_handler, store=False,
                             timeout=n_frames * per_index_timeout + 20), daemon=True)
    sniff_thread.start()
    time.sleep(1.5)
    for i in range(n_frames):
        if stop_event.is_set():
            break
        frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, index=i)
        tx_queue.put(frame)
        time.sleep(per_index_timeout)
        if i % 50 == 0 and i > 0:
            print(f"[initiator] Sent {i} frames...")
    time.sleep(2)
    stop_event.set()
    sniff_thread.join(timeout=2)
    print(f"[initiator] Collected {len(observed_by_initiator)} replies.")

# ---------- Key generation ----------
def generate_key(samples, z=0.6):
    vals = [v for v in samples.values() if v is not None]
    if not vals:
        return {}
    mean = statistics.mean(vals)
    std = statistics.pstdev(vals) if len(vals) > 1 else 1.0
    bits = {}
    for k, v in samples.items():
        if v is None:
            continue
        if v > mean + z * std:
            bits[k] = 1
        elif v < mean - z * std:
            bits[k] = 0
    return bits

# ---------- Main ----------
def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--n", type=int, default=300)
    parser.add_argument("--listen", type=float, default=2.0)
    parser.add_argument("--per-index-timeout", type=float, default=0.05)
    parser.add_argument("--z", type=float, default=0.6)
    args = parser.parse_args()

    try:
        subprocess.run(["bash", "monitor-mode.sh", args.iface, "2"], check=False)
    except Exception:
        pass

    tx_thread = threading.Thread(target=tx_worker, daemon=True)
    tx_thread.start()

    role = negotiate_role(args.listen)
    if role == "initiator":
        run_initiator(args.n, args.per_index_timeout)
        data = observed_by_initiator
    else:
        run_responder(args.n, args.per_index_timeout)
        data = observed_by_responder

    bits = generate_key(data, args.z)
    key_bits = "".join(str(bits[i]) for i in sorted(bits))
    key_hash = hashlib.sha256(key_bits.encode()).hexdigest()

    print(f"[post] Generated key length={len(bits)} bits")
    print(f"[post] SHA256={key_hash}")

    with open(f"{role}_samples.json", "w") as f:
        json.dump({str(k): v for k, v in data.items()}, f, indent=2)
    with open(f"{role}_key.json", "w") as f:
        json.dump({"bits": key_bits, "sha256": key_hash}, f, indent=2)
    print(f"[done] Saved samples and key for {role}")

    stop_event.set()
    tx_thread.join(timeout=1)

if __name__ == "__main__":
    main()
