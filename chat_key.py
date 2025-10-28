#!/usr/bin/env python3
"""
key_exchange.py -- Part 2: Secret key generation by rapid RSSI exchange (threaded role election).

Usage (example):
  sudo python3 key_exchange.py --iface wlan0 --n 300 --listen 2 --per-index-timeout 0.5

Notes:
 - Interface must be in monitor mode on the same channel on both devices.
 - Run the same program on both devices; they auto-elect roles.
 - The script writes:
    initiator_samples.json and responder_samples.json
"""

import argparse
import json
import threading
import time
from queue import Queue, Empty
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sniff, sendp, get_if_hwaddr

# ---------- Globals ----------
args = None
stop_event = threading.Event()
tx_queue = Queue()

# RSSI samples
observed_by_initiator = {}
observed_by_responder = {}

# Role and negotiation flags
role_lock = threading.Lock()
role = "unknown"
heard_ready_begin = threading.Event()
heard_ready_exchange = threading.Event()

# Constants
SSID_READY_BEGIN = b"Ready to Begin"
SSID_READY_EXCHANGE = b"Ready to Exchange"
IDX_ELT_ID = 221


# ---------- Helper functions ----------
def build_beacon_frame(iface_mac: str, ssid_bytes: bytes, index: int = None):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=iface_mac, addr3=iface_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID=0, info=ssid_bytes)
    frame = RadioTap() / dot11 / beacon / essid
    if index is not None:
        frame = frame / Dot11Elt(ID=IDX_ELT_ID, info=str(index).encode())
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
    if hasattr(packet, "dBm_AntSignal"):
        try:
            return int(packet.dBm_AntSignal)
        except Exception:
            return None
    return None


# ---------- Handlers ----------
def negotiation_handler(packet):
    if not packet.haslayer(Dot11Beacon):
        return
    ssid = get_ssid_from_packet(packet)
    if not ssid:
        return
    if ssid == SSID_READY_BEGIN:
        heard_ready_begin.set()
    elif ssid == SSID_READY_EXCHANGE:
        heard_ready_exchange.set()


def responder_handler(packet):
    if not packet.haslayer(Dot11Beacon):
        return
    idx = get_index_from_packet(packet)
    if idx is None:
        return
    rssi = get_rssi(packet)
    observed_by_responder[idx] = rssi

    try:
        iface_mac = get_if_hwaddr(args.iface)
    except Exception:
        iface_mac = "02:00:00:00:00:00"
    reply = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, index=idx)
    tx_queue.put(reply)


def initiator_reply_handler(packet):
    if not packet.haslayer(Dot11Beacon):
        return
    ssid = get_ssid_from_packet(packet)
    if ssid != SSID_READY_EXCHANGE:
        return
    idx = get_index_from_packet(packet)
    if idx is None:
        return
    rssi = get_rssi(packet)
    observed_by_initiator[idx] = rssi


# ---------- TX worker ----------
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


# ---------- Threaded Role Election ----------
def threaded_role_election(listen_time=2.0):
    """
    Both devices run this concurrently:
      - Each starts sending 'Ready to Begin'
      - Each also listens for peer's 'Ready to Begin'
      - The first to *hear* the other switches to responder
    """
    global role
    iface_mac = get_if_hwaddr(args.iface)

    def broadcaster():
        frame = build_beacon_frame(iface_mac, SSID_READY_BEGIN)
        while not heard_ready_begin.is_set() and not stop_event.is_set():
            tx_queue.put(frame)
            time.sleep(0.1)

    def listener():
        sniff(iface=args.iface, prn=negotiation_handler, timeout=listen_time, store=False)

    # Launch threads
    tb = threading.Thread(target=broadcaster, daemon=True)
    tl = threading.Thread(target=listener, daemon=True)
    tb.start()
    tl.start()

    tl.join(timeout=listen_time + 1)
    heard = heard_ready_begin.is_set()

    if heard:
        with role_lock:
            role = "responder"
        print("[role] Heard another device's beacon -> acting as responder.")
    else:
        with role_lock:
            role = "initiator"
        print("[role] Did not hear peer -> acting as initiator.")

    stop_event.clear()  # ensure exchange can start fresh
    return role


# ---------- Main Exchange Logic ----------
def run_responder(n_frames, per_index_timeout):
    print("[responder] starting responder mode.")
    sniff_thread = threading.Thread(
        target=lambda: sniff(iface=args.iface, prn=responder_handler, store=False, timeout=n_frames * 0.02 + 10),
        daemon=True,
    )
    sniff_thread.start()

    max_wait = max(20, n_frames * 0.02 + 10)
    waited = 0.0
    while waited < max_wait and len(observed_by_responder) < n_frames:
        time.sleep(0.5)
        waited += 0.5

    print("[responder] finished sniffing.")
    stop_event.set()
    sniff_thread.join(timeout=1)


def run_initiator(n_frames, per_index_timeout):
    print("[initiator] starting initiator mode.")
    iface_mac = get_if_hwaddr(args.iface)

    ready_frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE)
    tx_queue.put(ready_frame)

    sniff_thread = threading.Thread(
        target=lambda: sniff(iface=args.iface, prn=initiator_reply_handler, store=False, timeout=n_frames * 0.01 + 5),
        daemon=True,
    )
    sniff_thread.start()

    for i in range(n_frames):
        if stop_event.is_set():
            break
        frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, index=i)
        tx_queue.put(frame)
        start = time.time()
        while (time.time() - start) < per_index_timeout:
            if i in observed_by_initiator:
                break
            time.sleep(0.005)
        if i % 50 == 0 and i > 0:
            print(f"[initiator] sent {i} frames so far...")

    print("[initiator] finished sending frames.")
    time.sleep(0.5)
    stop_event.set()
    sniff_thread.join(timeout=1)


# ---------- Main ----------
def main():
    global args, role
    parser = argparse.ArgumentParser(description="Threaded RSSI key exchange.")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--n", type=int, default=300)
    parser.add_argument("--listen", type=float, default=2.0)
    parser.add_argument("--per-index-timeout", type=float, default=0.5)
    parser.add_argument("--out-prefix", default="")
    args = parser.parse_args()

    tx_thread = threading.Thread(target=tx_worker, daemon=True)
    tx_thread.start()

    # --- threaded election ---
    role = threaded_role_election(args.listen)

    # --- Run main phase ---
    if role == "initiator":
        run_initiator(args.n, args.per_index_timeout)
    else:
        # announce Ready to Exchange to confirm to initiator
        tx_queue.put(build_beacon_frame(get_if_hwaddr(args.iface), SSID_READY_EXCHANGE))
        run_responder(args.n, args.per_index_timeout)

    stop_event.set()
    tx_thread.join(timeout=1)

    # --- Save results ---
    prefix = args.out_prefix or ""
    with open(prefix + "initiator_samples.json", "w") as f:
        json.dump(observed_by_initiator, f, indent=2)
    with open(prefix + "responder_samples.json", "w") as f:
        json.dump(observed_by_responder, f, indent=2)

    print(f"[main] done. Initiator: {len(observed_by_initiator)}, Responder: {len(observed_by_responder)}")


if __name__ == "__main__":
    main()
