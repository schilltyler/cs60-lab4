#!/usr/bin/env python3
"""
key_exchange.py -- Part 2: Secret key generation by rapid RSSI exchange (threaded RSSI measurement).

Usage:
  sudo python3 key_exchange.py --iface wlan0 --n 300 --listen 2 --per-index-timeout 0.5

Notes:
 - Interface must be in monitor mode on the same channel on both devices.
 - Run the same program on both devices; roles are determined dynamically by packet flow.
 - Outputs:
    initiator_samples.json
    responder_samples.json
"""

import argparse
import json
import threading
import time
from queue import Queue, Empty
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sniff, sendp
from random import randint

# ---------- Globals ----------
args = None
stop_event = threading.Event()
tx_queue = Queue()

observed_by_initiator = {}
observed_by_responder = {}

responder_flag = threading.Event()  # True if this device becomes responder
initiator_ready = threading.Event()  # True if initiator received responder's ack

IDX_ELT_ID = 221
SSID_READY_BEGIN = b"Ready to Begin"
SSID_READY_EXCHANGE = b"Ready to Exchange"


# ---------- Helper functions ----------
def safe_get_iface_mac(iface: str) -> str:
    """Get interface MAC safely. Return random locally-administered MAC if fails."""
    from scapy.all import get_if_hwaddr
    try:
        return get_if_hwaddr(iface)
    except Exception:
        rand_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(randint(0, 255) for _ in range(5))
        print(f"[warn] Could not get MAC for {iface}, using {rand_mac}")
        return rand_mac


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


# ---------- Packet Handlers ----------
def negotiation_handler(packet):
    """Handle role negotiation beacons."""
    ssid = get_ssid_from_packet(packet)
    if not ssid:
        return

    # Become responder if we see "Ready to Begin"
    if ssid == SSID_READY_BEGIN:
        if not responder_flag.is_set():
            responder_flag.set()
            # Immediately send ACK to initiator
            iface_mac = safe_get_iface_mac(args.iface)
            ack_frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE)
            tx_queue.put(ack_frame)
            print("[role] Detected peer 'Ready to Begin'. Acting as responder.")
    elif ssid == SSID_READY_EXCHANGE:
        # Initiator sees ACK
        initiator_ready.set()
        print("[role] Detected peer 'Ready to Exchange'. Acting as initiator.")


def responder_handler(packet):
    """Collect RSSI samples as responder."""
    idx = get_index_from_packet(packet)
    if idx is None:
        return
    rssi = get_rssi(packet)
    observed_by_responder[idx] = rssi

    iface_mac = safe_get_iface_mac(args.iface)
    reply = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, index=idx)
    tx_queue.put(reply)


def initiator_reply_handler(packet):
    """Collect RSSI samples as initiator."""
    ssid = get_ssid_from_packet(packet)
    if ssid != SSID_READY_EXCHANGE:
        return
    idx = get_index_from_packet(packet)
    if idx is None:
        return
    rssi = get_rssi(packet)
    observed_by_initiator[idx] = rssi


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


# ---------- Role Election ----------
def negotiate_role(listen_time=2.0):
    """Sniff first, then send if needed. Determines initiator/responder via packet flow."""
    iface_mac = safe_get_iface_mac(args.iface)

    def sniffer():
        sniff(iface=args.iface, prn=negotiation_handler, store=False, timeout=listen_time)

    sniff_thread = threading.Thread(target=sniffer, daemon=True)
    sniff_thread.start()

    # Wait briefly to see if we detect a peer
    time.sleep(listen_time)

    if not responder_flag.is_set():
        # We didn't see any "Ready to Begin" -> we become initiator
        print("[role] No peer detected -> acting as initiator.")
        initiator_frame = build_beacon_frame(iface_mac, SSID_READY_BEGIN)
        while not initiator_ready.is_set() and not stop_event.is_set():
            tx_queue.put(initiator_frame)
            time.sleep(0.1)
        return "initiator"
    else:
        return "responder"


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
    iface_mac = safe_get_iface_mac(args.iface)

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
    global args
    parser = argparse.ArgumentParser(description="RSSI key exchange using control-flow-based role election.")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--n", type=int, default=300)
    parser.add_argument("--listen", type=float, default=2.0)
    parser.add_argument("--per-index-timeout", type=float, default=0.5)
    parser.add_argument("--out-prefix", default="")
    args = parser.parse_args()

    tx_thread = threading.Thread(target=tx_worker, daemon=True)
    tx_thread.start()

    role = negotiate_role(args.listen)

    if role == "initiator":
        run_initiator(args.n, args.per_index_timeout)
    else:
        run_responder(args.n, args.per_index_timeout)

    stop_event.set()
    tx_thread.join(timeout=1)

    prefix = args.out_prefix or ""
    with open(prefix + "initiator_samples.json", "w") as f:
        json.dump(observed_by_initiator, f, indent=2)
    with open(prefix + "responder_samples.json", "w") as f:
        json.dump(observed_by_responder, f, indent=2)

    print(f"[main] done. Initiator: {len(observed_by_initiator)}, Responder: {len(observed_by_responder)}")


if __name__ == "__main__":
    main()
