#!/usr/bin/env python3
"""
key_exchange.py -- Part 2: Secret key generation by rapid RSSI exchange.

Usage (example):
  sudo python3 chat_key.py --iface wlan0 --n 300 --listen 2 --per-index-timeout 0.5

Notes:
 - Interface must be in monitor mode on the same channel on both devices.
 - You must run the same program on both devices; they auto-elect roles.
 - The script writes two files at exit:
    initiator_samples.json and responder_samples.json
   containing { index: rssi } pairs observed by each device.
"""

import argparse
import json
import threading
import time
from queue import Queue, Empty

from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    sniff,
    sendp,
    get_if_hwaddr,
)

# ---------- Config and globals ----------
args = None
stop_event = threading.Event()

# Shared data
observed_by_initiator = {}  # index -> rssi measured by initiator (from responder reply)
observed_by_responder = {}  # index -> rssi measured by responder (when initiator frame received)

# Role variables
role_lock = threading.Lock()
role = "unknown"  # 'initiator' or 'responder'

# State for negotiation
heard_ready_begin = threading.Event()
heard_ready_exchange = threading.Event()

# Make responses fast by using a small outbound queue processed by a dedicated sender thread
tx_queue = Queue()

# Constants
SSID_READY_BEGIN = b"Ready to Begin"
SSID_READY_EXCHANGE = b"Ready to Exchange"
IDX_ELT_ID = 221  # vendor-specific element for carrying the index (safe for lab use)


# ---------- Helper functions ----------
def build_beacon_frame(iface_mac: str, ssid_bytes: bytes, index: int = None):
    """
    Construct a RadioTap + Dot11 Beacon + SSID element, optionally with a vendor
    element that encodes an integer index.
    We use broadcast addr1 so the other device in monitor mode will see it.
    """
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=iface_mac, addr3=iface_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID=0, info=ssid_bytes)  # ID=0 -> SSID
    frame = RadioTap() / dot11 / beacon / essid
    if index is not None:
        idx_bytes = str(index).encode()
        idx_elt = Dot11Elt(ID=IDX_ELT_ID, info=idx_bytes)
        frame = frame / idx_elt
    return frame


def get_dot11elt_by_id(packet, eid):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        try:
            if elt.ID == eid:
                return elt
        except Exception:
            pass
        # move to next Dot11Elt (scapy payload chaining)
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def get_ssid_from_packet(packet):
    elt = get_dot11elt_by_id(packet, 0)
    if elt:
        try:
            return elt.info
        except Exception:
            return None
    return None


def get_index_from_packet(packet):
    elt = get_dot11elt_by_id(packet, IDX_ELT_ID)
    if elt and elt.info:
        try:
            return int(elt.info.decode(errors="ignore"))
        except Exception:
            return None
    return None


def get_rssi(packet):
    # Different drivers expose RSSI slightly differently. Scapy often has packet.dBm_AntSignal.
    # We try common attributes and return an int or None.
    rssi = None
    if hasattr(packet, "dBm_AntSignal"):
        try:
            rssi = int(packet.dBm_AntSignal)
        except Exception:
            rssi = None
    # Could add other heuristics here if needed.
    return rssi


# ---------- Packet handlers ----------
def negotiation_handler(packet):
    """
    Called during the initial small listening window to detect 'Ready to Begin'
    and 'Ready to Exchange' frames to determine roles.
    """
    if not packet.haslayer(Dot11Beacon) or not packet.haslayer(Dot11Elt):
        return
    ssid = get_ssid_from_packet(packet)
    if not ssid:
        return
    if ssid == SSID_READY_BEGIN:
        heard_ready_begin.set()
    elif ssid == SSID_READY_EXCHANGE:
        heard_ready_exchange.set()


def responder_handler(packet):
    """
    Responder: upon receiving initiator's frame (with index), record RSSI and
    send back a quick reply encoding the same index.
    This handler aims to be lightweight and send the reply immediately.
    """
    global observed_by_responder
    if not packet.haslayer(Dot11Beacon) or not packet.haslayer(Dot11Elt):
        return
    ssid = get_ssid_from_packet(packet)
    if ssid != SSID_READY_EXCHANGE and ssid != SSID_READY_BEGIN:
        # we expect initiator frames to contain SSID_READY_EXCHANGE (or the beacon format we used)
        # but tolerate either during development
        pass

    idx = get_index_from_packet(packet)
    if idx is None:
        return

    rssi = get_rssi(packet)
    # store the responder's observed rssi for that index (may overwrite duplicates; fine)
    observed_by_responder[idx] = rssi

    # Immediately craft a small reply that echoes the index so the initiator can measure RSSI.
    # Use the same SSID_READY_EXCHANGE to mark it's a reply.
    try:
        iface_mac = get_if_hwaddr(args.iface)
    except Exception:
        iface_mac = "02:00:00:00:00:00"

    reply = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, index=idx)
    # Send via tx_queue to avoid blocking scapy's handler for too long
    tx_queue.put(reply)


def initiator_reply_handler(packet):
    """
    Initiator: listens for replies from responder that include an echoed index.
    When a reply is seen, record RSSI into observed_by_initiator[index].
    """
    if not packet.haslayer(Dot11Beacon) or not packet.haslayer(Dot11Elt):
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
    """Simple thread that pulls frames from tx_queue and sends them with sendp."""
    while not stop_event.is_set():
        try:
            frame = tx_queue.get(timeout=0.2)
        except Empty:
            continue
        try:
            sendp(frame, iface=args.iface, inter=0, verbose=False)
        except Exception as e:
            # non-fatal — log and continue
            print(f"[tx_worker] sendp error: {e}")
        finally:
            tx_queue.task_done()


# ---------- High-level behaviors ----------
def listen_for_role(listen_time):
    """
    Listen for a small window for 'Ready to Begin' frames.
    If heard, this node becomes responder. If not, it will be initiator.
    Returns role string.
    """
    print(f"[listen] listening on {args.iface} for {listen_time}s to detect peer...")
    # sniff with timeout but using negotiation_handler to set events
    sniff(iface=args.iface, prn=negotiation_handler, timeout=listen_time, store=False)
    if heard_ready_begin.is_set():
        print("[listen] Heard Ready to Begin -> become responder.")
        return "responder"
    else:
        print("[listen] Did not hear Ready to Begin -> become initiator.")
        return "initiator"


def run_responder(n_frames, per_index_timeout):
    """
    Responder main: sniff incoming frames and reply quickly. Runs until stop_event or
    until we've observed enough indices (heuristic).
    """
    print("[responder] starting responder mode.")
    # Start sniffing with responder_handler
    # We'll run until stop_event set; sniff in a loop to allow reacting to stop_event
    while not stop_event.is_set():
        sniff(iface=args.iface, prn=responder_handler, timeout=1, store=False)
        # Stop condition: if we've seen at least n_frames indices, we can stop
        if len(observed_by_responder) >= n_frames:
            print(f"[responder] observed >= {n_frames} indices; stopping.")
            break
    print("[responder] responder finished sniffing.")


def run_initiator(n_frames, per_index_timeout):
    """
    Initiator: send a sequence of frames with indices 0..n_frames-1 and wait for replies.
    For each index we:
      - transmit the frame carrying the index (as a beacon)
      - wait up to per_index_timeout seconds for a reply that echoes the index
      - continue to next index
    """
    print("[initiator] starting initiator mode.")
    try:
        iface_mac = get_if_hwaddr(args.iface)
    except Exception:
        iface_mac = "02:00:00:00:00:00"

    # Pre-send a "Ready to Exchange" beacon so responder knows we want to exchange (optional)
    ready_frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE)
    tx_queue.put(ready_frame)

    for i in range(n_frames):
        if stop_event.is_set():
            break
        frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, index=i)
        # send the frame (via tx_queue) and then wait a short time for a reply to be observed
        tx_queue.put(frame)
        start = time.time()
        # poll for reply
        while (time.time() - start) < per_index_timeout:
            # if reply came in, observed_by_initiator will have key i
            if i in observed_by_initiator:
                break
            time.sleep(0.005)
        # continue to next index regardless
        if i % 50 == 0 and i > 0:
            print(f"[initiator] sent {i} frames so far...")
    print("[initiator] finished sending frames.")


# ---------- Main ----------
def main():
    global args, role

    parser = argparse.ArgumentParser(description="Rapid RSSI key-exchange skeleton (lab part 2).")
    parser.add_argument("--iface", required=True, help="monitor-mode interface to use (e.g., wlan0)")
    parser.add_argument("--n", type=int, default=300, help="number of frame indices to attempt")
    parser.add_argument("--listen", type=float, default=2.0, help="initial listen time (s) to detect peer")
    parser.add_argument(
        "--per-index-timeout",
        type=float,
        default=0.5,
        help="how long (s) to wait for a reply per index (initiator)",
    )
    parser.add_argument("--out-prefix", default="", help="optional prefix for output filenames")
    args = parser.parse_args()

    # Start tx worker
    th_tx = threading.Thread(target=tx_worker, daemon=True)
    th_tx.start()

    # 1) role election: listen first for a short window
    role = listen_for_role(args.listen)

    # If this node did not hear Ready to Begin (so it is initiator), start broadcasting 'Ready to Begin'
    # until a peer replies with Ready to Exchange OR until a small timeout.
    if role == "initiator":
        # Start a short background broadcaster to announce presence until we hear Ready to Exchange
        try:
            iface_mac = get_if_hwaddr(args.iface)
        except Exception:
            iface_mac = "02:00:00:00:00:00"

        stop_announce = threading.Event()

        def announcer():
            frame = build_beacon_frame(iface_mac, SSID_READY_BEGIN)
            while not stop_announce.is_set() and not heard_ready_exchange.is_set():
                tx_queue.put(frame)
                time.sleep(0.08)  # rapid broadcast for a short period

        announcer_t = threading.Thread(target=announcer, daemon=True)
        announcer_t.start()

        # Meanwhile sniff for "Ready to Exchange" to confirm a responder exists
        sniff(iface=args.iface, prn=negotiation_handler, timeout=3, store=False)
        if heard_ready_exchange.is_set():
            print("[initiator] heard Ready to Exchange from responder; proceeding.")
            stop_announce.set()
        else:
            print("[initiator] no responder heard after announce window; still proceeding as initiator.")
            stop_announce.set()

        # Start a sniff thread to record replies while we send
        sniff_thread = threading.Thread(
            target=lambda: sniff(iface=args.iface, prn=initiator_reply_handler, store=False, timeout=args.n * 0.01 + 5),
            daemon=True,
        )
        sniff_thread.start()

        # Run initiator exchange
        run_initiator(args.n, args.per_index_timeout)

        # give a short grace period for late replies
        time.sleep(0.5)
        stop_event.set()
        sniff_thread.join(timeout=1)

    else:  # responder
        # Upon hearing Ready to Begin we should reply with Ready to Exchange once so the initiator knows we're a responder.
        # That was handled in negotiation_handler by setting heard_ready_begin; we now send one Ready to Exchange beacon.
        try:
            iface_mac = get_if_hwaddr(args.iface)
        except Exception:
            iface_mac = "02:00:00:00:00:00"

        # send an acknowledgement
        ack = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE)
        tx_queue.put(ack)

        # Start a thread to sniff and handle initiator frames
        sniff_thread = threading.Thread(target=lambda: sniff(iface=args.iface, prn=responder_handler, store=False, timeout=args.n * 0.02 + 10), daemon=True)
        sniff_thread.start()

        # Let responder run until it has observed n distinct indices or a generous timeout
        # run_responder will call sniff in a loop as well, but here we simply wait
        # Use a loop and a maximum wait time
        max_wait = max(20, args.n * 0.02 + 10)
        waited = 0.0
        interval = 0.5
        while waited < max_wait and len(observed_by_responder) < args.n:
            time.sleep(interval)
            waited += interval

        stop_event.set()
        sniff_thread.join(timeout=1)

    # shutdown tx worker
    stop_event.set()
    th_tx.join(timeout=1)

    # Dump results to files
    prefix = args.out_prefix or ""
    initiator_fname = prefix + "initiator_samples.json"
    responder_fname = prefix + "responder_samples.json"

    try:
        with open(initiator_fname, "w") as f:
            json.dump({str(k): observed_by_initiator[k] for k in observed_by_initiator}, f, indent=2)
        with open(responder_fname, "w") as f:
            json.dump({str(k): observed_by_responder[k] for k in observed_by_responder}, f, indent=2)
        print(f"[main] Saved initiator samples -> {initiator_fname}")
        print(f"[main] Saved responder samples -> {responder_fname}")
    except Exception as e:
        print(f"[main] failed to save results: {e}")

    print("[main] done. Print some stats:")
    print(f"  observed_by_initiator: {len(observed_by_initiator)} entries")
    print(f"  observed_by_responder: {len(observed_by_responder)} entries")


if __name__ == "__main__":
    main()
