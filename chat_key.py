#!/usr/bin/env python3
"""
key_exchange_fixed.py -- Part 2: Secret key generation by rapid RSSI exchange.

Usage:
  sudo python3 key_exchange_fixed.py --iface wlan0 --n 300 --listen 2 --per-index-timeout 0.05

Notes:
 - Interface must be in monitor mode on the same channel on both devices.
 - Run the same program on both devices; roles are determined dynamically by packet flow.
 - Outputs depend on role:
    initiator_samples.json  (if you became initiator)
    responder_samples.json  (if you became responder)
"""

import argparse
import json
import threading
import time
import hashlib
import math
import statistics
from queue import Queue, Empty
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sniff, sendp, get_if_hwaddr
from random import randint
import subprocess

# ---------- Constants ----------
IDX_ELT_ID = 221          # index element
IDX_LIST_ELT_ID = 222     # used-indices list exchange
COMMIT_ELT_ID = 223       # commit hash exchange
ACK_ELT_ID = 224          # simple ack (not strictly necessary)

SSID_READY_BEGIN = b"Ready to Begin"
SSID_READY_EXCHANGE = b"Ready to Exchange"

# ---------- Globals ----------
args = None
stop_event = threading.Event()
tx_queue = Queue()

observed_by_initiator = {}   # index -> rssi (initiator measured RSSI of replies)
observed_by_responder = {}   # index -> rssi (responder measured RSSI of initiator frames)

responder_flag = threading.Event()
initiator_ready = threading.Event()

# control-plane storage for index-list & commits received from peer
received_index_lists = []   # list of sets
received_commits = set()

# ---------- Helper functions ----------
def safe_get_iface_mac(iface: str) -> str:
    """Get interface MAC safely. Return random locally-administered MAC if fails."""
    try:
        return get_if_hwaddr(iface)
    except Exception:
        rand_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(randint(0, 255) for _ in range(5))
        print(f"[warn] Could not get MAC for {iface}, using {rand_mac}")
        return rand_mac

def build_beacon_frame(iface_mac: str, ssid_bytes: bytes, index: int = None, extra_elt=None):
    """
    Build a RadioTap/Beacon frame with SSID and optional Dot11Elt:
      - index: put under IDX_ELT_ID (221)
      - extra_elt: tuple (eid, bytes) for other control payloads
    """
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=iface_mac, addr3=iface_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID=0, info=ssid_bytes)
    frame = RadioTap() / dot11 / beacon / essid
    if index is not None:
        frame = frame / Dot11Elt(ID=IDX_ELT_ID, info=str(index).encode())
    if extra_elt is not None:
        eid, info = extra_elt
        frame = frame / Dot11Elt(ID=eid, info=info)
    return frame

def get_dot11elt_by_id(packet, eid):
    """Return first Dot11Elt in packet with ID == eid, else None."""
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if getattr(elt, "ID", None) == eid:
            return elt
        # traverse payload chain
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
    """
    Robust RSSI extraction:
     - try scapy's dBm_AntSignal property
     - attempt to read RadioTap fields if present
     - return None if not found
    """
    # common direct attribute
    if hasattr(packet, "dBm_AntSignal") and packet.dBm_AntSignal is not None:
        try:
            return int(packet.dBm_AntSignal)
        except Exception:
            pass
    # try RadioTap layer access
    try:
        rt = packet.getlayer(RadioTap)
        if rt:
            val = getattr(rt, "dBm_AntSignal", None)
            if val is not None:
                return int(val)
            # sometimes scapy doesn't expose, but the field may be in "notdecoded"
            if hasattr(rt, "notdecoded") and rt.notdecoded:
                raw = bytes(rt.notdecoded)
                # heuristic: search for a -xx byte; this is driver dependent
                for b in raw:
                    # RSSI typical -90..-30; in two's complement it's 166..226; try convert bytes that look like >128
                    if b >= 126:
                        v = b - 256
                        if -120 <= v <= -10:
                            return int(v)
    except Exception:
        pass
    # final fallback: None
    return None

# ---------- Packet Handlers (role negotiation & exchange) ----------
def negotiation_handler(packet):
    """Handle role negotiation beacons (Ready to Begin / Ready to Exchange)."""
    ssid = get_ssid_from_packet(packet)
    if not ssid:
        return

    # Become responder if we see "Ready to Begin"
    if ssid == SSID_READY_BEGIN:
        if not responder_flag.is_set():
            responder_flag.set()
            # Immediately send ACK to initiator (Ready to Exchange)
            iface_mac = safe_get_iface_mac(args.iface)
            ack_frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE)
            tx_queue.put(ack_frame)
            print("[role] Detected peer 'Ready to Begin'. Acting as responder (and sent Ready to Exchange).")
    elif ssid == SSID_READY_EXCHANGE:
        # Initiator sees ACK
        if not initiator_ready.is_set():
            initiator_ready.set()
            print("[role] Detected peer 'Ready to Exchange'. Acting as initiator.")

def responder_handler(packet):
    """Collect RSSI samples as responder when initiator sends indexed frames."""
    # only care about frames with our magic index elt
    idx = get_index_from_packet(packet)
    if idx is None:
        # also allow receiving index-list or commits during exchange phase
        # process index list if present
        idx_list_elt = get_dot11elt_by_id(packet, IDX_LIST_ELT_ID)
        if idx_list_elt and idx_list_elt.info:
            try:
                s = idx_list_elt.info.decode(errors="ignore")
                idxs = set(int(x) for x in s.split(",") if x.strip())
                print(f"[responder] received index-list from peer (len={len(idxs)})")
                received_index_lists.append(idxs)
            except Exception:
                pass
        commit_elt = get_dot11elt_by_id(packet, COMMIT_ELT_ID)
        if commit_elt and commit_elt.info:
            h = commit_elt.info.hex()
            print(f"[responder] received commit hash: {h[:16]}...")
            received_commits.add(h)
        return

    rssi = get_rssi(packet)
    observed_by_responder[idx] = rssi
    if rssi is not None:
        print(f"[responder] idx={idx}, rssi={rssi}")
    else:
        print(f"[responder] idx={idx}, rssi=None")

    # quickly reply to initiator with the same index encoded
    iface_mac = safe_get_iface_mac(args.iface)
    reply = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, index=idx)
    tx_queue.put(reply)

def initiator_reply_handler(packet):
    """Collect RSSI samples as initiator when responder replies with the index."""
    ssid = get_ssid_from_packet(packet)
    # accept replies only if SSID_READY_EXCHANGE (responder's reply)
    if ssid != SSID_READY_EXCHANGE:
        # also process index-list and commit frames similarly for control-plane
        idx_list_elt = get_dot11elt_by_id(packet, IDX_LIST_ELT_ID)
        if idx_list_elt and idx_list_elt.info:
            try:
                s = idx_list_elt.info.decode(errors="ignore")
                idxs = set(int(x) for x in s.split(",") if x.strip())
                print(f"[initiator] received index-list from peer (len={len(idxs)})")
                received_index_lists.append(idxs)
            except Exception:
                pass
        commit_elt = get_dot11elt_by_id(packet, COMMIT_ELT_ID)
        if commit_elt and commit_elt.info:
            h = commit_elt.info.hex()
            print(f"[initiator] received commit hash: {h[:16]}...")
            received_commits.add(h)
        return

    idx = get_index_from_packet(packet)
    if idx is None:
        return
    rssi = get_rssi(packet)
    observed_by_initiator[idx] = rssi
    if rssi is not None:
        print(f"[initiator] idx={idx}, rssi={rssi}")
    else:
        print(f"[initiator] idx={idx}, rssi=None")

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
        print("[role] No peer detected -> acting as initiator. Will send Ready to Begin until peer replies.")
        initiator_frame = build_beacon_frame(iface_mac, SSID_READY_BEGIN)
        # send repeatedly until we see Ready to Exchange (peer ack) or timeout
        start = time.time()
        while not initiator_ready.is_set() and (time.time() - start) < 10 and not stop_event.is_set():
            tx_queue.put(initiator_frame)
            time.sleep(0.1)
        if initiator_ready.is_set():
            print("[role] Received Ready to Exchange from responder.")
            return "initiator"
        else:
            # no reply within timeout -> still treat as initiator but warn
            print("[role] No responder replied within timeout; still acting as initiator.")
            return "initiator"
    else:
        print("[role] Peer indicated Ready to Begin -> acting as responder.")
        return "responder"

# ---------- Main Exchange Logic ----------
def run_responder(n_frames, per_index_timeout):
    print("[responder] starting responder mode.")
    sniff_thread = threading.Thread(
        target=lambda: sniff(iface=args.iface, prn=responder_handler, store=False,
                             timeout=n_frames * per_index_timeout + 15),
        daemon=True,
    )
    sniff_thread.start()

    # wait long enough for entire initiator transmission + margin
    max_wait = n_frames * per_index_timeout + 30

    waited = 0.0
    while waited < max_wait and len(observed_by_responder) < n_frames and not stop_event.is_set():
        time.sleep(0.5)
        waited += 0.5

    print("[responder] finished sniffing. Collected {} samples.".format(len(observed_by_responder)))
    stop_event.set()
    sniff_thread.join(timeout=1)

def run_initiator(n_frames, per_index_timeout):
    print("[initiator] starting initiator mode.")
    iface_mac = safe_get_iface_mac(args.iface)

    sniff_thread = threading.Thread(
        target=lambda: sniff(iface=args.iface, prn=initiator_reply_handler, store=False, timeout=n_frames * 0.02 + 30),
        daemon=True,
    )
    sniff_thread.start()

    # small delay to allow responder to start sniffing
    time.sleep(1.5)

    for i in range(n_frames):
        if stop_event.is_set():
            break
        frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, index=i)
        tx_queue.put(frame)
        start = time.time()
        # Wait for reply (the reply, if received, will populate observed_by_initiator[i])
        while (time.time() - start) < per_index_timeout:
            if i in observed_by_initiator:
                break
            time.sleep(0.002)
        # keep the loop going quickly; print progress occasionally
        if i % 50 == 0 and i > 0:
            print(f"[initiator] sent {i} frames so far...")

    print("[initiator] finished sending frames. Sent {} frames.".format(n_frames))
    # allow some time for last replies
    time.sleep(0.5)
    stop_event.set()
    sniff_thread.join(timeout=1)

# ---------- Post-processing: key generation and confirmation ----------
def generate_key_from_samples(samples_dict, z=0.6):
    """
    Given samples_dict: index -> rssi (some may be None), compute per-index bit decisions.
    Returns dict: index -> bit (0 or 1)
    """
    values = [v for v in samples_dict.values() if v is not None]
    if not values:
        return {}
    # if only one value, stdev cannot be computed; set stddev to small epsilon
    if len(values) < 2:
        mean_val = statistics.mean(values)
        std_val = 1.0
    else:
        mean_val = statistics.mean(values)
        std_val = statistics.pstdev(values)  # population stdev; or statistics.stdev for sample stdev
        if std_val == 0:
            std_val = 1.0
    bits = {}
    for idx, rssi in samples_dict.items():
        if rssi is None:
            continue
        if rssi > mean_val + z * std_val:
            bits[idx] = 1
        elif rssi < mean_val - z * std_val:
            bits[idx] = 0
        else:
            # discard index (not extreme enough)
            pass
    return bits

def indices_set_to_bytes(idxs):
    """Encode set of ints as comma-separated bytes (utf-8)."""
    if not idxs:
        return b""
    return ",".join(str(i) for i in sorted(idxs)).encode()

def bytes_to_indices_set(b):
    try:
        s = b.decode()
        return set(int(x) for x in s.split(",") if x.strip())
    except Exception:
        return set()

def compute_commit_hash_from_bits(bits_dict):
    """
    Given bits dict (index -> bit), produce canonical string ordered by index and return SHA256 bytes.
    """
    if not bits_dict:
        data = b""
    else:
        ordered = [str(bits_dict[i]) for i in sorted(bits_dict.keys())]
        data = ",".join(ordered).encode()
    return hashlib.sha256(data).digest()

def exchange_index_lists_and_commits(role, local_bits, exchange_time=3.0):
    """
    Both sides broadcast their used index list (IDX_LIST_ELT_ID) and commit (COMMIT_ELT_ID).
    They also listen during exchange_time for peer messages (sniff handlers already append to received_* globals).
    Returns: tuple(peer_index_set_union, peer_commit_hashes_set)
    """
    local_indices = set(local_bits.keys())
    iface_mac = safe_get_iface_mac(args.iface)

    # send our index list repeatedly for a short window
    payload = indices_set_to_bytes(local_indices)
    if payload:
        msg_frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, extra_elt=(IDX_LIST_ELT_ID, payload))
    else:
        msg_frame = None

    # send commit hash
    commit = compute_commit_hash_from_bits(local_bits)
    commit_frame = build_beacon_frame(iface_mac, SSID_READY_EXCHANGE, extra_elt=(COMMIT_ELT_ID, commit))

    # broadcast repeatedly for exchange_time seconds
    endt = time.time() + exchange_time
    while time.time() < endt and not stop_event.is_set():
        if msg_frame:
            tx_queue.put(msg_frame)
        tx_queue.put(commit_frame)
        time.sleep(0.15)

    # give a moment for incoming sniff processing
    time.sleep(0.5)

    # consolidate received lists and commits
    peer_indices_union = set()
    for s in received_index_lists:
        peer_indices_union.update(s)
    peer_commits = set(received_commits)
    return peer_indices_union, peer_commits

# ---------- Main ----------
def main():
    global args
    parser = argparse.ArgumentParser(description="RSSI key exchange with index & commit exchange.")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--n", type=int, default=300)
    parser.add_argument("--listen", type=float, default=2.0)
    parser.add_argument("--per-index-timeout", type=float, default=0.05)
    parser.add_argument("--out-prefix", default="")
    parser.add_argument("--z", type=float, default=0.6, help="z stddev threshold for bit selection")
    args = parser.parse_args()

    # try to call monitor-mode helper if present (best-effort)
    try:
        subprocess.run(["bash", "monitor-mode.sh", args.iface, "10"], check=False)
    except Exception:
        pass

    tx_thread = threading.Thread(target=tx_worker, daemon=True)
    tx_thread.start()

    role = negotiate_role(args.listen)

    if role == "initiator":
        run_initiator(args.n, args.per_index_timeout)
    else:
        run_responder(args.n, args.per_index_timeout)

    # ensure tx worker stopped after exchange
    stop_event.set()
    tx_thread.join(timeout=1)

    prefix = args.out_prefix or ""
    if role == "initiator":
        with open(prefix + "initiator_samples.json", "w") as f:
            json.dump({str(k): v for k, v in observed_by_initiator.items()}, f, indent=2)
    else:
        with open(prefix + "responder_samples.json", "w") as f:
            json.dump({str(k): v for k, v in observed_by_responder.items()}, f, indent=2)

    # Post-process: generate keys
    if role == "initiator":
        local_samples = observed_by_initiator
    else:
        local_samples = observed_by_responder

    print("[post] computing bits from local samples...")
    bits = generate_key_from_samples(local_samples, z=args.z)
    print(f"[post] local bit decisions count: {len(bits)} (z={args.z})")

    # Exchange index-lists and commits with peer (both sides send/listen)
    print("[post] exchanging index lists and commit hashes with peer...")
    peer_indices, peer_commits = exchange_index_lists_and_commits(role, bits, exchange_time=4.0)

    # Determine common indices: intersection of our used indices with peer indices
    my_indices = set(bits.keys())
    if peer_indices:
        common = my_indices.intersection(peer_indices)
    else:
        # If we didn't receive peer index list, try any received lists that may be in received_index_lists
        # (this was already merged into peer_indices above), else fallback to intersection with empty -> empty
        common = set()

    print(f"[post] my_indices={len(my_indices)}, peer_indices={len(peer_indices)}, common={len(common)}")

    # Build final key from common indices (ordered)
    final_bits_ordered = []
    for idx in sorted(common):
        final_bits_ordered.append(str(bits[idx]))
    final_key_str = "".join(final_bits_ordered)
    final_key_bytes = final_key_str.encode()
    final_hash = hashlib.sha256(final_key_bytes).hexdigest()

    print(f"[post] final key length (bits): {len(final_bits_ordered)}")
    print(f"[post] final key (as bits): {final_key_str if len(final_bits_ordered) <= 128 else final_key_str[:128] + '...'}")
    print(f"[post] final key SHA256: {final_hash}")

    # Compare commits: if peer_commits contains our final_hash, we know they have same key
    # Note: our commit format earlier used raw digest bytes, while peer_commits stores hex strings of digest bytes,
    # so compute comparable format: commit stored as hex
    my_commit_hex = hashlib.sha256(final_key_bytes).digest().hex()
    match_found = False
    if peer_commits:
        if my_commit_hex in peer_commits:
            match_found = True
            print("[post] MATCH: peer reported same commit hash -> keys match.")
        else:
            # maybe peer sent commit of ordered bits differently; compare the textual SHA hex as well
            if final_hash in peer_commits:
                match_found = True
                print("[post] MATCH (hash hex): peer reported same hex hash -> keys match.")
            else:
                print("[post] NO MATCH: peer commit(s) do not match our computed commit.")
    else:
        print("[post] WARNING: did not receive any peer commit hashes during exchange - cannot confirm automatically.")

    # Save final key info to file
    out_info = {
        "role": role,
        "local_samples_count": len(local_samples),
        "local_bit_count": len(bits),
        "common_bit_count": len(final_bits_ordered),
        "final_key_bits": final_key_str,
        "final_key_sha256": final_hash,
        "match_confirmed": match_found,
    }
    out_fname = prefix + ("initiator_key_result.json" if role == "initiator" else "responder_key_result.json")
    with open(out_fname, "w") as f:
        json.dump(out_info, f, indent=2)

    print(f"[main] done. Results written to {out_fname}")

if __name__ == "__main__":
    main()
