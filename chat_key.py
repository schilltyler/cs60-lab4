#!/usr/bin/env python3
"""
key_exchange.py
Implements Part 2: Secret key generation by rapid RSSI exchange.

Usage:
  sudo python3 key_exchange.py --iface wlan0 --channel 6 --n 300 --z 0.6

Run the same script on two devices (same channel). They will auto-select roles.
"""

import argparse
import threading
import time
import json
import hashlib
from queue import Queue, Empty

from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Elt,
    sendp,
    sniff,
    get_if_hwaddr,
)


# -------------------------
# Utility functions
# -------------------------
def get_rssi(packet):
    # Try common radiotap RSSI field names (drivers vary)
    r = getattr(packet, "dBm_AntSignal", None)
    if r is None:
        r = getattr(packet, "dBm_AntSig", None)
    return r


def make_payload(tag, payload_dict):
    # payload: KEYX:<json>
    return ("KEYX:" + json.dumps({"t": tag, **payload_dict})).encode()


def parse_payload(info_bytes):
    try:
        s = info_bytes.decode(errors="ignore")
        if not s.startswith("KEYX:"):
            return None
        j = json.loads(s[len("KEYX:") :])
        return j  # dict with 't' and other fields
    except Exception:
        return None


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# -------------------------
# Frame send helpers
# -------------------------
def send_keyx_frame(iface, dst_mac, src_mac, tag, payload_dict):
    """
    Build and send a Dot11 frame carrying a vendor-specific Dot11Elt
    with the KEYX: JSON payload.
    """
    dot11 = Dot11(type=2, subtype=0, addr1=dst_mac, addr2=src_mac, addr3=src_mac)
    elt = Dot11Elt(ID=221, info=make_payload(tag, payload_dict))
    frame = RadioTap() / dot11 / elt
    sendp(frame, iface=iface, verbose=False)


def broadcast_keyx_frame(iface, src_mac, tag, payload_dict):
    dot11 = Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=src_mac)
    elt = Dot11Elt(ID=221, info=make_payload(tag, payload_dict))
    frame = RadioTap() / dot11 / elt
    sendp(frame, iface=iface, verbose=False)


# -------------------------
# Main class
# -------------------------
class KeyExchanger:
    def __init__(self, iface, channel, n=300, z=0.6, timeout=3.0):
        self.iface = iface
        self.channel = channel
        self.n = n
        self.z = z
        self.timeout = timeout

        self.my_mac = get_if_hwaddr(iface)
        self.peer_mac = None

        # Storage: index -> rssi
        self.received = {}  # frames we received (index -> rssi)
        self.replies = {}  # replies we received (index -> rssi)

        self.sniffer_thread = None
        self.sniff_q = Queue()

        # role state
        self.role = None  # 'initiator' or 'responder'

        # control flags
        self.running = True

    def start_sniffer(self):
        def handle(pkt):
            # We only care about Dot11 with Dot11Elt ID221 carrying KEYX
            try:
                if not pkt.haslayer(Dot11Elt):
                    return
                # find the first Dot11Elt with ID 221
                el = pkt.getlayer(Dot11Elt)
                # Scapy may chain Dot11Elt; iterate to find 221
                while el is not None and getattr(el, "ID", None) != 221:
                    el = el.payload.getlayer(Dot11Elt)
                if el is None:
                    return
                parsed = parse_payload(el.info)
                if parsed is None:
                    return
                # attach rssi if present
                rssi = get_rssi(pkt)
                # normalise MACs
                src = pkt.addr2
                self.sniff_q.put((parsed, src, rssi))
            except Exception:
                # don't crash on weird packets
                return

        self.sniffer_thread = threading.Thread(
            target=lambda: sniff(iface=self.iface, prn=handle, store=False)
        )
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

    def elect_role(self):
        """
        Try to detect whether somebody is already offering to start.
        If we see KEYX_READY from another device, we become responder.
        Otherwise we become initiator (we broadcast KEYX_READY).
        """
        print("[*] Role election: listening for responder offers ...")
        start = time.time()
        # listen for a short period to see if another node is broadcasting KEYX_READY
        while time.time() - start < self.timeout:
            try:
                parsed, src, rssi = self.sniff_q.get(timeout=0.5)
                t = parsed.get("t")
                if t == "READY":
                    # another node is ready — we are responder
                    print(f"[+] Heard READY from {src} -> becoming RESPONDER")
                    self.peer_mac = src
                    # reply with READY_ACK (to tell initiator we're here)
                    send_keyx_frame(self.iface, src, self.my_mac, "READY_ACK", {"note": "here"})
                    self.role = "responder"
                    return
            except Empty:
                continue

        # If we got here, no one announced readiness: become initiator
        print("[*] No READY found -> become INITIATOR, broadcasting READY ...")
        # broadcast ready until we receive a READY_ACK or timeout
        start = time.time()
        while time.time() - start < self.timeout:
            broadcast_keyx_frame(self.iface, self.my_mac, "READY", {"note": "init"})
            # wait a bit and check for responses
            wait_start = time.time()
            while time.time() - wait_start < 0.3:
                try:
                    parsed, src, rssi = self.sniff_q.get(timeout=0.3)
                    if parsed.get("t") == "READY_ACK":
                        print(f"[+] Got READY_ACK from {src}. Peer set -> become INITIATOR")
                        self.peer_mac = src
                        self.role = "initiator"
                        return
                except Empty:
                    break
        # if no ACK -> become initiator anyway (maybe peer will hear our READY later)
        print("[*] No READY_ACK received; still acting as INITIATOR (will attempt exchanges)")
        self.role = "initiator"

    def exchange_frames(self):
        """
        Initiator sends index frames 0..n-1 and expects quick reply from responder.
        Responder listens for index frames, records RSSI, replies quickly with same index.
        Both record rssi for index: initiator records rssi of the reply; responder records rssi of initial.
        """
        print(f"[*] Starting exchange: role={self.role}, n={self.n}, z={self.z}")

        if self.role == "initiator":
            # loop over indices. For each index, send a frame addressed to peer and wait for reply.
            for idx in range(self.n):
                if not self.running:
                    break
                # send index frame
                payload = {"idx": idx}
                send_keyx_frame(self.iface, self.peer_mac or "ff:ff:ff:ff:ff:ff", self.my_mac, "IDX", payload)
                # wait short time to receive reply
                tstart = time.time()
                got_reply = False
                while time.time() - tstart < 0.5:
                    try:
                        parsed, src, rssi = self.sniff_q.get(timeout=0.1)
                        t = parsed.get("t")
                        if t == "IDX_REPLY" and parsed.get("idx") == idx and src == (self.peer_mac or src):
                            # record reply rssi (this is RSSI measured by initiator of reply from responder)
                            self.replies[idx] = rssi
                            got_reply = True
                            break
                        # We may see other frames (keep them processed)
                        # Also handle READY frames that may come late
                    except Empty:
                        continue
                if not got_reply:
                    # mark as missed
                    # leave absent in replies (dropped)
                    pass
                # tiny pause to keep reciprocity window small
                time.sleep(0.005)

        elif self.role == "responder":
            # Keep listening for IDX frames. When one arrives, record its rssi and reply with IDX_REPLY.
            start_time = time.time()
            while len(self.received) < self.n and (time.time() - start_time) < (self.n * 0.6 + 10):
                try:
                    parsed, src, rssi = self.sniff_q.get(timeout=1.0)
                except Empty:
                    continue
                t = parsed.get("t")
                if t == "IDX" and "idx" in parsed:
                    idx = parsed["idx"]
                    # record rssi observed for this index
                    self.received[idx] = rssi
                    self.peer_mac = src
                    # reply quickly to initiator with IDX_REPLY including index
                    send_keyx_frame(self.iface, src, self.my_mac, "IDX_REPLY", {"idx": idx})
                elif t == "READY":
                    # if late READY arrives, ack it
                    send_keyx_frame(self.iface, src, self.my_mac, "READY_ACK", {"note": "late"})
                # else ignore other types
            # done
        else:
            print("[!] Unknown role in exchange_frames")

        print("[*] Frame exchange complete.")
        # allow a short settle time for any last packets to arrive
        time.sleep(0.3)
        # Drain any remaining sniff queue items into local storage if relevant
        while True:
            try:
                parsed, src, rssi = self.sniff_q.get_nowait()
                t = parsed.get("t")
                if t == "IDX" and "idx" in parsed and self.role == "responder":
                    self.received[parsed["idx"]] = rssi
                elif t == "IDX_REPLY" and "idx" in parsed and self.role == "initiator":
                    self.replies[parsed["idx"]] = rssi
            except Empty:
                break

    def compute_bits(self):
        """
        Compute bits from RSSIs on this device.
        For responder: use self.received (index->rssi) -> rssi_list
        For initiator: use self.replies (index->rssi) -> rssi_list
        """
        if self.role == "responder":
            rdict = self.received
        else:
            rdict = self.replies

        if not rdict:
            print("[!] No RSSI measurements recorded on this device.")
            return {}, {}

        # Build ordered lists
        indices = sorted(rdict.keys())
        vals = [rdict[i] for i in indices]

        # compute mean & std (sample std)
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / len(vals)
        std = var ** 0.5 if var > 0 else 0.0

        bits = {}
        for idx in indices:
            v = rdict[idx]
            if std == 0:
                # degenerate: if all equal, no indices selected
                continue
            if v > mean + self.z * std:
                bits[idx] = 1
            elif v < mean - self.z * std:
                bits[idx] = 0
            else:
                # skip index
                continue

        print(f"[*] Device computed {len(bits)} candidate bits from {len(indices)} measurements (mean={mean:.2f}, std={std:.2f})")
        return bits, {"mean": mean, "std": std, "count": len(indices)}

    def reconcile_indices(self, my_indices):
        """
        Exchange index lists with peer so both can compute intersection.
        We send our index list (not bit values). This reveals which indices had enough deviation to be used,
        but not whether those indices were 0 or 1 bits.
        Implemented as:
         - initiator sends JSON list 'IDX_LIST' to peer
         - responder upon receiving it sends back its own IDX_LIST
        Both then compute intersection.
        """
        send_tag = "IDX_LIST"
        payload = {"indices": my_indices}
        if self.role == "initiator":
            # send index list to peer and wait for peer's list
            send_keyx_frame(self.iface, self.peer_mac, self.my_mac, send_tag, {"indices": my_indices})
            # wait
            peer_list = None
            tstart = time.time()
            while time.time() - tstart < 5.0:
                try:
                    parsed, src, rssi = self.sniff_q.get(timeout=0.5)
                except Empty:
                    continue
                if parsed.get("t") == "IDX_LIST" and "indices" in parsed:
                    peer_list = parsed["indices"]
                    break
            if peer_list is None:
                print("[!] Did not receive peer indices.")
                peer_list = []
        else:  # responder
            # wait to receive initiator's list
            peer_list = None
            tstart = time.time()
            while time.time() - tstart < 5.0:
                try:
                    parsed, src, rssi = self.sniff_q.get(timeout=0.5)
                except Empty:
                    continue
                if parsed.get("t") == "IDX_LIST" and "indices" in parsed:
                    peer_list = parsed["indices"]
                    # reply with our list
                    # build my list and reply
                    send_keyx_frame(self.iface, src, self.my_mac, send_tag, {"indices": my_indices})
                    break
            if peer_list is None:
                print("[!] Did not receive initiator's indices in time.")
                peer_list = []

        # compute intersection
        my_set = set(my_indices)
        peer_set = set(peer_list)
        intersection = sorted(list(my_set & peer_set))
        print(f"[*] Reconciled indices: I had {len(my_indices)} indices, peer had {len(peer_list)} indices, common {len(intersection)}")
        return intersection

    def commit_and_confirm(self, final_bits):
        """
        Confirm that both devices have the same final bit string without revealing it:
        initiator sends HASH(key) and responder compares.
        """
        # build bitstring in order of indices
        # final_bits: dict idx->bit
        indices = sorted(final_bits.keys())
        bitstr = "".join(str(final_bits[i]) for i in indices)
        commit = sha256_hex(bitstr.encode())

        if self.role == "initiator":
            # send commit
            send_keyx_frame(self.iface, self.peer_mac, self.my_mac, "COMMIT", {"h": commit})
            # wait for peer response
            got = None
            tstart = time.time()
            while time.time() - tstart < 5.0:
                try:
                    parsed, src, rssi = self.sniff_q.get(timeout=0.5)
                except Empty:
                    continue
                if parsed.get("t") == "COMPARISON" and "result" in parsed:
                    got = parsed.get("result")
                    break
            if got == "MATCH":
                print("[+] Peer reports MATCH. Keys agreed.")
                return True, bitstr
            else:
                print("[-] Peer reports MISMATCH or no reply.")
                return False, bitstr

        else:  # responder
            # wait for commit
            commit_h = None
            tstart = time.time()
            while time.time() - tstart < 5.0:
                try:
                    parsed, src, rssi = self.sniff_q.get(timeout=0.5)
                except Empty:
                    continue
                if parsed.get("t") == "COMMIT" and "h" in parsed:
                    commit_h = parsed["h"]
                    initiator_mac = src
                    break
            if commit_h is None:
                print("[!] Did not receive commit in time.")
                return False, ""
            # compute my own hash
            myhash = sha256_hex(bitstr.encode())
            if myhash == commit_h:
                # send MATCH
                send_keyx_frame(self.iface, initiator_mac, self.my_mac, "COMPARISON", {"result": "MATCH"})
                print("[+] Sent MATCH")
                return True, bitstr
            else:
                send_keyx_frame(self.iface, initiator_mac, self.my_mac, "COMPARISON", {"result": "MISMATCH"})
                print("[-] Sent MISMATCH")
                return False, bitstr

    def run(self):
        print(f"[*] Starting key exchange on iface {self.iface} (mac={self.my_mac}) channel={self.channel}")
        self.start_sniffer()
        time.sleep(0.2)
        self.elect_role()
        if self.role is None:
            print("[!] Could not decide role. Exiting.")
            return

        # If responder but peer_mac unknown, wait short time to see peer announce
        if self.role == "responder" and self.peer_mac is None:
            # short wait to capture the initiator MAC
            t0 = time.time()
            while self.peer_mac is None and time.time() - t0 < 2.0:
                try:
                    parsed, src, rssi = self.sniff_q.get(timeout=0.5)
                    if parsed.get("t") == "READY":
                        self.peer_mac = src
                        send_keyx_frame(self.iface, src, self.my_mac, "READY_ACK", {"note": "here2"})
                        break
                except Empty:
                    continue

        # perform exchange
        self.exchange_frames()

        # compute bits on each device
        bits_dict, stats = self.compute_bits()
        my_indices = sorted(bits_dict.keys())

        # exchange index lists and compute intersection (reconciliation)
        common = self.reconcile_indices(my_indices)

        # build final bits only from intersection, keep order
        final_bits = {}
        for idx in sorted(common):
            final_bits[idx] = bits_dict[idx]

        if not final_bits:
            print("[!] No common bits available after reconciliation. Try again with different z or more exchanges.")
        else:
            print(f"[*] Final key length (bits): {len(final_bits)}")

        # commit and confirm
        success, bitstr = self.commit_and_confirm(final_bits)
        if success:
            print("[*] Key confirmed by both devices.")
            print(f"[*] Final key (bits) — indices: {sorted(final_bits.keys())} -> {bitstr}")
        else:
            print("[!] Key confirmation failed or mismatched.")
            print(f"[*] Local candidate key (bits) indices: {sorted(final_bits.keys())} -> {bitstr}")

        # stop
        self.running = False
        time.sleep(0.2)
        print("[*] Done.")


# -------------------------
# CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="RSSI-based key exchange demo (Part 2)")
    parser.add_argument("--iface", required=True, help="monitor-mode interface (e.g., wlan0 or wlxaabbccddeeff)")
    parser.add_argument("--channel", type=int, default=6, help="channel (for your monitor mode script)")
    parser.add_argument("--n", type=int, default=200, help="number of index frames to attempt")
    parser.add_argument("--z", type=float, default=0.6, help="threshold in std deviations for bit selection")
    parser.add_argument("--timeout", type=float, default=3.0, help="timeout during role election")
    args = parser.parse_args()

    exch = KeyExchanger(iface=args.iface, channel=args.channel, n=args.n, z=args.z, timeout=args.timeout)
    exch.run()


if __name__ == "__main__":
    main()
