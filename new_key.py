#!/usr/bin/env python3
"""
Wi-Fi RSSI-Based Key Exchange Protocol (Refactored)
Automatic role determination and symmetric key generation over Wi-Fi RSSI.
"""

import sys
import time
import numpy as np
import hashlib
import subprocess
from scapy.all import *
from collections import defaultdict
import threading
import os

# Configuration
INTERFACE = "wlan0"
CHANNEL = 3
NUM_FRAMES = 300
TIMEOUT_ROLE = 5
Z_THRESHOLD = 1.5

# Frame identifiers
FRAME_READY = b"KEY_EXCHANGE_READY_V1"
FRAME_ACK = b"KEY_EXCHANGE_ACK_V1"
FRAME_DATA_PREFIX = b"KEY_DATA_"
FRAME_INDICES = b"KEY_INDICES_"
FRAME_COMMIT = b"KEY_COMMIT_"
FRAME_RESULT = b"KEY_RESULT_"

# MAC placeholders
MY_MAC = "02:00:00:00:00:01"
BROADCAST = "ff:ff:ff:ff:ff:ff"


# ---------------------------------------------------------
# Setup and utility functions
# ---------------------------------------------------------

def init_monitor():
    """
    Enable monitor mode on the specified Wi-Fi interface and channel.
    """
    print("[*] Setting up monitor mode...")
    print(f"[*] Interface: {INTERFACE}, Channel: {CHANNEL}")
    try:
        result = subprocess.run(
            ['sudo', './monitor-mode.sh', INTERFACE, str(CHANNEL)],
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout:
            print(result.stdout)
        time.sleep(1)
        print(f"[+] Monitor mode enabled on {INTERFACE} channel {CHANNEL}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error setting monitor mode: {e}")
        if e.stderr:
            print(f"    Error details: {e.stderr}")
        if e.stdout:
            print(f"    Output: {e.stdout}")
        return False
    except FileNotFoundError:
        print("[-] monitor-mode.sh not found in current directory.")
        print("    Ensure the script is present and executable (chmod +x).")
        return False


def fetch_mac():
    """
    Retrieve the MAC address for the active interface.
    """
    try:
        result = subprocess.run(
            ['cat', f'/sys/class/net/{INTERFACE}/address'],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except:
        return "02:00:00:00:00:01"


def make_frame(frame_type, payload=b"", dst="ff:ff:ff:ff:ff:ff"):
    """
    Construct a custom 802.11 frame with a given type and payload.
    """
    if isinstance(frame_type, str):
        frame_type = frame_type.encode()
    if isinstance(payload, str):
        payload = payload.encode()
    return (RadioTap() /
            Dot11(type=2, subtype=0, addr1=dst, addr2=MY_MAC, addr3=MY_MAC) /
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
            SNAP(OUI=0x000000, code=0x88B5) /
            Raw(load=frame_type + payload))


def read_payload(pkt):
    """
    Extract the raw payload from a Scapy packet if available.
    """
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    if pkt.haslayer(SNAP) and getattr(pkt[SNAP], "code", None) == 0x88B5:
        p = pkt[SNAP].payload
        return bytes(p.load) if hasattr(p, "load") else b""
    return b""


def read_rssi(pkt):
    """
    Extract RSSI value from the RadioTap header.
    """
    if pkt.haslayer(RadioTap):
        for attr in ['dBm_AntSignal', 'dbm_antsignal', 'dbmAntsignal']:
            if hasattr(pkt[RadioTap], attr):
                return getattr(pkt[RadioTap], attr)
    return None


# ---------------------------------------------------------
# Main Key Exchange Class
# ---------------------------------------------------------

class KeyExchangeDevice:
    """
    Represents a device participating in the RSSI-based key exchange.
    Handles all protocol phases: role setup, RSSI collection, key derivation,
    index exchange, and verification.
    """
    def __init__(self):
        self.role = None
        self.rssi_data = {}
        self.key_bits = {}
        self.final_key = ""
        self.partner_mac = None
        self.frame_received = threading.Event()
        self.received_frame_data = None

    def assign_role(self):
        """
        Phase 1: Determine whether the device acts as initiator or responder
        using a three-way handshake based on READY and ACK frames.
        """
        print("\n[*] Phase 1: Determining role...")
        print(f"[*] My MAC: {MY_MAC}")

        role_event = threading.Event()
        partner_mac = [None]
        final_role = ['initiator']
        send_ack = [False]

        def broadcast():
            while not role_event.is_set():
                frame = make_frame(FRAME_ACK if send_ack[0] else FRAME_READY,
                                   dst=partner_mac[0] if send_ack[0] else BROADCAST)
                sendp(frame, iface=INTERFACE, verbose=False)
                time.sleep(0.1)

        def listen():
            def handler(pkt):
                if role_event.is_set():
                    return True
                if not pkt.haslayer(Dot11) or pkt[Dot11].addr2 == MY_MAC:
                    return
                payload = read_payload(pkt)
                other_mac = pkt[Dot11].addr2

                if FRAME_READY in payload:
                    partner_mac[0] = other_mac
                    if MY_MAC.lower() > other_mac.lower():
                        final_role[0] = 'responder'
                        send_ack[0] = True
                        print(f"[+] RESPONDER role selected.")
                    else:
                        final_role[0] = 'initiator'
                        print(f"[+] INITIATOR role selected.")

                elif FRAME_ACK in payload:
                    if final_role[0] == 'initiator':
                        partner_mac[0] = other_mac
                        for _ in range(5):
                            sendp(make_frame(FRAME_ACK, dst=other_mac),
                                  iface=INTERFACE, verbose=False)
                            time.sleep(0.05)
                        role_event.set()
                    elif final_role[0] == 'responder' and send_ack[0]:
                        if other_mac == partner_mac[0]:
                            role_event.set()
                return

            sniff(iface=INTERFACE, prn=handler, stop_filter=lambda x: role_event.is_set())

        threading.Thread(target=broadcast, daemon=True).start()
        threading.Thread(target=listen, daemon=True).start()
        role_event.wait()

        self.role = final_role[0]
        self.partner_mac = partner_mac[0]
        print(f"[+] Final Role: {self.role.upper()} with Partner {self.partner_mac}")

    def send_frames(self):
        """
        Phase 2 (Initiator): Send frames with index payloads and record RSSI from responses.
        """
        print(f"\n[*] Phase 2: Initiator sending {NUM_FRAMES} frames...")
        print("[*] WAVE YOUR HAND between devices now!")
        time.sleep(2)

        for idx in range(NUM_FRAMES):
            payload = str(idx).encode()
            frame = make_frame(FRAME_DATA_PREFIX, payload, dst=self.partner_mac)
            self.frame_received.clear()
            self.received_frame_data = None

            def handler(pkt):
                if pkt.haslayer(Dot11) and pkt[Dot11].addr2 == self.partner_mac:
                    payload = read_payload(pkt)
                    if FRAME_DATA_PREFIX in payload:
                        try:
                            reply_idx = int(payload.decode().split('KEY_DATA_')[1])
                            if reply_idx == idx:
                                rssi = read_rssi(pkt)
                                if rssi is not None:
                                    self.received_frame_data = (idx, rssi)
                                    self.frame_received.set()
                        except:
                            pass

            sniffer = AsyncSniffer(iface=INTERFACE, prn=handler,
                                   stop_filter=lambda x: self.frame_received.is_set())
            sniffer.start()
            sendp(frame, iface=INTERFACE, verbose=False)

            if self.frame_received.wait(timeout=2):
                idx, rssi = self.received_frame_data
                self.rssi_data[idx] = rssi
            else:
                print(f"[WARN] No reply for frame {idx}")

            if sniffer.running:
                sniffer.stop()
            sniffer.join(timeout=1)
            if (idx + 1) % 50 == 0:
                print(f"[*] Progress: {idx + 1}/{NUM_FRAMES}")

        print(f"[+] Collected {len(self.rssi_data)} RSSI samples.")

    def recv_frames(self):
        """
        Phase 2 (Responder): Receive indexed frames and send responses.
        """
        print(f"\n[*] Phase 2: Responder collecting frames...")
        received = [0]

        def handler(pkt):
            if pkt.haslayer(Dot11) and pkt[Dot11].addr2 == self.partner_mac:
                payload = read_payload(pkt)
                if FRAME_DATA_PREFIX in payload:
                    try:
                        idx = int(payload.decode().split('KEY_DATA_')[1])
                        if idx not in self.rssi_data:
                            rssi = read_rssi(pkt)
                            if rssi is not None:
                                self.rssi_data[idx] = rssi
                                reply = make_frame(FRAME_DATA_PREFIX, str(idx), dst=self.partner_mac)
                                sendp(reply, iface=INTERFACE, verbose=False)
                                received[0] += 1
                                if received[0] % 50 == 0:
                                    print(f"[*] Progress: {received[0]}")
                    except:
                        pass

        sniff(iface=INTERFACE, prn=handler,
              stop_filter=lambda x: received[0] >= NUM_FRAMES,
              timeout=NUM_FRAMES)
        print(f"[+] Received {len(self.rssi_data)} RSSI samples.")

    def derive_bits(self):
        """
        Phase 3: Generate key bits based on RSSI deviation thresholds.
        """
        print("\n[*] Phase 3: Generating key bits...")
        if not self.rssi_data:
            print("[-] No RSSI data available.")
            sys.exit(1)

        values = list(self.rssi_data.values())
        mean, std = np.mean(values), np.std(values)
        upper, lower = mean + Z_THRESHOLD * std, mean - Z_THRESHOLD * std

        for idx, rssi in self.rssi_data.items():
            if rssi > upper:
                self.key_bits[idx] = 1
            elif rssi < lower:
                self.key_bits[idx] = 0

        print(f"[+] Generated {len(self.key_bits)} bits from RSSI data.")

        def share_indices(self):
        """
        Phase 4 (Initiator): Exchange index positions and build shared key.
        """
        print("\n[*] Phase 4: Sharing indices...")
        indices = sorted(self.key_bits.keys())
        indices_str = ','.join(map(str, indices))
        for _ in range(3):
            sendp(make_frame(FRAME_INDICES, indices_str, dst=self.partner_mac),
                  iface=INTERFACE, verbose=False)
            time.sleep(0.05)

        received = [False]
        common_indices = [None]

        def handler(pkt):
            if pkt.haslayer(Dot11) and pkt[Dot11].addr2 == self.partner_mac:
                payload = read_payload(pkt)
                if FRAME_INDICES in payload:
                    try:
                        s = payload.decode().split('KEY_INDICES_')[1]
                        common_indices[0] = [int(x) for x in s.split(',') if x]
                        received[0] = True
                        return True
                    except:
                        pass

        sniff(iface=INTERFACE, prn=handler, timeout=10.0,
              stop_filter=lambda x: received[0])

        if not received[0]:
            print("[-] Failed to receive common indices.")
            sys.exit(1)

        common = common_indices[0]
        self.final_key = ''.join(str(self.key_bits[i]) for i in common if i in self.key_bits)
        print(f"[+] Shared key length: {len(self.final_key)} bits")

        # --- Added section ---
        # Compute SHA-256 hash and print diagnostics
        final_hash = hashlib.sha256(self.final_key.encode()).hexdigest()
        print(f"[info] Generated key length: {len(self.final_key)} bits")
        print(f"[info] Final hash (SHA-256): {final_hash}")
        # ----------------------

    def recv_indices(self):
        """
        Phase 4 (Responder): Receive initiator indices and respond with common set.
        """
        print("\n[*] Phase 4: Receiving indices...")
        received = [False]
        indices_initiator = [None]

        def handler(pkt):
            if pkt.haslayer(Dot11) and pkt[Dot11].addr2 == self.partner_mac:
                payload = read_payload(pkt)
                if FRAME_INDICES in payload:
                    try:
                        s = payload.decode().split('KEY_INDICES_')[1]
                        indices_initiator[0] = [int(x) for x in s.split(',') if x]
                        received[0] = True
                        return True
                    except:
                        pass

        sniff(iface=INTERFACE, prn=handler, timeout=10.0,
              stop_filter=lambda x: received[0])

        if not received[0]:
            print("[-] Did not receive initiator indices.")
            sys.exit(1)

        mine, theirs = set(self.key_bits.keys()), set(indices_initiator[0])
        common = sorted(mine & theirs)
        indices_str = ','.join(map(str, common))
        for _ in range(3):
            sendp(make_frame(FRAME_INDICES, indices_str, dst=self.partner_mac),
                  iface=INTERFACE, verbose=False)
            time.sleep(0.05)

        self.final_key = ''.join(str(self.key_bits[i]) for i in common)
        print(f"[+] Shared key length: {len(self.final_key)} bits")

        # Compute SHA-256 hash and print diagnostics
        final_hash = hashlib.sha256(self.final_key.encode()).hexdigest()
        print(f"[info] Generated key length: {len(self.final_key)} bits")
        print(f"[info] Final hash (SHA-256): {final_hash}")


    def commit_key(self):
        """
        Phase 5 (Initiator): Send hash commitment and wait for verification.
        """
        print("\n[*] Phase 5: Committing key...")
        my_hash = hashlib.sha256(self.final_key.encode()).hexdigest()
        for _ in range(3):
            sendp(make_frame(FRAME_COMMIT, my_hash, dst=self.partner_mac),
                  iface=INTERFACE, verbose=False)
            time.sleep(0.05)

        received, match = [False], [False]

        def handler(pkt):
            if pkt.haslayer(Dot11) and pkt[Dot11].addr2 == self.partner_mac:
                payload = read_payload(pkt)
                if FRAME_RESULT in payload:
                    result = payload.decode().split('KEY_RESULT_')[1]
                    match[0] = (result == "MATCH")
                    received[0] = True
                    return True

        sniff(iface=INTERFACE, prn=handler, timeout=10.0,
              stop_filter=lambda x: received[0])

        if received[0]:
            print("[+] Keys match!" if match[0] else "[-] Key mismatch detected.")
        else:
            print("[-] No verification response received.")

    def verify_commit(self):
        """
        Phase 5 (Responder): Verify initiator key hash and respond with match result.
        """
        print("\n[*] Phase 5: Verifying key...")
        their_hash = [None]
        received = [False]

        def handler(pkt):
            if pkt.haslayer(Dot11) and pkt[Dot11].addr2 == self.partner_mac:
                payload = read_payload(pkt)
                if FRAME_COMMIT in payload:
                    try:
                        their_hash[0] = payload.decode().split('KEY_COMMIT_')[1]
                        received[0] = True
                        return True
                    except:
                        pass

        sniff(iface=INTERFACE, prn=handler, timeout=10.0,
              stop_filter=lambda x: received[0])

        if not received[0]:
            print("[-] No commitment received.")
            return

        my_hash = hashlib.sha256(self.final_key.encode()).hexdigest()
        if my_hash == their_hash[0]:
            result = b"MATCH"
            print("[+] Keys verified successfully.")
        else:
            result = b"MISMATCH"
            print("[-] Key mismatch detected.")

        for _ in range(3):
            sendp(make_frame(FRAME_RESULT, result, dst=self.partner_mac),
                  iface=INTERFACE, verbose=False)
            time.sleep(0.05)

    def run(self):
        """
        Execute all phases of the key exchange protocol.
        """
        self.assign_role()
        if self.role == 'initiator':
            self.send_frames()
        else:
            self.recv_frames()
        self.derive_bits()
        if self.role == 'initiator':
            self.share_indices()
        else:
            self.recv_indices()
        if self.role == 'initiator':
            self.commit_key()
        else:
            self.verify_commit()


# ---------------------------------------------------------
# Entry Point
# ---------------------------------------------------------

def main():
    global MY_MAC
    print("=" * 60)
    print("Wi-Fi RSSI-Based Key Exchange (Refactored)")
    print("=" * 60)

    if os.geteuid() != 0:
        print("[-] Must be run as root.")
        sys.exit(1)

    if not init_monitor():
        sys.exit(1)

    MY_MAC = fetch_mac()
    print(f"[*] My MAC: {MY_MAC}")

    device = KeyExchangeDevice()
    device.run()


if __name__ == "__main__":
    main()
