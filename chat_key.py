#!/usr/bin/env python3
"""
Wi-Fi RSSI-based Key Exchange Protocol
Implements automatic role determination and symmetric key generation
Assistance with LLMs for bytes manipulation, index communication, hash-based verification, 
packet filtering, and debugging. Most functions were refactored/reformatted with the help of AI.
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
INTERFACE = "wlan0"  # Interface name 
CHANNEL = 1          # Channel Number
NUM_FRAMES = 300
TIMEOUT_ROLE = 5  # seconds to listen for initiator
Z_THRESHOLD = 1.5  # standard deviations for key generation

# Frame types
FRAME_READY = b"KEY_EXCHANGE_READY_V1"
FRAME_ACK = b"KEY_EXCHANGE_ACK_V1"
FRAME_DATA_PREFIX = b"KEY_DATA_"
FRAME_INDICES = b"KEY_INDICES_"
FRAME_COMMIT = b"KEY_COMMIT_"
FRAME_RESULT = b"KEY_RESULT_"

# MAC addresses (To be set in runtime)
MY_MAC = "02:00:00:00:00:01"  
BROADCAST = "ff:ff:ff:ff:ff:ff"


def setup_monitor_mode():
    """Initialize monitor mode using the script with interface and channel arguments"""
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
        print("[-] set_monitor_mode.sh not found in current directory")
        print("    Make sure the script is present and executable (chmod +x set_monitor_mode.sh)")
        return False


def get_my_mac():
    """Get the MAC address of our interface"""
    try:
        result = subprocess.run(['cat', f'/sys/class/net/{INTERFACE}/address'], 
                              capture_output=True, text=True, check=True)
        mac = result.stdout.strip()
        return mac
    except:
        # Fallback to a random MAC if we can't read it
        return "02:00:00:00:00:01"


# GenAI helped identify that addr3 inconsistency can cause packet filtering and also suggesting using 
# an experimental ID for SNAP instead of IPv4s
def create_frame(frame_type, payload=b"", dst="ff:ff:ff:ff:ff:ff"):
    if isinstance(frame_type, str): frame_type = frame_type.encode()
    if isinstance(payload, str):    payload = payload.encode()
    return (RadioTap() /
            Dot11(type=2, subtype=0, addr1=dst, addr2=MY_MAC, addr3=MY_MAC) /
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
            SNAP(OUI=0x000000, code=0x88B5) /   # IEEE experimental Ethertype
            Raw(load=frame_type + payload))

def extract_payload(pkt):
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    if pkt.haslayer(SNAP) and getattr(pkt[SNAP], "code", None) == 0x88B5:
        p = pkt[SNAP].payload
        return bytes(p.load) if hasattr(p, "load") else b""
    return b""


def get_rssi(pkt):
    """Extract RSSI from RadioTap header"""
    if pkt.haslayer(RadioTap):
        try:
            if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                return pkt[RadioTap].dBm_AntSignal
            elif hasattr(pkt[RadioTap], 'dbm_antsignal'):
                return pkt[RadioTap].dbm_antsignal
            elif hasattr(pkt[RadioTap], 'dbmAntsignal'):
                return pkt[RadioTap].dbmAntsignal
        except:
            pass
    return None


class KeyExchangeDevice:
    def __init__(self):
        self.role = None
        self.rssi_data = {}
        self.key_bits = {}
        self.final_key = ""
        self.partner_mac = None
        self.stop_sniffing = False
        self.frame_received = threading.Event()
        self.received_frame_data = None
    
    def determine_role(self):
      """Phase 1: Simultaneous broadcast & listen with three-way handshake"""
      print("\n[*] Phase 1: Determining role...")
      print(f"[*] My MAC: {MY_MAC}")

      # Shared state
      role_determined = threading.Event()  # Kill switch
      partner_mac = [None]
      final_role = ['initiator']  # Default to initiator
      send_ack = [False]  # Flag for responder to send ACK

      def broadcast_thread():
          """Continuously broadcast READY frames, then ACKs if responder"""
          while not role_determined.is_set():
              if send_ack[0]:
                  # Responder mode: send ACK to initiator
                  ack_frame = create_frame(FRAME_ACK, dst=partner_mac[0])
                  sendp(ack_frame, iface=INTERFACE, verbose=False)
              else:
                  # Initial mode: broadcast READY
                  ready_frame = create_frame(FRAME_READY)
                  sendp(ready_frame, iface=INTERFACE, verbose=False)
              time.sleep(0.1)

      def listen_thread():
          """Listen for READY or ACK frames and determine role immediately"""
          def packet_handler(pkt):
              if role_determined.is_set():
                  return True
            

              try:
                  if not pkt.haslayer(Dot11) or pkt[Dot11].addr2 == MY_MAC:
                      return

                  payload = extract_payload(pkt)
                  other_mac = pkt[Dot11].addr2
                  # Heard READY frame - collision detected
                  if FRAME_READY in payload:
                      print(f"[!] Collision detected with {other_mac}")
                      partner_mac[0] = other_mac

                      # Compare MACs to determine role
                      if MY_MAC.lower() > other_mac.lower():
                          final_role[0] = 'responder'
                          print(f"[+] Becoming RESPONDER (lower MAC)")
                          print("[*] Sending ACK to initiator...")

                          # Switch to sending ACKs (broadcast thread will handle it)
                          # Don't set role_determined yet - wait for final ACK
                          send_ack[0] = True

                      else:
                          # Don't set role_determined yet - wait for ACK
                          final_role[0] = 'initiator'
                          print(f"[+] Becoming INITIATOR (higher MAC)")
                          print("[*] Waiting for ACK from responder...")

                  # Heard ACK frame
                  
                  elif FRAME_ACK in payload:
                      if final_role[0] == 'initiator':
                          # Initiator receiving ACK from responder (step 2 of handshake)
                          print(f"[+] Received ACK from responder {other_mac}")
                          partner_mac[0] = other_mac

                          # Send final ACK to complete handshake (step 3)
                          print("[*] Sending final ACK to complete handshake...")
                          for _ in range(5):
                              final_ack = create_frame(FRAME_ACK, dst=other_mac)
                              sendp(final_ack, iface=INTERFACE, verbose=False)
                              time.sleep(0.05)

                          role_determined.set()
                          return True

                      elif final_role[0] == 'responder' and send_ack[0]:
                          # Responder receiving final ACK from initiator (step 3 of handshake)
                          if other_mac == partner_mac[0]:
                              print(f"[+] Received final ACK from initiator {other_mac}")
                              role_determined.set()
                              return True

              except Exception as e:
                  pass

          # Listen indefinitely until role is determined
          sniff(iface=INTERFACE, prn=packet_handler,
                stop_filter=lambda x: role_determined.is_set())

      # Start both threads
      broadcaster = threading.Thread(target=broadcast_thread, daemon=True)
      listener = threading.Thread(target=listen_thread, daemon=True)

      broadcaster.start()
      listener.start()

      # Wait for role determination (no timeout - wait indefinitely)
      role_determined.wait()

      # Set the final state
      self.role = final_role[0]
      self.partner_mac = partner_mac[0]

      print(f"[+] Final role: {self.role.upper()}")
      print(f"[+] Partner MAC: {self.partner_mac}")
      print("[+] Three-way handshake complete!")

    def exchange_frames_initiator(self):
        """Phase 2: Initiator sends indexed frames and receives replies"""
        print(f"\n[*] Phase 2: Exchanging {NUM_FRAMES} frames...")
        print("[*] WAVE YOUR HAND between the devices NOW!")
        time.sleep(2)
        
        for idx in range(NUM_FRAMES):
            # Send frame with index
            payload = str(idx).encode()
            frame = create_frame(FRAME_DATA_PREFIX, payload, dst=self.partner_mac)
            
            # Setup listener for reply
            self.frame_received.clear()
            self.received_frame_data = None
            
            def reply_handler(pkt):
                try:
                    if pkt.haslayer(Dot11):
                        if pkt[Dot11].addr2 == self.partner_mac:
                            payload = extract_payload(pkt)
                            if FRAME_DATA_PREFIX in payload:
                                # Extract index from reply
                                try:
                                    payload_str = payload.decode('utf-8', errors='ignore')
                                    reply_idx_str = payload_str.split('KEY_DATA_')[1]
                                    reply_idx = int(reply_idx_str)
                                    
                                    if reply_idx == idx:
                                        rssi = get_rssi(pkt)
                                        if rssi is not None:
                                            self.received_frame_data = (idx, rssi)
                                            self.frame_received.set()
                                            return
                                except Exception as e:
                                    print(f"[DEBUG] reply_handler parse error: {e}")
                                    pass
                except Exception as e:
                    print(f"[DEBUG] reply_handler error: {e}")
                    pass
                return
            
            # Start listening
            sniffer = AsyncSniffer(iface=INTERFACE, prn=reply_handler,
                                 stop_filter=lambda x: self.frame_received.is_set())
            sniffer.start()
            
            # Send frame
            sendp(frame, iface=INTERFACE, verbose=False)
            
            # Wait for reply
            if self.frame_received.wait(timeout=2):
                idx, rssi = self.received_frame_data
                self.rssi_data[idx] = rssi
            else:
                print(f"[WARN] No reply for frame {idx}")

            if sniffer.running:
                sniffer.stop()
            sniffer.join(timeout=1)
            
            # Progress indicator
            if (idx + 1) % 50 == 0:
                print(f"[*] Progress: {idx + 1}/{NUM_FRAMES} frames")
        
        print(f"[+] Received {len(self.rssi_data)}/{NUM_FRAMES} frames")
    
    def exchange_frames_responder(self):
        """Phase 2: Responder receives indexed frames and replies"""
        print(f"\n[*] Phase 2: Exchanging {NUM_FRAMES} frames...")
        print("[*] WAVE YOUR HAND between the devices NOW!")
        
        received_count = [0]
        
        def frame_handler(pkt):
            try:
                if pkt.haslayer(Dot11):
                    if pkt[Dot11].addr2 == self.partner_mac:
                        payload = extract_payload(pkt)
                        if FRAME_DATA_PREFIX in payload:
                            try:
                                # Extract index
                                payload_str = payload.decode('utf-8', errors='ignore')
                                idx_str = payload_str.split('KEY_DATA_')[1]
                                idx = int(idx_str)
                                # Only process each index once
                                if idx not in self.rssi_data:
                                    # Measure RSSI
                                    rssi = get_rssi(pkt)
                                    if rssi is not None:
                                        self.rssi_data[idx] = rssi
                                        
                                        # Immediately reply with same index
                                        reply_payload = str(idx).encode()
                                        reply = create_frame(FRAME_DATA_PREFIX, reply_payload, 
                                                           dst=self.partner_mac)
                                        sendp(reply, iface=INTERFACE, verbose=False)
                                        
                                        received_count[0] += 1
                                        if received_count[0] % 50 == 0:
                                            print(f"[*] Progress: {received_count[0]} frames")
                                        
                                        # Stop after receiving NUM_FRAMES
                                        if received_count[0] >= NUM_FRAMES:
                                            return
                            except Exception as e:
                                print(f"[DEBUG] frame_handler parse error: {e}")
                                pass
            except Exception as e:
                print(f"[DEBUG] frame_handler error: {e}")
                pass
            return
        
        # Listen for frames
        sniff(iface=INTERFACE, prn=frame_handler, 
              stop_filter=lambda x: received_count[0] >= NUM_FRAMES,
              timeout=NUM_FRAMES * 1.0)
        
        print(f"[+] Received {len(self.rssi_data)}/{NUM_FRAMES} frames")
    
    def generate_key_bits(self):
        """Phase 3: Generate key bits from RSSI measurements"""
        print("\n[*] Phase 3: Generating key bits from RSSI...")
        
        if len(self.rssi_data) == 0:
            print("[-] No RSSI data collected!")
            sys.exit(1)
        
        rssi_values = list(self.rssi_data.values())
        mean = np.mean(rssi_values)
        std = np.std(rssi_values)
        
        print(f"[*] RSSI Statistics:")
        print(f"    Mean: {mean:.2f} dBm")
        print(f"    Std Dev: {std:.2f} dBm")
        print(f"    Min: {min(rssi_values)} dBm, Max: {max(rssi_values)} dBm")
        print(f"    Threshold: ±{Z_THRESHOLD} std dev")
        
        upper_threshold = mean + Z_THRESHOLD * std
        lower_threshold = mean - Z_THRESHOLD * std
        
        print(f"    Upper threshold: {upper_threshold:.2f} dBm")
        print(f"    Lower threshold: {lower_threshold:.2f} dBm")
        
        print(self.rssi_data.items())  # Debugging line to show RSSI data
        for idx, rssi in self.rssi_data.items():
            if rssi > upper_threshold:
                self.key_bits[idx] = 1
            elif rssi < lower_threshold:
                self.key_bits[idx] = 0
        
        print(f"[+] Generated {len(self.key_bits)} key bits from {len(self.rssi_data)} measurements")
        
        # Show some example indices
        if len(self.key_bits) > 0:
            sample_indices = sorted(self.key_bits.keys())[:10]
            print(f"    Sample indices used: {sample_indices}...")
    
    def exchange_indices_initiator(self):
        """Phase 4: Exchange indices to find common bits"""
        print("\n[*] Phase 4: Finding common indices...")
        
        # Send our indices to responder
        my_indices = sorted(self.key_bits.keys())
        indices_str = ','.join(map(str, my_indices))
        
        print(f"[*] Sending {len(my_indices)} indices to responder...")
        
        # Send multiple times for reliability
        for _ in range(3):
            frame = create_frame(FRAME_INDICES, indices_str.encode(), dst=self.partner_mac)
            sendp(frame, iface=INTERFACE, verbose=False)
            time.sleep(0.05)
        
        # Wait for common indices from responder
        print("[*] Waiting for common indices...")

        common_received = [False]
        common_indices = [None]
        
        def indices_handler(pkt):
            try:
                if pkt.haslayer(Dot11):
                    if pkt[Dot11].addr2 == self.partner_mac:
                        payload = extract_payload(pkt)
                        if FRAME_INDICES in payload:
                            try:
                                payload_str = payload.decode('utf-8', errors='ignore')
                                indices_str = payload_str.split('KEY_INDICES_')[1]
                                indices = [int(x) for x in indices_str.split(',') if x]
                                common_indices[0] = indices
                                common_received[0] = True
                                return True
                            except:
                                pass
            except:
                pass
            return
        
        sniff(iface=INTERFACE, prn=indices_handler, timeout=10.0,
              stop_filter=lambda x: common_received[0])
        
        if not common_received[0]:
            print("[-] Failed to receive common indices!")
            sys.exit(1)
        
        # Build final key from common indices
        common = common_indices[0]
        self.final_key = ''.join(str(self.key_bits[idx]) for idx in common if idx in self.key_bits)
        
        print(f"[+] Common indices: {len(common)}")
        print(f"[+] Final key length: {len(self.final_key)} bits")
        print(f"[+] Final key: {self.final_key}")
    
    def exchange_indices_responder(self):
        """Phase 4: Receive indices and send back common ones"""
        print("\n[*] Phase 4: Finding common indices...")
        
        # Wait for initiator indices
        print("[*] Waiting for initiator indices...")
        
        initiator_indices = [None]
        indices_received = [False]
        
        def indices_handler(pkt):
            try:
                if pkt.haslayer(Dot11):
                    if pkt[Dot11].addr2 == self.partner_mac:
                        payload = extract_payload(pkt)
                        if FRAME_INDICES in payload:
                            try:
                                payload_str = payload.decode('utf-8', errors='ignore')
                                indices_str = payload_str.split('KEY_INDICES_')[1]
                                indices = [int(x) for x in indices_str.split(',') if x]
                                initiator_indices[0] = indices
                                indices_received[0] = True
                                return True
                            except:
                                pass
            except:
                pass
            return
        
        sniff(iface=INTERFACE, prn=indices_handler, timeout=10.0,
              stop_filter=lambda x: indices_received[0])
        
        if not indices_received[0]:
            print("[-] Failed to receive initiator indices!")
            sys.exit(1)
        
        # Find common indices
        my_indices = set(self.key_bits.keys())
        their_indices = set(initiator_indices[0])
        common = sorted(my_indices & their_indices)
        
        print(f"[+] My indices: {len(my_indices)}")
        print(f"[+] Their indices: {len(their_indices)}")
        print(f"[+] Common indices: {len(common)}")
        
        # Send common indices back (multiple times for reliability)
        indices_str = ','.join(map(str, common))
        for _ in range(3):
            frame = create_frame(FRAME_INDICES, indices_str.encode(), dst=self.partner_mac)
            sendp(frame, iface=INTERFACE, verbose=False)
            time.sleep(0.05)
        
        # Build final key
        self.final_key = ''.join(str(self.key_bits[idx]) for idx in common)
        print(f"[+] Final key length: {len(self.final_key)} bits")
        print(f"[+] Final key: {self.final_key}")
    
    def verify_key_initiator(self):
        """Phase 5: Commit to key and verify match"""
        print("\n[*] Phase 5: Verifying key match...")
        
        # Compute hash of our key
        my_hash = hashlib.sha256(self.final_key.encode()).hexdigest()
        
        print(f"[*] My key hash: {my_hash[:16]}...")
        print("[*] Sending commitment to responder...")
        
        # Send commitment (multiple times)
        for _ in range(3):
            frame = create_frame(FRAME_COMMIT, my_hash.encode(), dst=self.partner_mac)
            sendp(frame, iface=INTERFACE, verbose=False)
            time.sleep(0.05)
        
        # Wait for verification result
        print("[*] Waiting for verification result...")
        
        result_received = [False]
        match_result = [False]
        
        def result_handler(pkt):
            try:
                if pkt.haslayer(Dot11):
                    if pkt[Dot11].addr2 == self.partner_mac:
                        payload = extract_payload(pkt)
                        if FRAME_RESULT in payload:
                            payload_str = payload.decode('utf-8', errors='ignore')
                            result = payload_str.split('KEY_RESULT_')[1]
                            match_result[0] = (result == "MATCH")
                            result_received[0] = True
                            return True
            except:
                pass
            return
        
        sniff(iface=INTERFACE, prn=result_handler, timeout=10.0,
              stop_filter=lambda x: result_received[0])
        
        if result_received[0]:
            if match_result[0]:
                print("\n" + "="*60)
                print("[+] SUCCESS! Keys match!")
                print(f"[+] Shared key: {self.final_key}")
                print(f"[+] Key length: {len(self.final_key)} bits")
                print(f"[+] Key hash: {my_hash}")
                print("="*60)
            else:
                print("\n[-] FAILURE: Keys do not match!")
        else:
            print("[-] No response from responder")
    
    def verify_key_responder(self):
        """Phase 5: Receive commitment and verify"""
        print("\n[*] Phase 5: Verifying key match...")
        
        # Wait for commitment
        print("[*] Waiting for initiator commitment...")
        
        their_hash = [None]
        commit_received = [False]
        
        def commit_handler(pkt):
            try:
                if pkt.haslayer(Dot11):
                    if pkt[Dot11].addr2 == self.partner_mac:
                        payload = extract_payload(pkt)
                        if FRAME_COMMIT in payload:
                            payload_str = payload.decode('utf-8', errors='ignore')
                            hash_val = payload_str.split('KEY_COMMIT_')[1]
                            their_hash[0] = hash_val
                            commit_received[0] = True
                            return True
            except:
                pass
            return
        
        sniff(iface=INTERFACE, prn=commit_handler, timeout=10.0,
              stop_filter=lambda x: commit_received[0])
        
        if not commit_received[0]:
            print("[-] Failed to receive commitment!")
            return
        
        # Verify our key matches
        my_hash = hashlib.sha256(self.final_key.encode()).hexdigest()
        
        print(f"[*] Their hash: {their_hash[0][:16]}...")
        print(f"[*] My hash:    {my_hash[:16]}...")
        
        if my_hash == their_hash[0]:
            print("\n" + "="*60)
            print("[+] SUCCESS! Keys match!")
            print(f"[+] Shared key: {self.final_key}")
            print(f"[+] Key length: {len(self.final_key)} bits")
            print(f"[+] Key hash: {my_hash}")
            print("="*60)
            
            # Send success (multiple times)
            for _ in range(3):
                frame = create_frame(FRAME_RESULT, b"MATCH", dst=self.partner_mac)
                sendp(frame, iface=INTERFACE, verbose=False)
                time.sleep(0.05)
        else:
            print("\n[-] FAILURE: Keys do not match!")
            
            # Send failure
            for _ in range(3):
                frame = create_frame(FRAME_RESULT, b"MISMATCH", dst=self.partner_mac)
                sendp(frame, iface=INTERFACE, verbose=False)
                time.sleep(0.05)
    
    def run(self):
        """Main execution flow"""
        # Phase 1: Determine role
        self.determine_role()
        
        # Phase 2: Exchange frames
        if self.role == 'initiator':
            self.exchange_frames_initiator()
        else:
            self.exchange_frames_responder()
        
        # Phase 3: Generate key bits
        self.generate_key_bits()
        
        # Phase 4: Exchange indices
        if self.role == 'initiator':
            self.exchange_indices_initiator()
        else:
            self.exchange_indices_responder()
        
        # Phase 5: Verify key
        if self.role == 'initiator':
            self.verify_key_initiator()
        else:
            self.verify_key_responder()


def main():
    global MY_MAC
    
    print("="*60)
    print("Wi-Fi RSSI-Based Key Exchange")
    print("="*60)
    
    # Check for root
    if os.geteuid() != 0:
        print("[-] This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Setup monitor mode
    if not setup_monitor_mode():
        sys.exit(1)
    
    # Get MAC address
    MY_MAC = get_my_mac()
    print(f"[*] My MAC: {MY_MAC}")
    
    # Run key exchange
    device = KeyExchangeDevice()
    device.run()


if __name__ == "__main__":
    main()