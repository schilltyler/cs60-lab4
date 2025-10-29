"""
Used LLM to modify packet format (to Dot11)
"""

from scapy.all import *
import subprocess

subprocess.run(["bash", "monitor-mode.sh", "wlan0", "2"])

dot11 = Dot11(type=0, subtype=8,
              addr1="ff:ff:ff:ff:ff:ff",
              addr2="bc:07:1d:74:50:df",
              addr3="bc:07:1d:74:50:df")

beacon = Dot11Beacon(cap="ESS")
essid = Dot11Elt(ID="SSID", info="Survivor Beacon", len=15)

frame = RadioTap()/dot11/beacon/essid

try:
    sendp(frame, iface="wlan0", inter=0.1, loop=1, verbose=False)
except KeyboardInterrupt:
    print("\nStopped beacon transmission")
