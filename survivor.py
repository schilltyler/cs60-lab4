from scapy.all import *

dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
              addr2="08:00:27:6e:81:3e", addr3="08:00:27:6e:81:3e")

beacon = Dot11Beacon(cap="ESS")
essid = Dot11Elt(ID="SSID", info="Survivor Beacon", len=15)

frame = RadioTap()/dot11/beacon/essid

try:
    while True:
        sendp(frame, iface="wlxbc071d297881", inter=0.1, loop=1, verbose=False)
except KeyboardInterrupt:
    print("Stopped beacon transmission")
