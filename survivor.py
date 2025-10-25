from scapy.all import *

# ether destination is random MAC I got from searching random MAC online
frame = RadioTap() / Ether(dst="EF:53:3F:92:34:EF", src="96:66:7b:64:96:f0")

try:
    while True:
        sendp(frame, verbose=False)

except KeyboardInterrupt:
    print("Program stopped")
