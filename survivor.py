from scapy.all import *

# ether destination is random MAC I got from searching random MAC online
#frame = RadioTap() / Ether(dst="EF:53:3F:92:34:EF", src="96:66:7b:64:96:f0")
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="08:00:27:6e:81:3e", addr3="08:00:27:6e:81:3e")
frame = RadioTap()/dot11
try:
    while True:
        sendp(frame, verbose=False)

except KeyboardInterrupt:
    print("Program stopped")
