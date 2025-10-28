'''
Key program
'''
from scapy.all import *
from statistics import stdev, sum
import time

'''
frame = RadioTap() / Ether(dst="E0:DD:AC:54:59:49", src="b6:0b:8a:51:4d:5e")

def analyze_frame(packet):
    # do something

sniff(iface="wlp0s20f0u9", prn=analyze_frame)

# rapid send packets
indeces[]
rssi_vals[]
for i in range(300):
    reply = srp(frame)
    if reply != None:
        indeces.append(reply.) # figure out how to encode index
        rssi_vals.append(reply.dBM_AntSignal)

# calculate avg and standard deviation
avg = sum(rssi_vals) / len(rssi_vals)
std_dev = stdev(rssi_vals)

z_value = 1
new_bit = 0;
for i in range(rssi_vals):
    if (rssi_vals[i] > avg + (z_value * std_dev)):
        new_bit = 1
        key = (key << 1) | new_bit
    else:
        new_bit = 0
        key = (key << 1) | new_bit


dot11 = Dot11(type=0, subtype=8,
              addr1="ff:ff:ff:ff:ff:ff",
              addr2="8a:36:19:76:a6:7e",
              addr3="8a:36:19:76:a6:7e")

'''



def process_packet(packet):
    nonlocal responder
    nonlocal response
    if packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11Elt):
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
        if ssid == "Ready to Begin":
            beacon = Dot11Beacon(cap="ESS")
            essid = Dot11Elt(ID="SSID", info="Ready to Exchange", len=14)

            ack_frame = RadioTap()/dot11/beacon/essid
            sendp(frame, iface="wlp0s20f0u9", inter=0.1, loop=1, verbose=False)
            responder = True
            print("I am the responder")

        if ssid == "Ready to Exchange":
            response = True
            print("I am the initiator")

def sniffer(q):
    sniff(iface="wlp0s20f0u9", prn=process_packet, store=False)

def sender(q):
    time.sleep(3)
    if responder == False:
        beacon = Dot11Beacon(cap="ESS")
        essid = Dot11Elt(ID="SSID", info="Ready to Begin", len=14)
        frame = RadioTap()/dot11/beacon/essid
        
        while response != True:
            sendp(frame, iface="wlp0s20f0u9", inter=0.1, verbose=False)


responder = False
response = False
q = Queue()

thread1 = thread.Thread(target=sniffer, args=(q, ))
thread2 = thread.Thread(target=sender, args=(q, ))

thread1.start()
thread2.start()

thread1.join()
thread2.join()


except KeyboardInterrupt:
    print("Program stopped")
