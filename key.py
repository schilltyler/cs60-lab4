'''
Key program
'''
from scapy.all import *
from statistics import stdev, sum

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

