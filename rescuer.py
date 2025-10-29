"""
Rescuer script.

Used LLM to modify packet format (to Dot 11).
"""

from scapy.all import *
import curses
import threading
from queue import Queue
import subprocess

output = []

subprocess.run(["bash", "monitor-mode.sh", "wlan0", "2"])

def ncurses(q):
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.scrollok(True)

    try:
        while True:
            data = q.get()
            stdscr.addstr(f"{data}\n")
            stdscr.refresh()
    except KeyboardInterrupt:
        curses.endwin()

def print_packet(packet):
    if packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11Elt):
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
        if ssid == "Survivor Beacon":
            rssi = getattr(packet, 'dBm_AntSignal', None)
            if rssi is not None:
                q.put(f"Beacon from {packet.addr2} | RSSI: {rssi} dBm")
                output.append(rssi)

def sniffer(q):
    sniff(iface="wlan0", prn=print_packet, store=False)

q = Queue()

thread1 = threading.Thread(target=ncurses, args=(q,))
thread2 = threading.Thread(target=sniffer, args=(q,))

thread1.start()
thread2.start()

try:
    thread1.join()
    thread2.join()
except KeyboardInterrupt:
    print("\nProgram stopped")
