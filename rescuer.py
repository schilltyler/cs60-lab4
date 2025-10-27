from scapy.all import *
import curses
import threading
from queue import Queue

output = []

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
    # Only process Dot11 frames (monitor mode)
    if packet.haslayer(Dot11):
        # Compare against the beacon’s destination MAC
        if packet.addr1 == "EF:53:3F:92:34:EF":
            # Safely get RSSI (may not exist on all drivers)
            if hasattr(packet, 'dBm_AntSignal'):
                rssi = packet.dBm_AntSignal
                q.put(f"RSSI: {rssi} dBm")
                output.append(rssi)

def sniffer(q):
    sniff(iface="wlxbc071d297881", prn=print_packet, store=False)

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
