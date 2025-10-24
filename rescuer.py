import curses

stdscr = curses.initscr()

'''
- use ethernet frame layer
- you get a src and dest MAC
- given that the rescuers will be in monitor mode,
we just need to send to any MAC address, don't need
to broadcast
- we can look at the IAAA website and find a MAC address
that has a high likelyhood of not being used
- there is a very VERY small chance that someone shows up
on the network with that MAC address, so you could just stop here
- however, if you really want to be sure, you can add some bytes
in the payload that say "hey I'm a survivor beacon"
'''

'''
How do we construct our survivor program?
Do we want to create a ping-like program?
What is a RadioTap header?
- When you send a RadioTap header it will track RSSI and other
data
'''

'''
How do we look through network traffic?
Could we make this easier by going up to the tcp layer
in the previous part, and thus we have a port to listen on?
How do we measure RSSI?
- Scapy has a layer for RSSI
'''
