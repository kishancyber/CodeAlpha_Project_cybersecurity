import threading
import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Packet handler function
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        if packet.haslayer(TCP):
            log.insert(tk.END, f"TCP Packet: {ip_src} -> {ip_dst}\n")
        elif packet.haslayer(UDP):
            log.insert(tk.END, f"UDP Packet: {ip_src} -> {ip_dst}\n")
        elif packet.haslayer(ICMP):
            log.insert(tk.END, f"ICMP Packet: {ip_src} -> {ip_dst}\n")
        else:
            log.insert(tk.END, f"Other IP Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})\n")

# Start sniffer
def start_sniffer(interface):
    sniff(iface=interface, prn=packet_handler, store=0)

# GUI Setup
def start_sniffing():
    interface = entry.get()
    thread = threading.Thread(target=start_sniffer, args=(interface,))
    thread.start()

root = tk.Tk()
root.title("Network Sniffer")
root.geometry("600x400")

frame = tk.Frame(root)
frame.pack()

entry = tk.Entry(frame)
entry.pack(side=tk.LEFT)

start_button = tk.Button(frame, text="Start Sniffer", command=start_sniffing)
start_button.pack(side=tk.LEFT)

log = tk.Text(root)
log.pack(fill=tk.BOTH, expand=1)

root.mainloop()
