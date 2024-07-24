from scapy.all import sniff

def packet_callback(packet):
    try:
         if packet.haslayer('IP'):
             ip_src = packet['IP'].src
             ip_dst = packet['IP'].dst
             print(f"Packet: {ip_src} -> {ip_dst}")
             if packet.haslayer('TCP'):
                 print(f"TCP Packet: {packet['IP'].src}:{packet['TCP'].sport} -> {packet['IP'].dst}:{packet['TCP'].dport}")
             elif packet.haslayer('UDP'):
                 print(f"UDP Packet: {packet['IP'].src}:{packet['UDP'].sport} -> {packet['IP'].dst}:{packet['UDP'].dport}")
             elif packet.haslayer('ICMP'):
                 print(f"ICMP Packet: {packet['IP'].src} -> {packet['IP'].dst}")
     except Exception as e:
         print(f"Error processing packet: {e}")

def start_sniffing():
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
