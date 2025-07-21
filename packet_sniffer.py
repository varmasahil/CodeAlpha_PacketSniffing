from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import argparse
import pyfiglet
from datetime import datetime

def packet_callback(packet):
    """Process each captured packet and display relevant information"""
    print("\n" + "="*50)
    print(f"[+] New Packet: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Display Ethernet frame information
    if Ether in packet:
        ether = packet[Ether]
        print("\n[ Ethernet Frame ]")
        print(f"Source MAC: {ether.src}")
        print(f"Destination MAC: {ether.dst}")
        print(f"Type: {ether.type}")
       
    # Display IP layer information
    if IP in packet:
        ip = packet[IP]
        print("\n[IP Header]")
        print(f"Source IP: {ip.src}")
        print(f"Destination IP: {ip.dst}")
        print(f"Protocol: {ip.proto}")
        print(f"TTL: {ip.ttl}")
        print(f"Length: {ip.len}")
       
    # Display TCP information if present
    if TCP in packet:
        tcp = packet[TCP]
        print("\n[TCP Segment]")
        print(f"Source Port: {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print(f"Sequence Number: {tcp.seq}")
        print(f"Acknowledgment Number: {tcp.ack}")
        print(f"Flags: {tcp.flags}")
        print(f"Window Size: {tcp.window}")
      
        # Show payload if present
        if len(tcp.payload) > 0:
            print("\n[Payload]")
            try:
                payload = bytes(tcp.payload).decode('utf-8', errors='ignore')
                print(payload[:200])  # Print first 200 chars to avoid flooding
            except:
                print("Binary data")
          
    # Display UDP information if present
    elif UDP in packet:
        udp = packet[UDP]
        print("\n[UDP Datagram]")
        print(f"Source Port: {udp.sport}")
        print(f"Destination Port: {udp.dport}")
        print(f"Length: {udp.len}")
      
        # Show payload if present
        if len(udp.payload) > 0:
            print("\n[ Payload ]")
            try:
                payload = bytes(udp.payload).decode('utf-8', errors='ignore')
                print(payload[:200])  # Print first 200 chars
            except:
                print("Binary data")
            
    print("="*50 + "\n")
   
def start_sniffing(interface, count=0, filter_exp=None):
    """Start packet sniffing on the specified interface"""
    print(f"[*] Starting packet capture on interface {interface}...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        sniff(iface=interface, prn=packet_callback, count=count, filter=filter_exp, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
    except Exception as e:
        print(f"[!] Error: {e}")
       
def main():
    # Display banner
    banner = pyfiglet.figlet_format("Packet Sniffer", font="slant")
    print(banner)
    print("Network Traffic Analyzer\n")
    
    # Set up argument parser 
    parser = argparse.ArgumentParser(description="Network Packet Capture and Analysis Tool")
    parser.add_argument("-i", "--interface", help="Network interface to capture on", required=True)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 for unlimited)", default=0)
    parser.add_argument("-f", "--filter", help="BPF filter expression (e.g 'tcp port 80')")
    
    args = parser.parse_args()
    
    # Start packet capture 
    start_sniffing(interface=args.interface, count=args.count, filter_exp=args.filter)
    
if __name__ == "__main__":
    main()

