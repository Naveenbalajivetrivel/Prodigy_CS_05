from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = None
        
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        else:
            proto = "Other"
        
        print(f"Protocol: {proto}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        if proto == "TCP" or proto == "UDP":
            print(f"Source Port: {packet[proto].sport}")
            print(f"Destination Port: {packet[proto].dport}")

        print(f"Payload: {str(bytes(packet[IP].payload))}\n")

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
