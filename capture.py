# from scapy.layers.http import *
# from scapy.layers import *


from scapy.all import sniff, load_layer, Raw
from scapy.layers import *
from scapy.layers.tls.record import *
from scapy import packet

load_layer("http")
load_layer("tls")
def http_callback(packet):
    if packet.haslayer("HTTPRequest"):  # Check if the packet has an HTTP request layer
        print(f"HTTP Request: {packet.Method} {packet.Host}{packet.Path}")
def tls_callback(packet: packet):
    if packet.haslayer(TLS):
        client_hello = packet[TLS]

        # Extract source and destination IP/port
        src_ip = packet.src
        dst_ip = packet.dst
        src_port = packet.sport
        dst_port = packet.dport

        # Extract the Server Name Indication (SNI)
        sni = client_hello.servernames[0].servername.decode() if client_hello.servernames else "N/A"

        print(f"TLS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {sni}")

# Start sniffing (use an appropriate filter to capture only TCP packets)
sniff(filter="tcp", prn=tls_callback, store=False)
# sniff(filter="tcp port 80", prn=http_callback, store=False)