# from scapy.layers.http import *
# from scapy.layers import *


from scapy.all import * #sniff, load_layer
# from scapy.layers import *
# from scapy.layers.tls.record import *
from scapy.packet import Packet

load_layer("http")
load_layer("tls")
load_layer("dns")

def callback(packet: Packet):
    if packet.haslayer("HTTPRequest"):
        method = packet.Method.split("'")[1]
        if method == "GET" or method == "POST":
            print(f"HTTP Request: {method} {packet.Host.split("'")[1]}{packet.Path.split("'")[1]}")
    if packet.haslayer("TLS"):
        client_hello = packet["TLS"]

        src_ip = packet.src
        dst_ip = packet.dst
        src_port = packet.sport
        dst_port = packet.dport

        sni = client_hello.servernames[0].servername.decode("utf-8") if client_hello.servernames else "N/A"
        print(client_hello.servernames if client_hello.servernames else "N/A")

        print(f"TLS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {sni}")
    if packet.haslayer("DNS"):
        DNSRequest = packet["DNS"]

        src_ip = packet.src
        dst_ip = packet.dst
        src_port = packet.sport
        dst_port = packet.dport

        if DNSRequest["qtype"] == "A":
            print(f"DNS A Record: {src_ip}:{src_port} -> {dst_ip}:{dst_port} {DNSRequest["qname"]}")

# def http_callback(packet):
#     if packet.haslayer("HTTPRequest"):  # Check if the packet has an HTTP request layer
#         print(f"HTTP Request: {packet.Method} {packet.Host}{packet.Path}")
# def tls_callback(packet: Packet):
#     if packet.haslayer(TLS):
#         client_hello = packet[TLS]

#         # Extract source and destination IP/port
#         src_ip = packet.src
#         dst_ip = packet.dst
#         src_port = packet.sport
#         dst_port = packet.dport

#         # Extract the Server Name Indication (SNI)
#         sni = client_hello.servernames[0].servername.decode() if client_hello.servernames else "N/A"

#         print(f"TLS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {sni}")
# def test(packet: Packet):
#     print(packet.summary())

# # from scapy.all import sniff, IP, TCP, Raw

# def extract_sni(packet):
#     """
#     Extracts the Server Name Indication (SNI) from a TLS Client Hello message.
#     """
#     # print(packet.summary())
#     if packet.haslayer('TLS') and packet['TLS'].type == 22 and packet['TLS'].msg[0].msgtype == 1:
#         msg = packet['IP'].src +' ==> ' +packet['IP'].dst +' : '+ (packet['TLS']['TLS_Ext_ServerName'].servernames[0].servername).decode("utf-8")
#         print(msg)

#     if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
#         data = packet[Raw].load
#         if False and (packet.haslayer(TLS)):
#             print(packet.summary())
#             print(packet["TLS"].type)
#             print(packet["TLS"].msg)
#         # print(data)
#         # print(data[0] == 0x16)
#         # print(data[5] == 0x01)
#         # Check if this is a TLS Client Hello message
#         if data[0] == 0x16 and data[5] == 0x01:  # TLS Handshake (0x16), ClientHello (0x01)
#             try:
#                 # Locate the start of the SNI extension in the handshake message
#                 sni_offset = data.find(b'\x00\x00') + 9  # Finding the Server Name Indication
#                 sni_length = int.from_bytes(data[sni_offset:sni_offset + 2], "big")
#                 sni = data[sni_offset + 2:sni_offset + 2 + sni_length].decode()

#                 src_ip = packet[IP].src
#                 dst_ip = packet[IP].dst
#                 src_port = packet[TCP].sport
#                 dst_port = packet[TCP].dport

#                 print(f"TLS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {sni}")
#                 # print(packet.summary())

#             except Exception as e:
#                 pass  # Ignore packets that don't conform

# Sniff for TCP packets (capturing all ports)
sniff(prn=callback, store=False)
# Start sniffing (use an appropriate filter to capture only TCP packets)
# sniff(filter="tcp", prn=test, store=False)
# sniff(filter="tcp port 80", prn=http_callback, store=False)