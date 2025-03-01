# from scapy.layers.http import *
# from scapy.layers import *
#sniff, load_layer
# from scapy.layers import *
# from scapy.layers.tls.record import *
import sys
from scapy.all import * 
from scapy.packet import Packet
from datetime import datetime

load_layer("http")
load_layer("tls")
load_layer("dns")

def callback(packet: Packet):
    timestamp = datetime.fromtimestamp(packet.time)
    formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
    if packet.haslayer("HTTPRequest"):
        method = str(packet.Method).split("'")[1]
        if method == "GET" or method == "POST":
            src_ip = packet.src
            dst_ip = packet.dst
            src_port = packet.sport
            dst_port = packet.dport

            print(f"{formatted_time} HTTP\t{src_ip}:{src_port}\t-> {dst_ip}:{dst_port}{"\t" if dst_port > 99 else "\t\t"}{str(packet.Host).split("'")[1]} {method} {str(packet.Path).split("'")[1]}")
    if packet.haslayer("TLS") and packet['TLS'].type == 22 and packet['TLS'].msg[0].msgtype == 1:
        # print(f"TLS Test")
        client_hello = packet["TLS"]

        src_ip = packet.src
        dst_ip = packet.dst
        src_port = packet.sport
        dst_port = packet.dport

        
        sni = client_hello['TLS_Ext_ServerName'].servernames[0].servername.decode("utf-8")
        # print(client_hello['TLS_Ext_ServerName'].servernames if client_hello['TLS_Ext_ServerName'] else "N/A")

        print(f"{formatted_time} TLS\t{src_ip}:{src_port}\t-> {dst_ip}:{dst_port}{"\t" if dst_port > 99 else "\t\t"}{sni}")
    if packet.haslayer("DNSQR"):
        # print("DNS Test")
        
        DNSRequest = packet["DNSQR"]
        # print(DNSRequest.qtype)
        src_ip = packet.src
        dst_ip = packet.dst
        src_port = packet.sport
        dst_port = packet.dport

        if DNSRequest.qtype == 1: # 1 is type number for A record
            print(f"{formatted_time} DNS\t{src_ip}:{src_port}\t-> {dst_ip}:{dst_port}{"\t" if dst_port > 99 else "\t\t"}{str(DNSRequest.qname).split("'")[1]}")

interface = None
wfile = None
rfile = None
for i in range(len(sys.argv)):
    if (sys.argv[i] == "-i"):
        interface = str(sys.argv[i + 1])
        i += 1
    elif (sys.argv[i] == "-w"):
        wfile = str(sys.argv[i + 1])
        i += 1
    elif (sys.argv[i] == "-r"):
        rfile = str(sys.argv[i + 1])
        i += 1


packets = sniff(iface= interface if interface else "eth0", prn=callback, offline = rfile)
if wfile:
    try:
        wrpcap(wfile, packets)
    except Exception as e:
        raise e
# Start sniffing (use an appropriate filter to capture only TCP packets)
# sniff(filter="tcp", prn=test, store=False)
# sniff(filter="tcp port 80", prn=http_callback, store=False)