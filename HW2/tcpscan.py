# Created with the help of Copilot
import socket
import ssl
import argparse
from scapy.all import *

# Default ports to scan if -p is not provided
DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]

def parse_arguments():
    parser = argparse.ArgumentParser(description="TCP SYN Scanner and Service Fingerprinting Tool")
    parser.add_argument("target", help="Target IP address to scan")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 80 or 20-100)", default=None)
    return parser.parse_args()

def parse_port_range(port_range):
    if "-" in port_range:
        start, end = map(int, port_range.split("-"))
        return range(start, end + 1)
    else:
        return [int(port_range)]

def syn_scan(target, ports):
    open_ports = []
    for port in ports:
        print(f"Scanning port {port}...")
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == "SA":
            open_ports.append(port)
            sr(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1, verbose=0)  # Send RST to close connection
    return open_ports

def service_fingerprint(target, port):
    results = []
    
    try:
        # TLS server-initiated
        with socket.create_connection((target, port), timeout=3) as sock:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                data = tls_sock.recv(1024)
                if data:
                    results.append((2, "TLS server-initiated", data.decode(errors="replace")))
                    return results
    except Exception:
        pass

    try:
        # TCP server-initiated
        with socket.create_connection((target, port), timeout=3) as sock:
            data = sock.recv(1024)
            if data:
                results.append((1, "TCP server-initiated", data.decode(errors="replace")))
                return results
        
    
    except Exception:
        pass
    
    # Client-initiated probes
    probes = [
        ("GET / HTTP/1.0\r\n\r\n", 3, "HTTP server"),
        ("\r\n\r\n\r\n\r\n", 5, "Generic TCP server"),
    ]
    for probe, type_id, description in probes:

        try:
            # TLS probe
            with socket.create_connection((target, port), timeout=5) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                    tls_sock.sendall(probe.encode())
                    data = tls_sock.recv(1024)
                    
                    if data:
                        if (type_id == 3):
                            if data.startswith(b"HTTP/"):
                                results.append((type_id + 1, "HTTPS server", data.decode(errors="replace")))
                                return results
                            else:
                                results.append((type_id + 1, "Generic TLS server", data.decode(errors="replace")))
                                return results
                        else:
                            results.append((type_id + 1, "HTTPS server" if ((type_id + 1) == 4) else "Generic TLS server" if (type_id + 1) == 6 else "Unknown Type", data.decode(errors="replace")))
                            return results
                    else:
                        # If no data is received, assume it's a Generic TLS server
                        results.append((type_id + 1, "Generic TLS server", "No data received"))
                        return results
        except ConnectionRefusedError as e:
            pass
        except ssl.SSLError as e:
            pass
        except socket.timeout as e:
            # If a timeout occurs but not SSL error, assume it's a Generic TLS server
            results.append((type_id + 1, "Generic TLS server", f"No data received timeout error: {e}"))
            return results
        except Exception:
            pass

        try:
            # Non-TLS probe
            with socket.create_connection((target, port), timeout=5) as sock:
                sock.sendall(probe.encode())
                data = sock.recv(1024)
                if data:
                    if not data.startswith(b"HTTP/"):
                        results.append((type_id, "Generic TCP server", data.decode(errors="replace")))
                        return results
                    results.append((type_id, description, data.decode(errors="replace")))
                    return results
                else:
                    # If no data is received, assume it's a Generic TCP server
                    results.append((type_id, "Generic TCP server", "No data received"))
                    return results
        except Exception as e:
            # assume it's a Generic TCP server
            results.append((type_id, "Generic TCP server", f"No data received error: {e}"))
            return results
    return results

def main():
    args = parse_arguments()
    target = args.target
    ports = DEFAULT_PORTS if not args.ports else parse_port_range(args.ports)

    print(f"Scanning target: {target}")
    print(f"Ports to scan: {ports}")

    # Perform SYN scan
    open_ports = syn_scan(target, ports)
    print(f"Open ports: {open_ports}")

    # Perform service fingerprinting
    for port in open_ports:
        print(f"\nPort {port}:")
        fingerprints = service_fingerprint(target, port)
        for type_id, description, response in fingerprints:
            print(f"  Type: ({type_id}) {description}")
            print(f"  Response: {response[:1024].replace("�", ".")}")  # Print up to 1024 bytes of response

if __name__ == "__main__":
    main()
