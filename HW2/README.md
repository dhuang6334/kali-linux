usage: tcpscan.py [-h] [-p PORTS] target

TCP SYN Scanner and Service Fingerprinting Tool

positional arguments:
  target                Target IP address to scan

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Port range to scan (e.g., 80 or 20-100)

I've decided to SYN scan first before fingerprinting so that I can compile a list of open ports to check. This separates the functionality for SYN scan and fingerprinting and makes it easier to debug and handle errors in fingerprinting


Examples:
sudo python tcpscan.py -p 853 8.8.8.8 

    Scanning target: 8.8.8.8
    Ports to scan: [853]
    Scanning port 853...
    Open ports: [853]

    Port 853:
    Type: (4) Generic TLS server
    Response: No data received

sudo python tcpscan.py -p 465 smtp.gmail.com 
    Scanning target: smtp.gmail.com
    Ports to scan: [465]
    Scanning port 465...
    Open ports: [465]

    Port 465:
    Type: (2) TLS server-initiated
    Response: 220 smtp.gmail.com ESMTP af79cd13be357-7c5f765ad89sm310959485a.16 - gsmtp