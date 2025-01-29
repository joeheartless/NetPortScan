from scapy.all import *
from tqdm import tqdm

# Input target IP
target_ip = input("Enter the target IP: ")

# Port range from 1 to 10000
ports = range(1, 10001)
open_ports = []  # List to store open ports

# Loop for scanning ports with a progress bar
for port in tqdm(ports, desc="Scanning ports", unit="port"):
    # Send SYN packet to target port
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    response = sr1(pkt, timeout=1, verbose=0)
    
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 18:  # 18 = SYN+ACK
            open_ports.append(port)  # Store open port

# Display scan results
if open_ports:
    print("\nOpen Ports:")
    for port in open_ports:
        print(f"Port {port} open")
else:
    print("No open ports found.")

# OS detection (based on TTL and window size)
pkt = IP(dst=target_ip) / TCP(dport=80, flags="S")
response = sr1(pkt, timeout=1, verbose=0)

if response:
    ttl = response.ttl
    window_size = response.sprintf("%TCP.window%")
    print(f"\nTTL: {ttl}, Window Size: {window_size}")
    
    if ttl <= 64:
        print("Possible OS: Linux/Unix")
    elif ttl <= 128:
        print("Possible OS: Windows")
    else:
        print("OS cannot be determined")
else:
    print("No response for OS detection")
