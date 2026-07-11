#!/usr/bin/env python3
"""
Custom Network Packet Sniffer & Traffic Analyzer
Author: Dhanush
Description: Intercepts raw network packets, decodes OSI Layers 2-4, and flags unencrypted credentials.
"""

import socket
import struct
import sys
import re

def main():
    print("[*] Initializing Raw Socket Sniffer...")
    print("[*] Listening for traffic on all network interfaces...")
    print("[*] Press Ctrl+C to stop the capture.\n" + "="*60)
    
    # 1. Create Raw Socket
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("[!] FATAL: You must run this tool as ROOT (sudo python3 sniffer.py)")
        sys.exit(1)
        
    try:
        while True:
            # Receive raw packet data (buffer size 65565 bytes)
            raw_data, addr = conn.recvfrom(65565)
            
            # 2. Parse Layer 2 (Ethernet)
            dest_mac, src_mac, eth_proto, ip_payload = parse_ethernet_header(raw_data)
            
            # Protocol 8 corresponds to IPv4 (0x0800 in hex)
            if eth_proto == 8:
                # 3. Parse Layer 3 (IPv4)
                ttl, proto, src_ip, dest_ip, transport_payload = parse_ip_header(ip_payload)
                
                # Protocol 6 corresponds to TCP
                if proto == 6:
                    # 4. Parse Layer 4 (TCP)
                    src_port, dest_port, app_payload = parse_tcp_header(transport_payload)
                    
                    # Filter: Let's focus our output on common HTTP traffic (Port 80) or active data
                    if len(app_payload) > 0 and (dest_port == 80 or src_port == 80 or "HTTP" in str(app_payload)):
                        print(f"[TCP] {src_ip}:{src_port} -> {dest_ip}:{dest_port} | TTL: {ttl} | Payload: {len(app_payload)} bytes")
                        
                        # 5. Inspect Layer 7 (Application Payload) for sensitive credentials
                        inspect_payload(app_payload)
                        
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture. Exiting lab.")
        sys.exit(0)

def parse_ethernet_header(raw_data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    def format_mac(bytes_addr):
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(proto), raw_data[14:]

def parse_ip_header(raw_data):
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src_ip_str = socket.inet_ntoa(src_ip)
    dest_ip_str = socket.inet_ntoa(dest_ip)
    ihl = (raw_data[0] & 15) * 4
    return ttl, proto, src_ip_str, dest_ip_str, raw_data[ihl:]

def parse_tcp_header(raw_data):
    src_port, dest_port = struct.unpack('! H H', raw_data[:4])
    tcp_header_length = ((raw_data[12] >> 4) * 4)
    return src_port, dest_port, raw_data[tcp_header_length:]

def inspect_payload(payload):
    try:
        decoded_text = payload.decode('utf-8', errors='ignore')
        keywords = r'(password|passwd|pwd|user|username|login|authorization|bearer|post /)'
        if re.search(keywords, decoded_text, re.IGNORECASE):
            print("\n" + "!"*20 + " SENSITIVE DATA DETECTED " + "!"*20)
            print(decoded_text[:300].strip())
            print("="*60)
            with open("suspicious_traffic.log", "a") as log_file:
                log_file.write(decoded_text + "\n" + "="*60 + "\n")
    except Exception:
        pass

if __name__ == "__main__":
    main()
