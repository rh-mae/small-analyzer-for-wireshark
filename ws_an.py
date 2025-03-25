import pyshark
from collections import Counter
import ipaddress
import sys

def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def analyze_pcapng(file):
    cap = pyshark.FileCapture(file)
    
    ip_addresses = []
    dns_requests = []
    
    for packet in cap:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if not is_local_ip(src_ip):
                ip_addresses.append(src_ip)
            if not is_local_ip(dst_ip):
                ip_addresses.append(dst_ip)
        if 'DNS' in packet:
            dns_requests.append(packet.dns.qry_name)

    cap.close()

    most_common_ip = Counter(ip_addresses).most_common(1)[0]
    print(f"Most seen IP address: {most_common_ip[0]} with {most_common_ip[1]} appearances")

    dns_request_counts = Counter(dns_requests)
    unusual_dns_requests = [dns for dns, count in dns_request_counts.items() if count == 1]
    print(f"Unusual DNS requests: {unusual_dns_requests}")

    print(f"Total IP addresses seen: {len(set(ip_addresses))}")
    print(f"Total DNS requests: {len(dns_requests)}")
    print(f"Total unique DNS requests: {len(set(dns_requests))}")

pcapng_file = sys.argv[1]
analyze_pcapng(pcapng_file)
