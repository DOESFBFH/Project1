import scapy.all as scapy
import socket
import requests
import subprocess
import os
from tabulate import tabulate
from tqdm import tqdm  # Import tqdm for the progress bar

# Function to get the local machine's IP
def get_my_ip():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return ip

# Function to find live hosts in the given IP range (192.168.0.0/24)
def get_network_range(network='192.168.0.0/24'):
    # Scapy ARP request to find live hosts in the range
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # Collecting other IPs in the network (excluding local machine's IP)
    network_ips = []
    for element in answered_list:
        ip = element[1].psrc
        if ip != get_my_ip():  # Exclude your own IP from the list
            network_ips.append(ip)
    return network_ips

# Function to scan ports using SYN packets (Port scanning using Scapy)
def scan_ports(ip):
    open_ports = []
    for port in range(20, 1025):  # Scanning ports from 20 to 1024 (common ports)
        syn_packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(syn_packet, timeout=1, verbose=False)
        
        if response:
            if response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 18:  # TCP SYN-ACK
                open_ports.append(port)
    return open_ports

# Function to grab banners (Basic banner grabbing with a TCP connection)
def grab_banner(ip, port):
    try:
        # Create a socket to grab the banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return None

# Function to fetch CVEs for a given service
def get_cves_for_service(service_name):
    cve_url = f'https://cve.circl.lu/api/cve/{service_name}'
    response = requests.get(cve_url)
    if response.status_code == 200:
        return response.json()  # Returning the CVE details for this service
    return []

# Collect the IPs and service information
def collect_data():
    network_ips = get_network_range('192.168.0.0/24')  # Specify the network range here
    print(f"NETWORK IPs Found: {network_ips}")

    all_service_info = []
    
    # Using tqdm to display the progress of scanning IPs
    for ip in tqdm(network_ips, desc="Scanning Hosts", unit="IP"):
        open_ports = scan_ports(ip)
        for port in open_ports:
            banner = grab_banner(ip, port)
            if banner:
                service_info = {
                    'IP': ip,
                    'Port': port,
                    'Banner': banner
                }
                service_name = banner.split()[0]  # Assuming the first part of the banner is the service name
                cves = get_cves_for_service(service_name)
                if cves:
                    for cve in cves:
                        service_info['CVEs'] = cve.get('id', 'No CVEs found')
                else:
                    service_info['CVEs'] = 'No CVEs found'
                all_service_info.append(service_info)
    
    return all_service_info

# Main function to display results in a tabular format
def main():
    all_data = collect_data()

    # Prepare the table headers
    headers = ['IP', 'Port', 'Banner', 'CVEs']
    table_data = []

    for data in all_data:
        table_data.append([data['IP'], data['Port'], data['Banner'], data.get('CVEs', 'No CVEs')])
    
    # Displaying the data in a tabular format
    print("\nResults:")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

if __name__ == '__main__':
    main()
