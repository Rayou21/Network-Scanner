#!/usr/bin/env python3
import nmap
import argparse
import csv
import sys
from concurrent.futures import ThreadPoolExecutor

def check_nmap_installed():
    """Checks if nmap is installed on the system."""
    try:
        nmap.PortScanner()
    except nmap.PortScannerError:
        print("[-] Error: Nmap is not installed or not found in PATH.")
        sys.exit(1)

def ping_sweep(network):
    """Discovers live hosts on the network."""
    nm = nmap.PortScanner()
    print(f"[+] Running ping sweep on {network}...")
    # -sn: Ping scan / -n: No DNS resolution for speed
    nm.scan(hosts=network, arguments='-n -sn')
    return [host for host in nm.all_hosts() if nm[host].state() == "up"]

def scan_host_full(host):
    """Scans ports, detects services version and attempts OS fingerprinting."""
    nm = nmap.PortScanner()
    print(f"[+] Detailed scan for {host}...")
    
    # -O: OS detection (may require sudo/admin)
    # -sV: Service version detection
    try:
        nm.scan(host, '1-1024', arguments='-sV -O')
    except Exception as e:
        return host, [], "Unknown"

    # OS Guessing
    os_guess = "Unknown"
    if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
        os_guess = nm[host]['osmatch'][0]['name']

    results = []
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            details = nm[host][proto][port]
            if details['state'] == "open":
                results.append({
                    "port": port,
                    "proto": proto,
                    "service": details.get('name', 'unknown'),
                    "version": details.get('product', '') + " " + details.get('version', '')
                })
    return host, results, os_guess

def save_to_csv(data, filename="scan_report.csv"):
    """Exports results to a CSV file."""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(["IP", "OS", "Port", "Protocol", "Service", "Version"])
        for host_info in data:
            host_ip = host_info['ip']
            os = host_info['os']
            for p in host_info['ports']:
                writer.writerow([host_ip, os, p['port'], p['proto'], p['service'], p['version']])
    print(f"\n[+] Full report saved to: {filename}")

def main():
    check_nmap_installed()
    
    parser = argparse.ArgumentParser(description="Multi-threaded Network Scanner with OS Detection")
    parser.add_argument("network", help="Network range in CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent scans (default: 10)")
    args = parser.parse_args()

    # 1. Host Discovery
    up_hosts = ping_sweep(args.network)
    if not up_hosts:
        print("[-] No hosts found.")
        return

    print(f"[!] {len(up_hosts)} hosts detected. Launching multi-threaded scan...")

    # 2. Parallel Scanning
    final_data = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_host_full, host): host for host in up_hosts}
        
        for future in futures:
            ip, ports, os = future.result()
            print(f"--- {ip} ({os}) ---")
            if not ports:
                print("  No open ports found.")
            for p in ports:
                print(f"  > Port {p['port']}: {p['service']} {p['version']}")
            
            final_data.append({"ip": ip, "os": os, "ports": ports})

    # 3. Export
    save_to_csv(final_data)

if __name__ == "__main__":
    main()
