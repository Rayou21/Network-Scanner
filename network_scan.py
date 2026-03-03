#!/usr/bin/env python3
import nmap
import argparse
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_nmap_installed():
    try:
        nmap.PortScanner()
    except nmap.PortScannerError:
        print("[-] Error: Nmap is not installed or not found in PATH.")
        sys.exit(1)

def ping_sweep(network):
    nm = nmap.PortScanner()
    print(f"[+] Running ping sweep on {network}...")
    nm.scan(hosts=network, arguments='-n -sn')
    return [host for host in nm.all_hosts() if nm[host].state() == "up"]

def scan_host_full(host):
    nm = nmap.PortScanner()
    try:
        nm.scan(host, '1-1024', arguments='-sV -O')
    except Exception:
        return host, [], "Unknown"

    os_guess = "Unknown"
    if host in nm.all_hosts():
        if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
            os_guess = nm[host]['osmatch'][0]['name']

    results = []
    if host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                details = nm[host][proto][port]
                if details['state'] == "open":
                    results.append({
                        "port": port,
                        "proto": proto,
                        "service": details.get('name', 'unknown'),
                        "version": f"{details.get('product', '')} {details.get('version', '')}".strip()
                    })

    return host, results, os_guess

def save_to_csv(data, filename="scan_report.csv"):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(["IP", "OS", "Port", "Protocol", "Service", "Version"])
        for host_info in data:
            ip, os_name = host_info['ip'], host_info['os']
            for p in host_info['ports']:
                writer.writerow([ip, os_name, p['port'], p['proto'], p['service'], p['version']])

    print(f"\n[+] Full report saved to: {filename}")

def main():
    check_nmap_installed()

    parser = argparse.ArgumentParser(description="Multi-threaded Network Scanner")
    parser.add_argument("network", help="Network range (e.g., 192.168.1.0/24)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--csv", action="store_true", help="Export results to CSV")
    args = parser.parse_args()

    up_hosts = ping_sweep(args.network)

    if not up_hosts:
        print("[-] No active hosts found.")
        return

    final_data = []

    print(f"[+] Found {len(up_hosts)} active hosts. Starting detailed scan...\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_host_full, host) for host in up_hosts]

        for future in as_completed(futures):
            ip, ports, os_guess = future.result()

            print(f"--- {ip} ({os_guess}) ---")
            for p in ports:
                print(f"  > Port {p['port']}/{p['proto']} : {p['service']} {p['version']}")

            final_data.append({
                "ip": ip,
                "os": os_guess,
                "ports": ports
            })

    if args.csv:
        save_to_csv(final_data)

if __name__ == "__main__":
    main()
