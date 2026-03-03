#!/usr/bin/env python3
import nmap
import argparse
import csv


def ping_sweep(network):
    nm = nmap.PortScanner()
    print(f"[+] Running ping sweep on {network}...")
    nm.scan(hosts=network, arguments='-n -sn')

    up_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            up_hosts.append(host)
    return up_hosts


def scan_host_ports(host):
    nm = nmap.PortScanner()
    print(f"[+] Scanning ports 1–1024 on {host}...")
    nm.scan(host, '1-1024')

    results = []
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            state = nm[host][proto][port]['state']
            service = nm[host][proto][port].get('name', 'unknown')
            if state == "open":
                results.append((port, proto, state, service))
    return results


def save_to_csv(data, filename="scan_report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(["IP", "Port", "Protocol", "State", "Service"])
        for row in data:
            writer.writerow(row)
    print(f"[+] Report saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description="Network scanner using python-nmap")
    parser.add_argument("network", help="Network in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument("--csv", action="store_true", help="Export results to CSV")
    args = parser.parse_args()

    up_hosts = ping_sweep(args.network)

    print("\n=== Hosts UP ===")
    for host in up_hosts:
        print(host)

    all_results = []
    for host in up_hosts:
        ports = scan_host_ports(host)
        print(f"\n=== Results for {host} ===")
        if not ports:
            print("No open ports found.")
        else:
            for port, proto, state, service in ports:
                print(f"{host} : {port}/{proto} : {state} ({service})")
                all_results.append((host, port, proto, state, service))

    if args.csv:
        save_to_csv(all_results)


if __name__ == "__main__":
    main()
