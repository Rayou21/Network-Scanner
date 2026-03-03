# 🧪 NetworkScanner – Python Network Scanner (python‑nmap)

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Library](https://img.shields.io/badge/Library-python--nmap-orange)
![Tool](https://img.shields.io/badge/Tool-Network%20Scanner-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

**NetworkScanner** is a Python script that automates network discovery using the `python-nmap` library.  
It performs a **ping sweep**, identifies **active hosts**, scans **ports 1–1024**, and can optionally export results to **CSV**.

Designed for **cybersecurity learning**, **network enumeration**, and **Python automation practice**.

---

## 📝 Overview

NetworkScanner allows you to:

- 🌐 Discover active hosts on a network  
- 🔍 Scan ports 1–1024  
- 🏷️ Identify services running on open ports  
- 📄 Export results to CSV  
- ⚙️ Automate Nmap scans through Python  

This project continues my learning journey in:

- Python automation  
- Network scanning  
- Cybersecurity tooling  
- CLI development  

---

## ✨ Features

- CIDR input (e.g., `192.168.1.0/24`)  
- Ping sweep using Nmap (`-n -sn`)  
- Port scanning (`1-1024`)  
- Service detection  
- CSV export (`--csv`)  
- Clean and structured output  
- Works on Windows, Linux, macOS  

---

## 🔧 Usage

### Basic scan (ping sweep + ports)

```bash
python network_scan.py 192.168.1.0/24
```

### Export results to CSV

```bash
python network_scan.py 192.168.1.0/24 --csv
```

This generates:

```
scan_report.csv
```

Format:

```
IP ; Port ; Protocol ; State ; Service
```

---

## 💻 Script – network_scan.py

```python
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
```

---

## 🔎 Example Output

```
[+] Running ping sweep on 192.168.1.0/24...

=== Hosts UP ===
192.168.1.10
192.168.1.20

[+] Scanning ports 1–1024 on 192.168.1.10...

=== Results for 192.168.1.10 ===
192.168.1.10 : 22/tcp : open (ssh)
192.168.1.10 : 80/tcp : open (http)
```

---

## 🧪 How It Works

### 1. Ping Sweep  
Uses Nmap with:

- `-n` → disable DNS resolution  
- `-sn` → ping scan only  

### 2. Port Scan  
For each host:

```
nmap <host> 1-1024
```

### 3. Result Parsing  
Extracts:

- port  
- protocol  
- state  
- service  

### 4. CSV Export  
Uses Python’s built‑in `csv` module.

---

## 🎓 Why I Built This

This project helps me improve:

- Python automation  
- Network enumeration  
- Nmap scripting  
- Cybersecurity tooling  

It builds on the previous TCP port scanner and moves toward more advanced scanning techniques.

---

## 🚀 Future Improvements

- Asynchronous scanning  
- Multi-threading  
- Service version detection  
- OS detection  
- HTML/JSON reporting  

---

## ⚙️ Requirements

- Python 3.10+  
- python‑nmap  
- Nmap installed and available in PATH  

---

## 📂 License

MIT License – free to use, modify, and learn from.
