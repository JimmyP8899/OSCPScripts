#!/usr/bin/env python3

import subprocess
import ipaddress
import threading
import os
import argparse
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colored logging
def log(msg, level="info"):
    colors = {
        "info": "\033[93m",      # yellow
        "success": "\033[92m",   # green
        "command": "\033[96m",   # cyan
        "action": "\033[95m",    # magenta
        "error": "\033[91m",     # red
        "end": "\033[0m",
    }
    prefixes = {
        "info": "[+]",
        "success": "[+]",
        "command": "[+]",
        "action": "[+]",
        "error": "[-]"
    }
    prefix = prefixes.get(level, "[+]")
    color = colors.get(level, colors["info"])
    print(f"{color}{prefix} {msg}{colors['end']}", flush=True)

live_hosts = []
lock = threading.Lock()

def ping_host(ip, count=1, timeout=1):
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), str(ip)],
            capture_output=True,
            text=True
        )
        if "1 received" in result.stdout or "bytes from" in result.stdout:
            with lock:
                live_hosts.append(str(ip))
            log(f"Host is alive: {ip}", "success")
        else:
            log(f"No response from {ip}", "info")
    except Exception as e:
        log(f"Error pinging {ip}: {e}", "error")

def ping_sweep(network, threads=100):
    try:
        net = ipaddress.ip_network(network, strict=False)
    except Exception as e:
        log(f"Invalid network {network}: {e}", "error")
        return []

    ips = list(net.hosts())
    log(f"Starting ping sweep on {len(ips)} hosts in {network}", "action")

    thread_list = []
    for ip in ips:
        t = threading.Thread(target=ping_host, args=(ip,))
        t.start()
        thread_list.append(t)
        if len(thread_list) >= threads:
            for thr in thread_list:
                thr.join()
            thread_list = []

    for thr in thread_list:
        thr.join()

    log(f"Ping sweep complete. {len(live_hosts)} hosts alive.", "success")
    return live_hosts

def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except Exception:
        pass
    return "-"

def run_nmap_scan(ip):
    # Run a single nmap scan for OS detection and top 50 ports open
    cmd = ["nmap", "-O", "--top-ports", "50", "-Pn", ip]
    log(f"Running nmap scan on {ip}", "command")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout
    except Exception as e:
        log(f"nmap scan failed for {ip}: {e}", "error")
        return ""

def parse_nmap_output(output):
    os_info = "-"
    open_ports = []

    for line in output.splitlines():
        line = line.strip()
        # OS info detection
        if line.lower().startswith("os details:") or line.lower().startswith("running:"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                os_info = parts[1].strip()
        # Open ports detection
        port_match = re.match(r"^(\d+)\/tcp\s+open", line)
        if port_match:
            open_ports.append(port_match.group(1))

    if not open_ports:
        open_ports = ["-"]

    return os_info, open_ports

def scan_host(ip):
    hostname = resolve_hostname(ip)
    nmap_output = run_nmap_scan(ip)
    os_info, open_ports = parse_nmap_output(nmap_output)
    return {
        "ip": ip,
        "hostname": hostname,
        "os_info": os_info,
        "open_ports": open_ports
    }

def main():
    parser = argparse.ArgumentParser(description="Ping sweep + quick host info in single output file")
    parser.add_argument("network", help="Target network in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument("--threads", type=int, default=100, help="Max parallel ping threads")
    parser.add_argument("--scan_threads", type=int, default=10, help="Max parallel host scans")
    args = parser.parse_args()

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # Step 1: Ping sweep
    live = ping_sweep(args.network, threads=args.threads)
    if not live:
        log("No live hosts found.", "error")
        return

    log(f"Starting quick scans on {len(live)} hosts...", "action")
    results = []
    with ThreadPoolExecutor(max_workers=args.scan_threads) as executor:
        futures = {executor.submit(scan_host, ip): ip for ip in live}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                results.append(result)
                log(f"Completed scan for {ip}", "success")
            except Exception as e:
                log(f"Error scanning {ip}: {e}", "error")

    # Column widths and formatting with pipes
    IP_COL = 16
    HOSTNAME_COL = 15
    OS_COL = 60
    PORTS_COL = 20

    live_hosts_file = os.path.join(output_dir, "live_hosts.txt")
    with open(live_hosts_file, "w") as f:
        header = f"{'IP Address':<{IP_COL}} | {'Hostname':<{HOSTNAME_COL}} | {'Operating System':<{OS_COL}} | {'Common Open Ports':<{PORTS_COL}}\n"
        f.write(header)
        total_width = IP_COL + 3 + HOSTNAME_COL + 3 + OS_COL + 3 + PORTS_COL
        f.write("=" * total_width + "\n")
        for r in results:
            open_ports_str = ",".join(r["open_ports"]) if r["open_ports"] != ["-"] else "-"
            os_info = r['os_info'].replace("\n", " ").strip()
            f.write(f"{r['ip']:<{IP_COL}} | {r['hostname']:<{HOSTNAME_COL}} | {os_info:<{OS_COL}} | {open_ports_str:<{PORTS_COL}}\n")

    log(f"Summary saved to {live_hosts_file}", "success")

if __name__ == "__main__":
    main()
