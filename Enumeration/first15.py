#!/usr/bin/env python3

import subprocess
import os
import argparse
import re
import socket
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def run_command_async(command, output_file):
    log(f"Starting: {command}")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    f = open(output_file, "w")
    proc = subprocess.Popen(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
    return proc, f

def run_command_sync(command, output_file):
    log(f"Running: {command}")
    with open(output_file, "w") as f:
        subprocess.run(command, shell=True, stdout=f, stderr=subprocess.STDOUT)

def watch_proc(proc, filehandle, label):
    proc.wait()
    filehandle.close()
    log(f"[+] Finished: {label}")

def resolve_hostname(ip):
    log(f"Resolving hostname for {ip}")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        log(f"Resolved: {ip} → {hostname}")
        return hostname
    except socket.herror:
        log("No reverse DNS entry found.")
        return None

def add_to_hosts(ip, hostname):
    entry = f"{ip}\t{hostname}"
    try:
        with open("/etc/hosts", "r") as f:
            if hostname in f.read():
                log("/etc/hosts already contains this entry.")
                return
        with open("/etc/hosts", "a") as f:
            f.write(f"\n{entry}\n")
        log(f"Added to /etc/hosts: {entry}")
    except PermissionError:
        log("Permission denied to write to /etc/hosts. Run as root if needed.")

def extract_web_ports(nmap_output_path):
    log("Extracting web ports from full scan output...")
    web_ports = []
    with open(nmap_output_path, "r") as f:
        for line in f:
            if re.search(r"^\d+/tcp\s+open\s+.*http", line, re.IGNORECASE):
                port = int(line.split("/")[0])
                web_ports.append(port)
    log(f"Web ports found: {web_ports}")
    return list(set(web_ports))

def detect_windows(nmap_output_path):
    log("Checking for Windows OS indicators in full scan...")
    indicators = ["microsoft windows", "workgroup", "netbios", "smb", "windows server"]
    with open(nmap_output_path, "r") as f:
        content = f.read().lower()
        for ind in indicators:
            if ind in content:
                log(f"Windows OS indicator found: '{ind}'")
                return True
    log("No signs of Windows detected.")
    return False

def url_with_port(ip, port):
    return f"https://{ip}" if port == 443 else f"http://{ip}:{port}"

def check_robots_git(ip, port, outdir):
    log(f"Checking for robots.txt and .git on port {port}")
    base_url = url_with_port(ip, port)
    for path in ["robots.txt", ".git/HEAD"]:
        output = os.path.join(outdir, path.replace("/", "_") + ".txt")
        run_command_sync(f"curl -s -f {base_url}/{path} || echo Not Found", output)

def enumerate_web_port(ip, hostname, port, base_out):
    port_dir = os.path.join(base_out, f"port_{port}")
    os.makedirs(port_dir, exist_ok=True)
    url = url_with_port(ip, port)
    host = hostname if hostname else ip

    check_robots_git(ip, port, port_dir)

    threads = []
    tools = [
        (f"nikto -h {url}", os.path.join(port_dir, "nikto.txt")),
        (f"whatweb {host}", os.path.join(port_dir, "whatweb.txt")),
        (
            f"feroxbuster -u {url} -w /usr/share/wordlists/dirb/common.txt "
            f"-x .php,.phtml,.xml,.aspx --filter-status 404,400,403",
            os.path.join(port_dir, "feroxbuster.txt")
        )
    ]

    if hostname:
        tools.append(
            (
                f"gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt "
                f"-u {url} --exclude-length 334",
                os.path.join(port_dir, "gobuster_vhost.txt")
            )
        )

    for cmd, outfile in tools:
        t = threading.Thread(target=run_command_sync, args=(cmd, outfile))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def web_enumeration(ip, hostname, base_out, web_ports):
    log("Starting parallel web enumeration for detected HTTP services...")
    with ThreadPoolExecutor(max_workers=len(web_ports)) as executor:
        for port in web_ports:
            log(f"Enumerating port {port}")
            executor.submit(enumerate_web_port, ip, hostname, port, base_out)

def main():
    parser = argparse.ArgumentParser(description="Automated recon with full logging")
    parser.add_argument("ip", help="Target IP")
    parser.add_argument("output_dir", help="Base output directory")
    args = parser.parse_args()

    ip = args.ip
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    log("Starting initial Nmap scans...")

    nmap_scripts = os.path.join(output_dir, "nmap.txt")
    nmap_fullscan = os.path.join(output_dir, "fullscan.txt")
    nmap_udp = os.path.join(output_dir, "UDP.txt")

    proc_scripts, fh_scripts = run_command_async(f"nmap -sVC {ip} -Pn --open", nmap_scripts)
    proc_full, fh_full = run_command_async(f"nmap -p- -sVC {ip} -Pn --open", nmap_fullscan)
    proc_udp, fh_udp = run_command_async(f"nmap -p- -sU --max-retries 1 --min-rate 5000 -Pn --open {ip}", nmap_udp)

    # Monitor scans and log when they finish
    threading.Thread(target=watch_proc, args=(proc_scripts, fh_scripts, "nmap.txt")).start()
    threading.Thread(target=watch_proc, args=(proc_udp, fh_udp, "UDP.txt")).start()

    log("Waiting for full TCP scan to complete...")
    watch_proc(proc_full, fh_full, "fullscan.txt")

    if detect_windows(nmap_fullscan):
        log("Running enum4linux...")
        run_command_sync(f"enum4linux -a {ip}", os.path.join(output_dir, "enum4linux.txt"))

    hostname = resolve_hostname(ip)
    if hostname:
        add_to_hosts(ip, hostname)

    web_ports = extract_web_ports(nmap_fullscan)
    if web_ports:
        web_enumeration(ip, hostname, output_dir, web_ports)
    else:
        log("No HTTP services found.")

    log("All scans and enumeration steps finished.")

if __name__ == "__main__":
    main()
