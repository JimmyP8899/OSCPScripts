#!/usr/bin/env python3

import subprocess
import os
import argparse
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

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

def run_command_async(command, output_file):
    log(f"Starting: {command}", level="command")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    f = open(output_file, "w")
    proc = subprocess.Popen(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
    return proc, f

def run_command_sync(command, output_file):
    log(f"Running: {command}", level="command")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        subprocess.run(command, shell=True, stdout=f, stderr=subprocess.STDOUT)

def run_and_log(cmd, outfile, label):
    run_command_sync(cmd, outfile)
    log(f"Finished: {label}", level="success")

def watch_proc(proc, filehandle, label):
    proc.wait()
    filehandle.close()
    log(f"Finished: {label}", level="success")

def resolve_hostname(ip):
    log(f"Resolving hostname for {ip}", level="action")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        log(f"Resolved: {ip} → {hostname}", level="success")
        return hostname
    except socket.herror:
        log("No reverse DNS entry found.", level="info")
        return None

def add_to_hosts(ip, hostname):
    entry = f"{ip}\t{hostname}"
    try:
        with open("/etc/hosts", "r") as f:
            if hostname in f.read():
                log("/etc/hosts already contains this entry.", level="info")
                return
        with open("/etc/hosts", "a") as f:
            f.write(f"\n{entry}\n")
        log(f"Added to /etc/hosts: {entry}", level="success")
    except PermissionError:
        log("Permission denied to write to /etc/hosts. Run as root if needed.", level="error")

def extract_web_ports(nmap_output_path):
    log("Extracting web ports from full scan output...", level="action")
    web_ports = []
    with open(nmap_output_path, "r") as f:
        for line in f:
            if re.search(r"^\d+/tcp\s+open\s+.*http", line, re.IGNORECASE):
                port = int(line.split("/")[0])
                web_ports.append(port)
    log(f"Web ports found: {web_ports}", level="success")
    return list(set(web_ports))

def detect_windows(nmap_output_path):
    log("Checking for Windows OS indicators in full scan...", level="action")
    indicators = ["microsoft windows", "workgroup", "netbios", "smb", "windows server"]
    with open(nmap_output_path, "r") as f:
        content = f.read().lower()
        for ind in indicators:
            if ind in content:
                log(f"Windows OS indicator found: '{ind}'", level="success")
                return True
    log("No signs of Windows detected.", level="info")
    return False

def detect_domain_controller(nmap_output_path):
    log("Checking for domain controller indicators...", level="action")
    keywords = ["ldap", "kerberos", "domain controller", "active directory"]
    with open(nmap_output_path, "r") as f:
        content = f.read().lower()
        for k in keywords:
            if k in content:
                log(f"Domain controller indicator found: '{k}'", level="success")
                return True
    return False

def smb_detected(nmap_output_path):
    log("Checking for SMB services in full scan...", level="action")
    with open(nmap_output_path, "r") as f:
        for line in f:
            if re.search(r"^\d+/tcp\s+open\s+.*smb", line, re.IGNORECASE) or "microsoft-ds" in line.lower():
                log("SMB detected.", level="success")
                return True
    log("No SMB service found.", level="info")
    return False

def ftp_check_anonymous(ip):
    log("Checking for FTP anonymous login...", level="action")
    result = subprocess.run(
        f'echo -e "user anonymous\\npass test\\nquit" | ftp -n {ip}',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if "230" in result.stdout:
        log("Anonymous FTP login successful!", level="success")
    else:
        log("Anonymous FTP login not allowed.", level="info")

def dns_check(ip, domain, output_file):
    log(f"Running dig against DNS at {ip} for domain {domain}", level="action")
    run_command_sync(f"dig any {domain} @{ip}", output_file)
    log("Finished: dig DNS query", level="success")

def url_with_port(ip, port):
    return f"https://{ip}" if port == 443 else f"http://{ip}:{port}"

def enumerate_web_port(ip, hostname, port, base_out):
    port_dir = os.path.join(base_out, f"{port}_HTTP")
    os.makedirs(port_dir, exist_ok=True)
    url = url_with_port(ip, port)
    host = hostname if hostname else ip

    log(f"Checking for robots.txt and .git on port {port}", level="action")

    threads = [
        threading.Thread(target=run_and_log, args=(
            f"curl -s -f {url}/robots.txt || echo Not Found",
            os.path.join(port_dir, "robots.txt"),
            "robots.txt"
        )),
        threading.Thread(target=run_and_log, args=(
            f"curl -s -f {url}/.git/HEAD || echo Not Found",
            os.path.join(port_dir, "git_HEAD.txt"),
            ".git/HEAD"
        )),
        threading.Thread(target=run_and_log, args=(
            f"nikto -h {url}",
            os.path.join(port_dir, "nikto.txt"),
            "nikto"
        )),
        threading.Thread(target=run_and_log, args=(
            f"whatweb {host}",
            os.path.join(port_dir, "whatweb.txt"),
            "whatweb"
        )),
        threading.Thread(target=run_and_log, args=(
            f"feroxbuster -u {url} -w /usr/share/wordlists/dirb/common.txt "
            f"-x .php,.phtml,.xml,.aspx --filter-status 404,400,403",
            os.path.join(port_dir, "feroxbuster.txt"),
            "feroxbuster"
        ))
    ]

    if hostname:
        threads.append(threading.Thread(target=run_and_log, args=(
            f"gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt "
            f"-u {url} --exclude-length 334",
            os.path.join(port_dir, "gobuster_vhost.txt"),
            "gobuster vhost"
        )))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

def parse_services(nmap_output_path):
    """
    Parses nmap full scan output to get open ports and their service names.
    Returns a dict: {port: service_name}
    """
    services = {}
    with open(nmap_output_path, "r") as f:
        for line in f:
            # match lines like: 21/tcp   open  ftp
            m = re.match(r"^(\d+)\/tcp\s+open\s+(\S+)", line)
            if m:
                port = int(m.group(1))
                service = m.group(2).lower()
                services[port] = service
    return services

def main():
    parser = argparse.ArgumentParser(description="Automated recon with full logging")
    parser.add_argument("ip", help="Target IP")
    parser.add_argument("output_dir", help="Base output directory")
    args = parser.parse_args()

    ip = args.ip
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    log("Starting initial scans...", level="info")

    nmap_scripts = os.path.join(output_dir, "nmap.txt")
    nmap_fullscan = os.path.join(output_dir, "fullscan.txt")
    nmap_udp = os.path.join(output_dir, "UDP.txt")
    nuclei_output = os.path.join(output_dir, "nuclei.txt")

    proc_scripts, fh_scripts = run_command_async(f"nmap -sVC {ip} -Pn --open", nmap_scripts)
    proc_full, fh_full = run_command_async(f"nmap -p- -sVC {ip} -Pn --open", nmap_fullscan)
    proc_udp, fh_udp = run_command_async(f"nmap -p- -sU --max-retries 1 --min-rate 5000 -Pn --open {ip}", nmap_udp)
    proc_nuclei, fh_nuclei = run_command_async(f"nuclei -u {ip}", nuclei_output)

    threading.Thread(target=watch_proc, args=(proc_scripts, fh_scripts, "nmap.txt")).start()
    threading.Thread(target=watch_proc, args=(proc_udp, fh_udp, "UDP.txt")).start()
    threading.Thread(target=watch_proc, args=(proc_nuclei, fh_nuclei, "nuclei.txt")).start()

    log("Waiting for full TCP scan to complete...", level="info")
    watch_proc(proc_full, fh_full, "fullscan.txt")

    hostname = resolve_hostname(ip)
    if hostname:
        add_to_hosts(ip, hostname)

    if detect_windows(nmap_fullscan):
        run_command_sync(f"enum4linux -a {ip}", os.path.join(output_dir, "enum4linux.txt"))
        log("Finished: enum4linux", level="success")

    if detect_domain_controller(nmap_fullscan):
        log("Domain Controller likely present.", level="success")

    services = parse_services(nmap_fullscan)

    # FTP handling
    if 21 in services and services[21] == "ftp":
        ftp_dir = os.path.join(output_dir, "21_ftp")
        os.makedirs(ftp_dir, exist_ok=True)
        ftp_check_anonymous(ip)
        # You can save FTP related files in ftp_dir if you expand checks here

    # SMB handling - common SMB ports 445 and 139
    smb_ports = [port for port, svc in services.items() if svc in ("microsoft-ds", "netbios-ssn", "smb")]
    for port in smb_ports:
        smb_dir = os.path.join(output_dir, f"{port}_smb")
        os.makedirs(smb_dir, exist_ok=True)
        run_command_sync(f"smbmap -H {ip}", os.path.join(smb_dir, "smbmap.txt"))
        log(f"Finished: smbmap in {port}_smb directory", level="success")

    # DNS dig if DNS present - assume domain from hostname or fallback
    if any("domain" in svc for svc in services.values()):
        domain = hostname if hostname else "example.com"
        dns_out = os.path.join(output_dir, "dns_dig.txt")
        dns_check(ip, domain, dns_out)

    # Web enumeration ports
    web_ports = [port for port, svc in services.items() if "http" in svc]

    if web_ports:
        web_enumeration(ip, hostname, output_dir, web_ports)
    else:
        log("No HTTP services found.", level="info")

    log("All scans and enumeration steps finished.", level="success")

def web_enumeration(ip, hostname, base_out, web_ports):
    log("Starting parallel web enumeration for detected HTTP services...", level="action")
    with ThreadPoolExecutor(max_workers=len(web_ports)) as executor:
        futures = []
        for port in web_ports:
            log(f"Enumerating port {port}", level="action")
            futures.append(executor.submit(enumerate_web_port, ip, hostname, port, base_out))
        for future in futures:
            future.result()  # wait for all to finish


if __name__ == "__main__":
    main()
