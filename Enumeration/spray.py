#!/usr/bin/env python3

import subprocess
import argparse
import ipaddress
import concurrent.futures
from rich import print
from rich.console import Console
import platform
import os
import signal
import time

console = Console()
def check_rdp(ip, username, password, hash_mode):
    if hash_mode:
        return "[bold red][RDP][/bold red] [yellow]SKIPPED (hash not supported)[/yellow]"

    display = ":99"
    xvfb_cmd = ["Xvfb", display, "-screen", "0", "1024x768x16"]
    rdp_cmd = [
        "xfreerdp3",
        f"/v:{ip}",
        f"/u:{username}",
        f"/p:{password}",
        "/cert:ignore",
        "/auto-reconnect",
        "/log-level:ERROR"
    ]

    try:
        xvfb_proc = subprocess.Popen(xvfb_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)  # Give Xvfb time to start

        env = os.environ.copy()
        env["DISPLAY"] = display

        rdp_proc = subprocess.Popen(rdp_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)

        if rdp_proc.poll() is None:
            rdp_proc.terminate()
            xvfb_proc.terminate()
            return "[bold red][RDP][/bold red] [green]VALID[/green]"
        else:
            stdout, stderr = rdp_proc.communicate()
            xvfb_proc.terminate()
            if b"Authentication failure" in stderr:
                return "[bold red][RDP][/bold red] [red]INVALID[/red]"
            else:
                return "[bold red][RDP][/bold red] [yellow]UNKNOWN[/yellow]"

    except Exception as e:
        return f"[bold red][RDP][/bold red] [yellow]ERROR[/yellow] ({str(e)})"
def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] Command timed out"

def is_host_up(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    result = subprocess.run(["ping", param, "1", str(ip)], stdout=subprocess.DEVNULL)
    return result.returncode == 0

def check_smb(ip, username, password, hash_mode):
    auth_flag = f"-H '{password}'" if hash_mode else f"-p '{password}'"
    cmd = f"crackmapexec smb {ip} -u '{username}' {auth_flag} --no-bruteforce"
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        )
        output = result.stdout
    except subprocess.TimeoutExpired:
        return "[bold green][SMB][/bold green] [yellow]TIMEOUT[/yellow]"

    # Check for success
    for line in output.splitlines():
        if f"SMB" in line and ip in line and "[+]" in line:
            return "[bold green][SMB][/bold green] [green]VALID[/green]"

    # Failure indicators (including 'failure')
    failure_indicators = [
        "failure",
        "access denied",
        "nt_status_logon_failure",
        "status_logon_failure",
        "failed to authenticate",
        "authentication failed",
        "permission denied",
        "authentication error",
    ]

    # Check for failure
    output_lower = output.lower()
    if any(indicator in output_lower for indicator in failure_indicators):
        return "[bold green][SMB][/bold green] [red]INVALID[/red]"

    # If neither success nor failure indicators found
    return "[bold green][SMB][/bold green] [yellow]UNKNOWN[/yellow]"

def check_winrm(ip, username, password, hash_mode, domain=None):
    def run_cme(domain_param):
        auth_flag = f"-H '{password}'" if hash_mode else f"-p '{password}'"
        domain_flag = f"-d '{domain_param}'" if domain_param else ""
        cmd = f"crackmapexec winrm {ip} -u '{username}' {auth_flag} {domain_flag}".strip()
        return run_command(cmd)

    def has_success(output):
        return any("[+]" in line and "WINRM" in line for line in output.splitlines())

    def has_failure(output):
        return any("[-]" in line and "WINRM" in line for line in output.splitlines())

    # Run with user-specified domain if provided
    if domain:
        output_domain = run_cme(domain)
        if has_success(output_domain):
            return f"[bold cyan][WINRM][/bold cyan] [green]VALID[/green] (domain: {domain})"
        if has_failure(output_domain):
            # If domain run fails, try local domain before returning INVALID
            output_local = run_cme(".")
            if has_success(output_local):
                return "[bold cyan][WINRM][/bold cyan] [green]VALID[/green] (local)"
            if has_failure(output_local):
                return "[bold cyan][WINRM][/bold cyan] [red]INVALID[/red] (local)"
            return "[bold cyan][WINRM][/bold cyan] [yellow]UNKNOWN[/yellow]"

    # If no domain specified, try local domain only
    output_local = run_cme(".")
    if has_success(output_local):
        return "[bold cyan][WINRM][/bold cyan] [green]VALID[/green] (local)"
    if has_failure(output_local):
        return "[bold cyan][WINRM][/bold cyan] [red]INVALID[/red] (local)"

    return "[bold cyan][WINRM][/bold cyan] [yellow]UNKNOWN[/yellow]"

def check_rpc(ip, username, password, hash_mode):  # <-- updated
    if hash_mode:
        return "[bold bright_blue][RPC][/bold bright_blue] [yellow]SKIPPED (hash not supported)[/yellow]"
    cmd = f"rpcclient -U \"{username}%{password}\" {ip} -c exit"
    output = run_command(cmd)

    if "NT_STATUS_LOGON_FAILURE" in output or "NT_STATUS_ACCESS_DENIED" in output:
        return "[bold bright_blue][RPC][/bold bright_blue] [red]INVALID[/red]"
    elif "Cannot connect to server" in output or "Connection refused" in output:
        return "[bold bright_blue][RPC][/bold bright_blue] [yellow]UNREACHABLE[/yellow]"
    elif output.strip() == "":
        return "[bold bright_blue][RPC][/bold bright_blue] [green]VALID[/green]"
    else:
        return "[bold bright_blue][RPC][/bold bright_blue] [yellow]UNKNOWN[/yellow]"

def check_ssh(ip, username, password, hash_mode):  # <-- updated
    if hash_mode:
        return "[bold magenta][SSH][/bold magenta] [yellow]SKIPPED (hash not supported)[/yellow]"
    output = run_command(f"crackmapexec ssh {ip} -u '{username}' -p '{password}'")
    return "[bold magenta][SSH][/bold magenta] " + ("[green]VALID[/green]" if "VALID" in output.upper() else "[red]INVALID[/red]")

def check_psexec(ip, username, password, hash_mode):  # <-- updated
    if hash_mode:
        auth = f"'{username}':'{password}'"
    else:
        auth = f"'{username}':'{password}'"

    cmd = f"impacket-wmiexec {auth}@{ip} whoami"
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20
        )
        output = result.stdout
        #print(result) #debugging purpose
    except subprocess.TimeoutExpired:
        return "[bold yellow][WMI (PSEXEC)][/bold yellow] [yellow]TIMEOUT[/yellow]"

    output_lower = output.lower()
    if (
        "nt authority\\" in output_lower or
        "\\" in output_lower or
        "administrator" in output_lower or
        "microsoft windows" in output_lower
    ):
        return "[bold yellow][WMI (PSEXEC)][/bold yellow] [green]VALID[/green]"
    elif any(err in output_lower for err in [
        "logon failure", "denied", "nt_status_logon_failure",
        "wrong password", "invalid", "failed to authenticate"
    ]):
        return "[bold yellow][WMI (PSEXEC)][/bold yellow] [red]INVALID[/red]"
    else:
        return "[bold yellow][WMI (PSEXEC)][/bold yellow] [yellow]UNKNOWN[/yellow]"

def check_host(ip, username, password, hash_mode, domain):
    print(f"[bold white]Checking {ip}[/bold white]")
    print(check_smb(ip, username, password, hash_mode))
    print(check_winrm(ip, username, password, hash_mode, domain))
    print(check_ssh(ip, username, password, hash_mode))
    print(check_psexec(ip, username, password, hash_mode))
    print(check_rpc(ip, username, password, hash_mode))
    print(check_rdp(ip, username, password, hash_mode))  # <-- added
    print()

def main():
    parser = argparse.ArgumentParser(description="Credential checker across SMB, SSH, WinRM, and psexec")
    parser.add_argument("-u", "--username", required=True, help="Username or path to username file")
    parser.add_argument("-p", "--password", required=True, help="Password or NTLM hash or path to password file")
    parser.add_argument("-s", "--subnet", required=True, help="Target subnet in CIDR format (e.g., 192.168.1.0/24)")
    parser.add_argument("--hash", action="store_true", help="Treat password as NTLM hash")
    parser.add_argument("-d", "--domain", default=None, help="Domain name (optional). If not provided, will try local login.")

    args = parser.parse_args()
    hash_mode = args.hash

    # Check if username/password inputs are files
    if os.path.isfile(args.username):
        with open(args.username, "r") as f:
            usernames = [line.strip() for line in f if line.strip()]
    else:
        usernames = [args.username]

    if os.path.isfile(args.password):
        with open(args.password, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    else:
        passwords = [args.password]

    subnet = ipaddress.ip_network(args.subnet, strict=False)
    live_hosts = []

    console.print(f"[bold]Scanning subnet {args.subnet} for live hosts...[/bold]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(is_host_up, str(ip)): ip for ip in subnet.hosts()}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            if future.result():
                live_hosts.append(str(ip))

    console.print(f"\n[bold green][+] {len(live_hosts)} hosts are up. Starting credential checks...[/bold green]\n")

    for ip in live_hosts:
        for username in usernames:
            for password in passwords:
                console.print(f"[blue]Trying {username}:{password} on {ip}[/blue]")
                check_host(ip, username, password, hash_mode, args.domain)


if __name__ == "__main__":
    main()
