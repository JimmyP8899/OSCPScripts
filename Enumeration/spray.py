#!/usr/bin/env python3

import subprocess
import argparse
import ipaddress
import concurrent.futures
from rich import print
from rich.console import Console
import platform

console = Console()

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
def check_smb(ip, username, password):
    cmd = f"crackmapexec smb {ip} -u '{username}' -p '{password}' --no-bruteforce"
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

    # Look for success indicator lines
    valid_indicator = False
    for line in output.splitlines():
        # Check for a successful SMB login line
        if f"SMB" in line and ip in line and "[+]" in line:
            valid_indicator = True
            break

    if valid_indicator:
        return "[bold green][SMB][/bold green] [green]VALID[/green]"
    elif any(err in output.lower() for err in ["logon failure", "access denied", "nt_status_logon_failure"]):
        return "[bold green][SMB][/bold green] [red]INVALID[/red]"
    else:
        return "[bold green][SMB][/bold green] [yellow]UNKNOWN[/yellow]"


def check_winrm(ip, username, password):
    output = run_command(f"crackmapexec winrm {ip} -u '{username}' -p '{password}'")
    return "[bold cyan][WINRM][/bold cyan] " + ("[green]VALID[/green]" if "[+]" in output and "Pwn3d!" in output else "[red]INVALID[/red]")
def check_rpc(ip, username, password):
    cmd = f"rpcclient -U \"{username}%{password}\" {ip} -c exit"
    output = run_command(cmd)

    if "NT_STATUS_LOGON_FAILURE" in output or "NT_STATUS_ACCESS_DENIED" in output:
        return "[bold bright_blue][RPC][/bold bright_blue] [red]INVALID[/red]"
    elif "Cannot connect to server" in output or "Connection refused" in output:
        return "[bold bright_blue][RPC][/bold bright_blue] [yellow]UNREACHABLE[/yellow]"
    elif output.strip() == "":
        # No output usually means success and immediate exit
        return "[bold bright_blue][RPC][/bold bright_blue] [green]VALID[/green]"
    else:
        return "[bold bright_blue][RPC][/bold bright_blue] [yellow]UNKNOWN[/yellow]"

def check_host(ip, username, password):
    print(f"[bold white]Checking {ip}[/bold white]")
    print(check_smb(ip, username, password))
    print(check_winrm(ip, username, password))
    print(check_ssh(ip, username, password))
    print(check_psexec(ip, username, password))
    print(check_rpc(ip, username, password))  # Added here
    print()

def check_ssh(ip, username, password):
    output = run_command(f"crackmapexec ssh {ip} -u '{username}' -p '{password}'")
    return "[bold magenta][SSH][/bold magenta] " + ("[green]VALID[/green]" if "VALID" in output.upper() else "[red]INVALID[/red]")
def check_psexec(ip, username, password):
    cmd = f"impacket-wmiexec '{username}':'{password}'@{ip} whoami"
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
    except subprocess.TimeoutExpired:
        return "[bold yellow][WMI (PSEXEC)][/bold yellow] [yellow]TIMEOUT[/yellow]"

    output_lower = output.lower()

    # ✅ Success indicators
    if (
        "nt authority\\" in output_lower or
        "\\" in output_lower or
        "administrator" in output_lower or
        "microsoft windows" in output_lower
    ):
        return "[bold yellow][WMI (PSEXEC)][/bold yellow] [green]VALID[/green]"

    # ❌ Failure indicators
    elif any(err in output_lower for err in [
        "logon failure",
        "access denied",
        "nt_status_logon_failure",
        "wrong password",
        "failed to authenticate"
    ]):
        return "[bold yellow][WMI (PSEXEC)][/bold yellow] [red]INVALID[/red]"

    # 🤔 Unknown/ambiguous output
    else:
        return "[bold yellow][WMI (PSEXEC)][/bold yellow] [yellow]UNKNOWN[/yellow]"




def main():
    parser = argparse.ArgumentParser(description="Credential checker across SMB, SSH, WinRM, and psexec")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-s", "--subnet", required=True, help="Target subnet in CIDR format (e.g., 192.168.1.0/24)")

    args = parser.parse_args()

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
        check_host(ip, args.username, args.password)

if __name__ == "__main__":
    main()
