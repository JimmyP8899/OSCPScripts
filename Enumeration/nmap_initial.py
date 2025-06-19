#!/usr/bin/env python3

import subprocess
import os
import argparse

def run_parallel_scans(ip, output_dir):
    scans = {
        "nmap.txt": f"nmap -sVC {ip} -Pn --open",
        "fullscan.txt": f"nmap -p- -sVC {ip} -Pn --open",
        "UDP.txt": f"nmap -p- -sU --max-retries 1 --min-rate 5000 -Pn --open {ip}"
    }

    processes = []

    for filename, command in scans.items():
        output_path = os.path.join(output_dir, filename)
        print(f"[*] Starting: {command}")
        with open(output_path, "w") as f:
            proc = subprocess.Popen(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
            processes.append((proc, filename))

    for proc, filename in processes:
        proc.wait()
        print(f"[+] Finished: {filename}")

def main():
    parser = argparse.ArgumentParser(description="Run Nmap scans on a target IP in parallel")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("output_dir", help="Directory to save output files")
    args = parser.parse_args()

    ip = args.ip
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    run_parallel_scans(ip, output_dir)
    print("[*] All scans completed.")

if __name__ == "__main__":
    main()