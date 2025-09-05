# Not really needed use bulksnmpwalk or enumerate extended objects with snmpwalk
#!/usr/bin/env python3
import argparse
import subprocess
import os
import logging
import sys

# SNMP OIDs grouped by category
OIDS = {
    "System Information": [
        "1.3.6.1.2.1.1"
    ],
    "Processes": [
        "1.3.6.1.2.1.25.1.6.0",
        "1.3.6.1.2.1.25.4.2.1.2",
        "1.3.6.1.2.1.25.4.2.1.4"
    ],
    "Installed Software": [
        "1.3.6.1.2.1.25.6.3.1.2"
    ],
    "User Accounts": [
        "1.3.6.1.4.1.77.1.2.25"
    ],
    "Network Interfaces": [
        "1.3.6.1.2.1.2.2.1.2",
        "1.3.6.1.2.1.2.2.1.6",
        "1.3.6.1.2.1.4.20.1.1",
        "1.3.6.1.2.1.4.21",
        "1.3.6.1.2.1.4.22.1.2"
    ],
    "TCP and UDP": [
        "1.3.6.1.2.1.6.13.1.3",
        "1.3.6.1.2.1.7.5.1.2"
    ],
    "Storage Information": [
        "1.3.6.1.2.1.25.2.3.1.3",
        "1.3.6.1.2.1.25.2.3.1.5"
    ],
    "Extended Objects (if available)": [
        "NET-SNMP-EXTEND-MIB::nsExtendObjects"
    ]
}


def run_snmpwalk(ip, community, category, oid, outfile):
    """Run snmpwalk and append results to the output file."""
    cmd = ["snmpwalk", "-v2c", "-c", community, ip, oid]
    logging.info(f"[+] Running {category} - OID: {oid}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        with open(outfile, "a") as f:
            f.write(f"\n===== {category} ({oid}) =====\n")
            if result.stdout.strip():
                f.write(result.stdout)
            else:
                f.write("No output or OID not supported.\n")
    except Exception as e:
        logging.error(f"[-] Error running snmpwalk for {oid}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="SNMP Enumeration Script (replicates msfconsole scanner/snmp/snmp_enum)",
        usage="%(prog)s -t TARGET -o OUTPUT_DIR [-c COMMUNITY]"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("-c", "--community", default="public", help="SNMP community string (default: public)")
    args = parser.parse_args()

    ip = args.target
    outdir = args.output
    community = args.community

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s"
    )

    logging.info("[+] Starting SNMP Enumeration")
    logging.info(f"[+] Target: {ip}")
    logging.info(f"[+] Community: {community}")
    logging.info(f"[+] Output directory: {outdir}")

    # Ensure output directory exists
    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, f"snmp_enum.txt")

    # Clear file if already exists
    open(outfile, "w").close()

    # Loop through categories and OIDs
    for category, oids in OIDS.items():
        for oid in oids:
            run_snmpwalk(ip, community, category, oid, outfile)

    logging.info(f"[+] Enumeration complete. Results saved to {outfile}")


if __name__ == "__main__":
    if len(sys.argv) == 1:  # No args = show help
        print("Usage: python3 snmp_enum.py -t TARGET -o OUTPUT_DIR [-c COMMUNITY]")
        print("Example: python3 snmp_enum.py -t 192.168.1.10 -o ./results -c public")
        sys.exit(1)
    main()
