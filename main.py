from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from recon.dns_enum import enumerate_dns, discover_subdomains
from recon.scanner import scan_ports
from recon.reporting import write_reports

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$")


def validate_target(value: str) -> str:
    target = value.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        if not DOMAIN_RE.fullmatch(target):
            raise argparse.ArgumentTypeError("Enter a valid domain name or IP address.")
        return target.lower()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automated reconnaissance for explicitly authorized targets."
    )
    parser.add_argument("target", type=validate_target, help="Domain name or IP address")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm you own the target or have explicit permission")
    parser.add_argument("--ports", default="1-1000",
                        help="Nmap TCP port range (default: 1-1000)")
    parser.add_argument("--wordlist", default="wordlists/subdomains.txt",
                        help="Subdomain wordlist path")
    parser.add_argument("--no-port-scan", action="store_true",
                        help="Run DNS checks and subdomain discovery only")
    parser.add_argument("--no-subdomains", action="store_true",
                        help="Skip wordlist-based subdomain discovery")
    args = parser.parse_args()

    if not args.authorized:
        parser.error("Safety check: rerun with --authorized only if you have permission.")

    if not args.no_port_scan and not shutil.which("nmap"):
        parser.error("Nmap was not found on PATH. Install Nmap or use --no-port-scan.")

    started = datetime.now(timezone.utc)
    print(f"[+] Target: {args.target}")
    print("[+] Running DNS enumeration...")
    dns_data = enumerate_dns(args.target)

    subdomains = []
    if not args.no_subdomains and not _is_ip(args.target):
        print("[+] Checking subdomains from wordlist...")
        subdomains = discover_subdomains(args.target, Path(args.wordlist))

    ports = []
    if not args.no_port_scan:
        print(f"[+] Running Nmap service scan ({args.ports})...")
        ports = scan_ports(args.target, args.ports)

    finished = datetime.now(timezone.utc)
    results = {
        "target": args.target,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "authorization_confirmed": True,
        "dns": dns_data,
        "subdomains": subdomains,
        "ports": ports,
    }
    out_dir = Path("reports") / f"{_safe_name(args.target)}_{started.strftime('%Y%m%d_%H%M%S')}"
    out_dir.mkdir(parents=True, exist_ok=True)
    write_reports(results, out_dir)
    print(f"[+] Complete. Reports saved to: {out_dir.resolve()}")
    return 0


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\\n[!] Interrupted by user.", file=sys.stderr)
        raise SystemExit(130)
