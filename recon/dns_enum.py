from __future__ import annotations

import ipaddress
from pathlib import Path

import dns.resolver

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def enumerate_dns(target: str) -> dict:
    """Query common DNS record types; individual failures are recorded, not fatal."""
    if _is_ip(target):
        return {"note": "DNS record enumeration is skipped for IP-address targets."}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    output = {}
    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(target, record_type, raise_on_no_answer=False)
            output[record_type] = [answer.to_text() for answer in answers] if answers.rrset else []
        except Exception as exc:
            output[record_type] = []
            output.setdefault("_errors", {})[record_type] = type(exc).__name__
    return output


def discover_subdomains(domain: str, wordlist_path: Path) -> list[dict]:
    """Resolve candidate names from a local wordlist; no external data source is used."""
    if not wordlist_path.exists():
        raise FileNotFoundError(
            f"Wordlist not found: {wordlist_path}. Supply --wordlist or restore the default."
        )

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 2.0
    found = []
    candidates = [
        line.strip().lower()
        for line in wordlist_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    for label in candidates:
        # Avoid malformed labels and accidental nested names in a wordlist.
        if "." in label or len(label) > 63 or not all(
            c.isalnum() or c == "-" for c in label
        ):
            continue
        fqdn = f"{label}.{domain}"
        addresses = set()
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(fqdn, record_type)
                addresses.update(answer.to_text() for answer in answers)
            except Exception:
                pass
        if addresses:
            found.append({"hostname": fqdn, "addresses": sorted(addresses)})
    return found
