from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET


def scan_ports(target: str, ports: str = "1-1000") -> list[dict]:
    """Run a conservative Nmap TCP service/version scan and parse XML output."""
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap executable not found on PATH.")

    # Restrict syntax to simple Nmap port specifications; prevents option injection.
    allowed = set("0123456789,-")
    if not ports or any(ch not in allowed for ch in ports):
        raise ValueError("Invalid --ports value. Use e.g. 1-1000 or 22,80,443.")

    command = [
        "nmap", "-sT", "-sV", "-T3", "--top-ports", "1000",
        "-oX", "-", target
    ]
    # If the user explicitly supplies a port expression, use -p rather than --top-ports.
    if ports != "1-1000":
        command = ["nmap", "-sT", "-sV", "-T3", "-p", ports, "-oX", "-", target]

    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=900, check=False
    )
    if completed.returncode not in (0, 1):
        detail = completed.stderr.strip() or "Nmap exited with an error."
        raise RuntimeError(detail)

    try:
        root = ET.fromstring(completed.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("Could not parse Nmap XML output.") from exc

    results = []
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state_node = port.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            service = port.find("service")
            results.append({
                "protocol": port.get("protocol", ""),
                "port": int(port.get("portid", "0")),
                "state": state_node.get("state", ""),
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            })
    return results
