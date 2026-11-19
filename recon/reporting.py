from __future__ import annotations

import html
import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def write_reports(results: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_html(results, output_dir / "report.html")
    _write_pdf(results, output_dir / "report.pdf")


def _write_html(data: dict, path: Path) -> None:
    esc = lambda value: html.escape(str(value))
    dns_rows = "".join(
        f"<tr><th>{esc(key)}</th><td>{esc(', '.join(value) if isinstance(value, list) else value)}</td></tr>"
        for key, value in data["dns"].items()
    )
    sub_rows = "".join(
        f"<tr><td>{esc(item['hostname'])}</td><td>{esc(', '.join(item['addresses']))}</td></tr>"
        for item in data["subdomains"]
    ) or "<tr><td colspan='2'>No subdomains discovered from the supplied wordlist.</td></tr>"
    port_rows = "".join(
        f"<tr><td>{esc(p['protocol'])}/{p['port']}</td><td>{esc(p['service'])}</td><td>{esc((p['product'] + ' ' + p['version']).strip())}</td></tr>"
        for p in data["ports"]
    ) or "<tr><td colspan='3'>No open TCP ports reported.</td></tr>"

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon Report — {esc(data['target'])}</title>
<style>
body{{font:15px/1.55 system-ui,Segoe UI,sans-serif;background:#0b1020;color:#e8edf7;margin:0;padding:32px}}
main{{max-width:1000px;margin:auto}}h1,h2{{color:#8ab4ff}}section{{background:#141c31;border:1px solid #293653;border-radius:12px;padding:20px;margin:18px 0}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #293653;overflow-wrap:anywhere}}th{{color:#a9c7ff}}
small,.muted{{color:#aab6cc}}code{{color:#b9e6ca}}
</style></head><body><main>
<h1>Automated Reconnaissance Report</h1>
<p class="muted">Target: <strong>{esc(data['target'])}</strong> · Started: {esc(data['started_at'])} · Finished: {esc(data['finished_at'])}</p>
<p class="muted">Authorization was confirmed by the operator. Results are observations, not proof of vulnerability.</p>
<section><h2>DNS Enumeration</h2><table>{dns_rows}</table></section>
<section><h2>Discovered Subdomains</h2><table><tr><th>Hostname</th><th>Addresses</th></tr>{sub_rows}</table></section>
<section><h2>Open TCP Ports & Services</h2><table><tr><th>Port</th><th>Service</th><th>Product / Version</th></tr>{port_rows}</table></section>
</main></body></html>"""
    path.write_text(document, encoding="utf-8")


def _write_pdf(data: dict, path: Path) -> None:
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Automated Reconnaissance Report", styles["Title"]),
        Paragraph(f"Target: {data['target']}", styles["Heading2"]),
        Paragraph(f"Started: {data['started_at']}<br/>Finished: {data['finished_at']}", styles["BodyText"]),
        Spacer(1, 14),
        Paragraph("DNS Enumeration", styles["Heading2"]),
    ]

    dns_table = [["Record", "Values"]]
    for key, value in data["dns"].items():
        dns_table.append([str(key), ", ".join(value) if isinstance(value, list) else str(value)])
    story.append(_table(dns_table))
    story.extend([Spacer(1, 12), Paragraph("Discovered Subdomains", styles["Heading2"])])
    sub_table = [["Hostname", "Addresses"]]
    sub_table.extend([[item["hostname"], ", ".join(item["addresses"])] for item in data["subdomains"]])
    if len(sub_table) == 1:
        sub_table.append(["None found", ""])
    story.append(_table(sub_table))
    story.extend([Spacer(1, 12), Paragraph("Open TCP Ports & Services", styles["Heading2"])])
    port_table = [["Port", "Service", "Product / Version"]]
    port_table.extend([
        [f"{p['protocol']}/{p['port']}", p["service"], f"{p['product']} {p['version']}".strip()]
        for p in data["ports"]
    ])
    if len(port_table) == 1:
        port_table.append(["None found", "", ""])
    story.append(_table(port_table))
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "Authorized-use note: findings are informational and should be manually validated.",
        styles["Italic"]
    ))
    SimpleDocTemplate(str(path), pagesize=A4, rightMargin=36, leftMargin=36).build(story)


def _table(rows: list[list[str]]) -> Table:
    table = Table(rows, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dce8f7")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#14213d")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9aa9bd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table
