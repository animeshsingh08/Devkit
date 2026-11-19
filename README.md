# Automated Reconnaissance Framework

A Python CLI and FastAPI backend for **authorized** reconnaissance of a domain or IP address. It combines DNS record checks, wordlist-based subdomain discovery, Nmap service/version detection, and HTML/PDF reporting.

## Scope and safety

Use this tool only against systems you own or have explicit written permission to assess. The tool requires `--authorized` before it will run. Start with a target in a lab or staging environment.

The default Nmap profile scans the top 1,000 TCP ports with version detection and moderate timing (`-T3`). It does not run NSE scripts, exploit checks, brute-force logins, or stealth/evasion options.

## Requirements

- Python 3.10+
- Nmap installed and available on `PATH`
- Python packages: `dnspython`, `reportlab`, `fastapi`, `uvicorn`

Install:

```bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

Install Nmap separately:
- Windows: https://nmap.org/download.html
- macOS: `brew install nmap`
- Debian/Ubuntu/Kali: `sudo apt install nmap`

## Run

```bash
python main.py example.com --authorized
```

Custom ports and a custom subdomain wordlist:

```bash
python main.py example.com --authorized --ports 1-1024 --wordlist wordlists/subdomains.txt
```

Skip port scanning (DNS-only):

```bash
python main.py example.com --authorized --no-port-scan
```

Reports are written to `reports/<target>_<timestamp>/`:
- `report.html`
- `report.pdf`
- `results.json`

## Project layout

```text
automated-recon-framework/
├── main.py
├── requirements.txt
├── recon/
│   ├── __init__.py
│   ├── dns_enum.py
│   ├── scanner.py
│   └── reporting.py
├── wordlists/subdomains.txt
└── reports/
```

## Notes / limitations

- Subdomain discovery is a simple DNS wordlist check, not a guarantee of completeness.
- DNS answers and service banners can be incomplete or misleading.
- Nmap must be installed separately; installing the Python dependencies does not install Nmap.
- PDF generation requires ReportLab. HTML and JSON are also generated for easy future webpage integration.


## DevKit X integration

The `devkit_x_v3.html` file adds an **Automated Recon** module to the existing DevKit X single-file frontend. It communicates with this FastAPI backend; the browser itself does not run Nmap.

### Start the backend locally

```bash
pip install -r requirements.txt
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Open `devkit_x_v3.html` using VS Code Live Server. In DevKit, open **Automated Recon**, leave the API URL as `http://127.0.0.1:8000`, and click **Check backend connection**. Then enter an authorized target and confirm permission before starting a scan.

### Optional API key

Set `RECON_API_KEY` in the backend environment. Enter the same value in the DevKit API key field. Do not hardcode API keys into a public HTML file or commit them to Git.

### CORS for a hosted frontend

Set `RECON_CORS_ORIGINS` to a comma-separated list of exact trusted origins, for example:

```bash
RECON_CORS_ORIGINS=https://your-github-username.github.io
```

The backend must be deployed separately on a host where Nmap is installed. GitHub Pages cannot run Python, Nmap, or the API. Do not expose an unauthenticated reconnaissance API to the public internet. Prefer a private deployment, authentication proxy, HTTPS, rate limits, and network-level restrictions.

### API endpoints

- `GET /api/health` — backend and Nmap status
- `POST /api/scans` — queue an authorized scan
- `GET /api/scans/{job_id}` — job progress/status
- `GET /api/scans/{job_id}/results` — JSON findings
- `GET /api/scans/{job_id}/report/{html|pdf|json}` — download a report

Jobs are held in memory for this first integration and reset when the API restarts. This version is intended for local development / controlled use, not multi-user production deployment.
