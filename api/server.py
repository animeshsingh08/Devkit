from __future__ import annotations

import hmac
import ipaddress
import os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from recon.dns_enum import enumerate_dns, discover_subdomains
from recon.scanner import scan_ports
from recon.reporting import write_reports

BASE_DIR = Path(__file__).resolve().parents[1]
REPORTS_DIR = BASE_DIR / "reports"
WORDLIST = BASE_DIR / "wordlists" / "subdomains.txt"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$")
PORTS_RE = re.compile(r"^[0-9,-]{1,100}$")

app = FastAPI(title="DevKit Recon API", version="1.0.0", description="Authorized reconnaissance backend for DevKit X")
origins = [x.strip() for x in os.getenv("RECON_CORS_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:8000").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

executor = ThreadPoolExecutor(max_workers=2)
jobs: dict[str, dict] = {}
lock = threading.Lock()


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    ports: str = Field(default="1-1000", max_length=100)
    include_dns: bool = True
    include_subdomains: bool = True
    include_ports: bool = True
    authorized: bool = False


def require_api_key(x_api_key: str | None) -> None:
    expected = os.getenv("RECON_API_KEY", "").strip()
    if expected and (not x_api_key or not hmac.compare_digest(x_api_key, expected)):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


def validate_target(value: str) -> str:
    target = value.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        if not DOMAIN_RE.fullmatch(target):
            raise HTTPException(status_code=422, detail="Enter a valid domain name or IP address.")
        return target.lower()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def update_job(job_id: str, **changes) -> None:
    with lock:
        if job_id in jobs:
            jobs[job_id].update(changes)


def run_scan(job_id: str, request: ScanRequest, target: str) -> None:
    started = datetime.now(timezone.utc)
    data = {"target": target, "started_at": started.isoformat(), "authorization_confirmed": True,
            "dns": {}, "subdomains": [], "ports": []}
    try:
        if request.include_dns:
            update_job(job_id, status="running", stage="DNS enumeration", progress=15)
            data["dns"] = enumerate_dns(target)
        if request.include_subdomains and not is_ip(target):
            update_job(job_id, stage="Subdomain discovery", progress=35)
            data["subdomains"] = discover_subdomains(target, WORDLIST)
        if request.include_ports:
            update_job(job_id, stage="Nmap service scan", progress=55)
            data["ports"] = scan_ports(target, request.ports)
        data["finished_at"] = datetime.now(timezone.utc).isoformat()
        safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
        out_dir = REPORTS_DIR / f"{safe_target}_{started.strftime('%Y%m%d_%H%M%S')}_{job_id[:8]}"
        write_reports(data, out_dir)
        update_job(job_id, status="completed", stage="Completed", progress=100,
                   results=data, report_dir=str(out_dir))
    except Exception as exc:
        update_job(job_id, status="failed", stage="Failed", error=str(exc), progress=100)


@app.get("/api/health")
def health(x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    require_api_key(x_api_key)
    return {"status": "ok", "service": "DevKit Recon API", "nmap_available": __import__("shutil").which("nmap") is not None}


@app.post("/api/scans", status_code=202)
def create_scan(request: ScanRequest, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    require_api_key(x_api_key)
    if not request.authorized:
        raise HTTPException(status_code=400, detail="Confirm that you own the target or have explicit permission.")
    target = validate_target(request.target)
    if not request.include_dns and not request.include_subdomains and not request.include_ports:
        raise HTTPException(status_code=400, detail="Select at least one scan module.")
    if request.include_ports:
        if not PORTS_RE.fullmatch(request.ports):
            raise HTTPException(status_code=422, detail="Invalid port expression. Example: 1-1000 or 22,80,443.")
        for part in request.ports.split(","):
            bounds = part.split("-")
            try:
                nums = [int(x) for x in bounds]
            except ValueError:
                raise HTTPException(status_code=422, detail="Invalid port expression.")
            if len(nums) not in (1, 2) or any(n < 1 or n > 65535 for n in nums) or (len(nums) == 2 and nums[0] > nums[1]):
                raise HTTPException(status_code=422, detail="Ports must be between 1 and 65535, with valid ranges.")
    job_id = uuid.uuid4().hex
    with lock:
        jobs[job_id] = {"id": job_id, "status": "queued", "stage": "Queued", "progress": 0,
                        "target": target, "created_at": datetime.now(timezone.utc).isoformat()}
    executor.submit(run_scan, job_id, request, target)
    return {"id": job_id, "status": "queued"}


@app.get("/api/scans/{job_id}")
def scan_status(job_id: str, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    require_api_key(x_api_key)
    with lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scan job not found. Jobs are stored in memory and reset when the API restarts.")
        return {k: v for k, v in job.items() if k not in ("report_dir", "results")} | {
            "summary": ({"open_ports": len(job["results"]["ports"]),
                         "subdomains": len(job["results"]["subdomains"])} if job.get("results") else None),
            "reports_ready": bool(job.get("report_dir"))}


@app.get("/api/scans/{job_id}/results")
def scan_results(job_id: str, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    require_api_key(x_api_key)
    with lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scan job not found.")
        if job["status"] != "completed":
            raise HTTPException(status_code=409, detail="Scan has not completed.")
        return job["results"]


@app.get("/api/scans/{job_id}/report/{kind}")
def download_report(job_id: str, kind: str, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    require_api_key(x_api_key)
    if kind not in {"html", "pdf", "json"}:
        raise HTTPException(status_code=404, detail="Report type must be html, pdf or json.")
    with lock:
        job = jobs.get(job_id)
        if not job or job.get("status") != "completed" or not job.get("report_dir"):
            raise HTTPException(status_code=404, detail="Report is not available.")
        report_path = Path(job["report_dir"]) / ("report." + kind if kind != "json" else "results.json")
    if not report_path.is_file() or not report_path.resolve().is_relative_to(REPORTS_DIR.resolve()):
        raise HTTPException(status_code=404, detail="Report file not found.")
    media = {"html": "text/html", "pdf": "application/pdf", "json": "application/json"}[kind]
    return FileResponse(report_path, media_type=media, filename=report_path.name)
