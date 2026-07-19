from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from proofs.idor_proof import write_proof


ROOT_DIR = Path(__file__).resolve().parents[1]
DB_PATH = ROOT_DIR / "audit_console.sqlite3"
RUNS_DIR = ROOT_DIR / "runs"
ARTIFACTS_DIR = ROOT_DIR / "artifacts"
WEB_ENGINE_URL = os.environ.get("BUG_BUNNY_WEB_ENGINE_URL", "http://127.0.0.1:8787")
WEB_AUDIT_TIMEOUT_SECONDS = 90


class AuditCreateRequest(BaseModel):
    target: str = Field(min_length=1)
    scope_notes: str = ""
    authorized: bool = False


class AuditRunModel(BaseModel):
    run_id: str
    target: str
    target_type: str
    scope_notes: str
    authorized: bool
    status: str
    run_dir: str
    raw_dir: str
    reports_dir: str
    report_path: str | None = None
    created_at: str
    updated_at: str


class FindingModel(BaseModel):
    finding_id: str
    run_id: str
    severity: str
    title: str
    location: str
    hypothesis: str
    confidence: int
    evidence: dict[str, Any]
    remediation: str
    poc: str
    status: str
    created_at: str


app = FastAPI(title="Bug Bunny.ai Local Audit Console", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    RUNS_DIR.mkdir(exist_ok=True)
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_runs (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                scope_notes TEXT NOT NULL,
                authorized INTEGER NOT NULL,
                status TEXT NOT NULL,
                run_dir TEXT NOT NULL,
                raw_dir TEXT NOT NULL,
                reports_dir TEXT NOT NULL,
                report_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                location TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                remediation TEXT NOT NULL,
                poc TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES audit_runs(run_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id)")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def classify_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    return "repo_path"


def row_to_run(row: sqlite3.Row) -> AuditRunModel:
    return AuditRunModel(
        run_id=row["run_id"],
        target=row["target"],
        target_type=row["target_type"],
        scope_notes=row["scope_notes"],
        authorized=bool(row["authorized"]),
        status=row["status"],
        run_dir=row["run_dir"],
        raw_dir=row["raw_dir"],
        reports_dir=row["reports_dir"],
        report_path=row["report_path"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def row_to_finding(row: sqlite3.Row) -> FindingModel:
    return FindingModel(
        finding_id=row["finding_id"],
        run_id=row["run_id"],
        severity=row["severity"],
        title=row["title"],
        location=row["location"],
        hypothesis=row["hypothesis"],
        confidence=row["confidence"],
        evidence=json.loads(row["evidence_json"]),
        remediation=row["remediation"],
        poc=row["poc"],
        status=row["status"],
        created_at=row["created_at"],
    )


def get_run_or_404(run_id: str) -> AuditRunModel:
    with connect() as conn:
        row = conn.execute("SELECT * FROM audit_runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Audit run not found")
    return row_to_run(row)


def get_findings_for_run(run_id: str) -> list[FindingModel]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY created_at ASC, severity DESC",
            (run_id,),
        ).fetchall()
    return [row_to_finding(row) for row in rows]


def update_run_status(run_id: str, status: str, report_path: str | None = None) -> None:
    now = utc_now()
    with connect() as conn:
        if report_path is None:
            conn.execute(
                "UPDATE audit_runs SET status = ?, updated_at = ? WHERE run_id = ?",
                (status, now, run_id),
            )
        else:
            conn.execute(
                "UPDATE audit_runs SET status = ?, report_path = ?, updated_at = ? WHERE run_id = ?",
                (status, report_path, now, run_id),
            )


def mock_scan_payload(run: AuditRunModel) -> dict[str, Any]:
    target_label = run.target
    if run.target_type == "url":
        findings = [
            {
                "severity": "Medium",
                "title": "Missing Content-Security-Policy header",
                "location": target_label,
                "hypothesis": "The application does not advertise a CSP in mock scanner mode, increasing XSS blast radius if injection exists.",
                "confidence": 82,
                "evidence": {
                    "scanner": "mock-web-baseline",
                    "observed": "content-security-policy header absent in simulated response profile",
                    "mode": "mock",
                },
                "remediation": "Define a restrictive Content-Security-Policy and tune script/style sources.",
                "poc": f"curl -I {json.dumps(target_label)}",
            },
            {
                "severity": "Low",
                "title": "No clickjacking frame control detected",
                "location": target_label,
                "hypothesis": "The page may be embeddable unless runtime controls prevent framing.",
                "confidence": 70,
                "evidence": {
                    "scanner": "mock-web-baseline",
                    "observed": "x-frame-options and CSP frame-ancestors absent in simulated response profile",
                    "mode": "mock",
                },
                "remediation": "Add CSP frame-ancestors or X-Frame-Options according to product requirements.",
                "poc": f"curl -I {json.dumps(target_label)}",
            },
            {
                "severity": "Info",
                "title": "Security contact metadata not configured",
                "location": f"{target_label.rstrip('/')}/.well-known/security.txt",
                "hypothesis": "Researchers may not have a standard disclosure contact path.",
                "confidence": 55,
                "evidence": {
                    "scanner": "mock-route-baseline",
                    "observed": "security.txt absent in mock route profile",
                    "mode": "mock",
                },
                "remediation": "Publish /.well-known/security.txt with contact and policy details.",
                "poc": f"curl -sS {json.dumps(target_label.rstrip('/') + '/.well-known/security.txt')}",
            },
        ]
    else:
        findings = [
            {
                "severity": "Medium",
                "title": "Repository dependency review required",
                "location": target_label,
                "hypothesis": "Mock repo scan identified dependency metadata that should be checked with a real SCA tool next.",
                "confidence": 60,
                "evidence": {
                    "scanner": "mock-repo-baseline",
                    "observed": "repo path accepted and queued for dependency review",
                    "mode": "mock",
                },
                "remediation": "Run the repo through an SCA scanner and pin/patch vulnerable packages.",
                "poc": f"ls -la {json.dumps(target_label)}",
            }
        ]

    return {
        "run_id": run.run_id,
        "target": run.target,
        "target_type": run.target_type,
        "scope_notes": run.scope_notes,
        "scanner_mode": "mock",
        "generated_at": utc_now(),
        "findings": findings,
    }


def web_engine_request(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{WEB_ENGINE_URL}{path}",
        data=body,
        method="POST" if payload is not None else "GET",
        headers={"content-type": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Web audit engine rejected the request: {detail}") from error
    except (URLError, TimeoutError) as error:
        raise HTTPException(
            status_code=503,
            detail="Safe Web engine is unavailable. Start Bug Bunny with `npm run dev`.",
        ) from error


def load_engine_audit(run: AuditRunModel) -> dict[str, Any] | None:
    raw_path = Path(run.raw_dir) / "web_audit.json"
    if not raw_path.exists():
        return None
    return json.loads(raw_path.read_text(encoding="utf-8"))


def response_for_run(run: AuditRunModel, findings: list[FindingModel], markdown: str = "") -> dict[str, Any]:
    return {
        "audit": run.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
        "markdown": markdown,
        "engine_audit": load_engine_audit(run),
    }


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "bug-bunny-fastapi", "db_path": str(DB_PATH)}


@app.post("/api/proofs/idor/run")
def run_idor_verified_proof() -> dict[str, Any]:
    artifact_path = ARTIFACTS_DIR / "idor-before.json"
    proof = write_proof(artifact_path)
    if proof["verdict"] != "confirmed":
        raise HTTPException(status_code=500, detail="IDOR proof assertions did not hold.")
    return {"proof": proof, "artifact_path": str(artifact_path)}


@app.post("/api/audits/create")
def create_audit(payload: AuditCreateRequest) -> dict[str, Any]:
    target = payload.target.strip()
    scope_notes = payload.scope_notes.strip()
    if not payload.authorized:
        raise HTTPException(status_code=400, detail="Authorization checkbox must be true.")
    if not target:
        raise HTTPException(status_code=400, detail="Target URL or repo path is required.")
    if not scope_notes:
        raise HTTPException(status_code=400, detail="Scope notes are required.")

    target_type = classify_target(target)
    if target_type == "url":
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise HTTPException(status_code=400, detail="Target URL must include http:// or https://.")

    run_id = str(uuid.uuid4())
    run_dir = RUNS_DIR / run_id
    raw_dir = run_dir / "raw"
    reports_dir = run_dir / "reports"
    raw_dir.mkdir(parents=True, exist_ok=False)
    reports_dir.mkdir(parents=True, exist_ok=False)
    now = utc_now()

    with connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_runs (
                run_id, target, target_type, scope_notes, authorized, status,
                run_dir, raw_dir, reports_dir, report_path, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                target,
                target_type,
                scope_notes,
                1,
                "created",
                str(run_dir),
                str(raw_dir),
                str(reports_dir),
                None,
                now,
                now,
            ),
        )

    run = get_run_or_404(run_id)
    return {"audit": run.model_dump(), "findings": []}


@app.get("/api/audits")
def list_audits() -> dict[str, Any]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM audit_runs ORDER BY created_at DESC").fetchall()
    return {"audits": [row_to_run(row).model_dump() for row in rows]}


@app.get("/api/audits/{run_id}")
def get_audit(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    markdown = ""
    if run.report_path and Path(run.report_path).exists():
        markdown = Path(run.report_path).read_text(encoding="utf-8")
    return response_for_run(run, findings, markdown)


@app.post("/api/audits/{run_id}/run-web-audit")
def run_web_audit(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    if run.target_type != "url":
        raise HTTPException(status_code=400, detail="The live Web engine currently accepts HTTP(S) targets only.")

    update_run_status(run_id, "scanning")
    started = web_engine_request(
        "/api/audits",
        {
            "target": run.target,
            "scopeRules": run.scope_notes,
            "authorized": run.authorized,
            "mode": "authorized-safe-web",
        },
    )
    engine_id = started["audit"]["id"]
    deadline = time.monotonic() + WEB_AUDIT_TIMEOUT_SECONDS
    engine_audit = started["audit"]

    while engine_audit.get("status") not in {"complete", "failed"}:
        if time.monotonic() >= deadline:
            update_run_status(run_id, "failed")
            raise HTTPException(status_code=504, detail="Safe Web audit exceeded its 90-second limit.")
        time.sleep(0.2)
        engine_audit = web_engine_request(f"/api/audits/{engine_id}")["audit"]

    if engine_audit.get("status") == "failed":
        update_run_status(run_id, "failed")
        raise HTTPException(status_code=502, detail=engine_audit.get("error") or "Safe Web audit failed.")

    raw_path = Path(run.raw_dir) / "web_audit.json"
    raw_path.write_text(json.dumps(engine_audit, indent=2), encoding="utf-8")

    with connect() as conn:
        conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
        now = utc_now()
        for item in engine_audit.get("findings", []):
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, run_id, severity, title, location, hypothesis,
                    confidence, evidence_json, remediation, poc, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.get("id") or str(uuid.uuid4()),
                    run_id,
                    item.get("severity", "Info"),
                    item.get("title", "Untitled finding"),
                    item.get("path", run.target),
                    item.get("hypothesis", "Review the captured evidence."),
                    int(item.get("confidence", 0)),
                    json.dumps({"mode": "authorized-read-only", "observations": item.get("evidence", []), "validation": item.get("validation")}),
                    item.get("remediation", "Review and remediate the observed condition."),
                    item.get("poc", ""),
                    item.get("status", "Observed"),
                    now,
                ),
            )

    update_run_status(run_id, "web_audit_complete")
    run = get_run_or_404(run_id)
    return response_for_run(run, get_findings_for_run(run_id))


@app.post("/api/audits/{run_id}/run-mock-scan")
def run_mock_scan(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    update_run_status(run_id, "scanning")
    run = get_run_or_404(run_id)
    payload = mock_scan_payload(run)
    raw_path = Path(run.raw_dir) / "mock_scan.json"
    raw_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with connect() as conn:
        conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
        now = utc_now()
        for item in payload["findings"]:
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, run_id, severity, title, location, hypothesis,
                    confidence, evidence_json, remediation, poc, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    run_id,
                    item["severity"],
                    item["title"],
                    item["location"],
                    item["hypothesis"],
                    item["confidence"],
                    json.dumps(item["evidence"]),
                    item["remediation"],
                    item["poc"],
                    "mock-verified",
                    now,
                ),
            )

    update_run_status(run_id, "mock_scan_complete")
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    return {
        "audit": run.model_dump(),
        "raw_path": str(raw_path),
        "findings": [finding.model_dump() for finding in findings],
    }


@app.get("/api/audits/{run_id}/findings")
def list_findings(run_id: str) -> dict[str, Any]:
    get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    return {"findings": [finding.model_dump() for finding in findings]}


@app.post("/api/audits/{run_id}/generate-report")
def generate_report(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    if not findings:
        raise HTTPException(status_code=400, detail="Run a safe Web audit before generating a report.")

    report_path = Path(run.reports_dir) / "report.md"
    engine_audit = load_engine_audit(run)
    scanner_mode = "authorized-read-only" if engine_audit else "mock"
    lines = [
        "# Bug Bunny.ai Local Audit Report",
        "",
        f"- Run ID: `{run.run_id}`",
        f"- Target: `{run.target}`",
        f"- Target type: `{run.target_type}`",
        f"- Scanner mode: `{scanner_mode}`",
        f"- Generated: `{utc_now()}`",
        "",
        "## Scope Notes",
        run.scope_notes,
        "",
        "## Findings",
    ]
    for finding in findings:
        lines.extend(
            [
                "",
                f"### {finding.severity}: {finding.title}",
                f"- Location: `{finding.location}`",
                f"- Confidence: {finding.confidence}%",
                f"- Status: {finding.status}",
                f"- Hypothesis: {finding.hypothesis}",
                f"- Evidence: `{json.dumps(finding.evidence)}`",
                f"- PoC: `{finding.poc}`",
                f"- Remediation: {finding.remediation}",
            ]
        )
    lines.extend(
        [
            "",
            "## Notes",
            (
                "This report was generated from bounded live DNS and HTTP observations. "
                "Only GET and HEAD requests were used; no active exploitation was performed."
                if engine_audit
                else "This report was generated in mock scanner mode. No active exploitation was performed."
            ),
        ]
    )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    update_run_status(run_id, "report_generated", str(report_path))
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    response = response_for_run(run, findings, report_path.read_text(encoding="utf-8"))
    response["report_path"] = str(report_path)
    return response


@app.get("/api/audits/{run_id}/report", response_class=PlainTextResponse)
def get_report(run_id: str) -> str:
    run = get_run_or_404(run_id)
    if not run.report_path:
        raise HTTPException(status_code=404, detail="Report not generated yet.")
    report_path = Path(run.report_path)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file is missing.")
    return report_path.read_text(encoding="utf-8")
