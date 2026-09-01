"""
Run this once to scaffold the entire Threat Pipeline project.
    python setup_project.py
"""
import os, textwrap

ROOT = r"C:\Users\janme\OneDrive\Desktop\everything\Threat_pipeline"

FILES = {}

# ── requirements.txt ────────────────────────────────────────────────────────
FILES["requirements.txt"] = """\
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
pydantic>=2.7.0
python-multipart>=0.0.9
orjson>=3.10.0
httpx>=0.27.0
pytest>=8.2.0
pytest-asyncio>=0.23.0
"""

# ── src/__init__.py ──────────────────────────────────────────────────────────
FILES["src/__init__.py"] = "# src package\n"

# ── src/models/__init__.py ───────────────────────────────────────────────────
FILES["src/models/__init__.py"] = "# models package\n"

# ── src/detectors/__init__.py ────────────────────────────────────────────────
FILES["src/detectors/__init__.py"] = """\
from . import port_scan, ssh_bruteforce, suspicious_tls, beaconing
__all__ = ["port_scan", "ssh_bruteforce", "suspicious_tls", "beaconing"]
"""

# ── src/correlator/__init__.py ───────────────────────────────────────────────
FILES["src/correlator/__init__.py"] = "# correlator package\n"

# ── src/scoring/__init__.py ──────────────────────────────────────────────────
FILES["src/scoring/__init__.py"] = "# scoring package\n"

# ── data/.gitkeep ────────────────────────────────────────────────────────────
FILES["data/.gitkeep"] = "# drop real Zeek NDJSON logs here\n"

# ── src/models/log_models.py ─────────────────────────────────────────────────
FILES["src/models/log_models.py"] = '''\
"""Pydantic v2 input models for normalised Zeek log records."""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class ConnLog(BaseModel):
    model_config = {"populate_by_name": True}
    ts: float
    orig_h: str = Field(alias="id.orig_h")
    orig_p: int = Field(alias="id.orig_p")
    resp_h: str = Field(alias="id.resp_h")
    resp_p: int = Field(alias="id.resp_p")
    proto: Optional[str] = None
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None


class SSHLog(BaseModel):
    model_config = {"populate_by_name": True}
    ts: float
    orig_h: str = Field(alias="id.orig_h")
    resp_h: str = Field(alias="id.resp_h")
    resp_p: int = Field(alias="id.resp_p")
    auth_success: Optional[bool] = None
    auth_attempts: Optional[int] = None


class SSLLog(BaseModel):
    model_config = {"populate_by_name": True}
    ts: float
    orig_h: str = Field(alias="id.orig_h")
    resp_h: str = Field(alias="id.resp_h")
    resp_p: int = Field(alias="id.resp_p")
    version: Optional[str] = None
    cipher: Optional[str] = None
    validation_status: Optional[str] = None
    server_name: Optional[str] = None
    ja3: Optional[str] = None
    duration: Optional[float] = None


class LogBundle(BaseModel):
    conn_logs: list[ConnLog] = []
    ssh_logs: list[SSHLog] = []
    ssl_logs: list[SSLLog] = []

    @model_validator(mode="after")
    def at_least_one_non_empty(self) -> "LogBundle":
        if not self.conn_logs and not self.ssh_logs and not self.ssl_logs:
            raise ValueError(
                "LogBundle must contain at least one non-empty log list."
            )
        return self
'''

# ── src/models/alert_models.py ───────────────────────────────────────────────
FILES["src/models/alert_models.py"] = '''\
"""Output models for the threat detection and correlation pipeline."""
from __future__ import annotations
from enum import Enum
from typing import Any, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(str, Enum):
    PORT_SCAN = "PORT_SCAN"
    SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE"
    SUSPICIOUS_TLS = "SUSPICIOUS_TLS"
    BEACONING = "BEACONING"


class IncidentType(str, Enum):
    RECON_AND_INTRUSION = "RECON_AND_INTRUSION"
    MULTI_STAGE_ATTACK = "MULTI_STAGE_ATTACK"
    SINGLE_THREAT = "SINGLE_THREAT"


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    alert_type: AlertType
    severity: Severity
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = None
    timestamp: float
    description: str
    evidence: dict[str, Any] = {}


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_type: IncidentType
    title: str
    severity: Severity
    src_ip: str
    first_seen: float
    last_seen: float
    alert_ids: list[str]
    summary: str


class AnalysisSummary(BaseModel):
    total_conn_logs: int = 0
    total_ssh_logs: int = 0
    total_ssl_logs: int = 0
    total_alerts: int = 0
    total_incidents: int = 0


class AnalysisResponse(BaseModel):
    summary: AnalysisSummary
    raw_alerts: list[Alert] = []
    incidents: list[Incident] = []
'''

# ── src/detectors/port_scan.py ───────────────────────────────────────────────
FILES["src/detectors/port_scan.py"] = '''\
"""Port Scan Detector — sliding-window, one alert per (src, dst) pair."""
from __future__ import annotations
from collections import defaultdict
from ..models.log_models import ConnLog
from ..models.alert_models import Alert, AlertType, Severity

WINDOW_SECONDS: int = 60
MIN_PORTS: int = 20
HIGH_PORTS: int = 50


def detect(conn_logs: list[ConnLog]) -> list[Alert]:
    alerts: list[Alert] = []
    groups: dict[tuple[str, str], list[ConnLog]] = defaultdict(list)
    for log in conn_logs:
        groups[(log.orig_h, log.resp_h)].append(log)

    for (orig_h, resp_h), logs in groups.items():
        logs.sort(key=lambda x: x.ts)
        start = 0
        for end in range(len(logs)):
            while logs[end].ts - logs[start].ts > WINDOW_SECONDS:
                start += 1
            window = logs[start: end + 1]
            distinct_ports: set[int] = {l.resp_p for l in window}
            if len(distinct_ports) >= MIN_PORTS:
                severity = Severity.HIGH if len(distinct_ports) >= HIGH_PORTS else Severity.MEDIUM
                alerts.append(Alert(
                    alert_type=AlertType.PORT_SCAN,
                    severity=severity,
                    src_ip=orig_h,
                    dst_ip=resp_h,
                    timestamp=logs[start].ts,
                    description=(
                        f"Port scan: {orig_h} probed {len(distinct_ports)} distinct "
                        f"ports on {resp_h} within {WINDOW_SECONDS}s"
                    ),
                    evidence={
                        "distinct_ports_count": len(distinct_ports),
                        "sampled_ports": sorted(distinct_ports)[:10],
                        "window_start_ts": logs[start].ts,
                        "window_end_ts": logs[end].ts,
                        "connection_count": len(window),
                    },
                ))
                break  # one alert per pair
    return alerts
'''

# ── src/detectors/ssh_bruteforce.py ──────────────────────────────────────────
FILES["src/detectors/ssh_bruteforce.py"] = '''\
"""SSH Brute-Force Detector — single-record and sequence modes."""
from __future__ import annotations
from collections import defaultdict
from ..models.log_models import SSHLog
from ..models.alert_models import Alert, AlertType, Severity

WINDOW_SECONDS: int = 300
MIN_ATTEMPTS_SINGLE: int = 5
MIN_FAILURES_SEQUENCE: int = 3


def detect(ssh_logs: list[SSHLog]) -> list[Alert]:
    alerts: list[Alert] = []
    fired_ips: set[str] = set()
    groups: dict[str, list[SSHLog]] = defaultdict(list)
    for log in ssh_logs:
        groups[log.orig_h].append(log)

    for orig_h, logs in groups.items():
        if orig_h in fired_ips:
            continue
        logs.sort(key=lambda x: x.ts)

        # Mode 1 — single record with high attempt count
        for log in logs:
            if log.auth_attempts and log.auth_attempts > MIN_ATTEMPTS_SINGLE:
                severity = Severity.CRITICAL if log.auth_success else Severity.HIGH
                alerts.append(Alert(
                    alert_type=AlertType.SSH_BRUTE_FORCE,
                    severity=severity,
                    src_ip=orig_h,
                    dst_ip=log.resp_h,
                    dst_port=log.resp_p,
                    timestamp=log.ts,
                    description=(
                        f"SSH brute force from {orig_h}: "
                        f"{log.auth_attempts} attempts, success={log.auth_success}"
                    ),
                    evidence={
                        "mode": "single_record",
                        "auth_attempts": log.auth_attempts,
                        "auth_success": bool(log.auth_success),
                    },
                ))
                fired_ips.add(orig_h)
                break

        if orig_h in fired_ips:
            continue

        # Mode 2 — failures then success within window
        for anchor in logs:
            window_end = anchor.ts + WINDOW_SECONDS
            window = [l for l in logs if anchor.ts <= l.ts <= window_end]
            failures = [l for l in window if not l.auth_success]
            successes = [l for l in window if l.auth_success]
            if len(failures) >= MIN_FAILURES_SEQUENCE and successes:
                last = window[-1]
                alerts.append(Alert(
                    alert_type=AlertType.SSH_BRUTE_FORCE,
                    severity=Severity.CRITICAL,
                    src_ip=orig_h,
                    dst_ip=last.resp_h,
                    dst_port=last.resp_p,
                    timestamp=anchor.ts,
                    description=(
                        f"SSH brute force with successful login from {orig_h}: "
                        f"{len(failures)} failures then access granted"
                    ),
                    evidence={
                        "mode": "sequence",
                        "failed_attempts": len(failures),
                        "auth_success": True,
                        "window_start_ts": anchor.ts,
                        "window_end_ts": last.ts,
                    },
                ))
                fired_ips.add(orig_h)
                break
    return alerts
'''

# ── src/detectors/suspicious_tls.py ──────────────────────────────────────────
FILES["src/detectors/suspicious_tls.py"] = '''\
"""Suspicious TLS Detector — invalid cert, weak version, short session."""
from __future__ import annotations
import ipaddress
from ..models.log_models import SSLLog
from ..models.alert_models import Alert, AlertType, Severity

WEAK_VERSIONS: frozenset[str] = frozenset({
    "SSLv2", "SSLv3", "SSLv23",
    "TLSv10", "TLSv1", "TLSv1.0",
    "TLSv11", "TLSv1.1",
})
SHORT_DURATION: float = 5.0


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def detect(ssl_logs: list[SSLLog]) -> list[Alert]:
    alerts: list[Alert] = []
    for log in ssl_logs:
        triggers: list[str] = []
        if log.validation_status and log.validation_status.lower() not in ("ok", "valid"):
            triggers.append("invalid_cert")
        if log.version and log.version in WEAK_VERSIONS:
            triggers.append("weak_tls_version")
        if (log.duration is not None
                and log.duration < SHORT_DURATION
                and not _is_private(log.resp_h)):
            triggers.append("short_duration")
        if not triggers:
            continue
        severity = Severity.HIGH if len(triggers) >= 2 else Severity.MEDIUM
        alerts.append(Alert(
            alert_type=AlertType.SUSPICIOUS_TLS,
            severity=severity,
            src_ip=log.orig_h,
            dst_ip=log.resp_h,
            dst_port=log.resp_p,
            timestamp=log.ts,
            description=f"Suspicious TLS from {log.orig_h} to {log.resp_h}: {', '.join(triggers)}",
            evidence={
                "triggers": triggers,
                "trigger_count": len(triggers),
                "tls_version": log.version,
                "validation_status": log.validation_status,
                "duration": log.duration,
                "server_name": log.server_name,
                "ja3": log.ja3,
                "cipher": log.cipher,
            },
        ))
    return alerts
'''

# ── src/detectors/beaconing.py ────────────────────────────────────────────────
FILES["src/detectors/beaconing.py"] = '''\
"""Beaconing / C2 Detector — long-lived low-byte connections to bad ports."""
from __future__ import annotations
from ..models.log_models import ConnLog
from ..models.alert_models import Alert, AlertType, Severity

SUSPICIOUS_PORTS: frozenset[int] = frozenset(
    {4444, 1234, 31337, 5555, 6666, 6667, 9001, 9002, 8888, 1337, 65535, 2222, 3333, 7777}
)
CRITICAL_PORTS: frozenset[int] = frozenset({4444, 31337, 9001, 1337})
MIN_DURATION: float = 60.0
MAX_BYTES: int = 500


def detect(conn_logs: list[ConnLog]) -> list[Alert]:
    alerts: list[Alert] = []
    for log in conn_logs:
        if log.resp_p not in SUSPICIOUS_PORTS:
            continue
        if log.duration is None or log.duration < MIN_DURATION:
            continue
        if log.orig_bytes is None or log.orig_bytes >= MAX_BYTES:
            continue
        is_critical = log.resp_p in CRITICAL_PORTS
        alerts.append(Alert(
            alert_type=AlertType.BEACONING,
            severity=Severity.CRITICAL if is_critical else Severity.HIGH,
            src_ip=log.orig_h,
            dst_ip=log.resp_h,
            dst_port=log.resp_p,
            timestamp=log.ts,
            description=(
                f"Beaconing to {log.resp_h}:{log.resp_p} — "
                f"duration {log.duration:.1f}s, only {log.orig_bytes} bytes sent"
            ),
            evidence={
                "resp_port": log.resp_p,
                "is_critical_port": is_critical,
                "duration": log.duration,
                "orig_bytes": log.orig_bytes,
                "resp_bytes": log.resp_bytes,
                "conn_state": log.conn_state,
            },
        ))
    return alerts
'''

# ── src/correlator/incident_correlator.py ─────────────────────────────────────
FILES["src/correlator/incident_correlator.py"] = '''\
"""Incident Correlator — groups alerts by IP + time window into Incidents."""
from __future__ import annotations
from collections import defaultdict
from ..models.alert_models import Alert, AlertType, Incident, IncidentType, Severity

CORRELATION_WINDOW: int = 300
_SEV = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _bump(s: Severity) -> Severity:
    return _SEV[min(_SEV.index(s) + 1, 3)]


def _max_sev(sevs: list[Severity]) -> Severity:
    return max(sevs, key=lambda s: _SEV.index(s))


def correlate(alerts: list[Alert]) -> list[Incident]:
    if not alerts:
        return []
    incidents: list[Incident] = []
    groups: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        groups[a.src_ip].append(a)

    for src_ip, src_alerts in groups.items():
        src_alerts.sort(key=lambda a: a.timestamp)
        clusters: list[list[Alert]] = []
        cur = [src_alerts[0]]
        for a in src_alerts[1:]:
            if a.timestamp - cur[0].timestamp <= CORRELATION_WINDOW:
                cur.append(a)
            else:
                clusters.append(cur)
                cur = [a]
        clusters.append(cur)

        for cluster in clusters:
            types: set[AlertType] = {a.alert_type for a in cluster}
            max_s = _max_sev([a.severity for a in cluster])

            if AlertType.PORT_SCAN in types and AlertType.SSH_BRUTE_FORCE in types:
                itype = IncidentType.RECON_AND_INTRUSION
                max_s = _bump(max_s)
                title = f"Recon & Intrusion from {src_ip}"
                summary = (
                    f"Attacker {src_ip} performed port scan then SSH brute-force "
                    f"({len(cluster)} alerts: {', '.join(sorted(t.value for t in types))})."
                )
            elif len(types) >= 3:
                itype = IncidentType.MULTI_STAGE_ATTACK
                max_s = _bump(max_s)
                title = f"Multi-Stage Attack from {src_ip}"
                summary = (
                    f"Attacker {src_ip} used {len(types)} techniques "
                    f"({', '.join(sorted(t.value for t in types))}) across {len(cluster)} alerts."
                )
            else:
                itype = IncidentType.SINGLE_THREAT
                label = next(iter(types)).value.replace("_", " ").title()
                title = f"{label} from {src_ip}"
                summary = f"Single threat from {src_ip}: {next(iter(types)).value} — {len(cluster)} alert(s)."

            incidents.append(Incident(
                incident_type=itype,
                title=title,
                severity=max_s,
                src_ip=src_ip,
                first_seen=cluster[0].timestamp,
                last_seen=cluster[-1].timestamp,
                alert_ids=[a.alert_id for a in cluster],
                summary=summary,
            ))
    return incidents
'''

# ── src/scoring/severity_scorer.py ───────────────────────────────────────────
FILES["src/scoring/severity_scorer.py"] = '''\
"""Severity Scorer — canonical post-detection severity rules."""
from __future__ import annotations
from ..models.alert_models import Alert, AlertType, Severity


def score_alerts(alerts: list[Alert]) -> list[Alert]:
    for alert in alerts:
        if alert.alert_type == AlertType.PORT_SCAN:
            c = alert.evidence.get("distinct_ports_count", 0)
            alert.severity = Severity.HIGH if c >= 50 else Severity.MEDIUM
        elif alert.alert_type == AlertType.SSH_BRUTE_FORCE:
            alert.severity = Severity.CRITICAL if alert.evidence.get("auth_success") else Severity.HIGH
        elif alert.alert_type == AlertType.SUSPICIOUS_TLS:
            alert.severity = Severity.HIGH if alert.evidence.get("trigger_count", 1) >= 2 else Severity.MEDIUM
        elif alert.alert_type == AlertType.BEACONING:
            alert.severity = Severity.CRITICAL if alert.evidence.get("is_critical_port") else Severity.HIGH
    return alerts
'''

# ── src/pipeline.py ───────────────────────────────────────────────────────────
FILES["src/pipeline.py"] = '''\
"""Pipeline orchestrator — wires detectors → scorer → correlator."""
from __future__ import annotations
from .detectors import beaconing, port_scan, ssh_bruteforce, suspicious_tls
from .correlator.incident_correlator import correlate
from .models.alert_models import Alert, AnalysisResponse, AnalysisSummary
from .models.log_models import LogBundle
from .scoring.severity_scorer import score_alerts


def run_pipeline(bundle: LogBundle) -> AnalysisResponse:
    raw_alerts: list[Alert] = []
    if bundle.conn_logs:
        raw_alerts.extend(port_scan.detect(bundle.conn_logs))
        raw_alerts.extend(beaconing.detect(bundle.conn_logs))
    if bundle.ssh_logs:
        raw_alerts.extend(ssh_bruteforce.detect(bundle.ssh_logs))
    if bundle.ssl_logs:
        raw_alerts.extend(suspicious_tls.detect(bundle.ssl_logs))

    raw_alerts = score_alerts(raw_alerts)
    raw_alerts.sort(key=lambda a: a.timestamp)
    incidents = correlate(raw_alerts)

    return AnalysisResponse(
        summary=AnalysisSummary(
            total_conn_logs=len(bundle.conn_logs),
            total_ssh_logs=len(bundle.ssh_logs),
            total_ssl_logs=len(bundle.ssl_logs),
            total_alerts=len(raw_alerts),
            total_incidents=len(incidents),
        ),
        raw_alerts=raw_alerts,
        incidents=incidents,
    )
'''

# ── main.py ───────────────────────────────────────────────────────────────────
FILES["main.py"] = '''\
"""FastAPI entry point. Run: uvicorn main:app --reload --port 8000"""
from __future__ import annotations
import time
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from src.models.log_models import LogBundle
from src.models.alert_models import AnalysisResponse
from src.pipeline import run_pipeline

app = FastAPI(
    title="Threat Pipeline API",
    description="Zeek log threat detection and incident correlation service.",
    version="1.0.0",
)


@app.middleware("http")
async def add_process_time(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Process-Time-Ms"] = f"{(time.perf_counter()-start)*1000:.2f}"
    return response


@app.exception_handler(Exception)
async def global_exc(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": str(exc), "type": type(exc).__name__, "path": str(request.url)},
    )


@app.get("/health", tags=["Ops"])
async def health():
    return {"status": "ok", "service": "threat-pipeline", "version": "1.0.0"}


@app.post("/analyze", response_model=AnalysisResponse, tags=["Analysis"])
async def analyze(bundle: LogBundle) -> AnalysisResponse:
    """Submit Zeek log records → get alerts + correlated incidents."""
    return run_pipeline(bundle)
'''

# ── README.md ─────────────────────────────────────────────────────────────────
FILES["README.md"] = '''\
# Threat Pipeline

Detect and correlate cybersecurity incidents from normalised Zeek logs.

## Setup
```bash
python -m venv .venv && .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
'''

for rel_path, content in FILES.items():
    full_path = os.path.join(ROOT, rel_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(content))
    print(f"Created {rel_path}")

print("\nProject scaffold complete!")