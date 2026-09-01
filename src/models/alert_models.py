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
