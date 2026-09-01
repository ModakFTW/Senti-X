"""Suspicious TLS Detector — invalid cert, weak version, short session."""
from __future__ import annotations
import ipaddress
from ..models.log_models import SSLLog
from ..models.alert_models import Alert, AlertType, Severity

WEAK_VERSIONS: frozenset[str] = frozenset({
    "sslv2", "sslv3", "sslv23",
    "tlsv10", "tlsv1", "tlsv1.0",
    "tlsv11", "tlsv1.1",
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
        if log.validation_status and log.validation_status.strip().lower() not in ("ok", "valid"):
            triggers.append("invalid_cert")
        if log.version and log.version.strip().lower() in WEAK_VERSIONS:
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
