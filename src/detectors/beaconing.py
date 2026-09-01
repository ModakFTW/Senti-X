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
