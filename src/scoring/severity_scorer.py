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
