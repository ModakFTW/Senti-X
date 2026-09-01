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
