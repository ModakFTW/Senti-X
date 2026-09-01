"""
Pytest tests for the Threat Pipeline — detection, scoring, and correlation.
"""
import json
import pytest
from src.models.log_models import LogBundle, ConnLog, SSHLog, SSLLog
from src.pipeline import run_pipeline


def _make_bundle():
    """Build the canonical test LogBundle (port scan + SSH BF + TLS + beaconing)."""
    base_ts = 1788086000.0
    sample_ports = [
        133, 360, 804, 3589, 3771, 4498, 4690, 4838, 4848, 5773,
        6485, 8139, 9273, 9936, 9947, 1001, 1002, 1003, 1004, 1005,
        1006, 1007, 1008, 1009, 1010,
    ]
    conn_logs = [
        ConnLog(
            ts=base_ts + i * 2,
            **{"id.orig_h": "10.0.0.66", "id.orig_p": 45000 + i,
               "id.resp_h": "10.0.0.10", "id.resp_p": port},
            proto="tcp", service=None, duration=0.01,
            orig_bytes=40, resp_bytes=0, conn_state="REJ",
        )
        for i, port in enumerate(sample_ports)
    ]
    # Beaconing / C2 log
    conn_logs.append(ConnLog(
        ts=1788086800.0,
        **{"id.orig_h": "10.0.0.88", "id.orig_p": 51234,
           "id.resp_h": "203.0.113.55", "id.resp_p": 4444},
        proto="tcp", service=None, duration=118.675,
        orig_bytes=250, resp_bytes=944, conn_state="S1",
    ))

    ssh_logs = [SSHLog(
        ts=1788086100.0,
        **{"id.orig_h": "10.0.0.66", "id.resp_h": "10.0.0.10", "id.resp_p": 22},
        auth_attempts=6, auth_success=True,
    )]

    ssl_logs = [
        SSLLog(
            ts=1788086500.0 + offset,
            **{"id.orig_h": "10.0.0.77", "id.resp_h": "185.220.101.7", "id.resp_p": 443},
            version="TLSv1.0",
            cipher="TLS_RSA_WITH_RC4_128_SHA",
            validation_status="self signed certificate",
            server_name=None,
            ja3="e7d705a3286e19ea42f587b344ee6865",
            duration=2.5,
        )
        for offset in [0.0, 30.0, 60.0]
    ]

    return LogBundle(conn_logs=conn_logs, ssh_logs=ssh_logs, ssl_logs=ssl_logs)


def test_pipeline_runs_without_error():
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    assert response is not None


def test_summary_counts_match_input():
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    assert response.summary.total_conn_logs == len(bundle.conn_logs)
    assert response.summary.total_ssh_logs == len(bundle.ssh_logs)
    assert response.summary.total_ssl_logs == len(bundle.ssl_logs)


def test_detects_expected_alert_types():
    from src.models.alert_models import AlertType
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    alert_types = {a.alert_type for a in response.raw_alerts}
    assert AlertType.PORT_SCAN in alert_types, "Port scan should be detected"
    assert AlertType.SSH_BRUTE_FORCE in alert_types, "SSH brute force should be detected"
    assert AlertType.SUSPICIOUS_TLS in alert_types, "Suspicious TLS should be detected"
    assert AlertType.BEACONING in alert_types, "Beaconing should be detected"


def test_at_least_one_incident_correlated():
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    assert response.summary.total_incidents >= 1, "At least one incident should be correlated"


def test_recon_and_intrusion_incident_detected():
    """10.0.0.66 performs both a port scan and SSH brute force → RECON_AND_INTRUSION."""
    from src.models.alert_models import IncidentType
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    incident_types = {inc.incident_type for inc in response.incidents}
    assert IncidentType.RECON_AND_INTRUSION in incident_types, (
        "Port scan + SSH brute force from same IP should correlate to RECON_AND_INTRUSION"
    )


def test_beaconing_incident_correlated():
    """10.0.0.88 beacons to C2 port 4444 → incident for that IP."""
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    c2_incidents = [inc for inc in response.incidents if inc.src_ip == "10.0.0.88"]
    assert c2_incidents, "Beaconing from 10.0.0.88 should produce an incident"


def test_alert_ids_in_incidents_are_valid():
    """Every alert_id referenced in an incident must exist in raw_alerts."""
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    raw_ids = {a.alert_id for a in response.raw_alerts}
    for inc in response.incidents:
        for aid in inc.alert_ids:
            assert aid in raw_ids, f"Incident references unknown alert_id {aid}"


def test_alerts_sorted_by_timestamp():
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    timestamps = [a.timestamp for a in response.raw_alerts]
    assert timestamps == sorted(timestamps), "raw_alerts must be sorted by timestamp"


def test_empty_bundle_raises_validation_error():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        LogBundle(conn_logs=[], ssh_logs=[], ssl_logs=[])


def test_summary_totals_are_consistent():
    bundle = _make_bundle()
    response = run_pipeline(bundle)
    assert response.summary.total_alerts == len(response.raw_alerts)
    assert response.summary.total_incidents == len(response.incidents)


def test_ssh_brute_force_sequence_mode():
    """Test SSH brute force detection via sequence of failures followed by success."""
    from src.models.alert_models import AlertType, Severity
    logs = [
        SSHLog(ts=100.0, **{"id.orig_h": "192.168.1.50", "id.resp_h": "10.0.0.5", "id.resp_p": 22}, auth_attempts=1, auth_success=False),
        SSHLog(ts=110.0, **{"id.orig_h": "192.168.1.50", "id.resp_h": "10.0.0.5", "id.resp_p": 22}, auth_attempts=1, auth_success=False),
        SSHLog(ts=120.0, **{"id.orig_h": "192.168.1.50", "id.resp_h": "10.0.0.5", "id.resp_p": 22}, auth_attempts=1, auth_success=False),
        SSHLog(ts=130.0, **{"id.orig_h": "192.168.1.50", "id.resp_h": "10.0.0.5", "id.resp_p": 22}, auth_attempts=1, auth_success=True),
    ]
    bundle = LogBundle(ssh_logs=logs)
    response = run_pipeline(bundle)
    ssh_alerts = [a for a in response.raw_alerts if a.alert_type == AlertType.SSH_BRUTE_FORCE]
    assert len(ssh_alerts) == 1
    assert ssh_alerts[0].evidence.get("mode") == "sequence"
    assert ssh_alerts[0].severity == Severity.CRITICAL


def test_multi_stage_attack_incident():
    """Test correlation to MULTI_STAGE_ATTACK when an IP triggers 3+ alert types."""
    from src.models.alert_models import IncidentType
    base_ts = 1788086000.0
    # 25 port scans
    conn_logs = [
        ConnLog(
            ts=base_ts + i,
            **{"id.orig_h": "10.0.0.99", "id.orig_p": 40000 + i,
               "id.resp_h": "10.0.0.10", "id.resp_p": 1000 + i},
            proto="tcp", duration=0.01, orig_bytes=40, resp_bytes=0, conn_state="REJ",
        )
        for i in range(25)
    ]
    # Beaconing
    conn_logs.append(ConnLog(
        ts=base_ts + 30.0,
        **{"id.orig_h": "10.0.0.99", "id.orig_p": 55555,
           "id.resp_h": "198.51.100.2", "id.resp_p": 4444},
        proto="tcp", duration=120.0, orig_bytes=100, resp_bytes=500, conn_state="S1",
    ))
    # SSH brute force
    ssh_logs = [
        SSHLog(
            ts=base_ts + 45.0,
            **{"id.orig_h": "10.0.0.99", "id.resp_h": "10.0.0.10", "id.resp_p": 22},
            auth_attempts=8, auth_success=True,
        )
    ]
    bundle = LogBundle(conn_logs=conn_logs, ssh_logs=ssh_logs)
    response = run_pipeline(bundle)
    incident_types = {inc.incident_type for inc in response.incidents if inc.src_ip == "10.0.0.99"}
    assert IncidentType.MULTI_STAGE_ATTACK in incident_types


def test_correlate_empty_alerts():
    from src.correlator.incident_correlator import correlate
    assert correlate([]) == []


def test_suspicious_tls_case_and_private_ip():
    """Test TLS detector handles case-insensitive weak versions and skips short durations on private IPs."""
    from src.models.alert_models import AlertType
    ssl_logs = [
        # Public IP with short duration + weak TLS in lowercase
        SSLLog(
            ts=100.0,
            **{"id.orig_h": "10.0.0.1", "id.resp_h": "93.184.216.34", "id.resp_p": 443},
            version="tlsv1.0",
            duration=1.2,
            validation_status="ok",
        ),
        # Private IP with short duration and normal TLS -> should not trigger
        SSLLog(
            ts=200.0,
            **{"id.orig_h": "10.0.0.1", "id.resp_h": "192.168.1.200", "id.resp_p": 443},
            version="TLSv1.3",
            duration=1.0,
            validation_status="ok",
        ),
    ]
    bundle = LogBundle(ssl_logs=ssl_logs)
    response = run_pipeline(bundle)
    assert len(response.raw_alerts) == 1
    assert response.raw_alerts[0].alert_type == AlertType.SUSPICIOUS_TLS
    assert response.raw_alerts[0].dst_ip == "93.184.216.34"


