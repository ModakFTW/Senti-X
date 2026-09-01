"""
Pytest tests for the FastAPI service endpoints (/health and /analyze)
using Starlette's TestClient.
"""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health_returns_200():
    resp = client.get("/health")
    assert resp.status_code == 200


def test_health_response_body():
    resp = client.get("/health")
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "threat-pipeline"


def test_root_returns_200():
    resp = client.get("/")
    assert resp.status_code == 200


def test_root_response_body():
    resp = client.get("/")
    data = resp.json()
    assert data["service"] == "Threat Pipeline API"
    assert "docs" in data


def _analysis_payload():
    return {
        "conn_logs": [
            {
                "ts": 1788086000.0 + i * 2,
                "id.orig_h": "10.0.0.66",
                "id.orig_p": 45000 + i,
                "id.resp_h": "10.0.0.10",
                "id.resp_p": port,
                "proto": "tcp",
                "duration": 0.01,
                "orig_bytes": 40,
                "resp_bytes": 0,
                "conn_state": "REJ",
            }
            for i, port in enumerate(range(1000, 1025))
        ] + [
            {
                "ts": 1788086800.0,
                "id.orig_h": "10.0.0.88",
                "id.orig_p": 51234,
                "id.resp_h": "203.0.113.55",
                "id.resp_p": 4444,
                "proto": "tcp",
                "duration": 118.675,
                "orig_bytes": 250,
                "resp_bytes": 944,
                "conn_state": "S1",
            }
        ],
        "ssh_logs": [
            {
                "ts": 1788086100.0,
                "id.orig_h": "10.0.0.66",
                "id.resp_h": "10.0.0.10",
                "id.resp_p": 22,
                "auth_attempts": 6,
                "auth_success": True,
            }
        ],
        "ssl_logs": [
            {
                "ts": 1788086500.0,
                "id.orig_h": "10.0.0.77",
                "id.resp_h": "185.220.101.7",
                "id.resp_p": 443,
                "version": "TLSv1.0",
                "cipher": "TLS_RSA_WITH_RC4_128_SHA",
                "validation_status": "self signed certificate",
                "duration": 2.5,
            }
        ],
    }


def test_analyze_returns_200():
    resp = client.post("/analyze", json=_analysis_payload())
    assert resp.status_code == 200


def test_analyze_response_has_summary():
    resp = client.post("/analyze", json=_analysis_payload())
    data = resp.json()
    assert "summary" in data
    assert "raw_alerts" in data
    assert "incidents" in data


def test_analyze_detects_alerts():
    resp = client.post("/analyze", json=_analysis_payload())
    data = resp.json()
    assert data["summary"]["total_alerts"] > 0


def test_analyze_correlates_incidents():
    resp = client.post("/analyze", json=_analysis_payload())
    data = resp.json()
    assert data["summary"]["total_incidents"] > 0


def test_analyze_process_time_header_present():
    resp = client.post("/analyze", json=_analysis_payload())
    assert "x-process-time-ms" in resp.headers


def test_analyze_empty_bundle_returns_422():
    """Empty LogBundle should fail Pydantic validation → 422 Unprocessable Entity."""
    resp = client.post("/analyze", json={"conn_logs": [], "ssh_logs": [], "ssl_logs": []})
    assert resp.status_code == 422
