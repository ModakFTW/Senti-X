# Threat Pipeline

Detect and correlate cybersecurity incidents from normalised [Zeek](https://zeek.org/) logs.

Supports detection of:
- 🔍 **Port Scans** — sliding-window, distinct destination ports
- 🔑 **SSH Brute Force** — high attempt count or failures-then-success pattern
- 🔒 **Suspicious TLS** — weak versions, invalid certs, short sessions
- 📡 **Beaconing / C2** — long-lived, low-byte connections to known bad ports

Detected alerts are **scored** by severity and **correlated** into incidents (e.g. `RECON_AND_INTRUSION`, `MULTI_STAGE_ATTACK`).

---

## Quickstart

### Requirements
- Python 3.10+

### 1. Clone & set up

```bash
git clone <your-repo-url>
cd Threat_pipeline

# Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the API server

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000/docs** for the interactive Swagger UI.

---

## Running Tests

```bash
pytest -v
```

Expected output: all tests in `test_pipeline.py` and `test_api.py` pass.

---

## Project Structure

```
Threat_pipeline/
├── main.py                        # FastAPI app entry point
├── requirements.txt
├── conftest.py                    # Pytest path configuration
├── test_pipeline.py               # Unit tests (pipeline logic)
├── test_api.py                    # Integration tests (HTTP endpoints)
├── sample_incidents.json          # Reference incident data
└── src/
    ├── pipeline.py                # Orchestrates detectors → scorer → correlator
    ├── models/
    │   ├── log_models.py          # Pydantic input models (ConnLog, SSHLog, SSLLog)
    │   └── alert_models.py        # Pydantic output models (Alert, Incident, etc.)
    ├── detectors/
    │   ├── port_scan.py
    │   ├── ssh_bruteforce.py
    │   ├── suspicious_tls.py
    │   └── beaconing.py
    ├── scoring/
    │   └── severity_scorer.py
    └── correlator/
        └── incident_correlator.py
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Service info |
| `GET` | `/health` | Health check |
| `POST` | `/analyze` | Submit logs → get alerts + incidents |
| `GET` | `/docs` | Swagger UI |

### Example `POST /analyze` payload

```json
{
  "conn_logs": [
    {
      "ts": 1700000000.0,
      "id.orig_h": "10.0.0.1",
      "id.orig_p": 54321,
      "id.resp_h": "192.168.1.10",
      "id.resp_p": 22,
      "proto": "tcp",
      "duration": 0.5,
      "orig_bytes": 100,
      "resp_bytes": 200,
      "conn_state": "SF"
    }
  ],
  "ssh_logs": [],
  "ssl_logs": []
}
```
