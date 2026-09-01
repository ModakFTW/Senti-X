# SENTINEL-X Dataset & Demo Logs

This directory contains the synthetic attack datasets, raw Zeek logs, ground truth annotations, and pre-formatted demonstration payloads used to demonstrate and evaluate the **SENTINEL-X** Autonomous SOC & Threat Pipeline.

---

## 📁 Directory Structure

```
dataset/
├── raw/                      # Raw streaming Zeek JSON logs (~12,000 events)
│   ├── conn.log.json         # TCP/UDP connection logs (port scans, beaconing, C2)
│   ├── ssh.log.json          # SSH authentication logs (brute force sequences)
│   ├── ssl.log.json          # TLS/SSL handshake logs (weak ciphers, self-signed certs)
│   ├── dns.log.json          # DNS query/response logs (C2 domain lookups)
│   ├── http.log.json         # HTTP transaction logs (exfiltration POSTs)
│   └── notice.log.json       # Zeek security notices
├── demo/                     # Ready-to-use payloads for live demonstrations
│   ├── pipeline_payload.json # LogBundle ready for POST /pipeline (FastAPI)
│   ├── sample_incidents.json # Correlated incidents ready for triage & evaluation
│   └── sample_rag_query.json # Sample incident query for RAG triage endpoints
└── ground_truth/             # Ground truth labels & scenario documentation
    ├── attack_story.md       # Narrative description of the 6-stage attack scenario
    ├── ground_truth_labels.csv # Event-level MITRE ATT&CK labels (tactics & techniques)
    └── incident_ground_truth.json # Incident-level ground truth definitions & risk targets
```

---

## 🎯 6-Stage Attack Storyline

The dataset simulates a realistic multi-stage intrusion embedded inside background enterprise network traffic:

| Stage | Attack Phase | Target / Indicators | MITRE ATT&CK | Source Log |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 1** | **Reconnaissance** | External IP `185.220.101.45` scanning ports on `192.168.10.5` | T1046 (Network Service Discovery) | `conn.log.json` |
| **Stage 2** | **Brute Force** | 7 failed SSH logins followed by success on `192.168.10.5:22` | T1110 (Brute Force) | `ssh.log.json` |
| **Stage 3** | **Initial Access** | Unauthorized login establishing persistent SSH session | T1078 (Valid Accounts) | `ssh.log.json`, `conn.log.json` |
| **Stage 4** | **C2 Communication** | Periodic DNS queries and weak TLS to `malicious-c2.ru` | T1071.004, T1573 | `dns.log.json`, `ssl.log.json` |
| **Stage 5** | **Lateral Movement** | Internal RDP hops from `10.10.0.5` to `10.10.0.6` | T1021.001 (Remote Desktop Protocol) | `conn.log.json` |
| **Stage 6** | **Exfiltration** | Large HTTP POST payload sent to `185.220.101.99` | T1048 (Exfiltration Over Alternative Protocol) | `http.log.json` |

---

## 🚀 How to Show the Working

### 1. Test the Threat Detection & Correlation Pipeline

Start the Threat Pipeline API:
```bash
python main.py
# Server runs on http://127.0.0.1:8000
```

Send the demo payload to trigger detection, scoring, and multi-stage correlation:
```bash
curl -X POST "http://127.0.0.1:8000/pipeline" \
     -H "Content-Type: application/json" \
     -d @dataset/demo/pipeline_payload.json
```

**Expected Response**:
- **Detections**: Port Scan, SSH Brute Force, and Suspicious TLS alerts.
- **Correlated Incident**: Correlates the port scan and SSH brute force from `185.220.101.45` into a high-severity `RECON_AND_INTRUSION` incident.

### 2. Run Automated Pytest Tests
```bash
pytest test_pipeline.py test_api.py -v
```

### 3. Test the RAG Knowledge Retrieval & Evaluation Pipeline

Start the RAG API service:
```bash
uvicorn api.main:app --port 8001 --reload
```

Run the complete offline evaluation against the ground truth dataset:
```bash
python eval/run_eval.py
```
This evaluates detection precision/recall, incident correlation quality, and MITRE ATT&CK technique mapping against `dataset/ground_truth/ground_truth_labels.csv`.
