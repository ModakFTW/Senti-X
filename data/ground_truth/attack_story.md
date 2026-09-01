# SENTINEL-X — Attack Story
## Ground Truth Narrative: "Operation Phantom Reach"

**Date:** 2024-06-15  
**Duration:** ~3.5 hours (08:00 – 11:30 UTC)  
**Attacker Origin:** Tor exit node `185.220.101.45`  
**C2 Infrastructure:** `185.220.101.99` / `malicious-c2.ru`  
**Initial Target:** Auth server `192.168.10.5`

---

## Timeline

### Stage 1 — Recon (08:00 – 08:30 UTC)
**Technique:** T1046 — Network Service Scanning  
**Incident:** INC-001 (Priority: MEDIUM)

The attacker began by performing a TCP port scan across multiple internal servers from external IP `185.220.101.45` (a known Tor exit node). The scan probed 15 ports across multiple hosts, generating approximately 520 connection attempts with `conn_state` of `REJ`, `S0`, or `RSTOS0` (SYN sent, no response).

**Key indicators:**
- Source: `185.220.101.45` (external, Tor exit node)
- Targets: `192.168.10.5`, `192.168.10.10`, `192.168.10.20`
- Ports probed: 21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 5985, 8080, 8443
- Zeek notice generated: `Scan::Port_Scan`
- All connections failed (no services responded) except **port 22** on `192.168.10.5`

**Expected detection:** Anomaly on count of `REJ`/`S0` conn states from single external IP within short window.

---

### Stage 2 — SSH Brute Force (08:30 – 08:45 UTC)
**Technique:** T1110 — Brute Force  
**Incident:** INC-002 (Priority: HIGH)

Having identified SSH (port 22) open on `192.168.10.5`, the attacker launched a credential brute-force attack using an automated tool (Hydra/Medusa signature in SSH client string). 150 failed SSH authentication attempts were made over 7.5 minutes (~3 attempts per minute, staying below rate limits).

**Key indicators:**
- Source: `185.220.101.45` → Destination: `192.168.10.5:22`
- All 150 connections: `auth_success = false`
- SSH client string: `SSH-2.0-OpenSSH_8.9p1 Ubuntu`
- Short session durations (0.5 – 2.0 seconds per attempt)
- Zeek notice generated: `SSH::Password_Guessing`

**Expected detection:** Threshold alert on failed SSH auth count from single source within time window.

---

### Stage 3 — Initial Access / Valid Account (08:45 UTC)
**Technique:** T1078 — Valid Accounts  
**Incident:** INC-003 (Priority: CRITICAL)

At 08:45 UTC, the attacker successfully authenticated to `192.168.10.5:22`. The SSH session continued for approximately 10 minutes, with high data transfer volumes (50,000 – 200,000 bytes) indicating active command execution: system enumeration, staging malware, establishing persistence.

**Key indicators:**
- UID: `SUCCESS_SSH_UID` (single successful SSH session)
- Source: `185.220.101.45` → Destination: `192.168.10.5:22`
- `auth_success = true` — after 150 prior failed attempts
- Session duration: 120 – 600 seconds (active work)
- High `bytes_orig` indicating commands being sent
- **Correlation trigger:** Same src_ip as INC-002 brute force

**Expected detection:** Successful auth following brute force from same IP — high confidence T1078 after T1110.

---

### Stage 4 — C2 Beaconing via DNS (08:46 – 11:30 UTC)
**Technique:** T1071.004 — Application Layer Protocol: DNS  
**Incident:** INC-004 (Priority: CRITICAL)

Immediately after gaining access, the attacker's malware implant began beaconing to C2 infrastructure. The compromised host `192.168.10.5` sent periodic DNS queries to `malicious-c2.ru` every ~60 seconds (with ±5s jitter). Each successful DNS resolution (returning `185.220.101.99`) was followed by a short HTTPS connection to the C2 server.

**Key indicators:**
- Source: `192.168.10.5` (compromised internal server)
- DNS query: `malicious-c2.ru` every 60 ± 5 seconds
- Response IP: `185.220.101.99` (same ASN as initial attacker)
- 48 DNS beacon events over the attack duration
- 48 corresponding HTTPS connections to `185.220.101.99:443`
- TTL of 60 seconds (suspiciously short, prevents caching)
- Domain not in enterprise DNS allowlist

**Expected detection:** Regularity of DNS query interval + domain threat intel match + internal server making external DNS queries.

---

### Stage 5 — Lateral Movement via RDP (09:30 – 11:00 UTC)
**Technique:** T1021.001 — Remote Services: RDP  
**Incident:** INC-005 (Priority: HIGH)

Using credentials harvested from the compromised auth server, the attacker pivoted to two internal workstations (`10.10.0.6` and `10.10.0.7`) via RDP. These workstations host sensitive business data. Each RDP session lasted 5 – 30 minutes with significant data volumes.

**Key indicators:**
- Source: `192.168.10.5` (compromised auth server)
- Destinations: `10.10.0.6:3389`, `10.10.0.7:3389`
- 20 RDP sessions total (10 to each target)
- Session durations: 300 – 1800 seconds
- High bytes_total per session (100,000 – 500,000 bytes)
- Server-to-workstation RDP is anomalous (not legitimate admin pattern)

**Expected detection:** Server initiating RDP connections to workstations — reverse direction from normal admin traffic.

---

### Stage 6 — Data Exfiltration via HTTP POST (10:00 – 11:30 UTC)
**Technique:** T1048 — Exfiltration Over Alternative Protocol  
**Incident:** INC-006 (Priority: CRITICAL)

The final stage involved staged exfiltration of sensitive data via HTTP POST requests to the C2 server. 10 large POST requests were made to `https://malicious-c2.ru/upload/<random_id>`, each containing 5–50 MB of data (likely compressed, encrypted archives).

**Key indicators:**
- Source: `192.168.10.5` (compromised server)
- Destination: `185.220.101.99:443` / `malicious-c2.ru`
- HTTP method: POST
- `request_body_len`: 5,000,000 – 50,000,000 bytes per request
- Total estimated exfiltrated: ~200 MB
- User-agent: `Mozilla/5.0 (compatible; custom/1.0)` (generic, non-standard)
- Destination matches C2 IP from DNS beaconing (INC-004 correlation)

**Expected detection:** Outbound data volume >> baseline to known-bad IP. Correlation with C2 beacon destination.

---

## Alert Funnel (Expected System Output)

```
12,000 Total Events (background + attack)
         ↓
   742 Suspicious Events flagged by anomaly detection
         ↓
    87 Correlated Events (grouped by IP/session/TTP chain)
         ↓
    12 Incidents identified
         ↓
     3 Priority (CRITICAL) Incidents:
         - INC-003: Successful Unauthorized SSH Login
         - INC-004: C2 DNS Beaconing
         - INC-006: Large-Scale Data Exfiltration
```

## Incident Summary

| Incident | Title | Priority | Technique | Events |
|---|---|---|---|---|
| INC-001 | Network Port Scan from Tor Exit Node | MEDIUM | T1046 | ~520 conn + 1 notice |
| INC-002 | SSH Brute Force Attack on Auth Server | HIGH | T1110 | 150 ssh + 1 notice |
| INC-003 | Successful Unauthorized SSH Login | **CRITICAL** | T1078 | 1 ssh |
| INC-004 | C2 DNS Beaconing to Malicious Domain | **CRITICAL** | T1071.004 | 48 dns + 48 conn |
| INC-005 | Lateral Movement via RDP | HIGH | T1021.001 | 20 conn |
| INC-006 | Large-Scale Data Exfiltration via HTTP POST | **CRITICAL** | T1048 | 10 http |

## Attack Chain (MITRE Tactic Order)

```
Discovery → Credential Access → Initial Access → Command & Control → Lateral Movement → Exfiltration
  T1046         T1110               T1078            T1071.004          T1021.001          T1048
```

This represents a complete APT kill-chain that the SENTINEL-X system must detect, correlate, and report.
