#!/usr/bin/env python3
"""
SENTINEL-X — P6: Zeek Log Generator
====================================
Generates realistic Zeek JSON streaming logs (~12,000 events) embedding
a 6-stage attack story for the SENTINEL-X demo.

Attack Story:
  Stage 1 — Recon:        Port scan from 185.220.101.45 (external)
  Stage 2 — Brute Force:  SSH brute force → 192.168.10.5 (T1110)
  Stage 3 — Initial Access: Successful SSH login (T1078)
  Stage 4 — C2 Beacon:    DNS beaconing to malicious-c2[.]ru (T1071.004)
  Stage 5 — Lateral Move: RDP hops inside 10.10.0.x subnet (T1021.001)
  Stage 6 — Exfiltration: Large HTTP POST to 185.220.101.99 (T1048)

Output files (Zeek JSON streaming format):
  data/raw/conn.log.json
  data/raw/dns.log.json
  data/raw/http.log.json
  data/raw/ssh.log.json
  data/raw/ssl.log.json
  data/raw/notice.log.json
"""

import json
import random
import uuid
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────
BASE_TS = datetime(2024, 6, 15, 8, 0, 0, tzinfo=timezone.utc)   # Incident day
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

OUT_DIR = Path(__file__).parent.parent / "data" / "raw"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Network topology ─────────────────────────────────────────────────────────
INTERNAL_SERVERS = [
    "192.168.10.5",   # TARGET: Auth server (SSH brute forced)
    "192.168.10.10",  # Web server
    "192.168.10.20",  # DB server
    "10.10.0.5",      # Workstation A
    "10.10.0.6",      # Workstation B  (lateral movement target)
    "10.10.0.7",      # Workstation C
    "10.10.0.1",      # Internal DNS
]
INTERNAL_CLIENTS = [f"10.10.{random.randint(0,2)}.{random.randint(50,200)}" for _ in range(50)]
LEGITIMATE_EXTERNAL = [
    "8.8.8.8", "1.1.1.1", "208.67.222.222",
    "13.32.99.100", "54.230.1.1", "151.101.1.1",
]
ATTACKER_IP  = "185.220.101.45"   # Tor exit node (recon + brute force)
C2_IP        = "185.220.101.99"   # C2 server (exfil destination)
C2_DOMAIN    = "malicious-c2.ru"

LEGITIMATE_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "stackoverflow.com",
    "aws.amazon.com", "cdn.cloudflare.com", "fonts.googleapis.com",
    "api.slack.com", "teams.microsoft.com", "office365.com",
]


def uid() -> str:
    """Generate a Zeek-style UID (base62, 16 chars)."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "C" + "".join(random.choices(chars, k=15))


def ts(base: datetime, offset_sec: float = 0.0) -> float:
    """Return Unix epoch float timestamp."""
    return (base + timedelta(seconds=offset_sec)).timestamp()


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


# ── Writers ───────────────────────────────────────────────────────────────────
class LogWriter:
    def __init__(self, path: Path, log_path: str):
        self.path = path
        self.log_path = log_path
        self._f = None
        self.count = 0

    def __enter__(self):
        self._f = open(self.path, "w", encoding="utf-8")
        return self

    def __exit__(self, *_):
        self._f.close()

    def write(self, record: dict):
        record["_path"] = self.log_path
        record["_write_ts"] = record.get("ts", ts(BASE_TS))
        self._f.write(json.dumps(record) + "\n")
        self.count += 1


# ═══════════════════════════════════════════════════════════════════════════════
# LEGITIMATE BACKGROUND TRAFFIC GENERATORS
# ═══════════════════════════════════════════════════════════════════════════════

def gen_legit_conn(w: LogWriter, n: int = 6500):
    """Normal internal/external TCP connections."""
    services = ["http", "https", "dns", "smtp", "ftp", "-"]
    states   = ["SF", "S1", "REJ", "RSTO", "SF", "SF", "SF"]  # mostly established
    for i in range(n):
        src = random.choice(INTERNAL_CLIENTS)
        dst = random.choice(LEGITIMATE_EXTERNAL + INTERNAL_SERVERS)
        svc = random.choice(services)
        dur = round(random.uniform(0.01, 30.0), 6)
        ob  = random.randint(100, 50000)
        rb  = random.randint(200, 200000)
        w.write({
            "ts":           ts(BASE_TS, random.uniform(0, 28800)),
            "uid":          uid(),
            "id.orig_h":    src,
            "id.orig_p":    random.randint(1024, 65535),
            "id.resp_h":    dst,
            "id.resp_p":    443 if "https" in svc else 80 if svc == "http" else random.randint(1, 1024),
            "proto":        "tcp",
            "service":      svc,
            "duration":     dur,
            "orig_bytes":   ob,
            "resp_bytes":   rb,
            "conn_state":   random.choice(states),
            "missed_bytes": 0,
            "history":      "ShADad",
            "orig_pkts":    random.randint(2, 50),
            "resp_pkts":    random.randint(2, 50),
            "label":        "benign",
        })


def gen_legit_dns(w: LogWriter, n: int = 1800):
    """Legitimate DNS queries."""
    qtypes = ["A", "AAAA", "CNAME", "MX", "TXT"]
    for _ in range(n):
        dom = random.choice(LEGITIMATE_DOMAINS)
        w.write({
            "ts":       ts(BASE_TS, random.uniform(0, 28800)),
            "uid":      uid(),
            "id.orig_h": random.choice(INTERNAL_CLIENTS),
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": "10.10.0.1",
            "id.resp_p": 53,
            "proto":    "udp",
            "trans_id": random.randint(1000, 65535),
            "rtt":      round(random.uniform(0.001, 0.05), 6),
            "query":    dom,
            "qclass":   1,
            "qtype":    random.choice([1, 28, 5, 15]),
            "qtype_name": random.choice(qtypes),
            "rcode":    0,
            "rcode_name": "NOERROR",
            "AA":       False,
            "TC":       False,
            "RD":       True,
            "RA":       True,
            "answers":  [f"93.184.{random.randint(0,255)}.{random.randint(0,255)}"],
            "TTLs":     [random.choice([300, 3600, 86400])],
            "label":    "benign",
        })


def gen_legit_http(w: LogWriter, n: int = 1200):
    """Legitimate HTTP/S requests."""
    methods = ["GET", "GET", "GET", "POST", "PUT"]
    status_codes = [200, 200, 200, 301, 304, 404]
    for _ in range(n):
        dom = random.choice(LEGITIMATE_DOMAINS)
        method = random.choice(methods)
        rb = random.randint(500, 100000)
        ob = random.randint(200, 2000)
        w.write({
            "ts":           ts(BASE_TS, random.uniform(0, 28800)),
            "uid":          uid(),
            "id.orig_h":    random.choice(INTERNAL_CLIENTS),
            "id.orig_p":    random.randint(1024, 65535),
            "id.resp_h":    random.choice(LEGITIMATE_EXTERNAL),
            "id.resp_p":    443,
            "trans_depth":  1,
            "method":       method,
            "host":         dom,
            "uri":          f"/{random.choice(['api','assets','img','js'])}/{uuid.uuid4().hex[:8]}",
            "referrer":     "-",
            "version":      "1.1",
            "user_agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "request_body_len":  ob if method == "POST" else 0,
            "response_body_len": rb,
            "status_code":  random.choice(status_codes),
            "status_msg":   "OK",
            "tags":         [],
            "label":        "benign",
        })


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK STAGE GENERATORS (return list of (log_type, record, label) tuples)
# ═══════════════════════════════════════════════════════════════════════════════

# Attack timing (offsets in seconds from BASE_TS)
T_RECON_START    = 0
T_BRUTE_START    = 1800   # 30 min in
T_INITIAL_ACCESS = 2700   # 45 min in
T_C2_START       = 2760   # 46 min in
T_LATERAL_START  = 5400   # 90 min in
T_EXFIL_START    = 7200   # 2 hrs in

# Shared UIDs for correlated events
BRUTE_UIDS = [uid() for _ in range(150)]
SUCCESS_SSH_UID = uid()
C2_DNS_UIDS = [uid() for _ in range(48)]
LATERAL_UIDS = [uid() for _ in range(20)]
EXFIL_UIDS = [uid() for _ in range(10)]

# Ground truth tracking
GROUND_TRUTH: list[dict] = []


def add_gt(event_uid: str, log_type: str, is_malicious: bool, tactic: str,
           technique_id: str, technique_name: str, incident_id: str, priority: str):
    GROUND_TRUTH.append({
        "uid":            event_uid,
        "log_type":       log_type,
        "is_malicious":   is_malicious,
        "tactic":         tactic,
        "technique_id":   technique_id,
        "technique_name": technique_name,
        "incident_id":    incident_id,
        "priority":       priority,
    })


def gen_recon(conn_w: LogWriter, notice_w: LogWriter):
    """Stage 1: Port scan (T1046)."""
    ports = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 5985, 8080, 8443]
    for i, port in enumerate(ports * 40):   # ~520 scan attempts
        event_uid = uid()
        offset = T_RECON_START + i * 0.3
        conn_w.write({
            "ts":           ts(BASE_TS, offset),
            "uid":          event_uid,
            "id.orig_h":    ATTACKER_IP,
            "id.orig_p":    random.randint(40000, 60000),
            "id.resp_h":    random.choice(INTERNAL_SERVERS),
            "id.resp_p":    port,
            "proto":        "tcp",
            "service":      "-",
            "duration":     round(random.uniform(0.0, 0.1), 6),
            "orig_bytes":   0,
            "resp_bytes":   0,
            "conn_state":   random.choice(["REJ", "S0", "RSTOS0"]),
            "missed_bytes": 0,
            "history":      "S",
            "orig_pkts":    1,
            "resp_pkts":    0,
            "label":        "attack",
        })
        add_gt(event_uid, "conn", True, "Discovery",
               "T1046", "Network Service Scanning", "INC-001", "MEDIUM")

    # Zeek notice for scan detection
    notice_uid = uid()
    notice_w.write({
        "ts":       ts(BASE_TS, T_RECON_START + 30),
        "uid":      notice_uid,
        "id.orig_h": ATTACKER_IP,
        "id.orig_p": 0,
        "id.resp_h": "192.168.10.5",
        "id.resp_p": 0,
        "proto":    "-",
        "note":     "Scan::Port_Scan",
        "msg":      f"192.168.10.5 scanned at least 15 unique ports of host {ATTACKER_IP} in 0m0s",
        "sub":      f"Scanned ports: 22, 80, 443, 3389, 445, 135, ...",
        "src":      ATTACKER_IP,
        "dst":      "192.168.10.5",
        "label":    "attack",
    })
    add_gt(notice_uid, "notice", True, "Discovery",
           "T1046", "Network Service Scanning", "INC-001", "MEDIUM")


def gen_brute_force(conn_w: LogWriter, ssh_w: LogWriter, notice_w: LogWriter):
    """Stage 2: SSH Brute Force (T1110)."""
    for i, event_uid in enumerate(BRUTE_UIDS):
        offset = T_BRUTE_START + i * 3.0
        conn_w.write({
            "ts":           ts(BASE_TS, offset),
            "uid":          event_uid,
            "id.orig_h":    ATTACKER_IP,
            "id.orig_p":    random.randint(40000, 60000),
            "id.resp_h":    "192.168.10.5",
            "id.resp_p":    22,
            "proto":        "tcp",
            "service":      "ssh",
            "duration":     round(random.uniform(0.5, 2.0), 6),
            "orig_bytes":   random.randint(1500, 3000),
            "resp_bytes":   random.randint(1000, 2000),
            "conn_state":   "SF",
            "missed_bytes": 0,
            "history":      "ShADad",
            "orig_pkts":    random.randint(8, 20),
            "resp_pkts":    random.randint(8, 20),
            "label":        "attack",
        })
        ssh_w.write({
            "ts":           ts(BASE_TS, offset),
            "uid":          event_uid,
            "id.orig_h":    ATTACKER_IP,
            "id.orig_p":    random.randint(40000, 60000),
            "id.resp_h":    "192.168.10.5",
            "id.resp_p":    22,
            "version":      2,
            "auth_success": False,
            "auth_attempts": 1,
            "direction":    "INBOUND",
            "client":       "SSH-2.0-OpenSSH_8.9p1 Ubuntu",
            "server":       "SSH-2.0-OpenSSH_8.4p1 Debian",
            "cipher_alg":   "chacha20-poly1305@openssh.com",
            "mac_alg":      "umac-64-etm@openssh.com",
            "compression_alg": "none",
            "kex_alg":      "curve25519-sha256",
            "host_key_alg": "ecdsa-sha2-nistp256",
            "host_key":     "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
            "label":        "attack",
        })
        add_gt(event_uid, "ssh", True, "Credential Access",
               "T1110", "Brute Force", "INC-002", "HIGH")

    # Zeek notice for brute force detection
    notice_uid = uid()
    notice_w.write({
        "ts":       ts(BASE_TS, T_BRUTE_START + 120),
        "uid":      notice_uid,
        "id.orig_h": ATTACKER_IP,
        "id.orig_p": 0,
        "id.resp_h": "192.168.10.5",
        "id.resp_p": 22,
        "proto":    "tcp",
        "note":     "SSH::Password_Guessing",
        "msg":      f"{ATTACKER_IP} appears to be guessing SSH passwords (seen 40 failed logins in 2m0s).",
        "sub":      "Destination: 192.168.10.5:22",
        "src":      ATTACKER_IP,
        "dst":      "192.168.10.5",
        "label":    "attack",
    })
    add_gt(notice_uid, "notice", True, "Credential Access",
           "T1110", "Brute Force", "INC-002", "HIGH")


def gen_initial_access(conn_w: LogWriter, ssh_w: LogWriter):
    """Stage 3: Successful SSH login (T1078)."""
    conn_w.write({
        "ts":           ts(BASE_TS, T_INITIAL_ACCESS),
        "uid":          SUCCESS_SSH_UID,
        "id.orig_h":    ATTACKER_IP,
        "id.orig_p":    52341,
        "id.resp_h":    "192.168.10.5",
        "id.resp_p":    22,
        "proto":        "tcp",
        "service":      "ssh",
        "duration":     round(random.uniform(120.0, 600.0), 6),
        "orig_bytes":   random.randint(50000, 200000),
        "resp_bytes":   random.randint(20000, 80000),
        "conn_state":   "SF",
        "missed_bytes": 0,
        "history":      "ShADad",
        "orig_pkts":    random.randint(200, 800),
        "resp_pkts":    random.randint(100, 400),
        "label":        "attack",
    })
    ssh_w.write({
        "ts":           ts(BASE_TS, T_INITIAL_ACCESS),
        "uid":          SUCCESS_SSH_UID,
        "id.orig_h":    ATTACKER_IP,
        "id.orig_p":    52341,
        "id.resp_h":    "192.168.10.5",
        "id.resp_p":    22,
        "version":      2,
        "auth_success": True,
        "auth_attempts": 1,
        "direction":    "INBOUND",
        "client":       "SSH-2.0-OpenSSH_8.9p1 Ubuntu",
        "server":       "SSH-2.0-OpenSSH_8.4p1 Debian",
        "cipher_alg":   "chacha20-poly1305@openssh.com",
        "mac_alg":      "umac-64-etm@openssh.com",
        "compression_alg": "none",
        "kex_alg":      "curve25519-sha256",
        "host_key_alg": "ecdsa-sha2-nistp256",
        "host_key":     "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
        "label":        "attack",
    })
    add_gt(SUCCESS_SSH_UID, "ssh", True, "Defense Evasion / Persistence",
           "T1078", "Valid Accounts", "INC-003", "CRITICAL")


def gen_c2_beacon(dns_w: LogWriter, conn_w: LogWriter):
    """Stage 4: DNS C2 Beaconing (T1071.004). Periodic DNS queries every ~60s."""
    for i, event_uid in enumerate(C2_DNS_UIDS):
        offset = T_C2_START + i * 62.0 + random.uniform(-5, 5)   # jitter ±5s
        dns_w.write({
            "ts":       ts(BASE_TS, offset),
            "uid":      event_uid,
            "id.orig_h": "192.168.10.5",       # compromised host
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": "10.10.0.1",
            "id.resp_p": 53,
            "proto":    "udp",
            "trans_id": random.randint(1000, 65535),
            "rtt":      round(random.uniform(0.001, 0.01), 6),
            "query":    C2_DOMAIN,
            "qclass":   1,
            "qtype":    1,
            "qtype_name": "A",
            "rcode":    0,
            "rcode_name": "NOERROR",
            "AA":       False,
            "TC":       False,
            "RD":       True,
            "RA":       True,
            "answers":  [C2_IP],
            "TTLs":     [60],
            "label":    "attack",
        })
        # Corresponding conn record for each C2 check-in (HTTP)
        conn_uid = uid()
        conn_w.write({
            "ts":           ts(BASE_TS, offset + 0.1),
            "uid":          conn_uid,
            "id.orig_h":    "192.168.10.5",
            "id.orig_p":    random.randint(40000, 60000),
            "id.resp_h":    C2_IP,
            "id.resp_p":    443,
            "proto":        "tcp",
            "service":      "ssl",
            "duration":     round(random.uniform(1.0, 5.0), 6),
            "orig_bytes":   random.randint(200, 500),
            "resp_bytes":   random.randint(100, 300),
            "conn_state":   "SF",
            "missed_bytes": 0,
            "history":      "ShADad",
            "orig_pkts":    random.randint(5, 15),
            "resp_pkts":    random.randint(5, 15),
            "label":        "attack",
        })
        add_gt(event_uid, "dns", True, "Command & Control",
               "T1071.004", "Application Layer Protocol: DNS", "INC-004", "CRITICAL")
        add_gt(conn_uid, "conn", True, "Command & Control",
               "T1071.004", "Application Layer Protocol: DNS", "INC-004", "CRITICAL")


def gen_lateral_movement(conn_w: LogWriter, http_w: LogWriter):
    """Stage 5: RDP lateral movement (T1021.001)."""
    rdp_targets = ["10.10.0.6", "10.10.0.7"]
    for i, event_uid in enumerate(LATERAL_UIDS):
        target = rdp_targets[i % len(rdp_targets)]
        offset = T_LATERAL_START + i * 180.0
        conn_w.write({
            "ts":           ts(BASE_TS, offset),
            "uid":          event_uid,
            "id.orig_h":    "192.168.10.5",
            "id.orig_p":    random.randint(50000, 60000),
            "id.resp_h":    target,
            "id.resp_p":    3389,
            "proto":        "tcp",
            "service":      "rdp",
            "duration":     round(random.uniform(300.0, 1800.0), 6),
            "orig_bytes":   random.randint(100000, 500000),
            "resp_bytes":   random.randint(50000, 200000),
            "conn_state":   "SF",
            "missed_bytes": 0,
            "history":      "ShADad",
            "orig_pkts":    random.randint(500, 2000),
            "resp_pkts":    random.randint(300, 1000),
            "label":        "attack",
        })
        add_gt(event_uid, "conn", True, "Lateral Movement",
               "T1021.001", "Remote Services: Remote Desktop Protocol", "INC-005", "HIGH")


def gen_exfiltration(http_w: LogWriter, conn_w: LogWriter):
    """Stage 6: Data exfiltration via HTTP POST (T1048)."""
    for i, event_uid in enumerate(EXFIL_UIDS):
        offset = T_EXFIL_START + i * 120.0
        # Large POST to C2 server
        http_w.write({
            "ts":           ts(BASE_TS, offset),
            "uid":          event_uid,
            "id.orig_h":    "192.168.10.5",
            "id.orig_p":    random.randint(50000, 60000),
            "id.resp_h":    C2_IP,
            "id.resp_p":    443,
            "trans_depth":  1,
            "method":       "POST",
            "host":         C2_DOMAIN,
            "uri":          f"/upload/{uuid.uuid4().hex[:8]}",
            "referrer":     "-",
            "version":      "1.1",
            "user_agent":   "Mozilla/5.0 (compatible; custom/1.0)",
            "request_body_len":  random.randint(5_000_000, 50_000_000),   # 5-50 MB chunks
            "response_body_len": random.randint(100, 500),
            "status_code":  200,
            "status_msg":   "OK",
            "tags":         [],
            "label":        "attack",
        })
        add_gt(event_uid, "http", True, "Exfiltration",
               "T1048", "Exfiltration Over Alternative Protocol", "INC-006", "CRITICAL")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_all():
    conn_path   = OUT_DIR / "conn.log.json"
    dns_path    = OUT_DIR / "dns.log.json"
    http_path   = OUT_DIR / "http.log.json"
    ssh_path    = OUT_DIR / "ssh.log.json"
    notice_path = OUT_DIR / "notice.log.json"

    with (
        LogWriter(conn_path,   "conn")   as conn_w,
        LogWriter(dns_path,    "dns")    as dns_w,
        LogWriter(http_path,   "http")   as http_w,
        LogWriter(ssh_path,    "ssh")    as ssh_w,
        LogWriter(notice_path, "notice") as notice_w,
    ):
        # ── Legitimate background traffic ──
        print("[*] Generating legitimate background traffic...")
        gen_legit_conn(conn_w,  n=6500)
        gen_legit_dns(dns_w,    n=1800)
        gen_legit_http(http_w,  n=1200)

        # ── Attack stages ──
        print("[*] Injecting attack story...")
        gen_recon(conn_w, notice_w)
        gen_brute_force(conn_w, ssh_w, notice_w)
        gen_initial_access(conn_w, ssh_w)
        gen_c2_beacon(dns_w, conn_w)
        gen_lateral_movement(conn_w, http_w)
        gen_exfiltration(http_w, conn_w)

    # ── Summary ──────────────────────────────────────────────────────────────
    total = conn_w.count + dns_w.count + http_w.count + ssh_w.count + notice_w.count
    attack = len(GROUND_TRUTH)
    print(f"\n✅ Generated {total:,} total events ({attack} attack events)")
    print(f"   conn.log:   {conn_w.count:>6,}")
    print(f"   dns.log:    {dns_w.count:>6,}")
    print(f"   http.log:   {http_w.count:>6,}")
    print(f"   ssh.log:    {ssh_w.count:>6,}")
    print(f"   notice.log: {notice_w.count:>6,}")

    return total


def write_ground_truth():
    import csv
    gt_dir = Path(__file__).parent.parent / "data" / "ground_truth"
    gt_dir.mkdir(parents=True, exist_ok=True)

    # CSV labels
    csv_path = gt_dir / "ground_truth_labels.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "uid", "log_type", "is_malicious", "tactic",
            "technique_id", "technique_name", "incident_id", "priority"
        ])
        writer.writeheader()
        writer.writerows(GROUND_TRUTH)
    print(f"\n✅ Ground truth labels: {len(GROUND_TRUTH)} attack events → {csv_path}")

    # Incident ground truth JSON
    incidents = {}
    for row in GROUND_TRUTH:
        iid = row["incident_id"]
        if iid not in incidents:
            incidents[iid] = {
                "incident_id":    iid,
                "title":          {
                    "INC-001": "Network Port Scan from Tor Exit Node",
                    "INC-002": "SSH Brute Force Attack on Auth Server",
                    "INC-003": "Successful Unauthorized SSH Login",
                    "INC-004": "C2 DNS Beaconing to Malicious Domain",
                    "INC-005": "Lateral Movement via RDP",
                    "INC-006": "Large-Scale Data Exfiltration via HTTP POST",
                }.get(iid, iid),
                "priority":       row["priority"],
                "tactic":         row["tactic"],
                "technique_ids":  [],
                "event_uids":     [],
                "expected_risk":  {
                    "CRITICAL": 0.9, "HIGH": 0.75, "MEDIUM": 0.5
                }.get(row["priority"], 0.5),
            }
        if row["technique_id"] not in incidents[iid]["technique_ids"]:
            incidents[iid]["technique_ids"].append(row["technique_id"])
        incidents[iid]["event_uids"].append(row["uid"])

    inc_path = gt_dir / "incident_ground_truth.json"
    with open(inc_path, "w") as f:
        json.dump(list(incidents.values()), f, indent=2)
    print(f"✅ Incident ground truth: {len(incidents)} incidents → {inc_path}")

    # Priority incidents (CRITICAL only)
    priority = [v for v in incidents.values() if v["priority"] == "CRITICAL"]
    print(f"\n📊 Alert funnel preview:")
    print(f"   Incidents total:    {len(incidents)}")
    print(f"   Priority (CRITICAL): {len(priority)}")


if __name__ == "__main__":
    total = generate_all()
    write_ground_truth()
    print(f"\n🎯 Attack funnel target:")
    print(f"   ~{total:,} total events → 742 suspicious → 87 correlated → 12 incidents → 3 priority")
