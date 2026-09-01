#!/usr/bin/env python3
"""
SENTINEL-X — P6: Zeek Log Normalizer
======================================
Reads raw Zeek JSON streaming logs → normalizes → writes to:
  1. data/clean/clean_events.jsonl   (flat normalized JSONL)
  2. SQLite DB: db/sentinelx.db      (events table, ready for RAG indexing)

Usage:
    python scripts/normalize_zeek.py
    python scripts/normalize_zeek.py --validate
    python scripts/normalize_zeek.py --input data/raw --output db/sentinelx.db
"""

import json
import sqlite3
import argparse
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).parent.parent
RAW_DIR  = ROOT / "data" / "raw"
CLEAN_DIR = ROOT / "data" / "clean"
DB_DIR   = ROOT / "db"
DB_PATH  = DB_DIR / "sentinelx.db"

# ── SQLite schema ─────────────────────────────────────────────────────────────
DDL_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    uid             TEXT PRIMARY KEY,
    log_type        TEXT NOT NULL,          -- conn / dns / http / ssh / notice
    ts_epoch        REAL NOT NULL,          -- Unix epoch float
    ts_iso          TEXT NOT NULL,          -- ISO-8601 UTC
    src_ip          TEXT,
    src_port        INTEGER,
    dst_ip          TEXT,
    dst_port        INTEGER,
    proto           TEXT,
    service         TEXT,
    duration_sec    REAL,
    bytes_orig      INTEGER,
    bytes_resp      INTEGER,
    bytes_total     INTEGER,
    conn_state      TEXT,
    is_internal_src INTEGER,                -- 0/1 boolean
    is_internal_dst INTEGER,
    label           TEXT DEFAULT 'benign',  -- benign / attack / suspicious
    raw_json        TEXT,                   -- original record for reference
    incident_id     TEXT,                   -- filled after correlation
    embedding_id    INTEGER,                -- FK → embeddings table
    created_at      TEXT DEFAULT (datetime('now'))
);
"""

DDL_INCIDENTS = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     TEXT PRIMARY KEY,
    title           TEXT,
    priority        TEXT,                   -- CRITICAL / HIGH / MEDIUM / LOW
    risk_score      REAL,
    tactic          TEXT,
    technique_ids   TEXT,                   -- JSON array
    src_ips         TEXT,                   -- JSON array
    dst_ips         TEXT,                   -- JSON array
    event_uids      TEXT,                   -- JSON array
    first_seen      TEXT,
    last_seen       TEXT,
    status          TEXT DEFAULT 'open',
    mitre_context   TEXT,                   -- RAG-retrieved MITRE text
    evidence_summary TEXT,                  -- RAG-retrieved log summary
    created_at      TEXT DEFAULT (datetime('now'))
);
"""

DDL_EMBEDDINGS = """
CREATE TABLE IF NOT EXISTS embeddings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type     TEXT NOT NULL,          -- event / mitre_chunk
    source_id       TEXT NOT NULL,          -- uid or technique_id+section
    chunk_text      TEXT NOT NULL,          -- text that was embedded
    embedding_blob  BLOB,                   -- float32 numpy array as bytes
    model_name      TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
);
"""

DDL_MITRE = """
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    tactic          TEXT NOT NULL,
    description     TEXT,
    detection       TEXT,
    mitigations     TEXT,                   -- JSON array
    data_sources    TEXT,                   -- JSON array
    related         TEXT,                   -- JSON array
    created_at      TEXT DEFAULT (datetime('now'))
);
"""

INTERNAL_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


def is_internal(ip: str | None) -> int:
    if not ip:
        return 0
    return int(any(ip.startswith(p) for p in INTERNAL_PREFIXES))


def normalize_record(raw: dict) -> dict | None:
    """Normalize a single Zeek JSON record into a flat event dict."""
    log_type = raw.get("_path", "unknown")
    epoch = raw.get("ts")
    if not epoch:
        return None

    ts_iso = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    src_ip  = raw.get("id.orig_h") or raw.get("src")
    dst_ip  = raw.get("id.resp_h") or raw.get("dst")
    src_port = raw.get("id.orig_p")
    dst_port = raw.get("id.resp_p")

    ob = raw.get("orig_bytes") or raw.get("request_body_len") or 0
    rb = raw.get("resp_bytes") or raw.get("response_body_len") or 0

    uid_val = raw.get("uid") or f"{log_type}_{epoch}_{src_ip}"

    return {
        "uid":           uid_val,
        "log_type":      log_type,
        "ts_epoch":      epoch,
        "ts_iso":        ts_iso,
        "src_ip":        src_ip,
        "src_port":      src_port,
        "dst_ip":        dst_ip,
        "dst_port":      dst_port,
        "proto":         raw.get("proto"),
        "service":       raw.get("service") or raw.get("qtype_name"),
        "duration_sec":  raw.get("duration") or raw.get("rtt") or 0.0,
        "bytes_orig":    ob,
        "bytes_resp":    rb,
        "bytes_total":   ob + rb,
        "conn_state":    raw.get("conn_state") or raw.get("rcode_name"),
        "is_internal_src": is_internal(src_ip),
        "is_internal_dst": is_internal(dst_ip),
        "label":         raw.get("label", "benign"),
        "raw_json":      json.dumps(raw),
        "incident_id":   None,
        "embedding_id":  None,
    }


def build_chunk_text(event: dict) -> str:
    """Build human-readable text from event for embedding."""
    parts = [
        f"log_type={event['log_type']}",
        f"src={event['src_ip']}:{event['src_port']}",
        f"dst={event['dst_ip']}:{event['dst_port']}",
        f"proto={event['proto']}",
    ]
    if event.get("service"):
        parts.append(f"service={event['service']}")
    if event.get("bytes_total"):
        parts.append(f"bytes={event['bytes_total']}")
    if event.get("duration_sec"):
        parts.append(f"duration={event['duration_sec']:.3f}s")
    if event.get("conn_state"):
        parts.append(f"state={event['conn_state']}")

    raw = json.loads(event["raw_json"])
    # Log-type specific enrichment
    if event["log_type"] == "dns":
        parts.append(f"query={raw.get('query','-')}")
        parts.append(f"answer={','.join(raw.get('answers',[]))}")
    elif event["log_type"] == "http":
        parts.append(f"method={raw.get('method','-')}")
        parts.append(f"host={raw.get('host','-')}")
        parts.append(f"uri={raw.get('uri','-')}")
        parts.append(f"status={raw.get('status_code','-')}")
    elif event["log_type"] == "ssh":
        parts.append(f"auth_success={raw.get('auth_success',False)}")
    elif event["log_type"] == "notice":
        parts.append(f"note={raw.get('note','-')}")
        parts.append(f"msg={raw.get('msg','-')}")

    return " | ".join(parts)


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(DDL_EVENTS)
    conn.execute(DDL_INCIDENTS)
    conn.execute(DDL_EMBEDDINGS)
    conn.execute(DDL_MITRE)
    conn.commit()
    return conn


def load_raw_logs(raw_dir: Path) -> list[dict]:
    """Load all Zeek JSON files from raw_dir, deduplicate by uid."""
    records = {}
    for log_file in sorted(raw_dir.glob("*.json")):
        count = 0
        with open(log_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    norm = normalize_record(rec)
                    if norm and norm["uid"] not in records:
                        records[norm["uid"]] = norm
                        count += 1
                except json.JSONDecodeError:
                    continue
        print(f"  Loaded {count:>6,} events from {log_file.name}")
    return list(records.values())


def insert_events(conn: sqlite3.Connection, events: list[dict]):
    """Insert normalized events into SQLite."""
    sql = """
    INSERT OR IGNORE INTO events
        (uid, log_type, ts_epoch, ts_iso, src_ip, src_port, dst_ip, dst_port,
         proto, service, duration_sec, bytes_orig, bytes_resp, bytes_total,
         conn_state, is_internal_src, is_internal_dst, label, raw_json,
         incident_id, embedding_id)
    VALUES
        (:uid, :log_type, :ts_epoch, :ts_iso, :src_ip, :src_port, :dst_ip, :dst_port,
         :proto, :service, :duration_sec, :bytes_orig, :bytes_resp, :bytes_total,
         :conn_state, :is_internal_src, :is_internal_dst, :label, :raw_json,
         :incident_id, :embedding_id)
    """
    conn.executemany(sql, events)
    conn.commit()


def write_clean_jsonl(events: list[dict], out_dir: Path):
    """Write normalized events to clean JSONL (without raw_json blob)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "clean_events.jsonl"
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            light = {k: v for k, v in ev.items() if k != "raw_json"}
            light["chunk_text"] = build_chunk_text(ev)
            f.write(json.dumps(light) + "\n")
    return path


def validate(db_path: Path):
    """Validate DB integrity and print stats."""
    conn = sqlite3.connect(str(db_path))
    total  = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    attack = conn.execute("SELECT COUNT(*) FROM events WHERE label='attack'").fetchone()[0]
    benign = conn.execute("SELECT COUNT(*) FROM events WHERE label='benign'").fetchone()[0]
    by_type = conn.execute(
        "SELECT log_type, COUNT(*) FROM events GROUP BY log_type ORDER BY 2 DESC"
    ).fetchall()
    conn.close()

    print("\n📊 Database Validation")
    print(f"{'Total events':<30} {total:>8,}")
    print(f"{'Attack events':<30} {attack:>8,}")
    print(f"{'Benign events':<30} {benign:>8,}")
    print("\nBy log type:")
    for lt, cnt in by_type:
        print(f"  {lt:<20} {cnt:>6,}")
    return total


def main():
    parser = argparse.ArgumentParser(description="Normalize Zeek logs → SQLite")
    parser.add_argument("--input",    default=str(RAW_DIR),  help="Raw log directory")
    parser.add_argument("--output",   default=str(DB_PATH),  help="SQLite DB path")
    parser.add_argument("--validate", action="store_true",   help="Validate only")
    args = parser.parse_args()

    db_path  = Path(args.output)
    raw_dir  = Path(args.input)

    if args.validate:
        if not db_path.exists():
            print(f"❌ DB not found: {db_path}", file=sys.stderr)
            sys.exit(1)
        validate(db_path)
        return

    print("[*] Initializing SQLite database...")
    conn = init_db(db_path)

    print(f"[*] Loading raw Zeek logs from {raw_dir}...")
    events = load_raw_logs(raw_dir)
    print(f"    → {len(events):,} unique events loaded")

    print("[*] Inserting events into SQLite...")
    insert_events(conn, events)
    conn.close()

    print("[*] Writing clean JSONL...")
    clean_path = write_clean_jsonl(events, CLEAN_DIR)

    total = validate(db_path)
    print(f"\n✅ Done. DB: {db_path}  |  JSONL: {clean_path}")
    print(f"   Total events: {total:,}")


if __name__ == "__main__":
    main()
