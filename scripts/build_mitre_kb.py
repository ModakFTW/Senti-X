#!/usr/bin/env python3
"""
SENTINEL-X — P6: MITRE KB Builder
====================================
Reads mitre_kb.json → produces:
  1. knowledge/mitre/mitre_chunks.jsonl   (pre-chunked text for embedding)
  2. Inserts into SQLite mitre_techniques table

Each technique is chunked into sections:
  - overview  (name + tactic + description)
  - detection (detection text + detection signals)
  - mitigation (mitigations list)
  - metadata  (data sources + related techniques + zeek tips)
"""

import json
import sqlite3
import sys
from pathlib import Path

ROOT       = Path(__file__).parent.parent
KB_PATH    = ROOT / "knowledge" / "mitre" / "mitre_kb.json"
CHUNKS_OUT = ROOT / "knowledge" / "mitre" / "mitre_chunks.jsonl"
DB_PATH    = ROOT / "db" / "sentinelx.db"


def chunk_technique(t: dict) -> list[dict]:
    """Split a technique into embeddable chunks with metadata."""
    tid  = t["technique_id"]
    name = t["name"]
    chunks = []

    # Chunk 1: Overview
    text = (
        f"MITRE ATT&CK Technique {tid}: {name}\n"
        f"Tactic: {t['tactic']}\n"
        f"Description: {t['description']}"
    )
    chunks.append({
        "chunk_id":     f"{tid}_overview",
        "technique_id": tid,
        "technique_name": name,
        "tactic":       t["tactic"],
        "section":      "overview",
        "chunk_text":   text,
    })

    # Chunk 2: Detection
    signals = "\n".join(f"  - {s}" for s in t.get("detection_signals", []))
    text = (
        f"Detection for {tid} ({name}):\n"
        f"{t['detection']}\n\n"
        f"Key detection signals:\n{signals}"
    )
    chunks.append({
        "chunk_id":     f"{tid}_detection",
        "technique_id": tid,
        "technique_name": name,
        "tactic":       t["tactic"],
        "section":      "detection",
        "chunk_text":   text,
    })

    # Chunk 3: Mitigations
    mit_lines = "\n".join(
        f"  - {m['id']} {m['name']}: {m['description']}"
        for m in t.get("mitigations", [])
    )
    text = (
        f"Mitigations for {tid} ({name}):\n{mit_lines}"
    )
    chunks.append({
        "chunk_id":     f"{tid}_mitigations",
        "technique_id": tid,
        "technique_name": name,
        "tactic":       t["tactic"],
        "section":      "mitigations",
        "chunk_text":   text,
    })

    # Chunk 4: Metadata + Zeek tips
    ds = ", ".join(t.get("data_sources", []))
    rel = ", ".join(t.get("related_techniques", []))
    zeek = ", ".join(t.get("zeek_log_types", []))
    text = (
        f"Metadata for {tid} ({name}):\n"
        f"Data Sources: {ds}\n"
        f"Related Techniques: {rel}\n"
        f"Relevant Zeek Log Types: {zeek}"
    )
    if t.get("example_query"):
        text += f"\nExample detection query:\n{t['example_query']}"
    chunks.append({
        "chunk_id":     f"{tid}_metadata",
        "technique_id": tid,
        "technique_name": name,
        "tactic":       t["tactic"],
        "section":      "metadata",
        "chunk_text":   text,
    })

    return chunks


def insert_to_db(techniques: list[dict]):
    if not DB_PATH.exists():
        print(f"⚠️  DB not found at {DB_PATH} — skipping DB insert (run normalize_zeek.py first)")
        return
    conn = sqlite3.connect(str(DB_PATH))
    sql = """
    INSERT OR REPLACE INTO mitre_techniques
        (technique_id, name, tactic, description, detection, mitigations, data_sources, related)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    for t in techniques:
        conn.execute(sql, (
            t["technique_id"],
            t["name"],
            t["tactic"],
            t["description"],
            t["detection"],
            json.dumps(t.get("mitigations", [])),
            json.dumps(t.get("data_sources", [])),
            json.dumps(t.get("related_techniques", [])),
        ))
    conn.commit()
    conn.close()
    print(f"✅ Inserted {len(techniques)} techniques into SQLite mitre_techniques table")


def main():
    print(f"[*] Loading MITRE KB from {KB_PATH}...")
    with open(KB_PATH, encoding="utf-8") as f:
        kb = json.load(f)

    techniques = kb["techniques"]
    print(f"    → {len(techniques)} techniques loaded")

    all_chunks = []
    for t in techniques:
        chunks = chunk_technique(t)
        all_chunks.extend(chunks)

    # Write chunks JSONL
    CHUNKS_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(CHUNKS_OUT, "w", encoding="utf-8") as f:
        for chunk in all_chunks:
            f.write(json.dumps(chunk) + "\n")

    print(f"✅ Wrote {len(all_chunks)} chunks → {CHUNKS_OUT}")

    # Insert techniques to DB
    insert_to_db(techniques)

    print(f"\n📚 Chunk breakdown:")
    by_tid = {}
    for c in all_chunks:
        by_tid.setdefault(c["technique_id"], []).append(c["section"])
    for tid, sections in by_tid.items():
        print(f"   {tid}: {', '.join(sections)}")


if __name__ == "__main__":
    main()
