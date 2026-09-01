"""
scripts/build_vectorstore.py
-----------------------------
SENTINEL-X vector-store population script.

Reads all events from the SQLite database (supplemented with
``clean_events.jsonl`` for chunk text when available) and all MITRE
ATT&CK chunks from ``knowledge/mitre/mitre_chunks.jsonl``, embeds
them with :class:`~rag.embedder.SentinelEmbedder`, and inserts the
results into the ``embeddings`` table.

Usage
-----
    python scripts/build_vectorstore.py --db data/sentinel.db
    python scripts/build_vectorstore.py --db data/sentinel.db --dry-run
    python scripts/build_vectorstore.py --db data/sentinel.db --batch-size 32

Options
-------
--db            Path to the SQLite database (required).
--dry-run       Print stats without writing to the database.
--batch-size N  Number of texts embedded in one forward pass (default 64).
--events-jsonl  Override path to clean_events.jsonl.
--mitre-jsonl   Override path to mitre_chunks.jsonl.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

# Ensure project root is on sys.path when run as a script
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from rag.embedder import SentinelEmbedder
from rag.vectorstore import SQLiteVectorStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_event_chunk(row: sqlite3.Row) -> str:
    """Construct a human-readable text chunk from an events row.

    Falls back gracefully when columns are NULL.
    """
    parts: list[str] = []
    if row["log_type"]:
        parts.append(f"log_type={row['log_type']}")
    if row["ts_iso"]:
        parts.append(f"ts={row['ts_iso']}")
    if row["src_ip"]:
        src = row["src_ip"]
        if row["src_port"]:
            src += f":{row['src_port']}"
        parts.append(f"src={src}")
    if row["dst_ip"]:
        dst = row["dst_ip"]
        if row["dst_port"]:
            dst += f":{row['dst_port']}"
        parts.append(f"dst={dst}")
    if row["proto"]:
        parts.append(f"proto={row['proto']}")
    if row["service"]:
        parts.append(f"service={row['service']}")
    if row["conn_state"]:
        parts.append(f"state={row['conn_state']}")
    if row["bytes_total"] is not None:
        parts.append(f"bytes={row['bytes_total']}")
    if row["label"]:
        parts.append(f"label={row['label']}")
    return " ".join(parts)


def _load_events_from_jsonl(path: str) -> dict[str, str]:
    """Load uid -> chunk_text mapping from a clean_events.jsonl file.

    Parameters
    ----------
    path:
        Path to the JSONL file produced by ``normalize_zeek.py``.

    Returns
    -------
    dict[str, str]
        Mapping ``uid -> chunk_text``.  Missing or malformed lines are
        skipped with a warning.
    """
    mapping: dict[str, str] = {}
    skipped = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                uid = rec.get("uid") or rec.get("id")
                chunk = rec.get("chunk_text") or rec.get("text") or ""
                if uid and chunk:
                    mapping[uid] = chunk
                else:
                    skipped += 1
            except json.JSONDecodeError:
                print(
                    f"  [WARN] build_vectorstore: JSON parse error at "
                    f"{path}:{lineno} -- skipping",
                    file=sys.stderr,
                )
                skipped += 1
    if skipped:
        print(
            f"  [WARN] Skipped {skipped} malformed record(s) in {path}",
            file=sys.stderr,
        )
    return mapping


def _load_mitre_chunks(path: str) -> list[dict]:
    """Load MITRE ATT&CK chunks from a JSONL file.

    Expected record keys (flexible):
        ``chunk_id``, ``technique_id``, ``tactic``, ``section``,
        ``chunk_text`` / ``text``

    Parameters
    ----------
    path:
        Path to ``mitre_chunks.jsonl``.

    Returns
    -------
    list[dict]
        Validated chunk records.
    """
    chunks: list[dict] = []
    skipped = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                technique_id = rec.get("technique_id", "")
                chunk_text   = rec.get("chunk_text") or rec.get("text") or ""
                if not technique_id or not chunk_text:
                    skipped += 1
                    continue
                chunks.append(
                    {
                        "chunk_id":     rec.get("chunk_id", ""),
                        "technique_id": technique_id,
                        "tactic":       rec.get("tactic", ""),
                        "section":      rec.get("section", "description"),
                        "chunk_text":   chunk_text,
                    }
                )
            except json.JSONDecodeError:
                print(
                    f"  [WARN] build_vectorstore: JSON parse error at "
                    f"{path}:{lineno} -- skipping",
                    file=sys.stderr,
                )
                skipped += 1
    if skipped:
        print(
            f"  [WARN] Skipped {skipped} invalid MITRE record(s) in {path}",
            file=sys.stderr,
        )
    return chunks


def _batch_embed(
    embedder: SentinelEmbedder,
    texts: list[str],
    batch_size: int,
    label: str,
) -> np.ndarray:
    """Embed a list of texts in batches, printing progress.

    Parameters
    ----------
    embedder:
        The :class:`SentinelEmbedder` instance to use.
    texts:
        Full list of strings to embed.
    batch_size:
        Forward-pass batch size.
    label:
        Human-readable label for the progress output.

    Returns
    -------
    np.ndarray
        Float32 matrix of shape ``(len(texts), EMBEDDING_DIM)``.
    """
    n = len(texts)
    results: list[np.ndarray] = []
    total_batches = (n + batch_size - 1) // batch_size

    for batch_idx in range(total_batches):
        start = batch_idx * batch_size
        end   = min(start + batch_size, n)
        batch = texts[start:end]
        vecs  = embedder.embed_batch(batch)
        results.append(vecs)

        done = end
        pct  = done / n * 100
        print(
            f"  [{label}] batch {batch_idx + 1}/{total_batches} "
            f"({done}/{n}, {pct:.1f}%)",
            end="\r",
        )

    print()  # newline after progress
    if not results:
        return np.empty((0, embedder.EMBEDDING_DIM), dtype=np.float32)
    return np.vstack(results).astype(np.float32)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def build_vectorstore(
    db_path: str,
    events_jsonl: Optional[str] = None,
    mitre_jsonl: Optional[str] = None,
    batch_size: int = 64,
    dry_run: bool = False,
) -> dict:
    """Populate the SQLite embeddings table for all events and MITRE chunks.

    Parameters
    ----------
    db_path:
        Absolute path to the SENTINEL-X SQLite database.
    events_jsonl:
        Optional path to ``clean_events.jsonl`` for pre-built chunk text.
        When absent, chunk text is re-generated from the events table.
    mitre_jsonl:
        Optional path to ``mitre_chunks.jsonl``.  Defaults to
        ``knowledge/mitre/mitre_chunks.jsonl`` relative to project root.
    batch_size:
        Embedding batch size (default 64).
    dry_run:
        When ``True``, no database writes are performed.

    Returns
    -------
    dict
        Summary statistics with keys:
        ``events_total``, ``events_embedded``, ``events_skipped``,
        ``mitre_total``, ``mitre_embedded``, ``elapsed_sec``.
    """
    t0 = time.perf_counter()
    project_root = Path(db_path).resolve().parent.parent

    print("=" * 60)
    print("SENTINEL-X  build_vectorstore")
    print("=" * 60)
    print(f"  DB        : {db_path}")
    print(f"  Batch size: {batch_size}")
    print(f"  Dry run   : {dry_run}")
    print()

    # ------------------------------------------------------------------
    # 1. Load events from SQLite
    # ------------------------------------------------------------------
    print("[1/4] Loading events from SQLite ...")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        event_rows = conn.execute(
            "SELECT uid, log_type, ts_iso, src_ip, src_port, dst_ip, dst_port, "
            "proto, service, conn_state, bytes_total, label, incident_id "
            "FROM events"
        ).fetchall()
    except sqlite3.OperationalError as exc:
        print(f"  [ERROR] Could not read events table: {exc}", file=sys.stderr)
        conn.close()
        sys.exit(1)
    finally:
        conn.close()

    print(f"  Found {len(event_rows)} event(s) in DB.")

    # Optional: override chunk_text from JSONL
    jsonl_map: dict[str, str] = {}
    if events_jsonl and Path(events_jsonl).exists():
        print(f"  Loading chunk_text overrides from {events_jsonl} ...")
        jsonl_map = _load_events_from_jsonl(events_jsonl)
        print(f"  Loaded {len(jsonl_map)} JSONL record(s).")
    else:
        # Try default location
        default_jsonl = project_root / "data" / "clean_events.jsonl"
        if default_jsonl.exists():
            print(f"  Auto-detected {default_jsonl} -- loading chunk_text ...")
            jsonl_map = _load_events_from_jsonl(str(default_jsonl))
            print(f"  Loaded {len(jsonl_map)} JSONL record(s).")

    # Build uid -> chunk_text list
    event_uids:   list[str] = []
    event_chunks: list[str] = []
    for row in event_rows:
        uid = row["uid"]
        if not uid:
            continue
        chunk = jsonl_map.get(uid) or _build_event_chunk(row)
        event_uids.append(uid)
        event_chunks.append(chunk)

    print(f"  Prepared {len(event_chunks)} event chunk(s) for embedding.")
    print()

    # ------------------------------------------------------------------
    # 2. Load MITRE chunks
    # ------------------------------------------------------------------
    print("[2/4] Loading MITRE ATT&CK chunks ...")
    if mitre_jsonl:
        mitre_path = Path(mitre_jsonl)
    else:
        mitre_path = project_root / "knowledge" / "mitre" / "mitre_chunks.jsonl"

    mitre_records: list[dict] = []
    if mitre_path.exists():
        mitre_records = _load_mitre_chunks(str(mitre_path))
        print(f"  Loaded {len(mitre_records)} MITRE chunk(s) from {mitre_path}.")
    else:
        print(
            f"  [WARN] mitre_chunks.jsonl not found at {mitre_path}. "
            "Skipping MITRE embeddings.",
            file=sys.stderr,
        )
    print()

    # ------------------------------------------------------------------
    # 3. Embed
    # ------------------------------------------------------------------
    print("[3/4] Embedding ...")
    embedder = SentinelEmbedder()

    event_embeddings: Optional[np.ndarray] = None
    if event_chunks:
        print(f"  Embedding {len(event_chunks)} event chunk(s) ...")
        event_embeddings = _batch_embed(
            embedder, event_chunks, batch_size, "events"
        )
        print(f"  Events embedded. Shape: {event_embeddings.shape}")

    mitre_texts = [r["chunk_text"] for r in mitre_records]
    mitre_embeddings: Optional[np.ndarray] = None
    if mitre_texts:
        print(f"  Embedding {len(mitre_texts)} MITRE chunk(s) ...")
        mitre_embeddings = _batch_embed(
            embedder, mitre_texts, batch_size, "mitre"
        )
        print(f"  MITRE embedded. Shape: {mitre_embeddings.shape}")

    print()

    # ------------------------------------------------------------------
    # 4. Insert into SQLite
    # ------------------------------------------------------------------
    print("[4/4] Writing to SQLite ...")
    events_embedded = 0
    events_skipped  = 0
    mitre_embedded  = 0

    if dry_run:
        events_embedded = len(event_chunks)
        mitre_embedded  = len(mitre_records)
        print(
            "  [DRY RUN] No writes performed. "
            f"Would embed {events_embedded} events and "
            f"{mitre_embedded} MITRE chunks."
        )
    else:
        with SQLiteVectorStore(db_path, embedder=embedder) as store:
            # Events
            if event_embeddings is not None:
                for i, (uid, chunk) in enumerate(
                    zip(event_uids, event_chunks)
                ):
                    try:
                        store.add_event_embedding(
                            uid=uid,
                            chunk_text=chunk,
                            embedding=event_embeddings[i],
                        )
                        events_embedded += 1
                    except Exception as exc:  # noqa: BLE001
                        print(
                            f"  [WARN] Failed to insert event uid={uid}: {exc}",
                            file=sys.stderr,
                        )
                        events_skipped += 1

                    if (i + 1) % 500 == 0 or (i + 1) == len(event_uids):
                        pct = (i + 1) / len(event_uids) * 100
                        print(
                            f"  events inserted: {i + 1}/{len(event_uids)} ({pct:.1f}%)",
                            end="\r",
                        )
                print()

            # MITRE chunks
            if mitre_embeddings is not None:
                for i, rec in enumerate(mitre_records):
                    chunk_id = rec["chunk_id"] or f"{rec['technique_id']}_{rec['section']}_{i}"
                    try:
                        store.add_mitre_embedding(
                            chunk_id=chunk_id,
                            chunk_text=rec["chunk_text"],
                            technique_id=rec["technique_id"],
                            tactic=rec["tactic"],
                            section=rec["section"],
                            embedding=mitre_embeddings[i],
                        )
                        mitre_embedded += 1
                    except Exception as exc:  # noqa: BLE001
                        print(
                            f"  [WARN] Failed to insert MITRE chunk {chunk_id}: {exc}",
                            file=sys.stderr,
                        )

                    if (i + 1) % 100 == 0 or (i + 1) == len(mitre_records):
                        pct = (i + 1) / len(mitre_records) * 100
                        print(
                            f"  mitre inserted: {i + 1}/{len(mitre_records)} ({pct:.1f}%)",
                            end="\r",
                        )
                print()

            final_stats = store.get_stats()

    elapsed = time.perf_counter() - t0

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Events total      : {len(event_uids)}")
    print(f"  Events embedded   : {events_embedded}")
    print(f"  Events skipped    : {events_skipped}")
    print(f"  MITRE chunks total: {len(mitre_records)}")
    print(f"  MITRE embedded    : {mitre_embedded}")
    print(f"  Elapsed           : {elapsed:.2f}s")

    if not dry_run:
        print()
        print("  DB stats after build:")
        for k, v in final_stats.items():
            print(f"    {k}: {v}")

    print("=" * 60)

    return {
        "events_total":    len(event_uids),
        "events_embedded": events_embedded,
        "events_skipped":  events_skipped,
        "mitre_total":     len(mitre_records),
        "mitre_embedded":  mitre_embedded,
        "elapsed_sec":     elapsed,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SENTINEL-X: Build the SQLite vector store from events and MITRE chunks."
    )
    parser.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="Path to the SENTINEL-X SQLite database.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print stats without writing to the database.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        metavar="N",
        help="Embedding batch size (default: 64).",
    )
    parser.add_argument(
        "--events-jsonl",
        metavar="PATH",
        default=None,
        help="Path to clean_events.jsonl (optional; auto-detected if omitted).",
    )
    parser.add_argument(
        "--mitre-jsonl",
        metavar="PATH",
        default=None,
        help="Path to mitre_chunks.jsonl (optional; auto-detected if omitted).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    build_vectorstore(
        db_path=args.db,
        events_jsonl=args.events_jsonl,
        mitre_jsonl=args.mitre_jsonl,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )