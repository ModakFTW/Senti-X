"""
rag/vectorstore.py
------------------
SENTINEL-X SQLite vector store.

Wraps the existing SQLite database (created by ``normalize_zeek.py``)
with methods for inserting and searching float32 embeddings stored as
BLOBs.  All similarity ranking is done in-process with numpy -- no
external vector-DB dependency is required.

Expected schema (pre-existing tables):
    events(uid, log_type, ts_epoch, ts_iso, src_ip, src_port, dst_ip,
           dst_port, proto, service, duration_sec, bytes_orig,
           bytes_resp, bytes_total, conn_state, is_internal_src,
           is_internal_dst, label, raw_json, incident_id,
           embedding_id, created_at)

    embeddings(id, source_type, source_id, chunk_text, embedding_blob,
               model_name, created_at)

    mitre_techniques(technique_id, name, tactic, description,
                     detection, mitigations, data_sources, related,
                     created_at)
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

import numpy as np

from rag.embedder import SentinelEmbedder


class SQLiteVectorStore:
    """Vector store backed by an existing SENTINEL-X SQLite database.

    Parameters
    ----------
    db_path:
        Absolute path to the SQLite database file.
    embedder:
        Optional pre-constructed :class:`SentinelEmbedder`.  A default
        instance is created lazily if not supplied.
    """

    def __init__(
        self,
        db_path: str,
        embedder: Optional[SentinelEmbedder] = None,
    ) -> None:
        self.db_path: str = db_path
        self._embedder: Optional[SentinelEmbedder] = embedder
        self._conn: sqlite3.Connection = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Schema guard
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        """Create the embeddings table if it does not exist yet."""
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS embeddings (
                id             TEXT PRIMARY KEY,
                source_type    TEXT NOT NULL,
                source_id      TEXT NOT NULL,
                chunk_text     TEXT NOT NULL,
                embedding_blob BLOB NOT NULL,
                model_name     TEXT NOT NULL,
                created_at     TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def embedder(self) -> SentinelEmbedder:
        """Return (or lazily create) the shared embedder instance."""
        if self._embedder is None:
            self._embedder = SentinelEmbedder()
        return self._embedder

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _new_id(self) -> str:
        return str(uuid.uuid4())

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def add_event_embedding(
        self,
        uid: str,
        chunk_text: str,
        embedding: np.ndarray,
    ) -> str:
        """Insert an event embedding and update the events table.

        Parameters
        ----------
        uid:
            Unique ID of the event row in the ``events`` table.
        chunk_text:
            Human-readable text representation that was embedded.
        embedding:
            Float32 numpy vector produced by :class:`SentinelEmbedder`.

        Returns
        -------
        str
            The newly assigned embedding UUID (also written to
            ``events.embedding_id``).
        """
        emb_id = self._new_id()
        blob: bytes = embedding.astype(np.float32).tobytes()
        now = self._now_iso()

        self._conn.execute(
            """
            INSERT OR REPLACE INTO embeddings
                (id, source_type, source_id, chunk_text, embedding_blob,
                 model_name, created_at)
            VALUES (?, 'event', ?, ?, ?, ?, ?)
            """,
            (emb_id, uid, chunk_text, blob, self.embedder.model_name, now),
        )
        self._conn.execute(
            "UPDATE events SET embedding_id = ? WHERE uid = ?",
            (emb_id, uid),
        )
        self._conn.commit()
        return emb_id

    def add_mitre_embedding(
        self,
        chunk_id: str,
        chunk_text: str,
        technique_id: str,
        tactic: str,
        section: str,
        embedding: np.ndarray,
    ) -> str:
        """Insert a MITRE ATT&CK chunk embedding.

        Parameters
        ----------
        chunk_id:
            Unique identifier for this chunk (e.g. ``"T1110_detection_0"``).
        chunk_text:
            The text that was embedded.
        technique_id:
            ATT&CK technique ID (e.g. ``"T1110"``).
        tactic:
            Tactic category (e.g. ``"credential-access"``).
        section:
            Which section the chunk came from (``"detection"``, etc.).
        embedding:
            Float32 numpy vector.

        Returns
        -------
        str
            The embedding UUID.
        """
        emb_id = self._new_id()
        blob: bytes = embedding.astype(np.float32).tobytes()
        now = self._now_iso()
        source_id = f"{technique_id}|{tactic}|{section}|{chunk_id}"

        self._conn.execute(
            """
            INSERT OR REPLACE INTO embeddings
                (id, source_type, source_id, chunk_text, embedding_blob,
                 model_name, created_at)
            VALUES (?, 'mitre_chunk', ?, ?, ?, ?, ?)
            """,
            (emb_id, source_id, chunk_text, blob, self.embedder.model_name, now),
        )
        self._conn.commit()
        return emb_id

    # ------------------------------------------------------------------
    # Search API
    # ------------------------------------------------------------------

    def search_events(
        self,
        query_embedding: np.ndarray,
        top_k: int = 10,
        incident_id: Optional[str] = None,
    ) -> list[dict]:
        """Retrieve the most similar log-event embeddings.

        All candidates are loaded into memory and ranked with numpy
        cosine similarity.

        Parameters
        ----------
        query_embedding:
            Float32 query vector.
        top_k:
            Number of results to return.
        incident_id:
            If supplied, only events with this ``incident_id`` are
            considered.

        Returns
        -------
        list[dict]
            Sorted by descending similarity.  Each dict contains:
            ``uid``, ``log_type``, ``ts_iso``, ``src_ip``, ``dst_ip``,
            ``chunk_text``, ``similarity_score``.
        """
        q = query_embedding.astype(np.float32)

        if incident_id:
            rows = self._conn.execute(
                """
                SELECT e.uid, e.log_type, e.ts_iso, e.src_ip, e.dst_ip,
                       em.chunk_text, em.embedding_blob
                FROM   embeddings em
                JOIN   events e ON e.embedding_id = em.id
                WHERE  em.source_type = 'event'
                  AND  e.incident_id  = ?
                """,
                (incident_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT e.uid, e.log_type, e.ts_iso, e.src_ip, e.dst_ip,
                       em.chunk_text, em.embedding_blob
                FROM   embeddings em
                JOIN   events e ON e.embedding_id = em.id
                WHERE  em.source_type = 'event'
                """,
            ).fetchall()

        if not rows:
            return []

        return self._rank_rows(
            rows=rows,
            query_vec=q,
            key_fields=["uid", "log_type", "ts_iso", "src_ip", "dst_ip", "chunk_text"],
            blob_field="embedding_blob",
            score_field="similarity_score",
            top_k=top_k,
        )

    def search_mitre(
        self,
        query_embedding: np.ndarray,
        top_k: int = 3,
    ) -> list[dict]:
        """Retrieve the most similar MITRE ATT&CK chunk embeddings.

        Parameters
        ----------
        query_embedding:
            Float32 query vector.
        top_k:
            Number of results to return.

        Returns
        -------
        list[dict]
            Each dict: ``technique_id``, ``technique_name``, ``tactic``,
            ``section``, ``chunk_text``, ``similarity_score``.
        """
        q = query_embedding.astype(np.float32)

        rows = self._conn.execute(
            """
            SELECT em.source_id, em.chunk_text, em.embedding_blob
            FROM   embeddings em
            WHERE  em.source_type = 'mitre_chunk'
            """,
        ).fetchall()

        if not rows:
            return []

        # Parse packed source_id back into components
        parsed: list[dict] = []
        blobs: list[bytes] = []
        for row in rows:
            parts = (row["source_id"] or "").split("|", 3)
            parsed.append(
                {
                    "technique_id": parts[0] if len(parts) > 0 else "",
                    "tactic":       parts[1] if len(parts) > 1 else "",
                    "section":      parts[2] if len(parts) > 2 else "",
                    "chunk_text":   row["chunk_text"],
                }
            )
            blobs.append(row["embedding_blob"])

        # Resolve technique names
        tech_names: dict[str, str] = {}
        try:
            name_rows = self._conn.execute(
                "SELECT technique_id, name FROM mitre_techniques"
            ).fetchall()
            tech_names = {r["technique_id"]: r["name"] for r in name_rows}
        except sqlite3.OperationalError:
            pass

        scores = self._batch_cosine(q, blobs)
        top_indices = np.argsort(scores)[::-1][:top_k]

        results: list[dict] = []
        for idx in top_indices:
            rec = dict(parsed[idx])
            rec["technique_name"] = tech_names.get(rec["technique_id"], "")
            rec["similarity_score"] = float(scores[idx])
            results.append(rec)

        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return indexing counts.

        Returns
        -------
        dict
            Keys: ``indexed_events``, ``indexed_mitre_chunks``,
            ``total_events``, ``total_mitre_techniques``.
        """

        def safe_count(sql: str, params: tuple = ()) -> int:
            try:
                return self._conn.execute(sql, params).fetchone()[0]
            except sqlite3.OperationalError:
                return 0

        return {
            "indexed_events": safe_count(
                "SELECT COUNT(*) FROM embeddings WHERE source_type = 'event'"
            ),
            "indexed_mitre_chunks": safe_count(
                "SELECT COUNT(*) FROM embeddings WHERE source_type = 'mitre_chunk'"
            ),
            "total_events": safe_count("SELECT COUNT(*) FROM events"),
            "total_mitre_techniques": safe_count(
                "SELECT COUNT(*) FROM mitre_techniques"
            ),
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __enter__(self) -> "SQLiteVectorStore":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _batch_cosine(query: np.ndarray, blobs: list[bytes]) -> np.ndarray:
        """Compute cosine similarity between query and a list of BLOBs."""
        if not blobs:
            return np.array([], dtype=np.float32)

        matrix = np.stack(
            [np.frombuffer(b, dtype=np.float32) for b in blobs]
        )  # (N, D)

        row_norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        row_norms = np.where(row_norms == 0, 1e-12, row_norms)
        matrix_norm = matrix / row_norms

        q_norm_val = float(np.linalg.norm(query))
        q_norm = query / max(q_norm_val, 1e-12)

        return (matrix_norm @ q_norm).astype(np.float32)

    def _rank_rows(
        self,
        rows: list,
        query_vec: np.ndarray,
        key_fields: list[str],
        blob_field: str,
        score_field: str,
        top_k: int,
    ) -> list[dict]:
        """Generic ranked-retrieval helper."""
        blobs = [row[blob_field] for row in rows]
        scores = self._batch_cosine(query_vec, blobs)
        top_indices = np.argsort(scores)[::-1][:top_k]

        results: list[dict] = []
        for idx in top_indices:
            row = rows[idx]
            rec = {field: row[field] for field in key_fields}
            rec[score_field] = float(scores[idx])
            results.append(rec)

        return results