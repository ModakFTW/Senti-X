"""
rag/retriever.py
----------------
SENTINEL-X evidence retrieval functions.

Provides clean, stateless functions for fetching the most relevant log
events and MITRE ATT&CK technique chunks for a given query.  These
functions are the primary interface consumed by the LangGraph pipeline
nodes in ``rag_pipeline.py``.
"""

from __future__ import annotations

from rag.embedder import SentinelEmbedder
from rag.vectorstore import SQLiteVectorStore


# Module-level embedder singleton -- created once, reused across calls.
_embedder: SentinelEmbedder | None = None


def _get_embedder() -> SentinelEmbedder:
    """Return the module-level :class:`SentinelEmbedder` singleton."""
    global _embedder
    if _embedder is None:
        _embedder = SentinelEmbedder()
    return _embedder


# ---------------------------------------------------------------------------
# Public retrieval API
# ---------------------------------------------------------------------------


def retrieve_evidence(
    incident_id: str,
    query_text: str,
    db_path: str,
    top_k: int = 10,
) -> list[dict]:
    """Retrieve the most relevant log events for an incident.

    Embeds ``query_text`` with the local sentence-transformer and returns
    the ``top_k`` most cosine-similar event embeddings that belong to
    ``incident_id``.

    Parameters
    ----------
    incident_id:
        Incident identifier used to filter the events table.
    query_text:
        Natural-language description of the behaviour to investigate.
    db_path:
        Absolute path to the SENTINEL-X SQLite database.
    top_k:
        Maximum number of evidence records to return.

    Returns
    -------
    list[dict]
        Each record contains:
        - ``uid``              -- event UID
        - ``log_type``        -- Zeek log type (e.g. ``"conn"``)
        - ``ts_iso``          -- ISO-8601 timestamp
        - ``src_ip``          -- source IP address
        - ``dst_ip``          -- destination IP address
        - ``chunk_text``      -- text that was embedded
        - ``similarity_score``-- cosine similarity to the query [0, 1]
    """
    embedder = _get_embedder()
    query_vec = embedder.embed(query_text)

    with SQLiteVectorStore(db_path, embedder=embedder) as store:
        results = store.search_events(
            query_embedding=query_vec,
            top_k=top_k,
            incident_id=incident_id if incident_id else None,
        )

    return results


def retrieve_mitre(
    query_text: str,
    db_path: str,
    top_k: int = 3,
) -> list[dict]:
    """Retrieve the most relevant MITRE ATT&CK technique chunks.

    Parameters
    ----------
    query_text:
        Natural-language description of the behaviour to match.
    db_path:
        Absolute path to the SENTINEL-X SQLite database.
    top_k:
        Maximum number of MITRE chunks to return.

    Returns
    -------
    list[dict]
        Each record contains:
        - ``technique_id``    -- ATT&CK ID (e.g. ``"T1110"``)
        - ``technique_name``  -- Human-readable name
        - ``tactic``          -- Tactic category
        - ``section``         -- Source section (``"detection"``, etc.)
        - ``chunk_text``      -- The embedded text chunk
        - ``similarity_score``-- Cosine similarity to the query [0, 1]
    """
    embedder = _get_embedder()
    query_vec = embedder.embed(query_text)

    with SQLiteVectorStore(db_path, embedder=embedder) as store:
        results = store.search_mitre(query_embedding=query_vec, top_k=top_k)

    return results


def retrieve_combined(
    incident_id: str,
    query_text: str,
    db_path: str,
    top_k_evidence: int = 10,
    top_k_mitre: int = 3,
) -> dict:
    """Run evidence and MITRE retrieval together.

    Embeds ``query_text`` once and reuses the vector for both searches,
    returning a single dict with both result sets.

    Parameters
    ----------
    incident_id:
        Incident identifier for event filtering.
    query_text:
        Natural-language investigation query.
    db_path:
        Absolute path to the SENTINEL-X SQLite database.
    top_k_evidence:
        Maximum evidence records to return.
    top_k_mitre:
        Maximum MITRE chunks to return.

    Returns
    -------
    dict
        ``{"evidence": [...], "mitre": [...]}``
    """
    embedder = _get_embedder()
    query_vec = embedder.embed(query_text)

    with SQLiteVectorStore(db_path, embedder=embedder) as store:
        evidence = store.search_events(
            query_embedding=query_vec,
            top_k=top_k_evidence,
            incident_id=incident_id if incident_id else None,
        )
        mitre = store.search_mitre(
            query_embedding=query_vec,
            top_k=top_k_mitre,
        )

    return {"evidence": evidence, "mitre": mitre}


# ---------------------------------------------------------------------------
# Quick smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m rag.retriever <db_path> [incident_id]")
        sys.exit(1)

    _db = sys.argv[1]
    _inc = sys.argv[2] if len(sys.argv) > 2 else ""

    combined = retrieve_combined(
        incident_id=_inc,
        query_text="SSH brute force login attempts",
        db_path=_db,
    )
    print(f"Evidence hits : {len(combined['evidence'])}")
    print(f"MITRE hits    : {len(combined['mitre'])}")
    for rec in combined["evidence"][:3]:
        print(f"  [{rec['similarity_score']:.3f}] {rec['uid']} {rec['chunk_text'][:80]}")
    for rec in combined["mitre"]:
        print(f"  [{rec['similarity_score']:.3f}] {rec['technique_id']} {rec['technique_name']}")