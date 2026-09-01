"""
rag_eval.py -- SENTINEL-X RAG Quality Evaluator
=================================================
Measures the quality of the Evidence RAG pipeline across three dimensions:

1. Evidence Faithfulness
   For each incident with a populated ``evidence_summary``, what fraction of
   the log UIDs cited in that summary actually belong to the ground-truth
   event set for that incident?

2. MITRE Relevance
   For each incident with a populated ``mitre_context``, does the retrieved
   MITRE technique match the expected technique(s) from the incident ground
   truth?

3. Citation Coverage
   What fraction of incidents have *both* ``evidence_summary`` and
   ``mitre_context`` populated (i.e. the RAG pipeline actually ran for them)?
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
DEFAULT_DB   = str(ROOT / "db" / "sentinelx.db")
DEFAULT_GT   = str(ROOT / "data" / "ground_truth" / "incident_ground_truth.json")


class RAGEvaluator:
    """Evaluate the quality of the Evidence RAG pipeline."""

    def __init__(self, db_path: str = DEFAULT_DB, ground_truth_incident_json: str = DEFAULT_GT):
        self.db_path  = db_path
        self.gt_path  = ground_truth_incident_json
        self._gt: list[dict] = self._load_ground_truth()
        self._gt_by_id: dict[str, dict] = {i["incident_id"]: i for i in self._gt}

    # ── Loading ────────────────────────────────────────────────────────────────

    def _load_ground_truth(self) -> list[dict]:
        p = Path(self.gt_path)
        if not p.exists():
            return []
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def _load_system_incidents(self) -> list[dict]:
        """Load incidents from the DB that have been processed by the RAG pipeline."""
        if not Path(self.db_path).exists():
            return []
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT incident_id, technique_ids, event_uids, evidence_summary, mitre_context "
            "FROM incidents"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ── Metric 1: Evidence Faithfulness ───────────────────────────────────────

    def evaluate_evidence_faithfulness(self) -> float:
        """
        For each incident with evidence_summary, parse cited UIDs and check
        how many are in the ground-truth event_uids for that incident.

        Returns:
            Average faithfulness score across incidents (0.0 – 1.0).
            Returns 1.0 if no incidents have been processed yet (vacuously true).
        """
        incidents = self._load_system_incidents()
        scored = []

        for inc in incidents:
            summary = inc.get("evidence_summary") or ""
            if not summary.strip():
                continue  # skip unprocessed incidents

            gt = self._gt_by_id.get(inc["incident_id"])
            if not gt:
                continue

            gt_uids: set[str] = set(gt.get("event_uids", []))
            if not gt_uids:
                continue

            # Extract Zeek-style UIDs from the summary text
            # Zeek UIDs: 'C' followed by ≥10 alphanumeric chars
            cited_uids: set[str] = set(re.findall(r"\bC[A-Za-z0-9]{10,}\b", summary))

            if not cited_uids:
                # No UIDs found in summary — treat as 0 faithfulness
                scored.append(0.0)
                continue

            faithful = len(cited_uids & gt_uids)
            score = faithful / len(cited_uids)
            scored.append(score)

        return float(sum(scored) / len(scored)) if scored else 1.0

    # ── Metric 2: MITRE Relevance ─────────────────────────────────────────────

    def evaluate_mitre_relevance(self, manual_labels: dict[str, list[str]] | None = None) -> float:
        """
        For each incident with mitre_context, check whether the retrieved
        MITRE techniques overlap with the expected techniques.

        Args:
            manual_labels: Optional override dict mapping incident_id →
                           list of expected technique IDs.

        Returns:
            Average relevance score across incidents (0.0 – 1.0).
        """
        incidents = self._load_system_incidents()
        scored = []

        for inc in incidents:
            context = inc.get("mitre_context") or ""
            if not context.strip():
                continue

            inc_id = inc["incident_id"]
            gt = self._gt_by_id.get(inc_id)

            # Resolve expected techniques
            if manual_labels and inc_id in manual_labels:
                expected: set[str] = set(manual_labels[inc_id])
            elif gt:
                expected = set(gt.get("technique_ids", []))
            else:
                continue

            if not expected:
                continue

            # Extract technique IDs mentioned in mitre_context
            retrieved: set[str] = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", context))

            if not retrieved:
                scored.append(0.0)
                continue

            # Jaccard-style relevance: |intersection| / |expected|
            overlap = len(retrieved & expected)
            score = overlap / len(expected)
            scored.append(min(score, 1.0))

        return float(sum(scored) / len(scored)) if scored else 1.0

    # ── Metric 3: Citation Coverage ───────────────────────────────────────────

    def evaluate_citation_coverage(self) -> float:
        """
        Fraction of incidents in the DB that have BOTH evidence_summary and
        mitre_context populated.

        Returns:
            Coverage ratio (0.0 – 1.0).
        """
        incidents = self._load_system_incidents()
        if not incidents:
            return 0.0

        covered = sum(
            1 for i in incidents
            if (i.get("evidence_summary") or "").strip()
            and (i.get("mitre_context") or "").strip()
        )
        return covered / len(incidents)

    # ── Combined ──────────────────────────────────────────────────────────────

    def compute(self) -> dict[str, Any]:
        """Run all three RAG quality metrics and return results dict."""
        incidents = self._load_system_incidents()
        processed = sum(
            1 for i in incidents
            if (i.get("evidence_summary") or "").strip()
        )

        return {
            "evidence_faithfulness": self.evaluate_evidence_faithfulness(),
            "mitre_relevance":       self.evaluate_mitre_relevance(),
            "citation_coverage":     self.evaluate_citation_coverage(),
            "incidents_in_db":       len(incidents),
            "incidents_processed":   processed,
            "ground_truth_incidents": len(self._gt),
            "rag_pipeline_ran":      processed > 0,
        }

    def print_report(self) -> None:
        """Print a formatted RAG quality report to stdout."""
        results = self.compute()

        print("\n" + "=" * 55)
        print("  RAG QUALITY METRICS")
        print("=" * 55)

        if not results["rag_pipeline_ran"]:
            print("\n  [WARNING] RAG pipeline has not been run yet.")
            print("  Run the RAG pipeline on at least one incident first.")
            print(f"\n  Incidents in DB:          {results['incidents_in_db']}")
            print(f"  Ground truth incidents:   {results['ground_truth_incidents']}")
            return

        def fmt(v: float) -> str:
            return f"{v:.1%}"

        print(f"\n  {'Metric':<35} {'Score':>8}")
        print(f"  {'-'*35} {'-'*8}")
        print(f"  {'Evidence Faithfulness':<35} {fmt(results['evidence_faithfulness']):>8}")
        print(f"  {'MITRE Relevance':<35} {fmt(results['mitre_relevance']):>8}")
        print(f"  {'Citation Coverage':<35} {fmt(results['citation_coverage']):>8}")
        print(f"\n  Incidents in DB:          {results['incidents_in_db']}")
        print(f"  Incidents with RAG output:{results['incidents_processed']}")
        print(f"  Ground truth incidents:   {results['ground_truth_incidents']}")
        print("=" * 55)


if __name__ == "__main__":
    evaluator = RAGEvaluator()
    evaluator.print_report()
