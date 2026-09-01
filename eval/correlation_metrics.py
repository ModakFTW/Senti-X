"""
correlation_metrics.py -- SENTINEL-X Correlation Evaluator
===========================================================
Measures how accurately SENTINEL-X groups raw events into incidents and
orders MITRE ATT&CK tactics along the correct attack-chain sequence.

Metrics produced
----------------
- incident_grouping_accuracy  : % of attack events placed in the correct incident
- attack_chain_accuracy       : % of incidents whose tactic order matches the
                                canonical kill-chain sequence
- adjusted_rand_index         : sklearn ARI between predicted and true cluster labels
- incidents_generated         : number of incidents in the DB
- incidents_expected          : number of incidents in ground truth
- events_correctly_grouped    : raw count of correctly grouped attack events
- events_total_attack         : total attack events in ground truth
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.metrics import adjusted_rand_score

try:
    from rich.console import Console
    from rich.table import Table
    _RICH = True
except ImportError:
    _RICH = False


# ---------------------------------------------------------------------------
# Canonical MITRE ATT&CK tactic kill-chain order
# ---------------------------------------------------------------------------

TACTIC_ORDER: list[str] = [
    "discovery",
    "credential access",
    "defense evasion",
    "command & control",
    "lateral movement",
    "exfiltration",
]


def _tactic_rank(tactic: str) -> int:
    """Return canonical position of *tactic* (case-insensitive); -1 if unknown."""
    return next(
        (i for i, t in enumerate(TACTIC_ORDER) if t in tactic.lower()),
        -1,
    )


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _load_db_incidents(db_path: str) -> pd.DataFrame:
    """Load the *incidents* table from SQLite."""
    path = Path(db_path)
    if not path.exists():
        return pd.DataFrame(
            columns=["incident_id", "tactic", "technique_ids", "event_uids"]
        )

    con = sqlite3.connect(str(path))
    try:
        df = pd.read_sql_query(
            "SELECT incident_id, tactic, technique_ids, event_uids FROM incidents",
            con,
        )
    except Exception:
        df = pd.DataFrame(
            columns=["incident_id", "tactic", "technique_ids", "event_uids"]
        )
    finally:
        con.close()

    return df


def _load_db_event_incident_map(db_path: str) -> dict[str, str]:
    """Return {uid: incident_id} for all events that belong to an incident."""
    path = Path(db_path)
    if not path.exists():
        return {}

    con = sqlite3.connect(str(path))
    try:
        df = pd.read_sql_query(
            "SELECT uid, incident_id FROM events WHERE incident_id IS NOT NULL",
            con,
        )
    except Exception:
        df = pd.DataFrame(columns=["uid", "incident_id"])
    finally:
        con.close()

    return dict(zip(df["uid"], df["incident_id"]))


def _load_ground_truth_incidents(json_path: str) -> list[dict]:
    """Parse the incident ground-truth JSON file."""
    p = Path(json_path)
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class CorrelationEvaluator:
    """Evaluates incident correlation quality for SENTINEL-X.

    Parameters
    ----------
    ground_truth_incident_json:
        Absolute path to ``incident_ground_truth.json``.
    db_path:
        Absolute path to ``sentinelx.db``.
    """

    def __init__(self, ground_truth_incident_json: str, db_path: str) -> None:
        self.ground_truth_incident_json = ground_truth_incident_json
        self.db_path = db_path

        self._gt_incidents: list[dict] = _load_ground_truth_incidents(
            ground_truth_incident_json
        )
        self._sys_incidents: pd.DataFrame = _load_db_incidents(db_path)
        self._sys_event_map: dict[str, str] = _load_db_event_incident_map(db_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_gt_event_map(self) -> dict[str, str]:
        """Return {uid: incident_id} from ground truth."""
        mapping: dict[str, str] = {}
        for inc in self._gt_incidents:
            iid = str(inc.get("incident_id", ""))
            for uid in inc.get("event_uids", []):
                mapping[str(uid)] = iid
        return mapping

    def _incident_grouping_accuracy(self) -> tuple[float, int, int]:
        """Compute grouping accuracy. Returns (accuracy, correct, total)."""
        gt_map = self._build_gt_event_map()
        if not gt_map:
            return 0.0, 0, 0

        correct = 0
        for uid, gt_iid in gt_map.items():
            sys_iid = self._sys_event_map.get(uid)
            if sys_iid is not None and str(sys_iid) == str(gt_iid):
                correct += 1

        total = len(gt_map)
        return (correct / total if total > 0 else 0.0), correct, total

    def _attack_chain_accuracy(self) -> float:
        """Compute the fraction of incidents whose tactic follows canonical order."""
        if self._sys_incidents.empty or not self._gt_incidents:
            return 0.0

        sys_tactic_map: dict[str, str] = {}
        for _, row in self._sys_incidents.iterrows():
            sys_tactic_map[str(row["incident_id"])] = str(row.get("tactic") or "")

        matched = 0
        total = 0
        for gt_inc in self._gt_incidents:
            gt_tactic = str(gt_inc.get("tactic") or "").lower()
            gt_rank = _tactic_rank(gt_tactic)
            if gt_rank == -1:
                continue

            iid = str(gt_inc.get("incident_id", ""))
            sys_tactic = sys_tactic_map.get(iid, "").lower()
            sys_rank = _tactic_rank(sys_tactic)

            total += 1
            if sys_rank != -1 and sys_rank == gt_rank:
                matched += 1

        return matched / total if total > 0 else 0.0

    def _compute_ari(self) -> float:
        """Compute Adjusted Rand Index between predicted and true cluster assignments."""
        gt_map = self._build_gt_event_map()
        if not gt_map or not self._sys_event_map:
            return 0.0

        uids = sorted(set(gt_map.keys()) & set(self._sys_event_map.keys()))
        if not uids:
            return 0.0

        gt_ids  = sorted(set(gt_map[u] for u in uids))
        sys_ids = sorted(set(self._sys_event_map[u] for u in uids))

        gt_enc  = {v: i for i, v in enumerate(gt_ids)}
        sys_enc = {v: i for i, v in enumerate(sys_ids)}

        y_true = [gt_enc[gt_map[u]] for u in uids]
        y_pred = [sys_enc[self._sys_event_map[u]] for u in uids]

        try:
            return float(adjusted_rand_score(y_true, y_pred))
        except Exception:
            return 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute(self) -> dict[str, Any]:
        """Compute all correlation metrics."""
        grouping_acc, correctly_grouped, total_attack = self._incident_grouping_accuracy()
        chain_acc = self._attack_chain_accuracy()
        ari       = self._compute_ari()

        return {
            "incident_grouping_accuracy": grouping_acc,
            "attack_chain_accuracy": chain_acc,
            "adjusted_rand_index": ari,
            "incidents_generated": len(self._sys_incidents),
            "incidents_expected": len(self._gt_incidents),
            "events_correctly_grouped": correctly_grouped,
            "events_total_attack": total_attack,
        }

    def print_report(self) -> None:
        """Print a formatted correlation metrics report to stdout."""
        metrics = self.compute()

        if _RICH:
            console = Console()
            table = Table(
                title="[bold cyan]SENTINEL-X -- Correlation Metrics[/bold cyan]",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Metric", style="cyan", min_width=32)
            table.add_column("Value", justify="right", min_width=12)

            rows = [
                ("Incident Grouping Accuracy",    f"{metrics['incident_grouping_accuracy']:.4f}"),
                ("Attack Chain Accuracy",         f"{metrics['attack_chain_accuracy']:.4f}"),
                ("Adjusted Rand Index (ARI)",     f"{metrics['adjusted_rand_index']:.4f}"),
                ("---",                           "---"),
                ("Incidents Generated",           str(metrics["incidents_generated"])),
                ("Incidents Expected",            str(metrics["incidents_expected"])),
                ("Events Correctly Grouped",      str(metrics["events_correctly_grouped"])),
                ("Total Attack Events",           str(metrics["events_total_attack"])),
            ]
            for label, value in rows:
                table.add_row(label, value)

            console.print(table)
        else:
            print("\n=== SENTINEL-X -- Correlation Metrics ===")
            for key, val in metrics.items():
                print(f"  {key:<35}: {val}")
            print()


# ---------------------------------------------------------------------------
# Module self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    gt_json = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "data/ground_truth/incident_ground_truth.json"
    )
    db = sys.argv[2] if len(sys.argv) > 2 else "db/sentinelx.db"

    evaluator = CorrelationEvaluator(
        ground_truth_incident_json=gt_json, db_path=db
    )
    evaluator.print_report()