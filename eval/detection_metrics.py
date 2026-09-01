"""
detection_metrics.py -- SENTINEL-X Detection Evaluator
=======================================================
Measures per-event detection quality by comparing the `label` field in the
``events`` DB table against the ground-truth labels CSV.

Metrics produced
----------------
- Precision, Recall, F1 (sklearn)
- False-Positive Rate  (FP / (FP + TN))
- ROC-AUC              (sklearn, using binary label scores)
- Raw confusion matrix counts: TP, FP, FN, TN
- Summary counts: total_events, flagged_events, actual_attack_events
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

try:
    from rich.console import Console
    from rich.table import Table
    _RICH = True
except ImportError:
    _RICH = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_db_events(db_path: str) -> pd.DataFrame:
    """Load the *events* table from the SQLite database.

    Returns a DataFrame with at least ``uid`` and ``label`` columns.
    Returns an empty DataFrame when the table is absent or empty.
    """
    path = Path(db_path)
    if not path.exists():
        return pd.DataFrame(columns=["uid", "label"])

    con = sqlite3.connect(str(path))
    try:
        df = pd.read_sql_query("SELECT uid, label FROM events", con)
    except Exception:
        df = pd.DataFrame(columns=["uid", "label"])
    finally:
        con.close()

    return df


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class DetectionEvaluator:
    """Evaluates SENTINEL-X per-event detection against ground truth labels.

    Parameters
    ----------
    ground_truth_csv:
        Absolute path to ``ground_truth_labels.csv``.
    db_path:
        Absolute path to ``sentinelx.db``.
    """

    # The value stored in ``events.label`` that indicates a malicious event.
    MALICIOUS_LABEL: str = "malicious"

    def __init__(self, ground_truth_csv: str, db_path: str) -> None:
        self.ground_truth_csv = ground_truth_csv
        self.db_path = db_path

        self._gt_df: pd.DataFrame = self._load_ground_truth()
        self._sys_df: pd.DataFrame = _load_db_events(db_path)
        self._merged: pd.DataFrame | None = None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_ground_truth(self) -> pd.DataFrame:
        """Parse ground-truth CSV; return empty frame on missing file."""
        p = Path(self.ground_truth_csv)
        if not p.exists():
            return pd.DataFrame(columns=["uid", "is_malicious"])
        df = pd.read_csv(p, dtype=str)
        df["is_malicious"] = df["is_malicious"].astype(str).str.strip().str.lower()
        df["is_malicious"] = df["is_malicious"].map(
            lambda v: 1 if v in {"1", "true", "yes", "malicious"} else 0
        )
        return df[["uid", "is_malicious"]]

    def _build_merged(self) -> pd.DataFrame:
        """Inner-join ground truth and system output on ``uid``."""
        if self._merged is not None:
            return self._merged

        if self._gt_df.empty or self._sys_df.empty:
            self._merged = pd.DataFrame(
                columns=["uid", "is_malicious", "label", "y_true", "y_pred"]
            )
            return self._merged

        merged = self._gt_df.merge(self._sys_df, on="uid", how="inner")
        merged["y_true"] = merged["is_malicious"].astype(int)
        merged["y_pred"] = (
            merged["label"]
            .astype(str)
            .str.strip()
            .str.lower()
            .map(lambda v: 1 if v == self.MALICIOUS_LABEL else 0)
        )
        self._merged = merged
        return self._merged

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute(self) -> dict[str, Any]:
        """Compute all detection metrics.

        Returns
        -------
        dict
            Keys: precision, recall, f1, false_positive_rate, roc_auc,
                  tp, fp, fn, tn, total_events, flagged_events,
                  actual_attack_events.
        """
        df = self._build_merged()

        if df.empty or df["y_true"].nunique() < 2:
            print(
                "WARNING: Insufficient data for detection metrics "
                "(empty join or only one class present)."
            )
            return {
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "false_positive_rate": 0.0,
                "roc_auc": 0.0,
                "tp": 0,
                "fp": 0,
                "fn": 0,
                "tn": 0,
                "total_events": len(df),
                "flagged_events": int(df["y_pred"].sum()) if not df.empty else 0,
                "actual_attack_events": int(df["y_true"].sum()) if not df.empty else 0,
            }

        y_true = df["y_true"].tolist()
        y_pred = df["y_pred"].tolist()

        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall    = float(recall_score(y_true, y_pred, zero_division=0))
        f1        = float(f1_score(y_true, y_pred, zero_division=0))

        try:
            roc_auc = float(roc_auc_score(y_true, y_pred))
        except ValueError:
            roc_auc = 0.0

        tp = int(sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1))
        fp = int(sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1))
        fn = int(sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0))
        tn = int(sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0))

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": fpr,
            "roc_auc": roc_auc,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "total_events": len(df),
            "flagged_events": int(df["y_pred"].sum()),
            "actual_attack_events": int(df["y_true"].sum()),
        }

    def print_report(self) -> None:
        """Print a rich-formatted detection metrics table to stdout."""
        metrics = self.compute()

        if _RICH:
            console = Console()
            table = Table(
                title="[bold cyan]SENTINEL-X -- Detection Metrics[/bold cyan]",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Metric", style="cyan", min_width=28)
            table.add_column("Value", justify="right", min_width=12)

            rows = [
                ("Precision",             f"{metrics['precision']:.4f}"),
                ("Recall",                f"{metrics['recall']:.4f}"),
                ("F1 Score",              f"{metrics['f1']:.4f}"),
                ("False Positive Rate",   f"{metrics['false_positive_rate']:.4f}"),
                ("ROC-AUC",               f"{metrics['roc_auc']:.4f}"),
                ("---",                   "---"),
                ("True Positives (TP)",   str(metrics["tp"])),
                ("False Positives (FP)",  str(metrics["fp"])),
                ("False Negatives (FN)",  str(metrics["fn"])),
                ("True Negatives (TN)",   str(metrics["tn"])),
                ("---",                   "---"),
                ("Total Events",          str(metrics["total_events"])),
                ("Flagged Events",        str(metrics["flagged_events"])),
                ("Actual Attack Events",  str(metrics["actual_attack_events"])),
            ]
            for label, value in rows:
                table.add_row(label, value)

            console.print(table)
        else:
            print("\n=== SENTINEL-X -- Detection Metrics ===")
            for key, val in metrics.items():
                print(f"  {key:<30}: {val}")
            print()


# ---------------------------------------------------------------------------
# Module self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    gt_csv = sys.argv[1] if len(sys.argv) > 1 else "data/ground_truth/ground_truth_labels.csv"
    db     = sys.argv[2] if len(sys.argv) > 2 else "db/sentinelx.db"

    evaluator = DetectionEvaluator(ground_truth_csv=gt_csv, db_path=db)
    evaluator.print_report()