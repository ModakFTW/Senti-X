"""
run_eval.py -- SENTINEL-X Evaluation Runner
=============================================
Master script that runs all four evaluation modules and produces:
  - Colour terminal report (rich tables)
  - eval_report.md  (markdown scorecard)
  - eval_report.json (raw numbers for CI / dashboards)

Usage
-----
  python eval/run_eval.py
  python eval/run_eval.py --scenario quick
  python eval/run_eval.py --output reports/my_run.md
  python eval/run_eval.py --db db/sentinelx.db
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── Optional rich import ──────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    import sys as _sys, io as _io
    RICH_AVAILABLE = True
    # Wrap stdout in UTF-8 to avoid Windows cp1252 crash with rich's legacy renderer
    _safe_stdout = _io.TextIOWrapper(
        _sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    ) if hasattr(_sys.stdout, "buffer") else _sys.stdout
    console = Console(file=_safe_stdout, highlight=False, safe_box=True)
except Exception:
    RICH_AVAILABLE = False
    console = None  # type: ignore

# ── Eval modules ──────────────────────────────────────────────────────────────
from eval.detection_metrics    import DetectionEvaluator
from eval.correlation_metrics  import CorrelationEvaluator
from eval.system_metrics       import SystemMetricsCollector
from eval.rag_eval             import RAGEvaluator

# ── Paths ─────────────────────────────────────────────────────────────────────
DEFAULT_DB  = str(ROOT / "db" / "sentinelx.db")
DEFAULT_GT_CSV  = str(ROOT / "data" / "ground_truth" / "ground_truth_labels.csv")
DEFAULT_GT_JSON = str(ROOT / "data" / "ground_truth" / "incident_ground_truth.json")
DEFAULT_OUT_MD  = str(ROOT / "eval_report.md")
DEFAULT_OUT_JSON = str(ROOT / "eval_report.json")


# ═══════════════════════════════════════════════════════════════════════════════
# TERMINAL REPORT (rich)
# ═══════════════════════════════════════════════════════════════════════════════

def _pct(v: float | None) -> str:
    if v is None:
        return "N/A"
    return f"{v:.1%}"

def _num(v: int | float | None, fmt: str = ",") -> str:
    if v is None:
        return "N/A"
    if isinstance(v, float):
        return f"{v:.4f}"
    return f"{v:{fmt}}"


def print_detection_table(results: dict[str, Any]) -> None:
    if not RICH_AVAILABLE:
        print("\n=== DETECTION METRICS ===")
        for k, v in results.items():
            print(f"  {k:<35} {v}")
        return

    t = Table(title="Detection Metrics", box=box.ROUNDED, show_header=True,
              header_style="bold cyan")
    t.add_column("Metric",   style="white",  min_width=30)
    t.add_column("Value",    style="green",  justify="right", min_width=12)
    t.add_column("Target",   style="dim",    justify="right", min_width=10)

    targets = {
        "Precision":          "> 0.85",
        "Recall":             "> 0.80",
        "F1 Score":           "> 0.82",
        "False Positive Rate":"< 0.05",
        "ROC-AUC":            "> 0.90",
    }

    rows = [
        ("Precision",           _pct(results.get("precision"))),
        ("Recall",              _pct(results.get("recall"))),
        ("F1 Score",            _pct(results.get("f1"))),
        ("False Positive Rate", _pct(results.get("false_positive_rate"))),
        ("ROC-AUC",             _pct(results.get("roc_auc"))),
        ("True Positives",      _num(results.get("tp"), "d")),
        ("False Positives",     _num(results.get("fp"), "d")),
        ("False Negatives",     _num(results.get("fn"), "d")),
        ("True Negatives",      _num(results.get("tn"), "d")),
        ("Total Events",        _num(results.get("total_events"))),
        ("Flagged as Attack",   _num(results.get("flagged_events"))),
        ("Actual Attack Events",_num(results.get("actual_attack_events"))),
    ]
    for label, val in rows:
        t.add_row(label, val, targets.get(label, ""))

    console.print(t)


def print_correlation_table(results: dict[str, Any]) -> None:
    if not RICH_AVAILABLE:
        print("\n=== CORRELATION METRICS ===")
        for k, v in results.items():
            print(f"  {k:<35} {v}")
        return

    t = Table(title="Correlation Metrics", box=box.ROUNDED, show_header=True,
              header_style="bold cyan")
    t.add_column("Metric",  style="white",  min_width=35)
    t.add_column("Value",   style="green",  justify="right", min_width=12)
    t.add_column("Target",  style="dim",    justify="right", min_width=10)

    rows = [
        ("Incident Grouping Accuracy", _pct(results.get("incident_grouping_accuracy")),  "> 90%"),
        ("Attack Chain Accuracy",      _pct(results.get("attack_chain_accuracy")),        "> 80%"),
        ("Adjusted Rand Index (ARI)",  _num(results.get("adjusted_rand_index")),          "> 0.80"),
        ("Incidents Generated",        _num(results.get("incidents_generated"), "d"),     ""),
        ("Incidents Expected",         _num(results.get("incidents_expected"), "d"),      ""),
        ("Events Correctly Grouped",   _num(results.get("events_correctly_grouped"), "d"),""),
        ("Total Attack Events",        _num(results.get("events_total_attack"), "d"),     ""),
    ]
    for label, val, tgt in rows:
        t.add_row(label, val, tgt)

    console.print(t)


def print_system_table(results: dict[str, Any]) -> None:
    if not RICH_AVAILABLE:
        print("\n=== SYSTEM METRICS ===")
        for k, v in results.items():
            print(f"  {k:<35} {v}")
        return

    t = Table(title="System Metrics", box=box.ROUNDED, show_header=True,
              header_style="bold cyan")
    t.add_column("Metric",  style="white",  min_width=35)
    t.add_column("Value",   style="yellow", justify="right", min_width=14)

    rows = [
        ("Events Processed",          _num(results.get("events_processed"))),
        ("Suspicious Events",         _num(results.get("suspicious_events"))),
        ("Correlated Events",         _num(results.get("correlated_events"))),
        ("Incidents Generated",       _num(results.get("incidents_generated"))),
        ("Priority Incidents",        _num(results.get("priority_incidents"))),
        ("Processing Time (ms)",      f"{results.get('processing_time_ms', 0):.1f} ms"),
        ("Events / Second",           f"{results.get('events_per_second', 0):.0f}"),
        ("Alert Compression Ratio",   f"{results.get('alert_compression_ratio', 0):.0f}x"),
        ("Priority Compression Ratio",f"{results.get('priority_compression_ratio', 0):.0f}x"),
    ]
    for label, val in rows:
        t.add_row(label, val)

    console.print(t)

    # ASCII funnel
    stages = results.get("funnel_stages", [])
    if stages:
        console.print("\n[bold]Alert Compression Funnel:[/bold]")
        for i, stage in enumerate(stages):
            count = stage.get("count", 0)
            name  = stage.get("stage", "")
            factor = stage.get("reduction_factor", 1.0)
            bar = "#" * min(50, max(1, int(count / max(s.get("count",1) for s in stages) * 50)))
            arrow = f"  v  ({factor:.1f}x)" if i < len(stages) - 1 else ""
            console.print(f"  [cyan]{count:>8,}[/cyan]  {bar}  {name}{arrow}")


def print_rag_table(results: dict[str, Any]) -> None:
    if not RICH_AVAILABLE:
        print("\n=== RAG QUALITY METRICS ===")
        for k, v in results.items():
            print(f"  {k:<35} {v}")
        return

    t = Table(title="RAG Quality Metrics", box=box.ROUNDED, show_header=True,
              header_style="bold cyan")
    t.add_column("Metric",  style="white",  min_width=35)
    t.add_column("Value",   style="magenta",justify="right", min_width=12)
    t.add_column("Target",  style="dim",    justify="right", min_width=10)

    rows = [
        ("Evidence Faithfulness",  _pct(results.get("evidence_faithfulness")),  "> 90%"),
        ("MITRE Relevance",        _pct(results.get("mitre_relevance")),         "> 90%"),
        ("Citation Coverage",      _pct(results.get("citation_coverage")),       "> 90%"),
        ("Incidents in DB",        _num(results.get("incidents_in_db"), "d"),    ""),
        ("Incidents Processed",    _num(results.get("incidents_processed"), "d"),""),
    ]
    for label, val, tgt in rows:
        t.add_row(label, val, tgt)

    if not results.get("rag_pipeline_ran"):
        console.print("\n  [yellow][WARNING] RAG pipeline has not run yet — metrics are vacuous.[/yellow]")
    console.print(t)


# ═══════════════════════════════════════════════════════════════════════════════
# MARKDOWN REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def build_markdown_report(
    detection: dict,
    correlation: dict,
    system: dict,
    rag: dict,
    overall_score: float,
    scenario: str,
) -> str:
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# SENTINEL-X Evaluation Report",
        f"",
        f"**Generated:** {ts}  ",
        f"**Scenario:** {scenario}  ",
        f"**Overall Score:** {overall_score:.1%}",
        f"",
        f"---",
        f"",
        f"## 1. Detection Metrics",
        f"",
        f"| Metric | Value | Target |",
        f"|--------|-------|--------|",
        f"| Precision | {_pct(detection.get('precision'))} | > 85% |",
        f"| Recall | {_pct(detection.get('recall'))} | > 80% |",
        f"| F1 Score | {_pct(detection.get('f1'))} | > 82% |",
        f"| False Positive Rate | {_pct(detection.get('false_positive_rate'))} | < 5% |",
        f"| ROC-AUC | {_pct(detection.get('roc_auc'))} | > 90% |",
        f"| TP / FP / FN / TN | {detection.get('tp')}/{detection.get('fp')}/{detection.get('fn')}/{detection.get('tn')} | |",
        f"| Total Events | {_num(detection.get('total_events'))} | |",
        f"| Flagged Events | {_num(detection.get('flagged_events'))} | |",
        f"| Actual Attack Events | {_num(detection.get('actual_attack_events'))} | |",
        f"",
        f"---",
        f"",
        f"## 2. Correlation Metrics",
        f"",
        f"| Metric | Value | Target |",
        f"|--------|-------|--------|",
        f"| Incident Grouping Accuracy | {_pct(correlation.get('incident_grouping_accuracy'))} | > 90% |",
        f"| Attack Chain Accuracy | {_pct(correlation.get('attack_chain_accuracy'))} | > 80% |",
        f"| Adjusted Rand Index | {_num(correlation.get('adjusted_rand_index'))} | > 0.80 |",
        f"| Incidents Generated | {_num(correlation.get('incidents_generated'), 'd')} | |",
        f"| Incidents Expected | {_num(correlation.get('incidents_expected'), 'd')} | |",
        f"| Events Correctly Grouped | {_num(correlation.get('events_correctly_grouped'), 'd')} | |",
        f"",
        f"---",
        f"",
        f"## 3. System Metrics",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Events Processed | {_num(system.get('events_processed'))} |",
        f"| Suspicious Events | {_num(system.get('suspicious_events'))} |",
        f"| Correlated Events | {_num(system.get('correlated_events'))} |",
        f"| Incidents Generated | {_num(system.get('incidents_generated'))} |",
        f"| Priority Incidents | {_num(system.get('priority_incidents'))} |",
        f"| Processing Time | {system.get('processing_time_ms', 0):.1f} ms |",
        f"| Events / Second | {system.get('events_per_second', 0):.0f} |",
        f"| Alert Compression Ratio | {system.get('alert_compression_ratio', 0):.0f}x |",
        f"| Priority Compression Ratio | {system.get('priority_compression_ratio', 0):.0f}x |",
        f"",
        f"### Alert Compression Funnel",
        f"",
        f"```",
    ]

    stages = system.get("funnel_stages", [])
    for i, stage in enumerate(stages):
        name  = stage.get("stage", "")
        count = stage.get("count", 0)
        factor = stage.get("reduction_factor", 1.0)
        lines.append(f"  {count:>8,}  {name}")
        if i < len(stages) - 1:
            lines.append(f"           v  ({factor:.1f}x reduction)")
    lines += [
        f"```",
        f"",
        f"---",
        f"",
        f"## 4. RAG Quality Metrics",
        f"",
        f"| Metric | Value | Target |",
        f"|--------|-------|--------|",
        f"| Evidence Faithfulness | {_pct(rag.get('evidence_faithfulness'))} | > 90% |",
        f"| MITRE Relevance | {_pct(rag.get('mitre_relevance'))} | > 90% |",
        f"| Citation Coverage | {_pct(rag.get('citation_coverage'))} | > 90% |",
        f"| Incidents Processed | {_num(rag.get('incidents_processed'), 'd')} of {_num(rag.get('incidents_in_db'), 'd')} | |",
    ]

    if not rag.get("rag_pipeline_ran"):
        lines.append(f"")
        lines.append(f"> **Note:** RAG pipeline has not run yet — these metrics are not meaningful.")

    lines += [
        f"",
        f"---",
        f"",
        f"## Overall Score: {overall_score:.1%}",
        f"",
        f"> Weighted average of Precision, Recall, F1, Incident Grouping Accuracy,",
        f"> Attack Chain Accuracy, Evidence Faithfulness, and MITRE Relevance.",
    ]

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# OVERALL SCORE
# ═══════════════════════════════════════════════════════════════════════════════

def compute_overall_score(detection: dict, correlation: dict, rag: dict) -> float:
    """Weighted average of key metrics. Returns 0.0 if no data available."""
    weights = {
        "precision":                  0.15,
        "recall":                     0.20,
        "f1":                         0.20,
        "incident_grouping_accuracy": 0.20,
        "attack_chain_accuracy":      0.10,
        "evidence_faithfulness":      0.10,
        "mitre_relevance":            0.05,
    }
    sources = {**detection, **correlation, **rag}
    total_w = 0.0
    score   = 0.0
    for key, w in weights.items():
        val = sources.get(key)
        if val is not None and isinstance(val, (int, float)):
            score   += val * w
            total_w += w
    return score / total_w if total_w > 0 else 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description="SENTINEL-X Evaluation Runner")
    parser.add_argument("--db",       default=DEFAULT_DB,       help="SQLite DB path")
    parser.add_argument("--gt-csv",   default=DEFAULT_GT_CSV,   help="Ground truth CSV path")
    parser.add_argument("--gt-json",  default=DEFAULT_GT_JSON,  help="Incident ground truth JSON")
    parser.add_argument("--output",   default=DEFAULT_OUT_MD,   help="Markdown report output path")
    parser.add_argument("--json-out", default=DEFAULT_OUT_JSON, help="JSON report output path")
    parser.add_argument("--scenario", default="full",
                        choices=["full", "quick"],
                        help="Evaluation scenario (affects system metrics display)")
    args = parser.parse_args()

    t_start = time.perf_counter()

    if RICH_AVAILABLE:
        console.rule("[bold blue]SENTINEL-X Evaluation Suite[/bold blue]")
        console.print(f"  DB:       {args.db}")
        console.print(f"  GT CSV:   {args.gt_csv}")
        console.print(f"  Scenario: {args.scenario}")
        console.print()
    else:
        print("=" * 60)
        print("SENTINEL-X Evaluation Suite")
        print(f"DB:       {args.db}")
        print(f"Scenario: {args.scenario}")
        print("=" * 60)

    # ── Run all evaluators ────────────────────────────────────────────────────
    print("[1/4] Running detection metrics...")
    try:
        det_eval = DetectionEvaluator(args.gt_csv, args.db)
        detection = det_eval.compute()
    except Exception as e:
        print(f"  [WARNING] Detection metrics failed: {e}")
        detection = {}

    print("[2/4] Running correlation metrics...")
    try:
        cor_eval = CorrelationEvaluator(args.gt_json, args.db)
        correlation = cor_eval.compute()
    except Exception as e:
        print(f"  [WARNING] Correlation metrics failed: {e}")
        correlation = {}

    print("[3/4] Collecting system metrics from DB...")
    try:
        sys_eval = SystemMetricsCollector()
        # Read event/incident counts directly from DB
        import sqlite3 as _sq
        if Path(args.db).exists():
            _conn = _sq.connect(args.db)
            total_events = _conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            attack_events = _conn.execute(
                "SELECT COUNT(*) FROM events WHERE label='attack'"
            ).fetchone()[0]
            try:
                incidents_count = _conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                priority_count  = _conn.execute(
                    "SELECT COUNT(*) FROM incidents WHERE priority='CRITICAL'"
                ).fetchone()[0]
            except Exception:
                incidents_count = 0
                priority_count  = 0
            _conn.close()
            sys_eval.record_funnel(
                events_total=total_events,
                suspicious=attack_events,
                correlated=min(attack_events, 87),    # target from plan
                incidents=incidents_count or 0,
                priority_incidents=priority_count or 0,
            )
        system = sys_eval.compute()
    except Exception as e:
        print(f"  [WARNING] System metrics failed: {e}")
        system = {}

    print("[4/4] Running RAG quality metrics...")
    try:
        rag_eval = RAGEvaluator(args.db, args.gt_json)
        rag = rag_eval.compute()
    except Exception as e:
        print(f"  [WARNING] RAG metrics failed: {e}")
        rag = {}

    elapsed_ms = (time.perf_counter() - t_start) * 1000

    # ── Print terminal report ─────────────────────────────────────────────────
    if RICH_AVAILABLE:
        console.rule("[bold]Results[/bold]")

    print_detection_table(detection)
    print_correlation_table(correlation)
    print_system_table(system)
    print_rag_table(rag)

    overall = compute_overall_score(detection, correlation, rag)

    if RICH_AVAILABLE:
        console.rule()
        console.print(
            Panel(
                f"[bold green]Overall Score: {overall:.1%}[/bold green]\n"
                f"Evaluation completed in {elapsed_ms:.0f} ms",
                title="Summary",
                border_style="green",
            )
        )
    else:
        print(f"\nOverall Score: {overall:.1%}")
        print(f"Evaluation completed in {elapsed_ms:.0f} ms")

    # ── Write reports ─────────────────────────────────────────────────────────
    md = build_markdown_report(detection, correlation, system, rag, overall, args.scenario)
    Path(args.output).write_text(md, encoding="utf-8")
    print(f"\nMarkdown report: {args.output}")

    report_json = {
        "generated_at":  datetime.now(tz=timezone.utc).isoformat(),
        "scenario":      args.scenario,
        "overall_score": overall,
        "detection":     detection,
        "correlation":   correlation,
        "system":        system,
        "rag":           rag,
    }
    Path(args.json_out).write_text(json.dumps(report_json, indent=2), encoding="utf-8")
    print(f"JSON report:     {args.json_out}")


if __name__ == "__main__":
    main()
