"""
system_metrics.py -- SENTINEL-X System Metrics Collector
=========================================================
Tracks operational pipeline performance: throughput, processing latency,
and alert compression across the full detection funnel.

Funnel stages (in order)
-------------------------
Raw Events -> Suspicious Events -> Correlated Events -> Incidents -> Priority Incidents

Metrics produced
----------------
- events_processed           : total events fed into the pipeline
- suspicious_events          : events flagged by detectors
- correlated_events          : events grouped into an incident
- incidents_generated        : number of incidents created
- priority_incidents         : high/critical priority incidents
- processing_time_ms         : wall-clock time (ms) between start/stop
- events_per_second          : throughput
- alert_compression_ratio    : events_processed / incidents_generated
- priority_compression_ratio : events_processed / priority_incidents
- funnel_stages              : list of per-stage dicts with reduction factors
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

try:
    from rich.console import Console
    from rich.table import Table
    _RICH = True
except ImportError:
    _RICH = False


# ---------------------------------------------------------------------------
# ASCII-art funnel renderer
# ---------------------------------------------------------------------------

_FUNNEL_TMPL = (
    "  +---------------------------------------------------+\n"
    "  |  {stage0:<27}  {count0:>8} events |\n"
    "  +------------------+--------------------------------+\n"
    "                     |  v  {rf1:.1f}x reduction\n"
    "            +--------+----------------------------+\n"
    "            |  {stage1:<24}  {count1:>8} events |\n"
    "            +--------+----------------------------+\n"
    "                     |  v  {rf2:.1f}x reduction\n"
    "          +----------+------------------------+\n"
    "          |  {stage2:<22}  {count2:>8} events |\n"
    "          +----------+------------------------+\n"
    "                     |  v  {rf3:.1f}x reduction\n"
    "         +-----------+---------------------+\n"
    "         |  {stage3:<18}  {count3:>8}        |\n"
    "         +-----------+---------------------+\n"
    "                     |  v  {rf4:.1f}x reduction\n"
    "        +------------+--------------------+\n"
    "        |  {stage4:<18}  {count4:>8}        |\n"
    "        +-----------------------------------+\n"
)


def _render_funnel(stages: list[dict]) -> str:
    """Render the 5-stage funnel as an ASCII-art string."""
    s  = stages
    rf = [st["reduction_factor"] for st in s]
    return _FUNNEL_TMPL.format(
        stage0=s[0]["stage"], count0=s[0]["count"],
        stage1=s[1]["stage"], count1=s[1]["count"], rf1=rf[1],
        stage2=s[2]["stage"], count2=s[2]["count"], rf2=rf[2],
        stage3=s[3]["stage"], count3=s[3]["count"], rf3=rf[3],
        stage4=s[4]["stage"], count4=s[4]["count"], rf4=rf[4],
    )


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class SystemMetricsCollector:
    """Collects and reports operational metrics for the SENTINEL-X pipeline.

    Typical usage::

        collector = SystemMetricsCollector()
        with collector.timer():
            run_pipeline(...)
        collector.record_funnel(
            events_total=10_000,
            suspicious=800,
            correlated=320,
            incidents=45,
            priority_incidents=12,
        )
        collector.print_report()
    """

    def __init__(self) -> None:
        self._start_ns: int | None = None
        self._stop_ns:  int | None = None
        self._processing_time_ms: float = 0.0

        self._events_processed:    int = 0
        self._suspicious_events:   int = 0
        self._correlated_events:   int = 0
        self._incidents_generated: int = 0
        self._priority_incidents:  int = 0

    # ------------------------------------------------------------------
    # Timer helpers
    # ------------------------------------------------------------------

    def start_timer(self) -> None:
        """Start the wall-clock timer."""
        self._start_ns = time.perf_counter_ns()

    def stop_timer(self) -> None:
        """Stop the wall-clock timer and record elapsed milliseconds."""
        if self._start_ns is None:
            raise RuntimeError("start_timer() must be called before stop_timer().")
        self._stop_ns = time.perf_counter_ns()
        elapsed_ns = self._stop_ns - self._start_ns
        self._processing_time_ms = elapsed_ns / 1_000_000.0

    @contextmanager
    def timer(self) -> Generator[None, None, None]:
        """Context manager that wraps start_timer / stop_timer.

        Example::

            with collector.timer():
                do_work()
        """
        self.start_timer()
        try:
            yield
        finally:
            self.stop_timer()

    # ------------------------------------------------------------------
    # Funnel recording
    # ------------------------------------------------------------------

    def record_funnel(
        self,
        events_total: int,
        suspicious: int,
        correlated: int,
        incidents: int,
        priority_incidents: int,
    ) -> None:
        """Record a single pass of the detection funnel.

        Parameters
        ----------
        events_total:
            Total raw events ingested.
        suspicious:
            Events flagged as suspicious by detection rules.
        correlated:
            Events successfully correlated into an incident.
        incidents:
            Number of distinct incidents created.
        priority_incidents:
            Number of high/critical priority incidents.
        """
        self._events_processed    = events_total
        self._suspicious_events   = suspicious
        self._correlated_events   = correlated
        self._incidents_generated = incidents
        self._priority_incidents  = priority_incidents

    # ------------------------------------------------------------------
    # Compute
    # ------------------------------------------------------------------

    def compute(self) -> dict[str, Any]:
        """Compute all system metrics."""
        ms  = self._processing_time_ms
        eps = (self._events_processed / (ms / 1000.0)) if ms > 0 else 0.0

        acr = (
            self._events_processed / self._incidents_generated
            if self._incidents_generated > 0 else 0.0
        )
        pcr = (
            self._events_processed / self._priority_incidents
            if self._priority_incidents > 0 else 0.0
        )

        def _rf(numerator: int) -> float:
            return (
                round(self._events_processed / numerator, 2)
                if numerator > 0 else 0.0
            )

        funnel_stages = [
            {"stage": "Raw Events",        "count": self._events_processed,    "reduction_factor": 1.0},
            {"stage": "Suspicious Events", "count": self._suspicious_events,   "reduction_factor": _rf(self._suspicious_events)},
            {"stage": "Correlated Events", "count": self._correlated_events,   "reduction_factor": _rf(self._correlated_events)},
            {"stage": "Incidents",         "count": self._incidents_generated, "reduction_factor": _rf(self._incidents_generated)},
            {"stage": "Priority Incidents","count": self._priority_incidents,  "reduction_factor": _rf(self._priority_incidents)},
        ]

        return {
            "events_processed":           self._events_processed,
            "suspicious_events":          self._suspicious_events,
            "correlated_events":          self._correlated_events,
            "incidents_generated":        self._incidents_generated,
            "priority_incidents":         self._priority_incidents,
            "processing_time_ms":         round(ms, 3),
            "events_per_second":          round(eps, 2),
            "alert_compression_ratio":    round(acr, 2),
            "priority_compression_ratio": round(pcr, 2),
            "funnel_stages":              funnel_stages,
        }

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def print_report(self) -> None:
        """Print system metrics and ASCII-art funnel to stdout."""
        metrics = self.compute()

        if _RICH:
            console = Console()
            table = Table(
                title="[bold cyan]SENTINEL-X -- System Metrics[/bold cyan]",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Metric", style="cyan", min_width=30)
            table.add_column("Value", justify="right", min_width=14)

            scalar_rows = [
                ("Events Processed",            str(metrics["events_processed"])),
                ("Suspicious Events",           str(metrics["suspicious_events"])),
                ("Correlated Events",           str(metrics["correlated_events"])),
                ("Incidents Generated",         str(metrics["incidents_generated"])),
                ("Priority Incidents",          str(metrics["priority_incidents"])),
                ("---",                         "---"),
                ("Processing Time (ms)",        f"{metrics['processing_time_ms']:.3f}"),
                ("Events / Second",             f"{metrics['events_per_second']:.2f}"),
                ("Alert Compression Ratio",     f"{metrics['alert_compression_ratio']:.2f}x"),
                ("Priority Compression Ratio",  f"{metrics['priority_compression_ratio']:.2f}x"),
            ]
            for label, value in scalar_rows:
                table.add_row(label, value)

            console.print(table)
            console.print("\n[bold cyan]Alert Funnel Visualization[/bold cyan]\n")
            console.print(_render_funnel(metrics["funnel_stages"]))
        else:
            print("\n=== SENTINEL-X -- System Metrics ===")
            for key, val in metrics.items():
                if key != "funnel_stages":
                    print(f"  {key:<33}: {val}")
            print()
            print(_render_funnel(metrics["funnel_stages"]))


# ---------------------------------------------------------------------------
# Module self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    collector = SystemMetricsCollector()

    with collector.timer():
        time.sleep(0.05)

    collector.record_funnel(
        events_total=50_000,
        suspicious=3_200,
        correlated=1_100,
        incidents=78,
        priority_incidents=18,
    )

    collector.print_report()