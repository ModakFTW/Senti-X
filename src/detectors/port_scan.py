"""Port Scan Detector — sliding-window, one alert per (src, dst) pair."""
from __future__ import annotations
from collections import defaultdict
from ..models.log_models import ConnLog
from ..models.alert_models import Alert, AlertType, Severity

WINDOW_SECONDS: int = 60
MIN_PORTS: int = 20
HIGH_PORTS: int = 50


def detect(conn_logs: list[ConnLog]) -> list[Alert]:
    alerts: list[Alert] = []
    groups: dict[tuple[str, str], list[ConnLog]] = defaultdict(list)
    for log in conn_logs:
        groups[(log.orig_h, log.resp_h)].append(log)

    for (orig_h, resp_h), logs in groups.items():
        logs.sort(key=lambda x: x.ts)
        start = 0
        for end in range(len(logs)):
            while logs[end].ts - logs[start].ts > WINDOW_SECONDS:
                start += 1
            window = logs[start: end + 1]
            distinct_ports: set[int] = {l.resp_p for l in window}
            if len(distinct_ports) >= MIN_PORTS:
                severity = Severity.HIGH if len(distinct_ports) >= HIGH_PORTS else Severity.MEDIUM
                alerts.append(Alert(
                    alert_type=AlertType.PORT_SCAN,
                    severity=severity,
                    src_ip=orig_h,
                    dst_ip=resp_h,
                    timestamp=logs[start].ts,
                    description=(
                        f"Port scan: {orig_h} probed {len(distinct_ports)} distinct "
                        f"ports on {resp_h} within {WINDOW_SECONDS}s"
                    ),
                    evidence={
                        "distinct_ports_count": len(distinct_ports),
                        "sampled_ports": sorted(distinct_ports)[:10],
                        "window_start_ts": logs[start].ts,
                        "window_end_ts": logs[end].ts,
                        "connection_count": len(window),
                    },
                ))
                break  # one alert per pair
    return alerts
