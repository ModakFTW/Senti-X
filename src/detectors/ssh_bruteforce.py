"""SSH Brute-Force Detector — single-record and sequence modes."""
from __future__ import annotations
from collections import defaultdict
from ..models.log_models import SSHLog
from ..models.alert_models import Alert, AlertType, Severity

WINDOW_SECONDS: int = 300
MIN_ATTEMPTS_SINGLE: int = 5
MIN_FAILURES_SEQUENCE: int = 3


def detect(ssh_logs: list[SSHLog]) -> list[Alert]:
    alerts: list[Alert] = []
    fired_ips: set[str] = set()
    groups: dict[str, list[SSHLog]] = defaultdict(list)
    for log in ssh_logs:
        groups[log.orig_h].append(log)

    for orig_h, logs in groups.items():
        if orig_h in fired_ips:
            continue
        logs.sort(key=lambda x: x.ts)

        # Mode 1 — single record with high attempt count
        for log in logs:
            if log.auth_attempts and log.auth_attempts > MIN_ATTEMPTS_SINGLE:
                severity = Severity.CRITICAL if log.auth_success else Severity.HIGH
                alerts.append(Alert(
                    alert_type=AlertType.SSH_BRUTE_FORCE,
                    severity=severity,
                    src_ip=orig_h,
                    dst_ip=log.resp_h,
                    dst_port=log.resp_p,
                    timestamp=log.ts,
                    description=(
                        f"SSH brute force from {orig_h}: "
                        f"{log.auth_attempts} attempts, success={log.auth_success}"
                    ),
                    evidence={
                        "mode": "single_record",
                        "auth_attempts": log.auth_attempts,
                        "auth_success": bool(log.auth_success),
                    },
                ))
                fired_ips.add(orig_h)
                break

        if orig_h in fired_ips:
            continue

        # Mode 2 — failures then success within window
        for anchor in logs:
            window_end = anchor.ts + WINDOW_SECONDS
            window = [l for l in logs if anchor.ts <= l.ts <= window_end]
            failures = [l for l in window if not l.auth_success]
            successes = [l for l in window if l.auth_success]
            if len(failures) >= MIN_FAILURES_SEQUENCE and successes:
                last = window[-1]
                alerts.append(Alert(
                    alert_type=AlertType.SSH_BRUTE_FORCE,
                    severity=Severity.CRITICAL,
                    src_ip=orig_h,
                    dst_ip=last.resp_h,
                    dst_port=last.resp_p,
                    timestamp=anchor.ts,
                    description=(
                        f"SSH brute force with successful login from {orig_h}: "
                        f"{len(failures)} failures then access granted"
                    ),
                    evidence={
                        "mode": "sequence",
                        "failed_attempts": len(failures),
                        "auth_success": True,
                        "window_start_ts": anchor.ts,
                        "window_end_ts": last.ts,
                    },
                ))
                fired_ips.add(orig_h)
                break
    return alerts
