"""Incident Correlator — groups alerts by IP + time window into Incidents."""
from __future__ import annotations
from collections import defaultdict
from ..models.alert_models import Alert, AlertType, Incident, IncidentType, Severity

CORRELATION_WINDOW: int = 300
_SEV = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _bump(s: Severity) -> Severity:
    return _SEV[min(_SEV.index(s) + 1, 3)]


def _max_sev(sevs: list[Severity]) -> Severity:
    return max(sevs, key=lambda s: _SEV.index(s))


def correlate(alerts: list[Alert]) -> list[Incident]:
    if not alerts:
        return []
    incidents: list[Incident] = []
    groups: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        groups[a.src_ip].append(a)

    for src_ip, src_alerts in groups.items():
        src_alerts.sort(key=lambda a: a.timestamp)
        clusters: list[list[Alert]] = []
        cur = [src_alerts[0]]
        for a in src_alerts[1:]:
            if a.timestamp - cur[0].timestamp <= CORRELATION_WINDOW:
                cur.append(a)
            else:
                clusters.append(cur)
                cur = [a]
        clusters.append(cur)

        for cluster in clusters:
            types: set[AlertType] = {a.alert_type for a in cluster}
            max_s = _max_sev([a.severity for a in cluster])

            if AlertType.PORT_SCAN in types and AlertType.SSH_BRUTE_FORCE in types:
                itype = IncidentType.RECON_AND_INTRUSION
                max_s = _bump(max_s)
                title = f"Recon & Intrusion from {src_ip}"
                summary = (
                    f"Attacker {src_ip} performed port scan then SSH brute-force "
                    f"({len(cluster)} alerts: {', '.join(sorted(t.value for t in types))})."
                )
            elif len(types) >= 3:
                itype = IncidentType.MULTI_STAGE_ATTACK
                max_s = _bump(max_s)
                title = f"Multi-Stage Attack from {src_ip}"
                summary = (
                    f"Attacker {src_ip} used {len(types)} techniques "
                    f"({', '.join(sorted(t.value for t in types))}) across {len(cluster)} alerts."
                )
            else:
                itype = IncidentType.SINGLE_THREAT
                label = next(iter(types)).value.replace("_", " ").title()
                title = f"{label} from {src_ip}"
                summary = f"Single threat from {src_ip}: {next(iter(types)).value} — {len(cluster)} alert(s)."

            incidents.append(Incident(
                incident_type=itype,
                title=title,
                severity=max_s,
                src_ip=src_ip,
                first_seen=cluster[0].timestamp,
                last_seen=cluster[-1].timestamp,
                alert_ids=[a.alert_id for a in cluster],
                summary=summary,
            ))
    return incidents
