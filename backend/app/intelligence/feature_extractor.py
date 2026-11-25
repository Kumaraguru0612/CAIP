"""
Temporal Feature Extractor
==========================
Converts a list of campaign events (either DB rows or CSV dicts) into a
rich feature vector combining temporal, severity, entity-diversity, and
MITRE-stage signals.
"""

from datetime import datetime
from typing import Any


STAGE_FLAGS = [
    ("has_initial_access",    {"Initial Access"}),
    ("has_execution",         {"Execution"}),
    ("has_persistence",       {"Persistence"}),
    ("has_privilege_esc",     {"Privilege Escalation"}),
    ("has_defense_evasion",   {"Defense Evasion"}),
    ("has_cred_access",       {"Credential Access"}),
    ("has_discovery",         {"Discovery"}),
    ("has_lateral",           {"Lateral Movement"}),
    ("has_collection",        {"Collection"}),
    ("has_c2",                {"Command & Control"}),
    ("has_exfiltration",      {"Exfiltration"}),
    ("has_impact",            {"Impact"}),
]


def _to_dt(ts: Any) -> datetime:
    """Coerce timestamp to datetime (handles string ISO and datetime objects)."""
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
    raise ValueError(f"Cannot parse timestamp: {ts!r}")


def extract_features(events: list[Any]) -> dict:
    """
    Parameters
    ----------
    events : list of DB Event objects OR list of dicts (from CSV rows)
             Must have fields: timestamp, severity, mitre_stage,
             mitre_technique, user, source_ip, domain

    Returns
    -------
    dict of feature_name -> numeric value
    """
    if not events:
        return {}

    def _get(ev, key):
        if isinstance(ev, dict):
            return ev.get(key)
        return getattr(ev, key, None)

    # ── Sort by timestamp ──────────────────────────────────────────────────
    sorted_evs = sorted(events, key=lambda e: _to_dt(_get(e, "timestamp")))
    timestamps = [_to_dt(_get(e, "timestamp")) for e in sorted_evs]
    severities = [int(_get(e, "severity") or 0) for e in sorted_evs]
    stages     = [(_get(e, "mitre_stage") or "").strip() for e in sorted_evs]
    techniques = [(_get(e, "mitre_technique") or "").strip() for e in sorted_evs]
    users      = [_get(e, "user") or "" for e in sorted_evs]
    ips        = [_get(e, "source_ip") or "" for e in sorted_evs]
    domains    = [_get(e, "domain") or "" for e in sorted_evs]

    n = len(sorted_evs)

    # ── Temporal deltas ────────────────────────────────────────────────────
    deltas_min = []
    for i in range(1, n):
        diff = (timestamps[i] - timestamps[i - 1]).total_seconds() / 60.0
        deltas_min.append(max(diff, 0.0))

    avg_delta       = sum(deltas_min) / len(deltas_min) if deltas_min else 0.0
    min_delta       = min(deltas_min) if deltas_min else 0.0
    max_delta       = max(deltas_min) if deltas_min else 0.0
    total_span_min  = (timestamps[-1] - timestamps[0]).total_seconds() / 60.0 if n > 1 else 0.0
    events_per_min  = n / total_span_min if total_span_min > 0 else float(n)

    # ── Severity stats ─────────────────────────────────────────────────────
    avg_sev = sum(severities) / n
    max_sev = max(severities)

    # ── Diversity stats ────────────────────────────────────────────────────
    unique_stages     = len(set(s for s in stages if s))
    unique_techniques = len(set(t for t in techniques if t))
    unique_users      = len(set(u for u in users if u))
    unique_ips        = len(set(ip for ip in ips if ip))
    unique_domains    = len(set(d for d in domains if d))

    # ── Stage flag vector ──────────────────────────────────────────────────
    stage_set = set(stages)
    flag_feats = {name: int(bool(stage_set & values)) for name, values in STAGE_FLAGS}

    # ── Stage transition time (between stage boundaries) ──────────────────
    stage_seq = []
    for i, st in enumerate(stages):
        if not stage_seq or stage_seq[-1][0] != st:
            stage_seq.append((st, i))

    stage_transition_times = []
    for i in range(1, len(stage_seq)):
        _, prev_idx = stage_seq[i - 1]
        _, curr_idx = stage_seq[i]
        dt = (timestamps[curr_idx] - timestamps[prev_idx]).total_seconds() / 60.0
        stage_transition_times.append(dt)

    avg_stage_transition = (
        sum(stage_transition_times) / len(stage_transition_times)
        if stage_transition_times else 0.0
    )
    longest_stage_gap = max(stage_transition_times) if stage_transition_times else 0.0

    features = {
        # Counts
        "num_events":              n,
        "unique_stages":           unique_stages,
        "unique_techniques":       unique_techniques,
        "unique_users":            unique_users,
        "unique_ips":              unique_ips,
        "unique_domains":          unique_domains,
        # Severity
        "avg_severity":            round(avg_sev, 2),
        "max_severity":            max_sev,
        # Temporal
        "avg_time_delta_min":      round(avg_delta, 2),
        "min_time_delta_min":      round(min_delta, 2),
        "max_time_delta_min":      round(max_delta, 2),
        "total_span_min":          round(total_span_min, 2),
        "events_per_minute":       round(events_per_min, 4),
        "avg_stage_transition_min":round(avg_stage_transition, 2),
        "longest_stage_gap_min":   round(longest_stage_gap, 2),
    }
    features.update(flag_feats)
    return features
