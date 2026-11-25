"""
CAIP Experiment Runner Utilities
===================================
Shared data loading, result reporting, and output utilities
used by all 6 IEEE experiments.
"""

import csv
import json
import os
import time
from collections import defaultdict
from datetime import datetime

DATASETS_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "datasets"))
RESULTS_DIR  = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "results"))


def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def load_campaigns_from_csv(filename: str) -> dict[str, list[dict]]:
    """
    Load a campaign CSV and return {campaign_id: [event_dicts]}.
    Works with caip_attack_dataset.csv, caip_validation_set.csv, caip_cicids_dataset.csv.
    """
    path = os.path.join(DATASETS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}")

    campaigns = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["severity"] = int(row.get("severity", 50))
            row["label"] = 1  # all dataset events are malicious
            campaigns[row["campaign_id"]].append(row)

    return dict(campaigns)


def load_all_datasets() -> tuple[dict, dict, dict]:
    """Load train, val, and CICIDS datasets."""
    train  = load_campaigns_from_csv("caip_attack_dataset.csv")
    val    = load_campaigns_from_csv("caip_validation_set.csv")
    try:
        cicids = load_campaigns_from_csv("caip_cicids_dataset.csv")
    except FileNotFoundError:
        cicids = {}
    return train, val, cicids


def flatten_events(campaigns: dict[str, list[dict]], label: int = 1) -> list[dict]:
    """Flatten campaign dict into event list, adding label."""
    events = []
    for cid, evts in campaigns.items():
        for e in evts:
            e = dict(e)
            e["label"] = label
            e["campaign_id"] = cid
            events.append(e)
    return events


def get_campaign_type(events: list[dict]) -> str:
    """Infer campaign type from events (uses campaign_type field if present)."""
    for e in events:
        if e.get("campaign_type"):
            return e["campaign_type"]
    # Fallback: infer from event types
    etypes = {e.get("event_type", "").lower() for e in events}
    if "ransomware_encrypt" in etypes: return "ransomware"
    if "exfil_https" in etypes or "exfil_ftp" in etypes: return "apt_exfiltration"
    if "dos_flood" in etypes or "ddos_flood" in etypes: return "dos_ddos"
    return "unknown"


def get_next_stage_label(events: list[dict]) -> str:
    """Get the ground-truth next stage label for a campaign."""
    for e in events:
        if e.get("next_stage_label"):
            return e["next_stage_label"]
    return "Unknown"


def get_ordered_stages(events: list[dict]) -> list[str]:
    """Return deduplicated MITRE stages in order of first occurrence."""
    stage_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command & Control", "Exfiltration", "Impact",
    ]
    seen, stages = set(), []
    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
    for e in sorted_events:
        s = e.get("mitre_stage", "")
        if s and s not in seen:
            seen.add(s)
            stages.append(s)
    stages.sort(key=lambda s: stage_order.index(s) if s in stage_order else 99)
    return stages


def compute_risk_score(events: list[dict]) -> int:
    """Lightweight risk score (mirrors RiskEngine logic, no ORM dependency)."""
    if not events:
        return 0
    sevs = [int(e.get("severity", 50)) for e in events]
    max_sev = max(sevs)
    boost = min(len(events) * 2.5, 20)
    crit = 0
    for e in events:
        if e.get("event_type", "").lower() in ["powershell", "credential_login", "brute_force"]:
            crit += 5
    crit = min(crit, 15)
    return min(int(max_sev + boost + crit), 100)


def save_result(experiment_name: str, result: dict):
    """Save experiment result as JSON to results/ directory."""
    ensure_results_dir()
    path = os.path.join(RESULTS_DIR, f"{experiment_name}.json")
    result["timestamp"] = datetime.utcnow().isoformat()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"  [Saved] {path}")
    return path


def load_result(experiment_name: str) -> dict:
    """Load a previously saved experiment result."""
    path = os.path.join(RESULTS_DIR, f"{experiment_name}.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def timeit(fn):
    """Measure wall-clock time in milliseconds."""
    start = time.perf_counter()
    result = fn()
    elapsed_ms = (time.perf_counter() - start) * 1000
    return result, elapsed_ms


class ExperimentTimer:
    """Context manager for timing experiment sections."""
    def __init__(self, label: str):
        self.label = label
        self.elapsed_ms = 0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000
