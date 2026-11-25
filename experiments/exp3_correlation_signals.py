"""
Experiment 3: Correlation Signal Ablation Study
================================================
Research question: How much does each correlation signal contribute to
correct campaign grouping?

CAIP currently uses 4 correlation signals:
  1. Same user (U)
  2. Same device_id (D)
  3. Same source_ip (I)
  4. Same domain (N)

We test 4 progressively richer configurations:
  Test 1: User only
  Test 2: User + Device
  Test 3: User + Device + IP
  Test 4: User + Device + IP + Domain

METRICS:
  - Grouping Precision: of event pairs we grouped together, how many
    are truly from the same campaign?
  - Grouping Recall: of event pairs that should be grouped, how many
    did we find?
  - Grouping F1: harmonic mean
  - False Merges: events from different campaigns incorrectly grouped
  - Missed Links: events from the same campaign not linked

IEEE CONTRIBUTION:
  "We show that multi-signal correlation (all 4 signals) achieves X%
   grouping F1, compared to Y% for single-signal (user-only) correlation,
   demonstrating the importance of entity-level context in campaign detection."
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import random
import numpy as np
from collections import defaultdict

from shared.metrics import grouping_metrics, print_table
from shared.experiment_runner import load_campaigns_from_csv, save_result, ExperimentTimer

random.seed(2024)

DATASETS_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "datasets"))


def enrich_events_with_device(campaigns: dict) -> dict:
    """
    Add synthetic device_id to events (derived from user assignment).
    Each user maps to 1-2 devices (realistic: shared workstations).
    """
    user_to_device = {}
    enriched = {}

    for cid, events in campaigns.items():
        enriched_events = []
        for e in events:
            e = dict(e)
            user = e.get("user", "unknown")
            if user not in user_to_device:
                # Assign 1 or 2 devices per user
                n_devices = random.choice([1, 1, 2])
                user_to_device[user] = [
                    f"WKSTN-{random.randint(1, 30):03d}"
                    for _ in range(n_devices)
                ]
            e["device_id"] = random.choice(user_to_device[user])
            enriched_events.append(e)
        enriched[cid] = enriched_events

    return enriched


def correlate_by_signals(
    campaigns: dict,
    use_user: bool = True,
    use_device: bool = False,
    use_ip: bool = False,
    use_domain: bool = False,
    time_window_minutes: int = 360,
) -> dict:
    """
    Simulate campaign correlation using the specified signals.
    Returns predicted_groups: {group_id: set(event_ids)}

    Strategy: greedy merging — each new event joins the first existing
    group that shares at least one signal with it.
    """
    groups = {}         # group_id -> list of events
    event_to_group = {} # event_id -> group_id
    group_counter = [0]

    def get_signals(event: dict) -> set:
        signals = set()
        if use_user and event.get("user"):
            signals.add(("user", event["user"]))
        if use_device and event.get("device_id"):
            signals.add(("device", event["device_id"]))
        if use_ip and event.get("source_ip"):
            signals.add(("ip", event["source_ip"]))
        if use_domain and event.get("domain"):
            signals.add(("domain", event["domain"]))
        return signals

    # Flatten and sort by timestamp
    all_events = []
    for cid, events in campaigns.items():
        for e in events:
            all_events.append(dict(e))
    all_events.sort(key=lambda e: e.get("timestamp", ""))

    # Build group signal index: signal → group_id set
    signal_to_groups = defaultdict(set)

    for event in all_events:
        eid = event.get("event_id", id(event))
        new_signals = get_signals(event)

        # Find matching groups (share at least one signal)
        candidate_groups = set()
        for sig in new_signals:
            candidate_groups |= signal_to_groups.get(sig, set())

        if candidate_groups:
            # Join the most recently active group
            target_gid = max(candidate_groups)
        else:
            # Start new group
            group_counter[0] += 1
            target_gid = group_counter[0]
            groups[target_gid] = []

        # Add event to group
        if target_gid not in groups:
            groups[target_gid] = []
        groups[target_gid].append(eid)
        event_to_group[eid] = target_gid

        # Update signal index
        for sig in new_signals:
            signal_to_groups[sig].add(target_gid)

    return {gid: set(eids) for gid, eids in groups.items()}


def build_true_groups(campaigns: dict) -> dict:
    """Build ground-truth grouping from campaign assignments."""
    return {
        cid: {e.get("event_id", f"{cid}_{i}") for i, e in enumerate(events)}
        for cid, events in campaigns.items()
    }


def run_experiment():
    print("\n" + "=" * 65)
    print("  EXPERIMENT 3: Correlation Signal Ablation")
    print("=" * 65)

    print("\n[1/3] Loading validation data...")
    val_campaigns = load_campaigns_from_csv("caip_validation_set.csv")

    # Also test on CICIDS dataset for external validity
    try:
        cicids_campaigns = load_campaigns_from_csv("caip_cicids_dataset.csv")
        use_cicids = True
    except FileNotFoundError:
        use_cicids = False

    # Enrich with device_id (synthetic, reproducible)
    val_enriched = enrich_events_with_device(val_campaigns)
    print(f"      Validation campaigns: {len(val_enriched)}")
    if use_cicids:
        cicids_enriched = enrich_events_with_device(cicids_campaigns)
        print(f"      CICIDS campaigns:     {len(cicids_enriched)}")

    print("\n[2/3] Running 4 signal configurations...")

    # Ground truth
    val_true_groups = build_true_groups(val_enriched)

    configurations = [
        ("User only",              dict(use_user=True, use_device=False, use_ip=False, use_domain=False)),
        ("User + Device",          dict(use_user=True, use_device=True,  use_ip=False, use_domain=False)),
        ("User + Device + IP",     dict(use_user=True, use_device=True,  use_ip=True,  use_domain=False)),
        ("All 4 Signals",          dict(use_user=True, use_device=True,  use_ip=True,  use_domain=True)),
    ]

    val_results = {}
    cicids_results = {}

    for name, kwargs in configurations:
        with ExperimentTimer(name) as t:
            pred_groups = correlate_by_signals(val_enriched, **kwargs)
        metrics = grouping_metrics(val_true_groups, pred_groups)
        val_results[name] = {**metrics, "time_ms": round(t.elapsed_ms, 2)}

        if use_cicids:
            cicids_true = build_true_groups(cicids_enriched)
            pred_cicids  = correlate_by_signals(cicids_enriched, **kwargs)
            cicids_results[name] = grouping_metrics(cicids_true, pred_cicids)

        print(f"      {name}: F1={metrics['grouping_f1']:.4f}, "
              f"Precision={metrics['grouping_precision']:.4f}, "
              f"Recall={metrics['grouping_recall']:.4f}")

    # ── Print table ────────────────────────────────────────────────────────────
    print("\n[3/3] Results:")

    rows = []
    for name, m in val_results.items():
        rows.append([
            name,
            m["grouping_f1"],
            m["grouping_precision"],
            m["grouping_recall"],
            m["false_merges"],
            m["missed_links"],
        ])

    print_table(
        "Experiment 3: Correlation Signal Ablation (Validation Set)",
        rows,
        ["Configuration", "Grouping F1", "Precision", "Recall", "False Merges", "Missed Links"],
    )

    if cicids_results:
        cicids_rows = []
        for name, m in cicids_results.items():
            cicids_rows.append([name, m["grouping_f1"], m["grouping_precision"],
                                 m["grouping_recall"], m["false_merges"]])
        print_table(
            "Experiment 3: Correlation Signal Ablation (CICIDS2017 Set)",
            cicids_rows,
            ["Configuration", "Grouping F1", "Precision", "Recall", "False Merges"],
        )

    result = {
        "experiment":       "exp3_correlation_signals",
        "validation_set":   val_results,
        "cicids_set":       cicids_results,
        "n_val_campaigns":  len(val_enriched),
        "n_cicids":         len(cicids_campaigns) if use_cicids else 0,
    }
    save_result("exp3_results", result)
    return result


if __name__ == "__main__":
    run_experiment()
