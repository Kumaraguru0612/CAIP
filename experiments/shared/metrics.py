"""
CAIP Experiment Shared Metrics
================================
All metric calculations used across the 6 IEEE experiments.
No external ML libraries needed — pure numpy + sklearn.
"""

from typing import Any
import numpy as np
from collections import defaultdict
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)


# ── Core classification metrics ───────────────────────────────────────────────

def binary_metrics(y_true: list, y_pred: list, pos_label=1) -> dict:
    """
    Returns precision, recall, F1, FPR, TPR, FNR for binary predictions.
    y_true and y_pred should be lists of 0/1 integers.
    """
    yt = np.array(y_true, dtype=int)
    yp = np.array(y_pred, dtype=int)

    tp = int(np.sum((yp == 1) & (yt == 1)))
    tn = int(np.sum((yp == 0) & (yt == 0)))
    fp = int(np.sum((yp == 1) & (yt == 0)))
    fn = int(np.sum((yp == 0) & (yt == 1)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr       = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    accuracy  = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    return {
        "precision":   round(precision, 4),
        "recall":      round(recall, 4),
        "f1":          round(f1, 4),
        "fpr":         round(fpr, 4),
        "fnr":         round(fnr, 4),
        "accuracy":    round(accuracy, 4),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }


def multiclass_metrics(y_true: list, y_pred: list, labels: list) -> dict:
    """Precision/Recall/F1 for multiclass, weighted average."""
    yt = np.array(y_true)
    yp = np.array(y_pred)
    return {
        "precision": round(float(precision_score(yt, yp, average="weighted", zero_division=0)), 4),
        "recall":    round(float(recall_score(yt, yp, average="weighted", zero_division=0)), 4),
        "f1":        round(float(f1_score(yt, yp, average="weighted", zero_division=0)), 4),
    }


# ── Alert reduction ───────────────────────────────────────────────────────────

def alert_reduction_metrics(
    baseline_alerts: int,
    caip_campaigns: int,
    total_events: int,
    true_campaigns: int,
) -> dict:
    """
    Quantifies how much CAIP reduces alert fragmentation.

    baseline_alerts  — how many alerts the baseline generated (≈ events)
    caip_campaigns   — how many campaign-level alerts CAIP generated
    total_events     — total events processed
    true_campaigns   — ground truth number of campaigns
    """
    reduction_pct = (baseline_alerts - caip_campaigns) / baseline_alerts * 100 if baseline_alerts > 0 else 0
    avg_events_per_alert_baseline = total_events / baseline_alerts if baseline_alerts > 0 else 0
    avg_events_per_campaign_caip  = total_events / caip_campaigns if caip_campaigns > 0 else 0

    return {
        "baseline_alerts":        baseline_alerts,
        "caip_campaign_alerts":   caip_campaigns,
        "total_events":           total_events,
        "alert_reduction_pct":    round(reduction_pct, 2),
        "avg_events_per_baseline_alert": round(avg_events_per_alert_baseline, 2),
        "avg_events_per_caip_campaign":  round(avg_events_per_campaign_caip, 2),
        "true_campaigns":         true_campaigns,
    }


# ── Campaign grouping metrics (Experiment 3) ──────────────────────────────────

def grouping_metrics(true_groups: dict, pred_groups: dict) -> dict:
    """
    Measures campaign correlation quality.

    true_groups: {campaign_id -> set(event_ids)}
    pred_groups: {predicted_group_id -> set(event_ids)}

    Returns: correct_grouping_rate, false_merge_rate, missed_link_rate, grouping_f1
    """
    # Build pairwise sets
    true_pairs = set()
    for group in true_groups.values():
        events = sorted(group)
        for i in range(len(events)):
            for j in range(i + 1, len(events)):
                true_pairs.add((events[i], events[j]))

    pred_pairs = set()
    for group in pred_groups.values():
        events = sorted(group)
        for i in range(len(events)):
            for j in range(i + 1, len(events)):
                pred_pairs.add((events[i], events[j]))

    if not true_pairs:
        return {"grouping_precision": 0, "grouping_recall": 0, "grouping_f1": 0,
                "correct_pairs": 0, "false_merges": 0, "missed_links": 0}

    correct = len(true_pairs & pred_pairs)
    false_merges = len(pred_pairs - true_pairs)
    missed_links = len(true_pairs - pred_pairs)

    precision = correct / len(pred_pairs) if pred_pairs else 0
    recall    = correct / len(true_pairs) if true_pairs else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "grouping_precision": round(precision, 4),
        "grouping_recall":    round(recall, 4),
        "grouping_f1":        round(f1, 4),
        "correct_pairs":      correct,
        "false_merges":       false_merges,
        "missed_links":       missed_links,
        "total_true_pairs":   len(true_pairs),
        "total_pred_pairs":   len(pred_pairs),
    }


# ── Prediction accuracy metrics (Experiment 4) ────────────────────────────────

# ── Prediction accuracy metrics (Experiment 4) ────────────────────────────────

def prediction_accuracy_metrics(
    predictions: list[dict],
) -> dict:
    """
    Evaluates attack stage prediction accuracy.

    Each element of predictions: {
        "predicted_top1":   str,
        "predicted_top3":   list[str],
        "actual":           str,
        "confidence_top1":  float,
    }
    """
    if not predictions:
        return {}

    top1_correct    = [p for p in predictions if p["predicted_top1"] == p["actual"]]
    top3_correct    = [p for p in predictions if p["actual"] in p.get("predicted_top3", [])]

    top1_acc = len(top1_correct) / len(predictions)
    top3_acc = len(top3_correct) / len(predictions)

    correct_confs = [p["confidence_top1"] for p in top1_correct if "confidence_top1" in p]
    wrong_confs   = [p["confidence_top1"] for p in predictions
                     if p not in top1_correct and "confidence_top1" in p]

    y_true = [p["actual"] for p in predictions]
    y_pred = [p["predicted_top1"] for p in predictions]
    stage_labels = sorted(list(set(y_true) | set(y_pred)))

    macro_prec = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    macro_rec  = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    macro_f1   = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weight_f1  = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=stage_labels)

    per_stage = {}
    for stage in stage_labels:
        stage_preds = [p for p in predictions if p["actual"] == stage]
        if stage_preds:
            correct_here = sum(1 for p in stage_preds if p["predicted_top1"] == stage)
            per_stage[stage] = {
                "n":        len(stage_preds),
                "top1_acc": round(correct_here / len(stage_preds), 4),
            }

    return {
        "n_predictions":         len(predictions),
        "top1_accuracy":         round(top1_acc, 4),
        "top3_accuracy":         round(top3_acc, 4),
        "macro_precision":       round(macro_prec, 4),
        "macro_recall":          round(macro_rec, 4),
        "macro_f1":              round(macro_f1, 4),
        "weighted_f1":           round(weight_f1, 4),
        "avg_confidence_correct":round(float(np.mean(correct_confs)), 4) if correct_confs else 0,
        "avg_confidence_wrong":  round(float(np.mean(wrong_confs)), 4)   if wrong_confs else 0,
        "confusion_matrix":      {"labels": stage_labels, "matrix": cm.tolist()},
        "per_stage_accuracy":    per_stage,
    }


# ── Cost routing metrics (Experiment 6) ──────────────────────────────────────

def routing_cost_metrics(routing_records: list[dict]) -> dict:
    """
    routing_records: list of {
        "tier": "monitor"|"investigate"|"twin",
        "risk_score": int,
        "cpu_ms": float,
        "ram_mb": float,
        "correct_decision": bool,
    }
    """
    tiers = {"monitor": [], "investigate": [], "twin": []}
    for r in routing_records:
        tier = r.get("tier", "monitor")
        if tier in tiers:
            tiers[tier].append(r)

    result: dict[str, Any] = {}
    for tier, records in tiers.items():
        if not records:
            result[tier] = {
                "count": 0,
                "pct": 0.0,
                "avg_cpu_ms": 0.0,
                "avg_ram_mb": 0.0,
                "accuracy": 0.0,
            }
            continue
        result[tier] = {
            "count":          len(records),
            "pct":            round(len(records) / len(routing_records) * 100, 1),
            "avg_cpu_ms":     round(float(np.mean([r.get("cpu_ms", 0) for r in records])), 2),
            "avg_ram_mb":     round(float(np.mean([r.get("ram_mb", 0) for r in records])), 2),
            "accuracy":       round(sum(1 for r in records if r.get("correct_decision")) / len(records), 4),
        }

    # Overall vs twin-for-all comparison
    total_cpu_selective  = sum(r.get("cpu_ms", 0) for r in routing_records)
    total_cpu_twin_all   = sum(10.0 for r in routing_records)  # 10ms per twin run (estimated)
    correct_selective    = sum(1 for r in routing_records if r.get("correct_decision"))
    accuracy_selective   = correct_selective / len(routing_records) if routing_records else 0.0

    result["summary"] = {
        "total_campaigns":      len(routing_records),
        "total_cpu_ms_caip":    round(float(total_cpu_selective), 2),
        "total_cpu_ms_twin_all":round(total_cpu_twin_all, 2),
        "cpu_savings_pct":      round((1 - total_cpu_selective / total_cpu_twin_all) * 100, 1)
                                if total_cpu_twin_all > 0 else 0.0,
        "overall_accuracy":     round(accuracy_selective, 4),
    }
    return result


# ── Table formatting for print output ─────────────────────────────────────────

def print_table(title: str, rows: list[list], headers: list[str]):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")
    col_w = max(16, max(len(h) for h in headers) + 2)
    header_str = "  " + "".join(h.ljust(col_w) for h in headers)
    print(header_str)
    print("  " + "-" * (col_w * len(headers)))
    for row in rows:
        print("  " + "".join(str(v).ljust(col_w) for v in row))
    print()
