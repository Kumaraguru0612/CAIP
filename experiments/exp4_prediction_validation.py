"""
Experiment 4: Attack Stage Prediction Validation (Longitudinal)
================================================================
Research question: How accurately does CAIP predict the next attack
stage compared to a rule-based baseline?

METHOD:
  For each campaign in the validation set, replay events one-by-one.
  At each stage boundary (when a new MITRE stage is first observed):
    1. Record the current observed stages
    2. Get predictions from BOTH ML and rule-based predictor
    3. Record the actual next stage (from next event)
    4. Compute correct/incorrect for both

This is the longitudinal Actual vs Predicted study.

METRICS:
  - Top-1 Accuracy: predicted top-1 stage matches actual next stage
  - Top-3 Accuracy: actual next stage is in top-3 predictions
  - Precision / Recall / F1 for stage classification
  - Per-stage accuracy breakdown (confusion matrix)
  - Avg confidence when correct vs wrong (calibration)

IEEE CONTRIBUTION:
  "We compare ML-based (XGBoost) vs rule-based (MITRE kill-chain)
   prediction across X longitudinal stage transitions, demonstrating
   that ML achieves Y% Top-1 accuracy vs Z% for rule-based, with
   A% improvement on minority stages."
"""

import sys, os
# Resolve project root regardless of CWD
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_BACKEND = os.path.normpath(os.path.join(_ROOT, "backend"))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, ".."))
sys.path.insert(0, _BACKEND)

import numpy as np
import random
from collections import defaultdict

from shared.metrics import prediction_accuracy_metrics, print_table
from shared.experiment_runner import (
    load_campaigns_from_csv, get_ordered_stages, save_result, ExperimentTimer,
)

random.seed(2024)
np.random.seed(2024)

STAGE_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command & Control", "Exfiltration", "Impact",
]


def simulate_longitudinal_predictions(
    campaigns: dict,
    predictor,
) -> tuple[list[dict], list[dict]]:
    """
    Replay each campaign event-by-event.
    At each stage boundary, record ML + rule predictions vs actual.

    Returns: (ml_predictions, rule_predictions)
    Each element: {
        "campaign_id": str,
        "at_stage": str,
        "predicted_top1": str,
        "predicted_top3": list[str],
        "confidence_top1": float,
        "actual": str,
    }
    """
    ml_records   = []
    rule_records = []

    for cid, events in campaigns.items():
        # Sort by timestamp
        sorted_evts = sorted(events, key=lambda e: e.get("timestamp", ""))
        seen_stages = []
        observed_so_far = []

        for i, event in enumerate(sorted_evts):
            current_stage = event.get("mitre_stage", "")
            observed_so_far.append(event)

            # Check if this is a NEW stage
            if current_stage and current_stage not in seen_stages:
                # Previous state: stages before this event
                prev_stages = list(seen_stages)

                if prev_stages:  # Only record if we have something to predict FROM
                    # What is the actual next stage we just observed?
                    actual = current_stage

                    # ML prediction (from observed_so_far minus current event)
                    events_before = observed_so_far[:-1]
                    try:
                        ml_preds = predictor.predict_next_stages_ml(events_before)
                    except Exception:
                        ml_preds = []

                    # Rule-based prediction
                    try:
                        rule_preds = predictor.predict_next_stages_rule_based(prev_stages)
                    except Exception:
                        rule_preds = []

                    # ML record
                    ml_top1  = ml_preds[0]["stage"] if ml_preds else "Unknown"
                    ml_conf  = ml_preds[0]["probability"] if ml_preds else 0.0
                    ml_top3  = [p["stage"] for p in ml_preds[:3]]

                    ml_records.append({
                        "campaign_id":    cid,
                        "at_stage":       prev_stages[-1] if prev_stages else "Start",
                        "observed_stages":list(prev_stages),
                        "predicted_top1": ml_top1,
                        "predicted_top3": ml_top3,
                        "confidence_top1":ml_conf,
                        "actual":         actual,
                    })

                    # Rule-based record
                    rule_top1 = rule_preds[0]["stage"] if rule_preds else "Unknown"
                    rule_conf = rule_preds[0]["probability"] if rule_preds else 0.0
                    rule_top3 = [p["stage"] for p in rule_preds[:3]]

                    rule_records.append({
                        "campaign_id":    cid,
                        "at_stage":       prev_stages[-1] if prev_stages else "Start",
                        "observed_stages":list(prev_stages),
                        "predicted_top1": rule_top1,
                        "predicted_top3": rule_top3,
                        "confidence_top1":rule_conf,
                        "actual":         actual,
                    })

                seen_stages.append(current_stage)

    return ml_records, rule_records


def build_confusion_data(records: list[dict]) -> dict:
    """Build per-stage confusion breakdown."""
    stage_data = defaultdict(lambda: {"n": 0, "correct_top1": 0, "correct_top3": 0})
    for r in records:
        actual = r["actual"]
        stage_data[actual]["n"] += 1
        if r["predicted_top1"] == actual:
            stage_data[actual]["correct_top1"] += 1
        if actual in r.get("predicted_top3", []):
            stage_data[actual]["correct_top3"] += 1

    result = {}
    for stage, data in stage_data.items():
        n = data["n"]
        result[stage] = {
            "n":         n,
            "top1_acc":  round(data["correct_top1"] / n, 4) if n else 0,
            "top3_acc":  round(data["correct_top3"] / n, 4) if n else 0,
        }
    return result


def run_experiment():
    print("\n" + "=" * 65)
    print("  EXPERIMENT 4: Attack Stage Prediction Validation")
    print("=" * 65)

    print("\n[1/4] Loading validation dataset...")
    val_campaigns = load_campaigns_from_csv("caip_validation_set.csv")
    print(f"      Campaigns: {len(val_campaigns)}")

    print("\n[2/4] Loading CAIP predictor...")
    predictor = None
    try:
        # _BACKEND already on sys.path from top of file
        from app.intelligence.attack_predictor import AttackPredictor
        predictor = AttackPredictor()
        print("      Predictor loaded.")
    except Exception as e:
        print(f"      ERROR: could not load predictor: {e}")
        return {}

    print("\n[3/4] Simulating longitudinal stage predictions...")
    with ExperimentTimer("sim") as t:
        ml_records, rule_records = simulate_longitudinal_predictions(val_campaigns, predictor)

    print(f"      Total prediction points: ML={len(ml_records)}, Rule={len(rule_records)}")
    print(f"      Simulation time: {t.elapsed_ms:.1f}ms")

    print("\n[4/4] Computing metrics...")

    ml_metrics   = prediction_accuracy_metrics(ml_records)
    rule_metrics = prediction_accuracy_metrics(rule_records)

    ml_confusion   = build_confusion_data(ml_records)
    rule_confusion = build_confusion_data(rule_records)

    # ── Print comparison table ─────────────────────────────────────────────────
    print_table(
        "Experiment 4: ML vs Rule-Based Prediction",
        [
            ["n_predictions",             len(ml_records),                 len(rule_records)],
            ["Top-1 Accuracy",            ml_metrics["top1_accuracy"],     rule_metrics["top1_accuracy"]],
            ["Top-3 Accuracy",            ml_metrics["top3_accuracy"],     rule_metrics["top3_accuracy"]],
            ["Macro Precision",           ml_metrics["macro_precision"],   rule_metrics["macro_precision"]],
            ["Macro Recall",              ml_metrics["macro_recall"],      rule_metrics["macro_recall"]],
            ["Macro F1",                  ml_metrics["macro_f1"],          rule_metrics["macro_f1"]],
            ["Weighted F1",               ml_metrics["weighted_f1"],       rule_metrics["weighted_f1"]],
            ["Avg conf (correct)",        ml_metrics["avg_confidence_correct"],  rule_metrics["avg_confidence_correct"]],
            ["Avg conf (wrong)",          ml_metrics["avg_confidence_wrong"],    rule_metrics["avg_confidence_wrong"]],
        ],
        ["Metric", "ML (XGBoost)", "Rule-Based"],
    )

    # ── Per-stage breakdown ────────────────────────────────────────────────────
    print("\n  Per-Stage Top-1 Accuracy Breakdown:")
    print("  " + "-" * 65)
    print(f"  {'Stage':<25} {'ML Acc':>8} {'Rule Acc':>10} {'N':>6}")
    print("  " + "-" * 65)
    all_stages = sorted(set(ml_confusion) | set(rule_confusion),
                        key=lambda s: STAGE_ORDER.index(s) if s in STAGE_ORDER else 99)
    for stage in all_stages:
        ml_data   = ml_confusion.get(stage, {})
        rule_data = rule_confusion.get(stage, {})
        n = ml_data.get("n", 0)
        ml_acc   = ml_data.get("top1_acc", 0)
        rule_acc = rule_data.get("top1_acc", 0)
        diff = "+" if ml_acc > rule_acc else ("-" if ml_acc < rule_acc else "=")
        print(f"  {stage:<25} {ml_acc:>8.4f} {rule_acc:>10.4f} {n:>6}  {diff}")

    result = {
        "experiment":       "exp4_prediction_validation",
        "random_seed":      42,
        "n_campaigns_val":  len(val_campaigns),
        "n_predictions":    len(ml_records),
        "model_parameters": {
            "model_type": "XGBClassifier",
            "n_estimators": 100,
            "max_depth": 5,
            "learning_rate": 0.05,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "sample_weight": "balanced",
        },
        "ml_metrics":       ml_metrics,
        "rule_metrics":     rule_metrics,
        "ml_per_stage":     ml_confusion,
        "rule_per_stage":   rule_confusion,
        "sample_records":   ml_records[:5],  # first 5 for inspection
    }

    save_result("exp4_results", result)
    return result


if __name__ == "__main__":
    run_experiment()
