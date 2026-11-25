"""
Validation Engine — Actual vs Predicted
=========================================
Runs the trained ML next-stage predictor on the 120-campaign hold-out
validation set and computes:

  • Top-1 Accuracy  : exact match between top prediction and ground truth
  • Top-3 Accuracy  : ground truth appears in top 3 predictions
  • Per-stage Precision / Recall / F1

These metrics are suitable for an IEEE paper evaluation section.
"""

import os
import csv
from collections import defaultdict

from app.intelligence.feature_extractor import extract_features
from app.intelligence.attack_predictor  import AttackPredictor, NEXT_STAGE_CLASSES


def run_validation(predictor: AttackPredictor | None = None) -> dict:
    """
    Parameters
    ----------
    predictor : AttackPredictor instance (will create one if None)

    Returns
    -------
    dict with:
      top1_accuracy, top3_accuracy, per_stage_metrics, confusion_summary,
      total_campaigns, correct_top1, correct_top3, per_campaign_results
    """
    val_path = os.path.normpath(os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "datasets", "caip_validation_set.csv"
    ))

    if not os.path.exists(val_path):
        return {"error": "Validation dataset not found. Run datasets/dataset_generator.py first."}

    # ── Load validation campaigns ─────────────────────────────────────────────
    campaigns: dict[str, list[dict]] = defaultdict(list)
    labels:    dict[str, str]        = {}

    with open(val_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cid = row["campaign_id"]
            campaigns[cid].append(row)
            labels[cid] = row["next_stage_label"]

    if predictor is None:
        predictor = AttackPredictor()

    # ── Evaluate ──────────────────────────────────────────────────────────────
    correct_top1 = 0
    correct_top3 = 0
    total        = 0

    # For per-stage precision/recall: {stage: {"tp","fp","fn"}}
    stage_stats: dict[str, dict[str, int]] = {
        s: {"tp": 0, "fp": 0, "fn": 0} for s in NEXT_STAGE_CLASSES
    }

    per_campaign = []

    for cid, events in campaigns.items():
        actual = labels.get(cid, "")
        if not actual or actual not in set(NEXT_STAGE_CLASSES):
            continue

        # ML-based prediction
        preds = predictor.predict_next_stages_ml(events)
        if not preds:
            continue

        top1_pred = preds[0]["stage"]
        top3_pred = [p["stage"] for p in preds[:3]]

        hit1 = (top1_pred == actual)
        hit3 = (actual in top3_pred)

        if hit1:
            correct_top1 += 1
            stage_stats[actual]["tp"] += 1
        else:
            stage_stats[actual]["fn"] += 1
            if top1_pred in stage_stats:
                stage_stats[top1_pred]["fp"] += 1

        if hit3:
            correct_top3 += 1

        total += 1

        per_campaign.append({
            "campaign_id":       cid,
            "actual_next_stage": actual,
            "predicted_top1":    top1_pred,
            "predicted_top3":    top3_pred,
            "top1_correct":      hit1,
            "top3_correct":      hit3,
            "confidence":        round(preds[0]["probability"], 4),
        })

    if total == 0:
        return {"error": "No valid campaigns in validation set."}

    top1_acc = correct_top1 / total
    top3_acc = correct_top3 / total

    # ── Per-stage P / R / F1 ──────────────────────────────────────────────────
    per_stage_metrics = {}
    for stage, stats in stage_stats.items():
        tp, fp, fn = stats["tp"], stats["fp"], stats["fn"]
        precision  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall     = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1         = (2 * precision * recall / (precision + recall)
                      if (precision + recall) > 0 else 0.0)
        if tp + fp + fn > 0:      # only show stages that appeared
            per_stage_metrics[stage] = {
                "precision": round(precision, 3),
                "recall":    round(recall, 3),
                "f1":        round(f1, 3),
                "support":   tp + fn,
            }

    return {
        "total_campaigns":  total,
        "correct_top1":     correct_top1,
        "correct_top3":     correct_top3,
        "top1_accuracy":    round(top1_acc, 4),
        "top3_accuracy":    round(top3_acc, 4),
        "per_stage_metrics":  per_stage_metrics,
        "per_campaign_results": per_campaign,
    }
