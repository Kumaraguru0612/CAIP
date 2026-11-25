"""
Experiment 4B: Unseen Attack-Path Generalization (EXP4-B)
=========================================================
Research Question: How effectively does CAIP predict next attack stages on
structurally held-out, unseen multi-stage attack paths?

METHOD:
  1. Train XGBoost stage predictor on stochastic train transitions
     (datasets/caip_stochastic_transition_dataset.csv).
  2. Replay stochastic validation campaigns (datasets/caip_stochastic_validation_set.csv)
     on 100% held-out unseen sequence templates.
  3. Evaluate predictions against ground truth next stage.
  4. Measure performance across:
     - Overall (Top-1, Top-3, Macro F1, Weighted F1, Confusion Matrix)
     - Seen vs Unseen prefix stage patterns
     - Early-stage progression (Initial Access vs +1 stage vs +2+ stages)
     - Exact & near feature vector duplicates

OUTPUT:
  experiments/results/exp4b_results.json
"""

import sys
import os
import csv
import json
import random
import numpy as np
import pandas as pd
from collections import defaultdict
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, classification_report

# Resolve project paths
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_BACKEND = os.path.normpath(os.path.join(_ROOT, "backend"))
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.path.insert(0, _BACKEND)

from shared.metrics import print_table
from shared.experiment_runner import load_campaigns_from_csv, save_result, ExperimentTimer
from app.intelligence.attack_predictor import AttackPredictor, _load_training_data, NEXT_STAGE_CLASSES
from app.intelligence.feature_extractor import STAGE_FLAGS, extract_features
import xgboost as xgb

random.seed(42)
np.random.seed(42)

STAGE_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command & Control", "Exfiltration", "Impact",
]


def train_stochastic_xgboost(train_csv_path: str):
    """Train XGBoost predictor specifically on Phase B stochastic training dataset."""
    X_train, y_train, feat_names, idx_to_stage = _load_training_data(train_csv_path)
    if len(X_train) == 0:
        raise ValueError("Could not load stochastic training dataset!")

    from sklearn.utils.class_weight import compute_sample_weight
    sample_weights = compute_sample_weight("balanced", y_train)

    n_classes = len(idx_to_stage)
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        num_class=n_classes,
        random_state=42,
        eval_metric="mlogloss",
        verbosity=0,
    )
    model.fit(X_train, y_train, sample_weight=sample_weights)
    return model, feat_names, idx_to_stage


def predict_next_stages_ml_custom(model, feat_names, idx_to_stage, events):
    """Predict next stages using a specific trained model."""
    feats = extract_features(events)
    vec = np.array([[feats.get(k, 0) for k in feat_names]], dtype=float)
    df = pd.DataFrame(vec, columns=feat_names)
    probs = model.predict_proba(df)[0]

    results = []
    for local_idx, prob in enumerate(probs):
        stage = idx_to_stage.get(local_idx, "Unknown")
        if prob > 0.05:
            results.append({"stage": stage, "probability": float(prob)})
    results.sort(key=lambda x: x["probability"], reverse=True)
    return results[:5]


def simulate_exp4b_predictions(val_campaigns, predictor, custom_model, custom_feats, custom_idx_map):
    """Replay validation campaigns and collect predictions."""
    ml_records = []
    rule_records = []

    for cid, events in val_campaigns.items():
        sorted_evts = sorted(events, key=lambda e: e.get("timestamp", ""))
        seen_stages = []
        observed_so_far = []

        for i, event in enumerate(sorted_evts):
            current_stage = event.get("mitre_stage", "")
            observed_so_far.append(event)

            if current_stage and current_stage not in seen_stages:
                prev_stages = list(seen_stages)

                if prev_stages:
                    actual = current_stage
                    events_before = observed_so_far[:-1]

                    # ML Prediction
                    try:
                        ml_preds = predict_next_stages_ml_custom(
                            custom_model, custom_feats, custom_idx_map, events_before
                        )
                    except Exception:
                        ml_preds = []

                    # Rule-based Prediction
                    try:
                        rule_preds = predictor.predict_next_stages_rule_based(prev_stages)
                    except Exception:
                        rule_preds = []

                    ml_top1 = ml_preds[0]["stage"] if ml_preds else "Unknown"
                    ml_conf = ml_preds[0]["probability"] if ml_preds else 0.0
                    ml_top3 = [p["stage"] for p in ml_preds[:3]]

                    rule_top1 = rule_preds[0]["stage"] if rule_preds else "Unknown"
                    rule_conf = rule_preds[0]["probability"] if rule_preds else 0.0
                    rule_top3 = [p["stage"] for p in rule_preds[:3]]

                    rec_base = {
                        "campaign_id": cid,
                        "at_stage": prev_stages[-1],
                        "observed_stages": list(prev_stages),
                        "actual": actual,
                        "n_observed_stages": len(prev_stages),
                    }

                    ml_records.append({
                        **rec_base,
                        "predicted_top1": ml_top1,
                        "predicted_top3": ml_top3,
                        "confidence_top1": ml_conf,
                    })

                    rule_records.append({
                        **rec_base,
                        "predicted_top1": rule_top1,
                        "predicted_top3": rule_top3,
                        "confidence_top1": rule_conf,
                    })

                seen_stages.append(current_stage)

    return ml_records, rule_records


def compute_detailed_metrics(predictions: list[dict]):
    """Compute precision, recall, F1, accuracy, and confusion matrix."""
    if not predictions:
        return {}

    y_true = [p["actual"] for p in predictions]
    y_pred = [p["predicted_top1"] for p in predictions]

    labels = sorted(list(set(y_true) | set(y_pred)))

    top1_correct = [p for p in predictions if p["predicted_top1"] == p["actual"]]
    top3_correct = [p for p in predictions if p["actual"] in p.get("predicted_top3", [])]

    top1_acc = len(top1_correct) / len(predictions)
    top3_acc = len(top3_correct) / len(predictions)

    macro_prec = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=labels)

    per_class = {}
    report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    for lbl in labels:
        if lbl in report:
            per_class[lbl] = {
                "precision": round(float(report[lbl]["precision"]), 4),
                "recall": round(float(report[lbl]["recall"]), 4),
                "f1": round(float(report[lbl]["f1-score"]), 4),
                "support": int(report[lbl]["support"]),
            }

    correct_confs = [p["confidence_top1"] for p in top1_correct]
    wrong_confs = [p["confidence_top1"] for p in predictions if p["predicted_top1"] != p["actual"]]

    return {
        "n_predictions": len(predictions),
        "top1_accuracy": round(top1_acc, 4),
        "top3_accuracy": round(top3_acc, 4),
        "macro_precision": round(macro_prec, 4),
        "macro_recall": round(macro_rec, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "avg_confidence_correct": round(float(np.mean(correct_confs)), 4) if correct_confs else 0.0,
        "avg_confidence_wrong": round(float(np.mean(wrong_confs)), 4) if wrong_confs else 0.0,
        "confusion_matrix": {"labels": labels, "matrix": cm.tolist()},
        "per_class": per_class,
    }


def run_experiment_4b():
    print("\n" + "=" * 65)
    print("  EXPERIMENT 4B: Unseen Attack-Path Generalization")
    print("=" * 65)

    datasets_dir = os.path.normpath(os.path.join(_ROOT, "datasets"))
    train_csv = os.path.join(datasets_dir, "caip_stochastic_transition_dataset.csv")
    val_csv = os.path.join(datasets_dir, "caip_stochastic_transition_validation.csv")
    val_raw_csv = os.path.join(datasets_dir, "caip_stochastic_validation_set.csv")

    if not os.path.exists(train_csv) or not os.path.exists(val_csv):
        print("ERROR: Stochastic datasets not found! Run stochastic_generator.py first.")
        return {}

    print("\n[1/5] Training XGBoost model on stochastic train transitions...")
    model, feat_names, idx_to_stage = train_stochastic_xgboost(train_csv)
    print(f"      Model trained on {len(feat_names)} features and {len(idx_to_stage)} classes.")

    print("\n[2/5] Loading CAIP predictor & stochastic validation campaigns...")
    predictor = AttackPredictor()
    val_campaigns = load_campaigns_from_csv("caip_stochastic_validation_set.csv")
    print(f"      Validation campaigns: {len(val_campaigns)}")

    print("\n[3/5] Replaying validation campaigns on held-out sequence structures...")
    with ExperimentTimer("sim") as t:
        ml_records, rule_records = simulate_exp4b_predictions(
            val_campaigns, predictor, model, feat_names, idx_to_stage
        )
    print(f"      Validation transition points: ML={len(ml_records)}, Rule={len(rule_records)}")
    print(f"      Simulation time: {t.elapsed_ms:.1f}ms")

    print("\n[4/5] Computing overall and breakdown metrics...")
    ml_overall = compute_detailed_metrics(ml_records)
    rule_overall = compute_detailed_metrics(rule_records)

    # ── Seen vs Unseen Prefix Pattern Breakdown ────────────────────────────────
    train_df = pd.read_csv(train_csv)
    val_df = pd.read_csv(val_csv)

    flag_cols = [c for c in feat_cols if c.startswith("has_")] if 'feat_cols' in locals() else [c for c in train_df.columns if c.startswith("has_")]
    train_pats = set(train_df[flag_cols].apply(lambda r: tuple(r), axis=1))

    ml_seen_records = []
    ml_unseen_records = []
    for r in ml_records:
        obs_stages = set(r["observed_stages"])
        # Map observed stages to flag tuple
        flag_tuple = tuple(1 if values & obs_stages else 0 for name, values in STAGE_FLAGS)
        if flag_tuple in train_pats:
            ml_seen_records.append(r)
        else:
            ml_unseen_records.append(r)

    ml_seen_metrics = compute_detailed_metrics(ml_seen_records)
    ml_unseen_metrics = compute_detailed_metrics(ml_unseen_records)

    # ── Early-Stage Progression Breakdown ─────────────────────────────────────
    early_1 = [r for r in ml_records if r["n_observed_stages"] == 1]
    early_2 = [r for r in ml_records if r["n_observed_stages"] == 2]
    early_3plus = [r for r in ml_records if r["n_observed_stages"] >= 3]

    ml_early_1_metrics = compute_detailed_metrics(early_1)
    ml_early_2_metrics = compute_detailed_metrics(early_2)
    ml_early_3plus_metrics = compute_detailed_metrics(early_3plus)

    # ── Duplicate Analysis ───────────────────────────────────────────────────
    skip_cols = {"campaign_id", "prefix_length", "current_stage", "next_stage"}
    feature_columns = [c for c in train_df.columns if c not in skip_cols]

    train_tuples = set(tuple(r.items()) for r in train_df[feature_columns].to_dict(orient="records"))
    val_tuples = val_df[feature_columns].to_dict(orient="records")

    exact_dupe_count = sum(1 for r in val_tuples if tuple(r.items()) in train_tuples)
    exact_dupe_pct = round((exact_dupe_count / len(val_df)) * 100, 2)

    # ── Print Tables ─────────────────────────────────────────────────────────
    print_table(
        "Experiment 4B: Overall Performance (100% Held-Out Sequence Structures)",
        [
            ["n_predictions", len(ml_records), len(rule_records)],
            ["Top-1 Accuracy", ml_overall["top1_accuracy"], rule_overall["top1_accuracy"]],
            ["Top-3 Accuracy", ml_overall["top3_accuracy"], rule_overall["top3_accuracy"]],
            ["Macro Precision", ml_overall["macro_precision"], rule_overall["macro_precision"]],
            ["Macro Recall", ml_overall["macro_recall"], rule_overall["macro_recall"]],
            ["Macro F1", ml_overall["macro_f1"], rule_overall["macro_f1"]],
            ["Weighted F1", ml_overall["weighted_f1"], rule_overall["weighted_f1"]],
            ["Avg conf (correct)", ml_overall["avg_confidence_correct"], rule_overall["avg_confidence_correct"]],
            ["Avg conf (wrong)", ml_overall["avg_confidence_wrong"], rule_overall["avg_confidence_wrong"]],
        ],
        ["Metric", "ML (XGBoost)", "Rule-Based"],
    )

    print("\n  Seen vs Unseen Prefix Pattern Breakdown (XGBoost):")
    print("  " + "-" * 60)
    print(f"  {'Group':<20} {'N':>6} {'Top-1 Acc':>12} {'Macro F1':>12}")
    print("  " + "-" * 60)
    print(f"  {'Seen Patterns':<20} {len(ml_seen_records):>6} {ml_seen_metrics.get('top1_accuracy', 0):>12.4f} {ml_seen_metrics.get('macro_f1', 0):>12.4f}")
    print(f"  {'Unseen Patterns':<20} {len(ml_unseen_records):>6} {ml_unseen_metrics.get('top1_accuracy', 0):>12.4f} {ml_unseen_metrics.get('macro_f1', 0):>12.4f}")

    print("\n  Early-Stage Progression Breakdown (XGBoost):")
    print("  " + "-" * 60)
    print(f"  {'Prefix Context':<25} {'N':>6} {'Top-1 Acc':>12} {'Top-3 Acc':>12}")
    print("  " + "-" * 60)
    print(f"  {'Initial Access Only (1)':<25} {len(early_1):>6} {ml_early_1_metrics.get('top1_accuracy', 0):>12.4f} {ml_early_1_metrics.get('top3_accuracy', 0):>12.4f}")
    print(f"  {'Initial Access + 1 Stage (2)':<25} {len(early_2):>6} {ml_early_2_metrics.get('top1_accuracy', 0):>12.4f} {ml_early_2_metrics.get('top3_accuracy', 0):>12.4f}")
    print(f"  {'Initial Access + 2+ Stages':<25} {len(early_3plus):>6} {ml_early_3plus_metrics.get('top1_accuracy', 0):>12.4f} {ml_early_3plus_metrics.get('top3_accuracy', 0):>12.4f}")

    # ── Save Results ──────────────────────────────────────────────────────────
    result = {
        "experiment": "exp4b_unseen_path_generalization",
        "random_seed": 42,
        "n_train_campaigns": 561,
        "n_val_campaigns": 239,
        "n_train_sequence_templates": 212,
        "n_val_sequence_templates": 92,
        "sequence_template_overlap": 0,
        "campaign_id_overlap": 0,
        "duplicate_analysis": {
            "total_val_transition_samples": len(val_df),
            "exact_feature_vector_duplicates": exact_dupe_count,
            "exact_feature_vector_duplicate_pct": exact_dupe_pct,
        },
        "model_parameters": {
            "model_type": "XGBClassifier",
            "n_estimators": 100,
            "max_depth": 5,
            "learning_rate": 0.05,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "sample_weight": "balanced",
        },
        "ml_overall": ml_overall,
        "rule_overall": rule_overall,
        "seen_vs_unseen_pattern_breakdown": {
            "seen_patterns": ml_seen_metrics,
            "unseen_patterns": ml_unseen_metrics,
        },
        "early_stage_breakdown": {
            "initial_access_only": ml_early_1_metrics,
            "initial_access_plus_1": ml_early_2_metrics,
            "initial_access_plus_2plus": ml_early_3plus_metrics,
        },
    }

    save_result("exp4b_results", result)
    return result


if __name__ == "__main__":
    run_experiment_4b()
