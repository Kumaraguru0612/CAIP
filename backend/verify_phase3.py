"""
CAIP Phase 3 — End-to-End Verification
========================================
Validates the complete Phase 3 pipeline without needing Postgres or Neo4j:
  1. Dataset generation check (CSV files exist, row counts correct)
  2. Temporal feature extraction on a sample campaign
  3. ML predictor training on the generated dataset
  4. Validation engine: Actual vs Predicted (accuracy + P/R/F1)
  5. Campaign similarity engine: finds top-3 matches
"""

import os
import sys
import csv

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["NEO4J_URI"]    = ""
sys.path.append(os.path.join(os.path.dirname(__file__)))

# ── 1. Dataset files ──────────────────────────────────────────────────────────
print("=== CAIP Phase 3 Verification ===\n")
print("[Step 1] Checking generated datasets...")

BASE = os.path.dirname(os.path.abspath(__file__))
TRAIN_CSV = os.path.join(BASE, "..", "datasets", "caip_attack_dataset.csv")
VAL_CSV   = os.path.join(BASE, "..", "datasets", "caip_validation_set.csv")

TRAIN_CSV = os.path.normpath(TRAIN_CSV)
VAL_CSV   = os.path.normpath(VAL_CSV)

assert os.path.exists(TRAIN_CSV), "Training CSV not found! Run: python datasets/dataset_generator.py"
assert os.path.exists(VAL_CSV),   "Validation CSV not found! Run: python datasets/dataset_generator.py"

with open(TRAIN_CSV, encoding="utf-8") as f:
    train_rows = list(csv.DictReader(f))
with open(VAL_CSV, encoding="utf-8") as f:
    val_rows = list(csv.DictReader(f))

train_campaigns = len({r["campaign_id"] for r in train_rows})
val_campaigns   = len({r["campaign_id"] for r in val_rows})

print(f"  Train : {train_campaigns} campaigns  ({len(train_rows)} events)")
print(f"  Val   : {val_campaigns} campaigns  ({len(val_rows)} events)")
assert train_campaigns >= 400, "Expected at least 400 training campaigns"
assert val_campaigns   >= 100, "Expected at least 100 validation campaigns"
print("  [PASS] Dataset files verified.\n")

# ── 2. Temporal feature extraction ───────────────────────────────────────────
print("[Step 2] Temporal feature extraction on sample campaign...")

from app.intelligence.feature_extractor import extract_features

# Grab first campaign's events
first_cid = train_rows[0]["campaign_id"]
sample_events = [r for r in train_rows if r["campaign_id"] == first_cid]
feats = extract_features(sample_events)

assert "num_events"         in feats
assert "avg_time_delta_min" in feats
assert "events_per_minute"  in feats
assert "unique_techniques"  in feats
assert "has_execution"      in feats

print(f"  Campaign  : {first_cid}")
print(f"  Events    : {feats['num_events']}")
print(f"  Avg delta : {feats['avg_time_delta_min']} min")
print(f"  Velocity  : {feats['events_per_minute']} evt/min")
print(f"  Techniques: {feats['unique_techniques']} unique")
print(f"  Stages    : {feats['unique_stages']} unique")
print("  [PASS] Temporal features extracted.\n")

# ── 3. ML predictor training ─────────────────────────────────────────────────
print("[Step 3] Training ML predictor on dataset...")

from app.intelligence.attack_predictor import AttackPredictor
predictor = AttackPredictor()

assert predictor.stage_model is not None, "ML stage model failed to train"
print(f"  ML feature vector length : {len(predictor.ml_feature_names)}")
print(f"  Feature names (first 5)  : {predictor.ml_feature_names[:5]}")

# Test ML prediction on sample campaign events
ml_preds = predictor.predict_next_stages_ml(sample_events)
print(f"  ML next-stage predictions for {first_cid}:")
for p in ml_preds:
    print(f"    {p['stage']:<30}  {p['probability']*100:.1f}%")

# Test rule-based prediction
stages = list({r["mitre_stage"] for r in sample_events if r.get("mitre_stage")})
rule_preds = predictor.predict_next_stages_rule_based(stages)
print(f"  Rule-based predictions (baseline):")
for p in rule_preds:
    print(f"    {p['stage']:<30}  {p['probability']*100:.1f}%")

print("  [PASS] Dual-mode predictor working.\n")

# ── 4. Validation: Actual vs Predicted ───────────────────────────────────────
print("[Step 4] Running validation engine on hold-out set...")

from app.intelligence.validation_engine import run_validation
results = run_validation(predictor)

assert "top1_accuracy" in results, f"Validation error: {results.get('error')}"
top1 = results["top1_accuracy"]
top3 = results["top3_accuracy"]
total = results["total_campaigns"]

print(f"  Total campaigns evaluated : {total}")
print(f"  Top-1 Accuracy            : {top1 * 100:.1f}%")
print(f"  Top-3 Accuracy            : {top3 * 100:.1f}%")
print()
print(f"  {'Stage':<30} {'Prec':>6} {'Rec':>6} {'F1':>6} {'Supp':>5}")
print(f"  {'-'*55}")
for stage, m in sorted(results["per_stage_metrics"].items(), key=lambda x: -x[1]["f1"]):
    print(f"  {stage:<30} {m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} {m['support']:>5}")

assert top1 > 0.40, f"Top-1 accuracy too low: {top1:.2f}"
assert top3 > 0.70, f"Top-3 accuracy too low: {top3:.2f}"
print("\n  [PASS] Validation passed.\n")

# ── 5. Campaign similarity ────────────────────────────────────────────────────
print("[Step 5] Testing campaign similarity engine...")

from app.intelligence.similarity_engine import SimilarityEngine
sim_engine = SimilarityEngine()   # loads reference dataset automatically

# Build a test query: Credential Phishing pattern
test_stages = ["Initial Access", "Credential Access", "Lateral Movement"]
matches = sim_engine.find_similar(test_stages, top_k=3)

print(f"  Query stages: {test_stages}")
print(f"  Top similar campaigns:")
for m in matches:
    print(f"    {m['campaign_id']}  sim={m['similarity']:.3f}  predicted_next={m['predicted_next_stage']}")

assert len(matches) > 0, "Similarity engine returned no matches"
assert matches[0]["similarity"] > 0.01, f"Similarity score unexpectedly low: {matches[0]['similarity']}"
print("  [PASS] Similarity engine working.\n")

print("=== All Phase 3 checks passed! ===")
print(f"\n  Key Research Metrics:")
print(f"    Top-1 Accuracy  : {top1 * 100:.1f}%")
print(f"    Top-3 Accuracy  : {top3 * 100:.1f}%")
print(f"    Dataset size    : {train_campaigns} train / {val_campaigns} val campaigns")
print(f"    Total events    : {len(train_rows) + len(val_rows)}")
