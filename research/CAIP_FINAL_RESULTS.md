# CAIP Final Experimental Results & Scientific Audit Report

## Final Frozen Results Table 🔒

All experimental results below are empirically generated and frozen from verified benchmark execution runs. The numbers correspond directly to JSON result artifacts persisted under `experiments/results/`.

| Experiment | Target Metric | Final Result | Verification Artifact | Benchmark Scope & Condition |
| :--- | :--- | ---: | :--- | :--- |
| **EXP1** | Alert Reduction | **80.0%** | [exp1_results.json](../experiments/results/exp1_results.json) | 600 raw alert events correlated into 120 campaign alerts |
| **EXP2** | Full Architecture F1 | **1.0000** | [exp2_results.json](../experiments/results/exp2_results.json) | Multi-stage correlation vs single-event ML baseline |
| **EXP3** | Grouping F1 | **0.9421** | [exp3_results.json](../experiments/results/exp3_results.json) | Multi-factor correlation (User, Device, IP, Domain; Prec: 0.8905, Rec: 1.0) |
| **EXP4** | Top-1 Accuracy | **90.37%** | [exp4_results.json](../experiments/results/exp4_results.json) | Known-path stage prediction (Top-3 Acc: 99.82%, Macro F1: 90.34%) |
| **EXP4-B** | Top-1 Accuracy | **26.35%** | [exp4b_results.json](../experiments/results/exp4b_results.json) | Structurally unseen attack paths (0 sequence template overlap) |
| **EXP4-B** | Top-3 Accuracy | **79.37%** | [exp4b_results.json](../experiments/results/exp4b_results.json) | Top-3 stage candidate set accuracy on 92 unseen sequence templates |
| **EXP5** | BLOCK F1 | **0.8163** | [exp5_results.json](../experiments/results/exp5_results.json) | Digital Twin decision quality (BLOCK Prec: 0.6897, Recall: 1.0000) |
| **EXP6** | CPU Savings | **7.54%** | [exp6_results.json](../experiments/results/exp6_results.json) | Cost-aware selective routing vs twin-for-all baseline |
| **EXP7** | Top-1 Accuracy | **96.49%** | [exp7_results.json](../experiments/results/exp7_results.json) | Archetype holdout test protocol (Detection F1: 1.0000) |
| **Tests** | Passed | **16/16** | `pytest` test suite | 100% test execution passing rate across `tests/` |

---

## EXP7 Scientific Audit Report (5-Check Audit)

Prior to documenting EXP7 Top-1 Accuracy (96.49%) in research literature, a 5-point scientific validation was conducted on `experiments/exp7_unseen_generalization.py`:

### Check 1 — Target Definition Audit
- **Code Inspection**: Line 140 in `experiments/exp7_unseen_generalization.py`:
  ```python
  actual_next = events[mid_idx].get("mitre_stage", "Unknown")
  ```
- **Finding**: Target is `target = next_stage` (the MITRE stage of event $E_{k+1}$ immediately following prefix $E_1 \dots E_k$), NOT `terminal_stage`.
- **Verdict**: ✅ **PASSED** — Target formulation is methodologically sound.

### Check 2 — Train/Test Campaign Separation
- **Code Inspection**: `split_known_vs_unseen_campaigns` partitions dataset by `campaign_id`.
- **Finding**: Training set (`caip_transition_dataset.csv`, 480 campaigns) and validation set (`caip_validation_set.csv`, 120 campaigns) have **0 Campaign ID overlap** ($\text{Train campaigns} \cap \text{Test campaigns} = 0$). No individual event rows from the same campaign span both sets.
- **Verdict**: ✅ **PASSED** — Campaign-level isolation enforced.

### Check 3 — Feature Construction & Leakage Audit
- **Code Inspection**: Features for prediction are generated via `predict_next_stages_ml(mid_events)` where `mid_events = events[:mid_idx]`.
- **Finding**: Target event $E_{k+1}$ is excluded from `mid_events`. Feature extraction receives only historical prefix events $E_1 \dots E_k$.
- **Verdict**: ✅ **PASSED** — Zero feature leakage.

### Check 4 — Sequence Template Overlap Audit
- **Calculation**:
  $$\text{TRAIN sequence templates} \cap \text{UNSEEN TEST sequence templates} = 7 \text{ templates}$$
- **Finding**: Because Phase A data is generated from 14 fixed synthetic campaign templates, splitting by campaign archetype (`data_theft`, `insider_threat`) results in sequence structures that overlap with training templates.
- **Verdict**: ⚠️ **CRITICAL INTERPRETATION NOTICE** — Because sequence template overlap is non-zero, EXP7 evaluates prediction accuracy when encountering **held-out campaign archetypes over known sequence structures**. It must NOT be claimed as structurally unseen attack-path generalization.

### Check 5 — Duplicate Feature Vector Audit
- **Calculation**:
  $$\text{Training feature vectors} \cap \text{Testing feature vectors} = 0 \text{ duplicate vectors (0.00\%)}$$
- **Finding**: Continuous-valued time delta and event frequency features make every campaign feature vector unique across training and test sets.
- **Verdict**: ✅ **PASSED** — No exact feature vector duplicates exist.

---

## Important Methodological Interpretation

To maintain complete scientific integrity in paper reporting and academic presentation, the evaluation conditions of **EXP4**, **EXP4-B**, and **EXP7** must be clearly distinguished:

1. **EXP4 (Known-Path Prediction Validation)**:
   - **Condition**: Evaluates next-stage prediction on known attack sequence structures using 80/20 campaign split.
   - **Metrics**: **Top-1 Accuracy = 90.37%**, **Top-3 Accuracy = 99.82%**, **Macro F1 = 90.34%**.
   - **Interpretation**: Demonstrates that XGBoost effectively learns multi-stage ATT&CK transition dynamics when sequence templates are observed during training.

2. **EXP4-B (Unseen Attack-Path Generalization)**:
   - **Condition**: Evaluates prediction on **structurally unseen attack paths** using a held-out sequence template split ($\text{Train templates} \cap \text{Test templates} = 0$, 212 train templates vs 92 test templates).
   - **Metrics**: **Top-1 Accuracy = 26.35%**, **Top-3 Accuracy = 79.37%**, **Macro F1 = 24.21%** (vs Rule-Based Top-1 = 12.49%, Top-3 = 29.63%).
   - **Interpretation**: Measures model generalization difficulty under non-deterministic branching and novel kill-chain paths. Top-3 accuracy (79.37%) confirms that while exact Top-1 prediction on unseen paths is challenging, the correct next stage remains highly ranked within the candidate set.

3. **EXP7 (Archetype Holdout Test Protocol)**:
   - **Condition**: Holds out specific campaign archetypes (`data_theft`, `insider_threat`) using intermediate campaign prefixes.
   - **Metrics**: **Top-1 Accuracy = 96.49%**, **Top-3 Accuracy = 96.49%**, **Detection F1 = 1.0000**.
   - **Interpretation**: Evaluates intermediate stage prediction accuracy on held-out campaign archetypes. Because sequence templates overlap with training data, EXP7 should be interpreted as archetype holdout validation rather than structural unseen-path generalization.

---

## Frozen Result Artifact Summary

All output JSON files have been generated, audited, and locked in the codebase:
- [exp1_results.json](../experiments/results/exp1_results.json)
- [exp2_results.json](../experiments/results/exp2_results.json)
- [exp3_results.json](../experiments/results/exp3_results.json)
- [exp4_results.json](../experiments/results/exp4_results.json)
- [exp4b_results.json](../experiments/results/exp4b_results.json)
- [exp5_results.json](../experiments/results/exp5_results.json)
- [exp6_results.json](../experiments/results/exp6_results.json)
- [exp7_results.json](../experiments/results/exp7_results.json)
