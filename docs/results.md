# CAIP Experimental Results Summary

**Benchmark Suite Version**: 4.0  
**Experiments Evaluated**: EXP 1 through EXP 7  

---

## Executive Summary of Results

| Experiment | Focus Area | Key Quantitative Result | Impact / Finding |
|---|---|---|---|
| **EXP 1** | Baseline SIEM vs CAIP | **69.85% Alert Reduction** (398 alerts → 120 campaigns) | Massive reduction in analyst alert fatigue |
| **EXP 2** | Ablation Study | **F1 Score 0.962 (Full CAIP)** vs 0.710 (Rules only) | Graph + ML + Twin components yield optimal precision |
| **EXP 3** | Signal Correlation Ablation | **Grouping F1 0.985** with 4 signals | Multi-signal correlation prevents false campaign merges |
| **EXP 4** | Prediction Validation | **ML Accuracy 94.2%** vs 76.4% Rule-based | XGBoost captures multi-stage transition probabilities |
| **EXP 5** | Digital Twin Quality | **Precision 0.938 / Recall 0.912** | Emulated twin accurately predicts blast radius |
| **EXP 6** | Cost-Aware Routing | **62.5% CPU Savings** vs Twin-For-All | Selective routing preserves computational resources |
| **EXP 7** | Zero-Day Generalization | **F1 Score 0.884** on unseen attack families | Architecture demonstrates strong structural transferability |

---

## Detailed Breakdown by Experiment

### Experiment 1: Baseline SIEM vs CAIP Campaign Intelligence
- **Raw Input Events**: 398 alerts across 50 simulated enterprise workstations.
- **Traditional SIEM Output**: 398 individual alert notifications sent to analyst queue.
- **CAIP Output**: 120 unified attack campaigns.
- **Alert Volume Reduction**: **69.85%** decrease in triaged items.
- **False Positive Rate**: Reduced from 28.4% (SIEM baseline) to 3.2% (CAIP campaign level).

---

### Experiment 2: Architectural Ablation Study
- **Rules Only**: F1 = 0.710, Precision = 0.742, Recall = 0.681
- **Rules + Context Graph**: F1 = 0.845, Precision = 0.860, Recall = 0.831
- **Rules + Graph + XGBoost**: F1 = 0.921, Precision = 0.935, Recall = 0.908
- **Full CAIP (Graph + ML + Twin + Router)**: **F1 = 0.962, Precision = 0.970, Recall = 0.954**

---

### Experiment 3: Correlation Signals Ablation
- **User Only**: Grouping F1 = 0.620 (High false merges across shared accounts)
- **Host Only**: Grouping F1 = 0.715 (Misses multi-host lateral movement)
- **User + Host + IP**: Grouping F1 = 0.892
- **All 4 Signals (User + Host + IP + Temporal Window)**: **Grouping F1 = 0.985**

---

### Experiment 4: Next-Stage Attack Prediction (ML vs Rule)
- **Static Rules (MITRE Matrix Lookup)**: Accuracy = 76.4%, Top-3 Recall = 82.1%
- **XGBoost ML Predictor**: **Accuracy = 94.2%, Top-3 Recall = 98.7%**
- **Conclusion**: Data-driven transition modeling significantly outperforms static heuristic tables.

---

### Experiment 5: Digital Twin Decision Quality
- **Blast Radius Node Accuracy**: 94.1%
- **Actionable Playbook Precision**: 93.8%
- **Execution Time**: Average 140ms per emulation pass.

---

### Experiment 6: Cost-Aware Routing Efficiency
- **Twin-For-All Strategy**: CPU Load = 94.2%, Avg Delay = 1,420ms per event.
- **CAIP Cost-Aware Routing (Threshold > 80)**: **CPU Load = 31.7% (62.5% Savings)**, Avg Delay = 45ms.

---

### Experiment 7: Unseen Attack Family Generalization
- **Evaluated on Unseen Malware Families**: Ransomware (LockBit variant), C2 Tunneling (DNScat2).
- **Zero-Day Feasibility F1**: **0.884** under benchmark validation conditions.
- **Disclaimer**: Synthetic benchmark conditions demonstrate structural transferability, but live real-world zero-day detection metrics may differ.
