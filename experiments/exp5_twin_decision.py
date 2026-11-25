"""
Experiment 5: Digital Twin Decision Quality
============================================
Research question: Does Digital Twin simulation improve decision accuracy
compared to risk-score-only blocking?

SETUP:
  50 HIGH-risk validation campaigns (risk_score >= 70)

  WITHOUT TWIN: Block/Allow decision = risk_score >= 70 → block
  WITH TWIN:    Run simulation, refine using projected stage + blast radius

GROUND TRUTH LABELS:
  Each campaign archetype has a "correct" response action.
  This represents what a human SOC analyst would do with full context.

  Campaign type → correct action:
    ransomware      → BLOCK (always isolate immediately)
    apt_exfiltration→ BLOCK (data already leaving)
    apt_full_chain  → BLOCK (confirmed APT)
    brute_force     → RATE_LIMIT + MFA (don't block immediately — lockout)
    dos_ddos        → RATE_LIMIT (not isolate — need traffic info)
    web_attack      → INVESTIGATE (may be scanner, not confirmed attacker)
    port_scan       → INVESTIGATE (could be internal scan)

METRICS:
  Decision Accuracy, FPR, FNR, Playbook Correctness

IEEE CONTRIBUTION:
  Digital Twin does not just reduce FP/FN — it also provides the
  CORRECT RESPONSE ACTION, not just "block/allow".

NOTE:
  The CAIP Digital Twin is a probabilistic simulation layer.
  It projects behavior and generates playbooks — it does NOT execute
  malware in a VM. This is noted as Phase 5 future work.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import time
import random
import numpy as np
from collections import defaultdict

from shared.metrics import binary_metrics, print_table
from shared.experiment_runner import (
    load_campaigns_from_csv, compute_risk_score, get_campaign_type,
    save_result, ExperimentTimer,
)

random.seed(2024)
np.random.seed(2024)

# Ground truth: campaign type → correct decision
CORRECT_DECISION = {
    "ransomware":        "BLOCK",
    "apt_exfiltration":  "BLOCK",
    "apt_full_chain":    "BLOCK",
    "brute_force":       "RATE_LIMIT",
    "dos_ddos":          "RATE_LIMIT",
    "web_attack":        "INVESTIGATE",
    "port_scan":         "INVESTIGATE",
    "unknown":           "INVESTIGATE",
}

# Risk-score only: maps risk level to action
RISK_SCORE_DECISION = {
    "HIGH":   "BLOCK",
    "MEDIUM": "INVESTIGATE",
    "LOW":    "MONITOR",
}


def get_risk_level(risk_score: int) -> str:
    if risk_score >= 70: return "HIGH"
    if risk_score >= 40: return "MEDIUM"
    return "LOW"


def twin_decision(campaign_type: str, events: list, risk_score: int) -> dict:
    """
    Simulate Digital Twin decision refinement.
    In the real system, this calls digital_twin.py.
    Here we replicate the logic without ORM dependency.
    """
    # Blast radius estimation
    users   = {e.get("user") for e in events if e.get("user")}
    ips     = {e.get("source_ip") for e in events if e.get("source_ip")}
    domains = {e.get("domain") for e in events if e.get("domain")}
    blast   = len(users) + len(ips) + len(domains)

    # Stage analysis
    stages = {e.get("mitre_stage") for e in events if e.get("mitre_stage")}
    has_exfil   = any("Exfil" in s for s in stages)
    has_lateral = any("Lateral" in s for s in stages)
    has_ransom  = any("Impact" in s for s in stages) or campaign_type == "ransomware"

    # Twin decision logic (mirrors digital_twin.py playbook selection)
    if has_ransom or has_exfil:
        decision = "BLOCK"
        confidence = 0.92
    elif has_lateral and blast >= 3:
        decision = "BLOCK"
        confidence = 0.87
    elif campaign_type in ("dos_ddos", "port_scan"):
        decision = "RATE_LIMIT"
        confidence = 0.82
    elif campaign_type == "brute_force":
        decision = "RATE_LIMIT"
        confidence = 0.79
    else:
        decision = "INVESTIGATE"
        confidence = 0.71

    # Adjust for risk score
    if risk_score >= 90 and decision == "INVESTIGATE":
        decision = "BLOCK"
        confidence = min(confidence + 0.08, 0.99)

    return {"decision": decision, "confidence": confidence, "blast": blast}


def run_experiment():
    print("\n" + "=" * 65)
    print("  EXPERIMENT 5: Digital Twin Decision Quality")
    print("=" * 65)

    print("\n[1/3] Loading high-risk campaigns...")
    val_campaigns = load_campaigns_from_csv("caip_validation_set.csv")

    # Select HIGH-risk campaigns (risk_score >= 70)
    high_risk = {
        cid: events
        for cid, events in val_campaigns.items()
        if compute_risk_score(events) >= 70
    }
    print(f"      High-risk campaigns (score >= 70): {len(high_risk)}")
    if not high_risk:
        print("      WARNING: No high-risk campaigns found. Using all validation campaigns.")
        high_risk = val_campaigns

    print("\n[2/3] Running Without-Twin vs With-Twin decisions...")

    without_twin = []
    with_twin    = []

    twin_time_total = 0.0

    for cid, events in high_risk.items():
        risk_score   = compute_risk_score(events)
        risk_level   = get_risk_level(risk_score)
        camp_type    = get_campaign_type(events)
        correct_act  = CORRECT_DECISION.get(camp_type, "INVESTIGATE")

        # ── Without Twin ──────────────────────────────────────────────────────
        wo_decision = RISK_SCORE_DECISION[risk_level]
        wo_correct  = int(wo_decision == correct_act)

        without_twin.append({
            "campaign_id":  cid,
            "risk_score":   risk_score,
            "camp_type":    camp_type,
            "decision":     wo_decision,
            "correct_act":  correct_act,
            "correct":      wo_correct,
        })

        # ── With Twin ─────────────────────────────────────────────────────────
        start = time.perf_counter()
        result = twin_decision(camp_type, events, risk_score)
        twin_ms = (time.perf_counter() - start) * 1000
        twin_time_total += twin_ms

        w_decision = result["decision"]
        w_correct  = int(w_decision == correct_act)

        with_twin.append({
            "campaign_id":   cid,
            "risk_score":    risk_score,
            "camp_type":     camp_type,
            "decision":      w_decision,
            "confidence":    result["confidence"],
            "correct_act":   correct_act,
            "correct":       w_correct,
            "twin_ms":       twin_ms,
            "blast":         result["blast"],
        })

    # ── Metrics ───────────────────────────────────────────────────────────────
    wo_acc = sum(r["correct"] for r in without_twin) / len(without_twin) if without_twin else 0
    w_acc  = sum(r["correct"] for r in with_twin) / len(with_twin) if with_twin else 0

    # Block = positive class (over-blocking = FP; missing block = FN)
    def compute_decision_metrics(records):
        block_tp = sum(1 for r in records if r["decision"] == "BLOCK" and r["correct_act"] == "BLOCK")
        block_fp = sum(1 for r in records if r["decision"] == "BLOCK" and r["correct_act"] != "BLOCK")
        block_fn = sum(1 for r in records if r["decision"] != "BLOCK" and r["correct_act"] == "BLOCK")
        block_tn = sum(1 for r in records if r["decision"] != "BLOCK" and r["correct_act"] != "BLOCK")
        prec   = block_tp / (block_tp + block_fp) if (block_tp + block_fp) > 0 else 0
        recall = block_tp / (block_tp + block_fn) if (block_tp + block_fn) > 0 else 0
        fpr    = block_fp / (block_fp + block_tn) if (block_fp + block_tn) > 0 else 0
        fnr    = block_fn / (block_fn + block_tp) if (block_fn + block_tp) > 0 else 0
        f1     = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
        return {"precision": round(prec, 4), "recall": round(recall, 4),
                "f1": round(f1, 4), "fpr": round(fpr, 4), "fnr": round(fnr, 4)}

    wo_metrics = compute_decision_metrics(without_twin)
    w_metrics  = compute_decision_metrics(with_twin)

    avg_twin_ms = twin_time_total / len(with_twin) if with_twin else 0

    print("\n[3/3] Results:")
    print_table(
        "Experiment 5: Decision Quality — Without vs With Twin",
        [
            ["n_campaigns",       len(without_twin),           len(with_twin)],
            ["Decision Accuracy", f"{wo_acc:.4f}",             f"{w_acc:.4f}"],
            ["BLOCK Precision",   wo_metrics["precision"],     w_metrics["precision"]],
            ["BLOCK Recall",      wo_metrics["recall"],        w_metrics["recall"]],
            ["BLOCK F1",          wo_metrics["f1"],            w_metrics["f1"]],
            ["False Positive Rate",wo_metrics["fpr"],          w_metrics["fpr"]],
            ["False Negative Rate",wo_metrics["fnr"],          w_metrics["fnr"]],
            ["Avg analysis time", "< 1ms (no twin)",           f"{avg_twin_ms:.2f}ms"],
        ],
        ["Metric", "Without Twin", "With Twin"],
    )

    # Per campaign-type breakdown
    type_wo = defaultdict(lambda: {"n": 0, "correct": 0})
    type_w  = defaultdict(lambda: {"n": 0, "correct": 0})
    for r in without_twin:
        type_wo[r["camp_type"]]["n"] += 1
        type_wo[r["camp_type"]]["correct"] += r["correct"]
    for r in with_twin:
        type_w[r["camp_type"]]["n"] += 1
        type_w[r["camp_type"]]["correct"] += r["correct"]

    print("\n  Decision Accuracy by Campaign Type:")
    print(f"  {'Type':<25} {'W/o Twin':>10} {'With Twin':>10} {'n':>5}")
    print("  " + "-" * 52)
    for t in sorted(set(type_wo) | set(type_w)):
        wo = type_wo[t]
        wt = type_w[t]
        wo_r = wo["correct"] / wo["n"] if wo["n"] else 0
        wt_r = wt["correct"] / wt["n"] if wt["n"] else 0
        delta = "+" if wt_r > wo_r else ("-" if wt_r < wo_r else "=")
        print(f"  {t:<25} {wo_r:>10.2%} {wt_r:>10.2%} {wo['n']:>5} {delta}")

    result = {
        "experiment":      "exp5_twin_decision_quality",
        "n_high_risk":     len(high_risk),
        "without_twin": {
            "decision_accuracy": round(wo_acc, 4),
            **wo_metrics,
        },
        "with_twin": {
            "decision_accuracy": round(w_acc, 4),
            **w_metrics,
            "avg_twin_ms": round(avg_twin_ms, 2),
        },
        "type_breakdown_without": dict(type_wo),
        "type_breakdown_with":    dict(type_w),
    }

    save_result("exp5_results", result)
    return result


if __name__ == "__main__":
    run_experiment()
