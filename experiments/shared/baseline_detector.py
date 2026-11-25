"""
CAIP Baseline Detector
========================
Implements the "individual alert" baseline system for comparison.

Architecture:
  Event → Per-event XGBoost binary classifier → Alert (malicious / benign)

This is the system CAIP is compared against. It processes each event
independently with no campaign correlation, no graph context, no prediction.
Every malicious-classified event generates a separate alert.

This is representative of traditional SIEM rule-based alerting where each
signature match fires independently.
"""

import csv
import os
import random
import numpy as np
import xgboost as xgb
from collections import defaultdict

random.seed(2024)
np.random.seed(2024)

# ── Event type one-hot encoding (covers all CAIP event types) ─────────────────
EVENT_TYPES = [
    "phishing_email", "url_visit", "sql_injection", "xss_attack",
    "vulnerability_exploit", "powershell", "script_execution", "macro_execution",
    "brute_force", "credential_login", "ftp_brute_force", "ssh_brute_force",
    "network_scan", "port_scan", "system_enum", "lateral_rdp", "lateral_smb",
    "data_staged", "dns_beacon", "http_c2", "suspicious_dns", "c2_beacon",
    "exfil_https", "exfil_ftp", "dns_exfil", "ransomware_encrypt",
    "dos_flood", "ddos_flood", "service_stop", "scheduled_task",
    # Benign event types (for realistic FPR)
    "normal_login", "normal_dns", "normal_http", "software_update",
    "file_access", "email_send", "vpn_connect", "backup_job",
]
ETYPE_IDX = {e: i for i, e in enumerate(EVENT_TYPES)}
N_EVENT_TYPES = len(EVENT_TYPES)

# ── Benign event generation ───────────────────────────────────────────────────
BENIGN_EVENT_TYPES = [
    "normal_login", "normal_dns", "normal_http", "software_update",
    "file_access", "email_send", "vpn_connect", "backup_job",
]


def generate_benign_events(n: int) -> list[dict]:
    """
    Generate synthetic benign events representing normal business activity.
    These have low severity (5-35) and normal event types.
    Required for realistic False Positive Rate measurement.
    """
    events = []
    for i in range(n):
        etype = random.choice(BENIGN_EVENT_TYPES)
        events.append({
            "event_id":      f"BENIGN-{i:05d}",
            "event_type":    etype,
            "severity":      random.randint(5, 35),
            "mitre_stage":   None,
            "mitre_technique": None,
            "source_ip":     f"10.{random.randint(0,5)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "user":          f"user{random.randint(1,50):02d}",
            "label":         0,   # benign
            "campaign_id":   f"BENIGN-CAMP-{i // 5:04d}",
        })
    return events


# ── Feature extraction for individual events ──────────────────────────────────

def extract_event_features(event: dict) -> np.ndarray:
    """
    Extract a feature vector from a single event for the baseline classifier.
    Features:
      - severity (normalised 0-1)
      - one-hot event type (N_EVENT_TYPES dims)
      - has_mitre_stage (bool)
      - stage_severity (severity × has_stage)
    Total: 2 + N_EVENT_TYPES features
    """
    sev = float(event.get("severity", 50)) / 100.0
    etype = str(event.get("event_type", "")).lower().strip()
    etype_vec = np.zeros(N_EVENT_TYPES)
    if etype in ETYPE_IDX:
        etype_vec[ETYPE_IDX[etype]] = 1.0

    has_stage = 1.0 if event.get("mitre_stage") else 0.0
    stage_sev = sev * has_stage

    return np.concatenate([[sev, has_stage, stage_sev], etype_vec])


# ── Baseline Detector class ───────────────────────────────────────────────────

class BaselineDetector:
    """
    Per-event binary classifier (malicious vs benign).
    Represents a traditional SIEM / signature-based alerting system.

    Training:
      - Positive (malicious) examples: events from the CAIP attack dataset
      - Negative (benign) examples: synthetic normal business activity
      - Classifier: XGBoost binary (fast, representative of ML-enhanced SIEM)

    Prediction:
      - One prediction per event
      - One alert per malicious-classified event
      - No grouping, no correlation, no campaign context
    """

    def __init__(self, dataset_path: str = None):
        self.model: xgb.XGBClassifier | None = None
        self.threshold = 0.5

        if dataset_path and os.path.exists(dataset_path):
            self._train(dataset_path)

    def _train(self, dataset_path: str):
        """Train on attack events (label=1) + synthetic benign events (label=0)."""
        # Load attack events
        attack_events = []
        with open(dataset_path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                row["label"] = 1
                row["severity"] = int(row.get("severity", 50))
                attack_events.append(row)

        # Generate balanced benign events
        n_benign = len(attack_events)
        benign_events = generate_benign_events(n_benign)

        all_events = attack_events + benign_events
        random.shuffle(all_events)

        X = np.array([extract_event_features(e) for e in all_events])
        y = np.array([int(e.get("label", 0)) for e in all_events])

        # 80/20 split
        split = int(0.8 * len(all_events))
        X_train, y_train = X[:split], y[:split]

        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.85,
            colsample_bytree=0.8,
            random_state=2024,
            eval_metric="logloss",
            verbosity=0,
        )
        self.model.fit(X_train, y_train)

        # Internal validation
        if len(X) > split:
            from sklearn.metrics import f1_score
            X_val, y_val = X[split:], y[split:]
            y_pred = self.model.predict(X_val)
            f1 = f1_score(y_val, y_pred)
            print(f"  [BaselineDetector] Trained. Internal val F1: {f1:.4f} (n={len(X_val)})")

    def predict_event(self, event: dict) -> dict:
        """
        Predict whether a single event is malicious.
        Returns: {"label": 0|1, "confidence": float, "alert_generated": bool}
        """
        if self.model is None:
            # Fallback: threshold on severity
            sev = float(event.get("severity", 50))
            label = 1 if sev >= 60 else 0
            return {"label": label, "confidence": sev / 100, "alert_generated": label == 1}

        X = extract_event_features(event).reshape(1, -1)
        prob = float(self.model.predict_proba(X)[0][1])
        label = 1 if prob >= self.threshold else 0
        return {"label": label, "confidence": prob, "alert_generated": label == 1}

    def process_events(self, events: list[dict]) -> dict:
        """
        Process a list of events independently (no correlation).

        Returns summary:
          total_events, alerts_generated, true_positives, false_positives,
          true_negatives, false_negatives, precision, recall, f1, fpr
        """
        tp = fp = tn = fn = 0
        alerts = []

        for event in events:
            result = self.predict_event(event)
            true_label = int(event.get("label", 1))  # default: malicious (attack dataset)
            pred_label = result["label"]

            if pred_label == 1 and true_label == 1: tp += 1
            elif pred_label == 1 and true_label == 0: fp += 1
            elif pred_label == 0 and true_label == 0: tn += 1
            else: fn += 1

            if result["alert_generated"]:
                alerts.append({
                    "event_id":   event.get("event_id", ""),
                    "event_type": event.get("event_type", ""),
                    "confidence": result["confidence"],
                    "true_label": true_label,
                })

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

        return {
            "total_events":      len(events),
            "alerts_generated":  len(alerts),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision":  round(precision, 4),
            "recall":     round(recall, 4),
            "f1":         round(f1, 4),
            "fpr":        round(fpr, 4),
            "alerts":     alerts,
        }
