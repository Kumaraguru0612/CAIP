"""
Unit tests for CAIP Attack Predictor (AttackPredictor)
======================================================
"""

import sys, os
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_BACKEND = os.path.normpath(os.path.join(_ROOT, "backend"))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.intelligence.attack_predictor import AttackPredictor

@pytest.fixture(scope="module")
def predictor():
    return AttackPredictor()

def test_rule_based_prediction(predictor):
    preds = predictor.predict_next_stages_rule_based(["Initial Access"])
    assert len(preds) > 0
    stages = [p["stage"] for p in preds]
    assert "Execution" in stages
    assert preds[0]["stage"] == "Execution"

def test_rule_based_execution_stage(predictor):
    preds = predictor.predict_next_stages_rule_based(["Initial Access", "Execution"])
    assert len(preds) > 0
    stages = [p["stage"] for p in preds]
    assert "Credential Access" in stages or "Command & Control" in stages

def test_ml_next_stage_prediction(predictor):
    events = [
        {"timestamp": "2026-08-15T10:00:00", "severity": 60, "mitre_stage": "Initial Access", "user": "u1", "source_ip": "10.0.0.1"},
        {"timestamp": "2026-08-15T10:05:00", "severity": 75, "mitre_stage": "Execution", "user": "u1", "source_ip": "10.0.0.1"},
    ]
    ml_preds = predictor.predict_next_stages_ml(events)
    assert len(ml_preds) > 0
    assert "stage" in ml_preds[0]
    assert "probability" in ml_preds[0]
    assert ml_preds[0]["probability"] > 0.0
