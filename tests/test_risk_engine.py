"""
Unit tests for CAIP Dynamic Risk Scorer (RiskEngine)
====================================================
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

from app.ingestion.normalizer import normalize_raw_log
from app.intelligence.risk_engine import RiskEngine

def test_risk_score_escalation():
    ev_low = normalize_raw_log({"severity": 40, "event_type": "phishing_email", "source": "SIEM"})
    res_low = RiskEngine.get_risk_analysis([ev_low])
    assert res_low["score"] < 50

    evs_high = [
        normalize_raw_log({"severity": 60, "event_type": "phishing_email", "source": "SIEM"}),
        normalize_raw_log({"severity": 75, "event_type": "powershell", "source": "EDR"}),
        normalize_raw_log({"severity": 85, "event_type": "credential_login", "source": "AD"}),
        normalize_raw_log({"severity": 95, "event_type": "suspicious_dns", "source": "DNS"}),
    ]
    res_high = RiskEngine.get_risk_analysis(evs_high)
    assert res_high["score"] >= 80
    assert "Credential access" in res_high["risk_factors"]
    assert "PowerShell execution" in res_high["risk_factors"]

def test_risk_score_empty():
    res_empty = RiskEngine.get_risk_analysis([])
    assert res_empty["score"] == 0
    assert res_empty["risk_factors"] == []
