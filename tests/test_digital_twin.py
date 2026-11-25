"""
Unit tests for CAIP Digital Twin Simulator (DigitalTwin)
========================================================
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
from app.intelligence.digital_twin import DigitalTwin

def test_digital_twin_simulation_high_risk():
    events = [
        normalize_raw_log({"timestamp": "2026-08-15T10:00:00", "severity": 65, "event_type": "phishing_email", "source": "SIEM", "user": "user01", "source_ip": "10.0.0.5", "domain": "mal.com"}),
        normalize_raw_log({"timestamp": "2026-08-15T10:05:00", "severity": 75, "event_type": "powershell", "source": "EDR", "user": "user01", "source_ip": "10.0.0.5", "domain": "mal.com"}),
        normalize_raw_log({"timestamp": "2026-08-15T10:10:00", "severity": 85, "event_type": "credential_login", "source": "AD", "user": "user01", "source_ip": "10.0.0.5", "domain": "mal.com"}),
        normalize_raw_log({"timestamp": "2026-08-15T10:15:00", "severity": 95, "event_type": "suspicious_dns", "source": "DNS", "user": "user01", "source_ip": "10.0.0.5", "domain": "mal.com"}),
    ]

    twin = DigitalTwin()
    campaign_mock = {"campaign_id": "CAM-TWIN-001", "attack_type": "Ransomware", "risk_score": 90}
    res = twin.simulate(campaign_mock, events)

    assert "blast_radius" in res
    assert "projected_stages" in res
    assert "playbook" in res
    assert res["risk_score"] == 90
    assert len(res["behaviour_log"]) >= 4

def test_digital_twin_empty_events():
    twin = DigitalTwin()
    campaign_mock = {"campaign_id": "CAM-TWIN-002", "attack_type": "Phishing Campaign", "risk_score": 20}
    res = twin.simulate(campaign_mock, [])
    assert "blast_radius" in res
    assert res["blast_radius"]["total_entities"] == 0
