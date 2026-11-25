"""
Unit tests for CAIP Event Normalizer (normalize_raw_log)
=========================================================
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

from app.ingestion.normalizer import normalize_raw_log, NormalizedEvent

def test_normalize_valid_event():
    raw_event = {
        "event_id": "EVT-TEST-001",
        "timestamp": "2026-08-15T12:00:00",
        "source": "EDR",
        "user": "alice01",
        "source_ip": "10.0.0.15",
        "domain": "login-verify.com",
        "event_type": "phishing_email",
        "severity": 65,
    }
    norm = normalize_raw_log(raw_event)

    assert isinstance(norm, NormalizedEvent)
    assert norm.event_id == "EVT-TEST-001"
    assert norm.user == "alice01"
    assert norm.source_ip == "10.0.0.15"
    assert norm.mitre_technique == "T1566"
    assert norm.mitre_stage == "Initial Access"
    assert norm.severity == 65

def test_normalize_execution_event():
    raw_event = {
        "event_id": "EVT-TEST-002",
        "timestamp": "2026-08-15T12:05:00",
        "source": "SIEM",
        "user": "alice01",
        "event_type": "powershell",
        "severity": 75,
    }
    norm = normalize_raw_log(raw_event)

    assert norm.mitre_technique == "T1059.001"
    assert norm.mitre_stage == "Execution"
    assert norm.severity == 75

def test_normalize_missing_fields_defaults():
    raw_event = {
        "source": "firewall",
        "event_type": "unknown_event",
    }
    norm = normalize_raw_log(raw_event)

    assert norm.user is None
    assert norm.mitre_stage is None
    assert norm.severity == 50
    assert norm.event_id.startswith("EVT-")

def test_sysmon_benign_notepad():
    raw_event = {
        "source": "Sysmon",
        "event_type": "process_creation",
        "process": "C:\\Windows\\System32\\notepad.exe",
        "user": "SYSTEM",
        "device": "DESKTOP-01"
    }
    norm = normalize_raw_log(raw_event)
    assert norm.severity == 10
    assert norm.security_status == "informational"
    assert norm.mitre_technique is None
    assert norm.mitre_stage is None
    assert norm.process_name == "C:\\Windows\\System32\\notepad.exe"

def test_sysmon_powershell_execution():
    raw_event = {
        "source": "Sysmon",
        "event_type": "process_creation",
        "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "alice",
        "device": "DESKTOP-01"
    }
    norm = normalize_raw_log(raw_event)
    assert norm.severity == 50
    assert norm.security_status == "review"
    assert norm.mitre_technique == "T1059.001"
    assert norm.mitre_stage == "Execution"

def test_sysmon_dns_query():
    raw_event = {
        "source": "Sysmon",
        "event_type": "dns_query",
        "domain": "example.com",
        "user": "alice",
        "device": "DESKTOP-01"
    }
    norm = normalize_raw_log(raw_event)
    assert norm.severity == 10
    assert norm.security_status == "informational"
    assert norm.mitre_technique is None
    assert norm.mitre_stage is None

def test_sysmon_credential_access():
    raw_event = {
        "source": "Sysmon",
        "event_type": "process_access",
        "process": "C:\\Windows\\System32\\lsass.exe",
        "user": "SYSTEM",
        "device": "DESKTOP-01"
    }
    norm = normalize_raw_log(raw_event)
    assert norm.severity == 90
    assert norm.security_status == "high_risk"
    assert norm.mitre_technique == "T1003"
    assert norm.mitre_stage == "Credential Access"

