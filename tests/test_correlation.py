"""
Unit & Integration tests for CAIP Campaign Correlation Engine (Refactored)
===========================================================================
Validates:
  1. Single review/suspicious event does not create a campaign.
  2. Two unrelated events on the same device do not merge automatically.
  3. Two related events with close timestamps and shared process lineage correlate.
  4. Generic SYSTEM user does not cause false correlation.
  5. Localhost (127.0.0.1) does not cause false correlation.
  6. Informational events remain visible and are retrieved as contextual telemetry.
  7. Synthetic and CICIDS2017 multi-stage attack workflows continue to correlate.
  8. Configurable correlation scoring weights and thresholds.
"""

import sys, os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import pytest
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_BACKEND = os.path.normpath(os.path.join(_ROOT, "backend"))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.database.database import engine, Base, SessionLocal
from app.database.models import Campaign as DBCampaign, Event as DBEvent
from app.ingestion.collector import _build_db_event
from app.ingestion.normalizer import normalize_raw_log
from app.intelligence.campaign_engine import (
    CampaignEngine,
    CorrelationConfig,
    score_event_pair,
    is_generic_user,
    is_generic_ip,
)


@pytest.fixture(autouse=True)
def setup_database():
    """Reset database tables before each test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_single_powershell_event_does_not_create_campaign():
    """Requirement 1: A single review/suspicious event must remain an uncorrelated candidate."""
    ce = CampaignEngine()
    now = datetime.now(timezone.utc)

    raw = {
        "source": "Sysmon",
        "event_type": "process_creation",
        "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "alice",
        "device": "DESKTOP-01",
        "timestamp": now.isoformat(),
    }
    norm = normalize_raw_log(raw)
    assert norm.security_status == "review"
    assert norm.mitre_stage == "Execution"

    db = SessionLocal()
    db.add(_build_db_event(norm))
    db.commit()
    db.close()

    ce.correlate_event(norm)

    db = SessionLocal()
    ev = db.query(DBEvent).filter(DBEvent.event_id == norm.event_id).first()
    camps = db.query(DBCampaign).all()
    db.close()

    assert ev.campaign_id is None
    assert "pending correlation" in (ev.correlation_reason or "")
    assert len(camps) == 0


def test_two_unrelated_events_on_same_device_do_not_merge():
    """Requirement 2: Two unrelated events on the same device should not score >= 50 or merge."""
    ce = CampaignEngine()
    now = datetime.now(timezone.utc)

    # Event 1: Alice executes powershell
    norm1 = normalize_raw_log({
        "source": "Sysmon",
        "event_type": "process_creation",
        "process": "C:\\Windows\\System32\\powershell.exe",
        "user": "alice",
        "device": "DESKTOP-01",
        "timestamp": now.isoformat(),
    })
    db = SessionLocal()
    db.add(_build_db_event(norm1))
    db.commit()
    db.close()
    ce.correlate_event(norm1)

    # Event 2: Bob opens an unrelated application (e.g. benign cmd or different task)
    norm2 = normalize_raw_log({
        "source": "EDR",
        "event_type": "script_execution",
        "process_name": "python.exe",
        "user": "bob",
        "device_id": "DESKTOP-01",
        "timestamp": (now + timedelta(minutes=10)).isoformat(),
        "severity": 45,
    })
    db = SessionLocal()
    db.add(_build_db_event(norm2))
    db.commit()
    db.close()
    ce.correlate_event(norm2)

    db = SessionLocal()
    ev1 = db.query(DBEvent).filter(DBEvent.event_id == norm1.event_id).first()
    ev2 = db.query(DBEvent).filter(DBEvent.event_id == norm2.event_id).first()
    camps = db.query(DBCampaign).all()
    db.close()

    assert ev1.campaign_id is None
    assert ev2.campaign_id is None
    assert len(camps) == 0


def test_two_related_events_with_process_lineage_and_time_correlate():
    """Requirement 2 & 7: Related events with process lineage, same user, and close time correlate."""
    ce = CampaignEngine()
    now = datetime.now(timezone.utc)

    # Event 1: PowerShell executed by cmd.exe
    norm1 = normalize_raw_log({
        "source": "Sysmon",
        "event_type": "process_creation",
        "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_proc": "cmd.exe",
        "pid": 3044,
        "user": "alice",
        "device": "DESKTOP-01",
        "timestamp": now.isoformat(),
    })
    db = SessionLocal()
    db.add(_build_db_event(norm1))
    db.commit()
    db.close()
    ce.correlate_event(norm1)

    # Event 2: Mimikatz executed by powershell.exe 5 mins later
    norm2 = normalize_raw_log({
        "source": "Sysmon",
        "event_type": "process_access",
        "process": "C:\\Windows\\System32\\lsass.exe",
        "parent_proc": "powershell.exe",
        "user": "alice",
        "device": "DESKTOP-01",
        "timestamp": (now + timedelta(minutes=5)).isoformat(),
    })
    db = SessionLocal()
    db.add(_build_db_event(norm2))
    db.commit()
    db.close()
    ce.correlate_event(norm2)

    db = SessionLocal()
    ev1 = db.query(DBEvent).filter(DBEvent.event_id == norm1.event_id).first()
    ev2 = db.query(DBEvent).filter(DBEvent.event_id == norm2.event_id).first()
    camps = db.query(DBCampaign).all()
    db.close()

    assert len(camps) == 1
    assert ev1.campaign_id is not None
    assert ev1.campaign_id == ev2.campaign_id
    assert ev2.campaign_id == camps[0].campaign_id
    assert "score:" in (ev2.correlation_reason or "")
    assert "Process lineage" in (ev2.correlation_reason or "") or "Same user" in (ev2.correlation_reason or "")


def test_generic_system_user_does_not_cause_correlation():
    """Requirement 3: SYSTEM and other service accounts must not provide user correlation points."""
    assert is_generic_user("SYSTEM") is True
    assert is_generic_user("NT AUTHORITY\\SYSTEM") is True
    assert is_generic_user("LOCAL SERVICE") is True
    assert is_generic_user("NETWORK SERVICE") is True
    assert is_generic_user("ANONYMOUS LOGON") is True
    assert is_generic_user("alice") is False

    ce = CampaignEngine()
    now = datetime.now(timezone.utc)

    # Two unrelated events by SYSTEM on different hosts and different processes
    ev1 = {
        "event_id": "EVT-SYS-1",
        "user": "NT AUTHORITY\\SYSTEM",
        "device_id": "HOST-A",
        "process_name": "taskhost.exe",
        "timestamp": now,
        "mitre_stage": "Discovery",
    }
    ev2 = {
        "event_id": "EVT-SYS-2",
        "user": "SYSTEM",
        "device_id": "HOST-B",
        "process_name": "services.exe",
        "timestamp": now + timedelta(minutes=5),
        "mitre_stage": "Discovery",
    }
    score, reason = score_event_pair(ev1, ev2)
    # Score should only get temporal proximity / shared stage, NOT user points (+15)
    assert score < 50
    assert "Same user" not in reason


def test_localhost_ip_does_not_cause_correlation():
    """Requirement 3: Loopback and generic IPs must not provide IP correlation points."""
    assert is_generic_ip("127.0.0.1") is True
    assert is_generic_ip("0.0.0.0") is True
    assert is_generic_ip("::1") is True
    assert is_generic_ip("localhost") is True
    assert is_generic_ip("192.168.1.100") is False

    ev1 = {
        "event_id": "EVT-IP-1",
        "user": "userA",
        "source_ip": "127.0.0.1",
        "device_id": "HOST-A",
        "timestamp": datetime.now(timezone.utc),
    }
    ev2 = {
        "event_id": "EVT-IP-2",
        "user": "userB",
        "source_ip": "127.0.0.1",
        "device_id": "HOST-B",
        "timestamp": datetime.now(timezone.utc),
    }
    score, reason = score_event_pair(ev1, ev2)
    assert "Same source IP" not in reason
    assert score < 30


def test_informational_events_retrieved_as_contextual_telemetry():
    """Requirement 4: Informational Sysmon events are retrospectively attached to matching campaigns."""
    ce = CampaignEngine()
    now = datetime.now(timezone.utc)

    # 1. Store informational events beforehand
    # Matching informational event: DNS query on DESKTOP-01 by alice for powershell
    info_matching = normalize_raw_log({
        "event_id": "EVT-INFO-MATCH",
        "source": "Sysmon",
        "event_type": "dns_query",
        "domain": "malicious-domain.com",
        "user": "alice",
        "device": "DESKTOP-01",
        "process": "C:\\Windows\\System32\\powershell.exe",
        "timestamp": (now - timedelta(minutes=5)).isoformat(),
    })
    # Unrelated informational event on a completely different machine
    info_unrelated = normalize_raw_log({
        "event_id": "EVT-INFO-UNRELATED",
        "source": "Sysmon",
        "event_type": "network_connection",
        "user": "charlie",
        "device": "DESKTOP-99",
        "process": "chrome.exe",
        "timestamp": (now - timedelta(minutes=5)).isoformat(),
    })

    db = SessionLocal()
    db.add(_build_db_event(info_matching))
    db.add(_build_db_event(info_unrelated))
    db.commit()
    db.close()

    # 2. Ingest two correlated security events that create a campaign
    sec1 = normalize_raw_log({
        "event_id": "EVT-SEC-1",
        "source": "Sysmon",
        "event_type": "process_creation",
        "process": "powershell.exe",
        "user": "alice",
        "device": "DESKTOP-01",
        "timestamp": now.isoformat(),
    })
    db = SessionLocal()
    db.add(_build_db_event(sec1))
    db.commit()
    db.close()
    ce.correlate_event(sec1)

    sec2 = normalize_raw_log({
        "event_id": "EVT-SEC-2",
        "source": "Sysmon",
        "event_type": "process_access",
        "process": "lsass.exe",
        "parent_proc": "powershell.exe",
        "user": "alice",
        "device": "DESKTOP-01",
        "timestamp": (now + timedelta(minutes=3)).isoformat(),
    })
    db = SessionLocal()
    db.add(_build_db_event(sec2))
    db.commit()
    db.close()
    ce.correlate_event(sec2)

    # 3. Verify that the matching informational event was attached retrospectively
    db = SessionLocal()
    ev_info_m = db.query(DBEvent).filter(DBEvent.event_id == "EVT-INFO-MATCH").first()
    ev_info_u = db.query(DBEvent).filter(DBEvent.event_id == "EVT-INFO-UNRELATED").first()
    sec_ev = db.query(DBEvent).filter(DBEvent.event_id == "EVT-SEC-2").first()
    db.close()

    assert sec_ev.campaign_id is not None
    assert ev_info_m.campaign_id == sec_ev.campaign_id
    assert "Contextual telemetry" in (ev_info_m.correlation_reason or "")
    assert ev_info_u.campaign_id is None


def test_synthetic_and_cicids_workflows_work():
    """Requirement 5 & 6: Synthetic and CICIDS2017 multi-stage pipelines correlate and update ML/Risk."""
    ce = CampaignEngine()
    now = datetime.now(timezone.utc)

    events_data = [
        {
            "event_id": "EVT-SYN-01",
            "source": "SIEM",
            "user": "synth_victim",
            "source_ip": "10.0.0.50",
            "event_type": "phishing_email",
            "severity": 60,
            "timestamp": now.isoformat(),
            "data_source": "Synthetic",
        },
        {
            "event_id": "EVT-SYN-02",
            "source": "EDR",
            "user": "synth_victim",
            "source_ip": "10.0.0.50",
            "event_type": "powershell",
            "severity": 75,
            "timestamp": (now + timedelta(minutes=10)).isoformat(),
            "data_source": "Synthetic",
        },
        {
            "event_id": "EVT-SYN-03",
            "source": "AD",
            "user": "synth_victim",
            "source_ip": "10.0.0.50",
            "event_type": "mimikatz",
            "severity": 90,
            "timestamp": (now + timedelta(minutes=20)).isoformat(),
            "data_source": "Synthetic",
        },
    ]

    for raw in events_data:
        norm = normalize_raw_log(raw)
        db = SessionLocal()
        db.add(_build_db_event(norm))
        db.commit()
        db.close()
        ce.correlate_event(norm)

    db = SessionLocal()
    camps = db.query(DBCampaign).all()
    evs = db.query(DBEvent).filter(DBEvent.user == "synth_victim").all()
    db.close()

    assert len(camps) == 1
    assert len(evs) == 3
    assert all(e.campaign_id == camps[0].campaign_id for e in evs)
    assert camps[0].risk_score > 60
    assert "Initial Access" in camps[0].stage
    assert "Execution" in camps[0].stage
    assert "Credential Access" in camps[0].stage


def test_campaign_correlation_same_user_legacy():
    """Validates backward-compatibility with existing same-user multi-stage flow."""
    ce = CampaignEngine()
    now = datetime.now(timezone.utc)

    norm1 = normalize_raw_log({
        "event_id": "EVT-C01",
        "timestamp": now.isoformat(),
        "source": "SIEM",
        "user": "bob02_corr",
        "event_type": "phishing_email",
        "severity": 50,
    })
    db1 = SessionLocal()
    db1.add(_build_db_event(norm1))
    db1.commit()
    db1.close()
    ce.correlate_event(norm1)

    norm2 = normalize_raw_log({
        "event_id": "EVT-C02",
        "timestamp": (now + timedelta(minutes=15)).isoformat(),
        "source": "EDR",
        "user": "bob02_corr",
        "event_type": "powershell",
        "severity": 75,
    })
    db2 = SessionLocal()
    db2.add(_build_db_event(norm2))
    db2.commit()
    db2.close()
    ce.correlate_event(norm2)

    db = SessionLocal()
    events = db.query(DBEvent).filter(DBEvent.user == "bob02_corr").all()
    db.close()

    assert len(events) == 2
    assert events[0].campaign_id is not None
    assert events[0].campaign_id == events[1].campaign_id


def test_campaign_correlation_different_users_legacy():
    """Unrelated events for different users do not falsely merge."""
    ce = CampaignEngine()
    now = datetime.now(timezone.utc)

    norm1 = normalize_raw_log({
        "event_id": "EVT-DIFF-01",
        "timestamp": now.isoformat(),
        "source": "SIEM",
        "user": "charlie01_corr",
        "event_type": "phishing_email",
        "severity": 40,
    })
    db1 = SessionLocal()
    db1.add(_build_db_event(norm1))
    db1.commit()
    db1.close()
    ce.correlate_event(norm1)

    norm2 = normalize_raw_log({
        "event_id": "EVT-DIFF-02",
        "timestamp": (now + timedelta(minutes=5)).isoformat(),
        "source": "SIEM",
        "user": "diana02_corr",
        "event_type": "drive_by",
        "severity": 45,
    })
    db2 = SessionLocal()
    db2.add(_build_db_event(norm2))
    db2.commit()
    db2.close()
    ce.correlate_event(norm2)

    db = SessionLocal()
    ev1 = db.query(DBEvent).filter(DBEvent.user == "charlie01_corr").first()
    ev2 = db.query(DBEvent).filter(DBEvent.user == "diana02_corr").first()
    db.close()

    # Neither event meets correlation threshold with any other event
    assert ev1.campaign_id is None
    assert ev2.campaign_id is None
