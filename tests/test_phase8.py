"""
Tests for Phase 8 — SOC Orchestration, SLA Performance, and Real Sysmon Validation
==================================================================================
Verifies:
  • 8.2 — Automated Incident Assignment (load-balanced assignment based on open queues)
  • 8.3 — Notification & Alerting Engine (broadcast, unread count, read tracking)
  • 8.4 — SLA & SOC Performance Tracking (MTTD, MTTA, MTTC, MTTR, SLA register)
  • 8.5 — Analyst Workload Dashboard (operations overview, load percentages)
  • 8.6 — Real Sysmon Live Attack Validation (Scenario A, B, and C with actual Windows Sysmon Event IDs)
"""

import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.database.database import Base, SessionLocal, engine
from app.database.models import (
    Campaign as DBCampaign, 
    Event as DBEvent, 
    SOCIncident, 
    CaseEvidence, 
    CaseNote,
    Notification
)
from app.intelligence.incident_engine import IncidentEngine
from app.intelligence.notification_engine import NotificationEngine
from app.intelligence.soc_ops_engine import SOCOpsEngine
from app.intelligence.sysmon_lab_validator import SysmonLabValidator
from app.main import app


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    session.query(Notification).delete()
    session.query(CaseEvidence).delete()
    session.query(CaseNote).delete()
    session.query(SOCIncident).delete()
    session.query(DBEvent).delete()
    session.query(DBCampaign).delete()
    session.commit()
    yield session
    session.close()


@pytest.fixture(scope="function")
def client(db_session):
    return TestClient(app)


def test_8_2_automated_incident_assignment(db_session):
    """
    Phase 8.2: If Analyst A has 5 open cases and Analyst B has 2 open cases,
    a newly escalated critical incident must automatically be assigned to Analyst B.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # Seed base campaign
    camp = DBCampaign(
        campaign_id="CAMP-WORKLOAD-TEST",
        target="WORKSTATION-01",
        attack_type="Privilege Escalation",
        stage="Privilege Escalation",
        confidence=0.92,
        risk="CRITICAL",
        risk_score=95
    )
    db_session.add(camp)

    # Seed Analyst A with 5 open cases
    for i in range(5):
        inc_a = SOCIncident(
            incident_id=f"INC-A-{i:03d}",
            campaign_id="CAMP-WORKLOAD-TEST",
            title=f"Case A{i}",
            severity="HIGH",
            priority="P2 - High",
            status="Investigating",
            assigned_to="SOC Analyst A",
            created_at=now
        )
        db_session.add(inc_a)

    # Seed Analyst B with 2 open cases
    for i in range(2):
        inc_b = SOCIncident(
            incident_id=f"INC-B-{i:03d}",
            campaign_id="CAMP-WORKLOAD-TEST",
            title=f"Case B{i}",
            severity="MEDIUM",
            priority="P3 - Medium",
            status="Investigating",
            assigned_to="SOC Analyst B",
            created_at=now
        )
        db_session.add(inc_b)

    db_session.commit()

    engine = IncidentEngine()
    workloads = engine.get_analyst_workloads(db_session)
    assert workloads["SOC Analyst A"] == 5
    assert workloads["SOC Analyst B"] == 2

    # Create new critical incident without manual assignment
    new_inc = engine.create_incident(
        campaign_id="CAMP-WORKLOAD-TEST",
        title="Critical Mimikatz Credential Theft",
        severity="CRITICAL",
        priority="P1 - Critical",
        assigned_to="Unassigned",
        auto_assign=True,
        db=db_session
    )

    # Verify auto-assigned to SOC Analyst B (lowest workload)
    assert new_inc["assigned_to"] == "SOC Analyst B"
    assert new_inc["status"] == "Assigned"


def test_8_3_notification_and_alerting_engine(db_session):
    """
    Phase 8.3: Tests in-app notification center broadcast and unread tracking.
    """
    notif_engine = NotificationEngine()

    # 1. Broadcast notifications
    n1 = notif_engine.create_notification(
        type="CRITICAL_INCIDENT",
        title="🔴 Critical Incident Opened: INC-2026-0042",
        message="Active LSASS credential theft confirmed.",
        severity="CRITICAL",
        link_type="incident",
        link_id="INC-2026-0042",
        db=db_session
    )
    n2 = notif_engine.create_notification(
        type="CONTAINMENT",
        title="✅ Host Contained",
        message="WORKSTATION-01 isolated from subnet.",
        severity="INFO",
        link_type="incident",
        link_id="INC-2026-0042",
        db=db_session
    )

    assert notif_engine.get_unread_count(db_session) == 2

    # 2. Mark single as read
    notif_engine.mark_as_read(n1["notification_id"], db_session)
    assert notif_engine.get_unread_count(db_session) == 1

    # 3. Mark all as read
    notif_engine.mark_all_as_read(db_session)
    assert notif_engine.get_unread_count(db_session) == 0


def test_8_4_sla_and_performance_tracking(db_session):
    """
    Phase 8.4: Track and compute MTTD, MTTA, MTTC, and MTTR.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    camp = DBCampaign(
        campaign_id="CAMP-SLA-TEST",
        target="FINANCE-01",
        attack_type="Ransomware Preparation",
        stage="Execution",
        confidence=0.9,
        risk="HIGH",
        risk_score=85,
        created_at=now
    )
    db_session.add(camp)

    # Telemetry event 3 minutes prior
    event = DBEvent(
        event_id="EVT-SLA-1",
        campaign_id="CAMP-SLA-TEST",
        timestamp=now - timedelta(minutes=3),
        source="Sysmon",
        event_type="Process Create",
        process_name="powershell.exe",
        severity=8
    )
    db_session.add(event)

    # Incident with triage, containment, resolution times
    inc = SOCIncident(
        incident_id="INC-SLA-001",
        campaign_id="CAMP-SLA-TEST",
        title="Ransomware Shadow Copy Deletion",
        severity="CRITICAL",
        priority="P1 - Critical",
        status="Closed",
        assigned_to="SOC Analyst A",
        created_at=now,
        triage_at=now + timedelta(minutes=4),       # MTTA = 4 min
        contained_at=now + timedelta(minutes=12),   # MTTC = 12 min
        resolved_at=now + timedelta(minutes=28),    # MTTR = 28 min
        sla_due_at=now + timedelta(hours=4),
        sla_status="Within SLA"
    )
    db_session.add(inc)
    db_session.commit()

    ops_engine = SOCOpsEngine()
    metrics = ops_engine.get_soc_performance_metrics(db_session)

    assert "mttd" in metrics
    assert "mtta" in metrics
    assert "mttc" in metrics
    assert "mttr" in metrics
    assert "min" in metrics["mtta"]["display"]
    assert "min" in metrics["mttc"]["display"]


def test_8_5_analyst_workload_breakdown(db_session):
    """
    Phase 8.5: Test SOC Operations Overview and Analyst Workload Distribution bars.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    camp = DBCampaign(
        campaign_id="CAMP-OPS-TEST",
        target="DESKTOP-05",
        attack_type="Intrusion",
        stage="Initial Access",
        confidence=0.8,
        risk="MEDIUM",
        risk_score=60
    )
    db_session.add(camp)

    # 3 active cases for Analyst A, 1 active for Analyst B
    for i in range(3):
        db_session.add(SOCIncident(
            incident_id=f"INC-OP-A{i}",
            campaign_id="CAMP-OPS-TEST",
            title=f"Incident A{i}",
            severity="HIGH",
            priority="P2 - High",
            status="Investigating",
            assigned_to="SOC Analyst A",
            created_at=now,
            sla_due_at=now + timedelta(hours=8)
        ))

    db_session.add(SOCIncident(
        incident_id="INC-OP-B1",
        campaign_id="CAMP-OPS-TEST",
        title="Incident B1",
        severity="LOW",
        priority="P3 - Medium",
        status="Investigating",
        assigned_to="SOC Analyst B",
        created_at=now,
        sla_due_at=now + timedelta(hours=24)
    ))
    db_session.commit()

    ops_engine = SOCOpsEngine()
    overview = ops_engine.get_operations_overview(db_session)
    workloads = ops_engine.get_analyst_workload_breakdown(db_session)

    assert overview["open_incidents"] == 4
    assert overview["closed_incidents"] == 0

    analyst_a = next(w for w in workloads if w["analyst_name"] == "SOC Analyst A")
    analyst_b = next(w for w in workloads if w["analyst_name"] == "SOC Analyst B")

    assert analyst_a["active_cases"] == 3
    assert analyst_b["active_cases"] == 1
    assert analyst_a["load_percentage"] > analyst_b["load_percentage"]


def test_8_6_real_sysmon_live_attack_validation(db_session):
    """
    Phase 8.6: Live attack validation using real Windows Sysmon telemetry schemas:
      • Scenario A: PowerShell Detection (Sysmon Event ID 1)
      • Scenario B: Discovery Sequence (whoami -> systeminfo -> net view)
      • Scenario C: Suspicious Network Activity (Event ID 1 -> Event ID 22 DNS -> Event ID 3 Network)
    """
    validator = SysmonLabValidator()
    report = validator.run_all_validation_scenarios(db_session)

    assert report["all_scenarios_passed"] is True
    scenarios = report["scenarios"]
    assert len(scenarios) == 3

    # Scenario A verification: PowerShell -> Sysmon Event ID 1 -> CAIP Detection Rule
    assert scenarios[0]["passed"] is True
    assert scenarios[0]["detection_rule"] is not None
    assert scenarios[0]["security_status"] in ["high_risk", "critical"]

    # Scenario B verification
    assert scenarios[1]["passed"] is True
    assert scenarios[1]["final_campaign_id"] is not None

    # Scenario C verification
    assert scenarios[2]["passed"] is True
    assert scenarios[2]["c2_domain"] == "beacon-channel-sync.xyz"
    assert scenarios[2]["destination_ip"] == "198.51.100.77"


def test_phase8_api_endpoints(client, db_session):
    """
    Test Phase 8 REST endpoints:
      • /api/v1/notifications
      • /api/v1/notifications/unread-count
      • /api/v1/soc-ops/overview
      • /api/v1/soc-ops/performance
      • /api/v1/soc-ops/workload
      • /api/v1/soc-ops/sla
      • /api/v1/sysmon-lab/validate
    """
    # 1. Notifications endpoints
    res = client.get("/api/v1/notifications")
    assert res.status_code == 200

    res = client.get("/api/v1/notifications/unread-count")
    assert res.status_code == 200
    assert "unread_count" in res.json()

    # 2. SOC Ops endpoints
    res = client.get("/api/v1/soc-ops/overview")
    assert res.status_code == 200
    assert "open_incidents" in res.json()

    res = client.get("/api/v1/soc-ops/performance")
    assert res.status_code == 200
    assert "mttd" in res.json()
    assert "mttr" in res.json()

    res = client.get("/api/v1/soc-ops/workload")
    assert res.status_code == 200
    assert len(res.json()) >= 3

    res = client.get("/api/v1/soc-ops/sla")
    assert res.status_code == 200

    # 3. Sysmon lab validation endpoint
    res = client.post("/api/v1/sysmon-lab/validate")
    assert res.status_code == 200
    assert res.json()["all_scenarios_passed"] is True
