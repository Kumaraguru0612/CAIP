"""
Tests for Phase 7 — SOC Incident & Case Management Architecture
===============================================================
Verifies:
  • 7.1 — Incident / Case Management (SOCIncident model, fields, campaign linkage)
  • 7.2 — Evidence Management (CaseEvidence, entity marking, retrieval, removal)
  • 7.3 — Analyst Notes & Combined Investigation Timeline (automated + analyst + status changes)
  • 7.4 — Analyst Assignment & Ownership (Unassigned, Analyst A/B, Lead, Priority P1-P4)
  • 7.5 — Case Status Workflow (Separate Campaign vs Incident lifecycle)
  • 7.6 — Investigation Report Generation (Structured JSON & Markdown report generation)
  • Fast API REST endpoints (/api/v1/incidents, evidence, notes, timeline, report)
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database.database import Base, SessionLocal, engine
from app.database.models import (
    Campaign as DBCampaign, 
    Event as DBEvent, 
    SOCIncident, 
    CaseEvidence, 
    CaseNote
)
from app.intelligence.incident_engine import IncidentEngine
from app.main import app


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
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


def test_7_1_incident_creation_and_fields(db_session):
    """Test 7.1: SOCIncident model creation and proper campaign linkage."""
    # Seed a campaign
    camp = DBCampaign(
        campaign_id="CAMPAIGN-DBDA6D",
        target="WORKSTATION-01",
        attack_type="Credential Theft",
        stage="Execution -> Credential Access",
        confidence=0.94,
        risk="CRITICAL",
        risk_score=95
    )
    db_session.add(camp)
    db_session.commit()

    engine = IncidentEngine()
    inc = engine.create_incident(
        campaign_id="CAMPAIGN-DBDA6D",
        title="Possible Credential Theft on WORKSTATION-01",
        severity="CRITICAL",
        priority="P1 - Critical",
        assigned_to="SOC Analyst 1",
        db=db_session
    )

    assert inc is not None
    assert inc["incident_id"].startswith("INC-")
    assert inc["campaign_id"] == "CAMPAIGN-DBDA6D"
    assert inc["severity"] == "CRITICAL"
    assert inc["priority"] == "P1 - Critical"
    assert inc["assigned_to"] == "SOC Analyst 1"
    assert inc["status"] in ["New", "Assigned"]
    assert inc["campaign"]["attack_type"] == "Credential Theft"


def test_7_2_evidence_management(db_session):
    """Test 7.2: Marking events, processes, domains, and hashes as case evidence."""
    camp = DBCampaign(
        campaign_id="CAMPAIGN-TEST01",
        target="DESKTOP-01",
        attack_type="Adversary Intrusion",
        stage="Execution",
        confidence=0.85,
        risk="HIGH",
        risk_score=80
    )
    db_session.add(camp)
    db_session.commit()

    engine = IncidentEngine()
    inc = engine.create_incident(campaign_id="CAMPAIGN-TEST01", db=db_session)
    inc_id = inc["incident_id"]

    # 1. Add Process evidence
    inc_after = engine.add_evidence(
        incident_id=inc_id,
        entity_type="process",
        entity_value="powershell.exe",
        reason="Encoded command cradle execution",
        added_by="SOC Analyst A",
        db=db_session
    )
    # 2. Add Domain evidence
    inc_after = engine.add_evidence(
        incident_id=inc_id,
        entity_type="domain",
        entity_value="evil-domain.com",
        reason="External C2 DNS beaconing",
        added_by="SOC Analyst A",
        db=db_session
    )
    # 3. Add Hash evidence
    inc_after = engine.add_evidence(
        incident_id=inc_id,
        entity_type="hash",
        entity_value="a3c5e8b1d2f40987654321fedcba0987654321fedcba0987654321fedcba0987",
        reason="Malicious dropper SHA256",
        added_by="SOC Analyst A",
        db=db_session
    )

    assert inc_after["evidence_count"] == 3
    ev_values = [e["entity_value"] for e in inc_after["evidence"]]
    assert "powershell.exe" in ev_values
    assert "evil-domain.com" in ev_values

    # Remove evidence
    target_ev_id = inc_after["evidence"][0]["evidence_id"]
    inc_removed = engine.remove_evidence(inc_id, target_ev_id, db_session)
    assert inc_removed["evidence_count"] == 2


def test_7_3_analyst_notes_and_combined_timeline(db_session):
    """Test 7.3: Combined investigation timeline with automated events, analyst actions, and status transitions."""
    now = datetime.utcnow()
    camp = DBCampaign(
        campaign_id="CAMPAIGN-DBDA6D",
        target="WORKSTATION-01",
        attack_type="Credential Theft",
        stage="Execution",
        confidence=0.9,
        risk="HIGH",
        risk_score=85
    )
    db_session.add(camp)

    # Telemetry events
    e1 = DBEvent(
        event_id="EVT-001",
        campaign_id="CAMPAIGN-DBDA6D",
        timestamp=now,
        source="Sysmon",
        event_type="Process Create",
        process_name="powershell.exe",
        severity=7,
        detection_reason="Encoded PowerShell cradle execution"
    )
    db_session.add(e1)
    db_session.commit()

    engine = IncidentEngine()
    inc = engine.create_incident(campaign_id="CAMPAIGN-DBDA6D", db=db_session)
    inc_id = inc["incident_id"]

    # Analyst adds notes
    engine.add_note(
        incident_id=inc_id,
        content="Confirmed suspicious PowerShell execution. Investigating LSASS access.",
        author="SOC Analyst A",
        author_type="ANALYST",
        action_tag="INVESTIGATION",
        db=db_session
    )
    engine.add_note(
        incident_id=inc_id,
        content="Endpoint isolated from network via SOAR playbook.",
        author="SOC Analyst A",
        author_type="ANALYST",
        action_tag="CONTAINMENT",
        db=db_session
    )

    # Fetch combined timeline
    timeline = engine.get_incident_timeline(inc_id, db_session)
    assert len(timeline) >= 3  # Telemetry Event + 2 Analyst Notes + initial system note

    types = [t["type"] for t in timeline]
    assert "TELEMETRY_EVENT" in types
    assert "ANALYST_ACTION" in types

    action_tags = [t.get("action_tag") for t in timeline if t.get("action_tag")]
    assert "INVESTIGATION" in action_tags
    assert "CONTAINMENT" in action_tags


def test_7_4_and_7_5_workflow_and_assignment_separation(db_session):
    """Test 7.4 & 7.5: Analyst assignment and separation of campaign vs incident status."""
    camp = DBCampaign(
        campaign_id="CAMPAIGN-LIFE",
        target="FINANCE-PC",
        attack_type="Ransomware Preparation",
        stage="Discovery",
        confidence=0.88,
        risk="HIGH",
        risk_score=82,
        status="Active Campaign"  # Threat status
    )
    db_session.add(camp)
    db_session.commit()

    engine = IncidentEngine()
    inc = engine.create_incident(campaign_id="CAMPAIGN-LIFE", db=db_session)
    inc_id = inc["incident_id"]

    # 1. Update assignment
    updated_inc = engine.update_incident(
        inc_id,
        {"assigned_to": "SOC Lead", "priority": "P1 - Critical"},
        db_session
    )
    assert updated_inc["assigned_to"] == "SOC Lead"
    assert updated_inc["priority"] == "P1 - Critical"
    assert updated_inc["status"] == "Assigned"

    # 2. Advance Incident Status: Assigned -> Investigating -> Closed
    engine.update_incident(inc_id, {"status": "Investigating"}, db_session)
    closed_inc = engine.update_incident(
        inc_id,
        {"status": "Closed", "resolution_summary": "Threat neutralized, workstation restored."},
        db_session
    )

    assert closed_inc["status"] == "Closed"
    assert closed_inc["resolved_at"] is not None

    # Verify Campaign status remained independent:
    db_session.refresh(camp)
    assert camp.status == "Active Campaign"  # Untouched


def test_7_6_investigation_report_generation(db_session):
    """Test 7.6: Investigation Report Generation (Markdown + structured JSON)."""
    now = datetime.utcnow()
    camp = DBCampaign(
        campaign_id="CAMPAIGN-DBDA6D",
        target="WORKSTATION-01",
        attack_type="Credential Theft",
        stage="Credential Access",
        confidence=0.95,
        risk="CRITICAL",
        risk_score=100,
        status="Contained"
    )
    db_session.add(camp)

    # Add events with processes, domains, LSASS access
    e1 = DBEvent(
        event_id="EVT-101",
        campaign_id="CAMPAIGN-DBDA6D",
        timestamp=now,
        source="Sysmon",
        event_type="Process Create",
        process_name="powershell.exe",
        domain="evil-domain.com",
        device_id="WORKSTATION-01",
        severity=8,
        detection_reason="Suspicious PowerShell Execution"
    )
    e2 = DBEvent(
        event_id="EVT-102",
        campaign_id="CAMPAIGN-DBDA6D",
        timestamp=now,
        source="Sysmon",
        event_type="Process Access",
        process_name="lsass.exe",
        mitre_technique="T1003",
        device_id="WORKSTATION-01",
        severity=10,
        detection_reason="LSASS memory access (mimikatz behavior)"
    )
    db_session.add_all([e1, e2])
    db_session.commit()

    engine = IncidentEngine()
    inc = engine.create_incident(campaign_id="CAMPAIGN-DBDA6D", assigned_to="SOC Analyst A", db=db_session)
    inc_id = inc["incident_id"]

    engine.add_note(inc_id, "Endpoint isolated from network.", "SOC Analyst A", "ANALYST", "CONTAINMENT", db_session)
    engine.add_note(inc_id, "Credentials reset.", "SOC Analyst A", "ANALYST", "CONTAINMENT", db_session)

    # Generate Report
    report = engine.generate_investigation_report(inc_id, db_session)

    assert report is not None
    assert report["incident_id"] == inc_id
    assert report["campaign_id"] == "CAMPAIGN-DBDA6D"
    
    md = report["report_markdown"]
    assert "CAIP INCIDENT INVESTIGATION REPORT" in md
    assert "WHAT HAPPENED" in md
    assert "ATTACK TIMELINE" in md
    assert "THREAT INDICATORS" in md
    assert "CORRELATION EXPLANATION" in md
    assert "RESPONSE & CONTAINMENT ACTIONS" in md
    assert "ANALYST NOTES" in md
    assert "evil-domain.com" in md
    assert "powershell.exe" in md
    assert "WORKSTATION-01" in md


def test_incident_api_endpoints(client, db_session):
    """Test all REST API endpoints for Phase 7."""
    camp = DBCampaign(
        campaign_id="CAMPAIGN-REST",
        target="SRV-01",
        attack_type="Data Exfiltration",
        stage="Exfiltration",
        confidence=0.9,
        risk="HIGH",
        risk_score=85
    )
    db_session.add(camp)
    db_session.commit()

    # 1. Create Incident via POST
    res = client.post("/api/v1/incidents", json={
        "campaign_id": "CAMPAIGN-REST",
        "title": "Exfiltration Incident on SRV-01",
        "severity": "HIGH",
        "priority": "P2 - High",
        "assigned_to": "SOC Analyst B"
    })
    assert res.status_code == 200
    inc_data = res.json()
    inc_id = inc_data["incident_id"]
    assert inc_data["assigned_to"] == "SOC Analyst B"

    # 2. List Incidents via GET
    res = client.get("/api/v1/incidents")
    assert res.status_code == 200
    assert len(res.json()) >= 1

    # 3. Add Evidence via POST
    res = client.post(f"/api/v1/incidents/{inc_id}/evidence", json={
        "entity_type": "ip",
        "entity_value": "198.51.100.45",
        "reason": "Suspicious outbound destination IP",
        "added_by": "SOC Analyst B"
    })
    assert res.status_code == 200
    assert res.json()["evidence_count"] >= 1

    # 4. Add Note via POST
    res = client.post(f"/api/v1/incidents/{inc_id}/notes", json={
        "content": "Firewall outbound rule applied for IP 198.51.100.45",
        "author": "SOC Analyst B",
        "action_tag": "CONTAINMENT"
    })
    assert res.status_code == 200

    # 5. Get Timeline
    res = client.get(f"/api/v1/incidents/{inc_id}/timeline")
    assert res.status_code == 200
    assert len(res.json()) >= 1

    # 6. Get Report
    res = client.get(f"/api/v1/incidents/{inc_id}/report")
    assert res.status_code == 200
    assert "report_markdown" in res.json()

    # 7. Get Linked Incident for Campaign
    res = client.get("/api/v1/campaigns/CAMPAIGN-REST/incident")
    assert res.status_code == 200
    assert res.json()["incident_id"] == inc_id
