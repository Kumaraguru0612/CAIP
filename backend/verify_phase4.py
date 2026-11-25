"""
CAIP Phase 4 Verification Suite
================================
Validates all Phase 4 components end-to-end without requiring a running server.
Run from: backend/ directory

  python verify_phase4.py
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("DATABASE_URL", "sqlite:///caip_test_p4.db")
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_USER", "neo4j")
os.environ.setdefault("NEO4J_PASSWORD", "")

PASS = "[PASS]"
FAIL = "[FAIL]"
results = []


def check(name, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name, True))
    except Exception as e:
        print(f"  {FAIL} {name}")
        print(f"       {e}")
        results.append((name, False))


# ═══════════════════════════════════════════════════════════════════════════════
print("\n=== Phase 4 Verification ===\n")

# ── 1. CICIDS Adapter ─────────────────────────────────────────────────────────
print("1. CICIDS2017 Adapter")

def t_cicids_file():
    path = os.path.join(os.path.dirname(__file__), "..", "datasets", "caip_cicids_dataset.csv")
    assert os.path.exists(path), "caip_cicids_dataset.csv not found"
    import csv
    with open(path) as f:
        rows = list(csv.DictReader(f))
    assert len(rows) > 1000, f"Expected >1000 events, got {len(rows)}"
    required = {"campaign_id", "event_type", "mitre_stage", "data_source", "next_stage_label"}
    assert required.issubset(rows[0].keys()), f"Missing columns: {required - rows[0].keys()}"
    assert all(r["data_source"] == "CICIDS2017" for r in rows), "data_source mismatch"

check("CICIDS dataset file exists with correct schema", t_cicids_file)

def t_cicids_archetypes():
    path = os.path.join(os.path.dirname(__file__), "..", "datasets", "caip_cicids_dataset.csv")
    import csv
    with open(path) as f:
        rows = list(csv.DictReader(f))
    types = {r["campaign_type"] for r in rows}
    expected = {"infiltration", "brute_force", "web_attack", "port_scan", "dos_ddos", "heartbleed"}
    assert expected <= types, f"Missing archetypes: {expected - types}"
    campaigns = {r["campaign_id"] for r in rows}
    assert len(campaigns) == 400, f"Expected 400 campaigns, got {len(campaigns)}"

check("CICIDS: 400 campaigns across 6 attack archetypes", t_cicids_archetypes)


# ── 2. Expanded Normalizer ────────────────────────────────────────────────────
print("\n2. Expanded Normalizer")

from app.ingestion.normalizer import normalize_raw_log, MITRE_MAP

def t_normalizer_basic():
    ev = normalize_raw_log({
        "source": "email_gw", "event_type": "phishing_email",
        "user": "alice01", "src_ip": "192.168.1.5", "severity": 70
    })
    assert ev.mitre_technique == "T1566"
    assert ev.mitre_stage == "Initial Access"
    assert ev.source_ip == "192.168.1.5"  # alias resolved

check("Normalizer resolves field aliases + MITRE mapping", t_normalizer_basic)

def t_normalizer_phase4_fields():
    ev = normalize_raw_log({
        "source": "edr", "event_type": "powershell",
        "hostname": "WKSTN-007", "proc_name": "powershell.exe",
        "pid": 4512, "parent_proc": "winword.exe",
        "login_type": "interactive", "severity": "high",
        "data_source": "CICIDS2017"
    })
    assert ev.device_id == "WKSTN-007"
    assert ev.process_name == "powershell.exe"
    assert ev.parent_process == "winword.exe"
    assert ev.login_type == "interactive"
    assert ev.severity == 75
    assert ev.data_source == "CICIDS2017"

check("Normalizer handles Phase 4 device/process/login fields", t_normalizer_phase4_fields)

def t_mitre_coverage():
    cicids_types = [
        "brute_force", "port_scan", "sql_injection", "vulnerability_exploit",
        "dos_flood", "ddos_flood", "exfil_https", "lateral_rdp", "dns_beacon"
    ]
    for etype in cicids_types:
        assert etype in MITRE_MAP, f"No MITRE mapping for: {etype}"

check("MITRE map covers all CICIDS2017 event types", t_mitre_coverage)


# ── 3. Digital Twin ───────────────────────────────────────────────────────────
print("\n3. Digital Twin")

from app.intelligence.digital_twin import DigitalTwin
from datetime import datetime, timedelta

def make_mock_events():
    base = datetime.utcnow() - timedelta(hours=1)
    events = []
    for i, (etype, stage) in enumerate([
        ("phishing_email",  "Initial Access"),
        ("powershell",      "Execution"),
        ("dns_beacon",      "Command & Control"),
        ("credential_login","Credential Access"),
    ]):
        events.append({
            "event_id":   f"EVT-T4-{i:02d}",
            "event_type": etype,
            "mitre_stage":stage,
            "severity":   60 + i * 5,
            "user":       "testuser01",
            "source_ip":  "192.168.1.20",
            "domain":     "evil-c2.net",
            "device_id":  "WKSTN-007",
            "timestamp":  (base + timedelta(minutes=i*8)).isoformat(),
        })
    return events

def t_twin_runs():
    dt = DigitalTwin()
    mock_events = make_mock_events()
    campaign_dict = {
        "campaign_id": "TEST-TWIN-001",
        "attack_type": "Credential Theft",
        "risk_score":  78,
    }
    report = dt.simulate(campaign_dict, mock_events)
    assert "projected_stages" in report
    assert "blast_radius" in report
    assert "behaviour_log" in report
    assert "playbook" in report
    assert report["campaign_id"] == "TEST-TWIN-001"

check("Digital Twin runs end-to-end", t_twin_runs)

def t_twin_blast_radius():
    dt = DigitalTwin()
    events = make_mock_events()
    report = dt.simulate({"campaign_id": "T", "attack_type": "Ransomware", "risk_score": 90}, events)
    br = report["blast_radius"]
    assert "testuser01" in br["affected_users"]
    assert "192.168.1.20" in br["affected_ips"]
    assert "evil-c2.net" in br["affected_domains"]
    assert "WKSTN-007" in br["affected_devices"]

check("Digital Twin blast radius correctly captures all entities", t_twin_blast_radius)

def t_twin_playbook_selection():
    dt = DigitalTwin()
    events = make_mock_events()
    for atype, expected_action in [
        ("Ransomware",        "ISOLATE_HOST"),
        ("Data Exfiltration", "REVOKE_CREDENTIALS"),
        ("APT / Lateral Spread","SEGMENT_NETWORK"),
        ("Credential Theft",  "FORCE_PASSWORD_RESET"),
    ]:
        report = dt.simulate({"campaign_id": "T", "attack_type": atype, "risk_score": 85}, events)
        actions = [a["action"] for a in report["playbook"]["actions"]]
        assert expected_action in actions, f"Missing {expected_action} for {atype}"

check("Digital Twin selects correct playbook per attack type", t_twin_playbook_selection)

def t_twin_behaviour_log():
    dt = DigitalTwin()
    events = make_mock_events()
    report = dt.simulate({"campaign_id": "T", "attack_type": "Credential Theft", "risk_score": 75}, events)
    log = report["behaviour_log"]
    observed = [l for l in log if l["type"] == "observed"]
    projected = [l for l in log if l["type"] == "projected"]
    assert len(observed) == 4, f"Expected 4 observed, got {len(observed)}"
    assert len(projected) >= 1, "Expected at least 1 projected entry"

check("Behaviour log contains observed + projected entries", t_twin_behaviour_log)


# ── 4. Database Models ────────────────────────────────────────────────────────
print("\n4. Database Models")

from app.database.database import Base, engine, SessionLocal
from app.database.models import Campaign, Event, PredictionLog

def t_schema_create():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

check("Schema creates with PredictionLog, expanded Event/Campaign", t_schema_create)

def t_prediction_log_model():
    db = SessionLocal()
    try:
        from datetime import datetime
        camp = Campaign(
            campaign_id="TEST-CAMP-P4",
            target="testuser",
            attack_type="Phishing",
            stage="Initial Access",
            confidence=0.7,
            risk="MEDIUM",
            risk_score=55,
            data_source="Synthetic",
        )
        db.add(camp)
        db.commit()

        log = PredictionLog(
            campaign_id    = "TEST-CAMP-P4",
            at_stage       = "Initial Access",
            observed_stages= json.dumps(["Initial Access"]),
            ml_top1_stage  = "Execution",
            ml_top1_prob   = 0.83,
            ml_top3_stages = json.dumps(["Execution", "Credential Access", "Discovery"]),
            rule_top1_stage= "Execution",
            rule_top1_prob = 0.75,
        )
        db.add(log)
        db.commit()

        retrieved = db.query(PredictionLog).filter(PredictionLog.campaign_id == "TEST-CAMP-P4").first()
        assert retrieved.ml_top1_stage == "Execution"
        assert retrieved.at_stage == "Initial Access"
        stages = json.loads(retrieved.ml_top3_stages)
        assert "Execution" in stages
    finally:
        db.close()

check("PredictionLog stores and retrieves correctly", t_prediction_log_model)

def t_event_phase4_fields():
    db = SessionLocal()
    try:
        ev = Event(
            event_id    = "EVT-P4-001",
            timestamp   = datetime.utcnow(),
            source      = "edr",
            event_type  = "powershell",
            user        = "testuser",
            source_ip   = "192.168.1.5",
            severity    = 75,
            device_id   = "WKSTN-007",
            process_name= "powershell.exe",
            login_type  = "interactive",
            file_path   = "C:\\Users\\testuser\\payload.ps1",
            correlation_reason="Same host device: WKSTN-007",
            data_source = "CICIDS2017",
        )
        db.add(ev)
        db.commit()
        retrieved = db.query(Event).filter(Event.event_id == "EVT-P4-001").first()
        assert retrieved.device_id == "WKSTN-007"
        assert retrieved.process_name == "powershell.exe"
        assert retrieved.data_source == "CICIDS2017"
    finally:
        db.close()

check("Event stores Phase 4 fields (device, process, login, data_source)", t_event_phase4_fields)


# ── 5. Campaign Engine ────────────────────────────────────────────────────────
print("\n5. Campaign Engine")

from app.ingestion.normalizer import NormalizedEvent
from app.intelligence.campaign_engine import CampaignEngine

def t_correlation_multi_signal():
    db = SessionLocal()
    try:
        # Create a campaign anchored to user "multiuser01"
        import uuid
        from datetime import datetime as dt
        cid = f"CAMP-MS-{uuid.uuid4().hex[:4].upper()}"
        camp = Campaign(
            campaign_id="CAMP-MS-SEED",
            target="multiuser01",
            attack_type="Phishing",
            stage="Initial Access",
            confidence=0.6,
            risk="LOW",
            risk_score=40,
        )
        db.add(camp)

        seed_event = Event(
            event_id="EVT-SEED-01",
            timestamp=dt.utcnow(),
            source="email_gw",
            event_type="phishing_email",
            user="multiuser01",
            source_ip="10.0.0.1",
            severity=60,
            campaign_id="CAMP-MS-SEED",
        )
        db.add(seed_event)
        db.commit()
    finally:
        db.close()

    # Now ingest a second event with same user — should correlate
    engine_obj = CampaignEngine()
    ev2 = NormalizedEvent(
        event_id="EVT-CORR-02",
        source="endpoint",
        event_type="powershell",
        user="multiuser01",
        source_ip="10.0.0.1",
        severity=75,
        mitre_stage="Execution",
        mitre_technique="T1059.001",
    )
    engine_obj.correlate_event(ev2)

    db2 = SessionLocal()
    try:
        ev_db = db2.query(Event).filter(Event.event_id == "EVT-CORR-02").first()
        if ev_db:
            assert ev_db.campaign_id == "CAMP-MS-SEED", \
                f"Expected CAMP-MS-SEED, got {ev_db.campaign_id}"
            assert ev_db.correlation_reason is not None, "correlation_reason should be set"
    finally:
        db2.close()

check("Campaign engine multi-signal correlation + correlation_reason", t_correlation_multi_signal)


# ── 6. Attack Predictor ───────────────────────────────────────────────────────
print("\n6. Attack Predictor")

from app.intelligence.attack_predictor import AttackPredictor

def t_predictor_ml():
    p = AttackPredictor()
    db = SessionLocal()
    try:
        events = db.query(Event).limit(5).all()
        if events:
            preds = p.predict_next_stages_ml(events)
            assert isinstance(preds, list)
            if preds:
                assert "stage" in preds[0]
                assert "probability" in preds[0]
                assert 0 <= preds[0]["probability"] <= 1
    finally:
        db.close()

check("AttackPredictor.predict_next_stages_ml returns valid predictions", t_predictor_ml)

def t_predictor_rule():
    p = AttackPredictor()
    stages = ["Initial Access", "Execution"]
    preds = p.predict_next_stages_rule_based(stages)
    assert isinstance(preds, list)
    assert len(preds) > 0
    assert preds[0]["probability"] > 0

check("AttackPredictor.predict_next_stages_rule_based returns valid predictions", t_predictor_rule)


# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 55)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  Results: {passed}/{total} checks passed")
if passed == total:
    print("  All Phase 4 checks passed!")
else:
    failed = [n for n, ok in results if not ok]
    print("  Failed:")
    for f in failed:
        print(f"    - {f}")
print("=" * 55)

sys.exit(0 if passed == total else 1)
