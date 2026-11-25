import os
import sys

# Set SQLite in-memory database configuration for testing
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["NEO4J_URI"] = ""  # Disables Neo4j to run validation standalone

# Add workspace directory to python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database.database import engine, Base, get_db, SessionLocal
from app.database.models import Event as DBEvent, Campaign as DBCampaign
from app.ingestion.normalizer import normalize_raw_log
from app.intelligence.campaign_engine import CampaignEngine
from app.intelligence.attack_predictor import AttackPredictor
from app.intelligence.risk_engine import RiskEngine
from app.xai.explainer import SHAPExplainer

def run_verification():
    print("=== CAIP Backend Phase 2 Verification Test ===")
    
    # 1. Initialize DB tables in-memory
    print("\n[Step 1] Initializing SQLite in-memory database...")
    Base.metadata.create_all(bind=engine)
    print("Database tables initialized successfully.")

    # 2. Setup mock raw events matching user request
    print("\n[Step 2] Defining mock security events...")
    raw_events = [
      {
        "event_id": "EVT-001",
        "timestamp": "2026-08-09T10:15:00",
        "source": "email_gateway",
        "event_type": "phishing_email",
        "user": "user01",
        "source_ip": "192.168.1.20",
        "domain": "example-login.com",
        "url": "https://example-login.com/login",
        "severity": 60
      },
      {
        "event_id": "EVT-002",
        "timestamp": "2026-08-09T10:16:00",
        "source": "proxy",
        "event_type": "url_visit",
        "user": "user01",
        "source_ip": "192.168.1.20",
        "domain": "example-login.com",
        "url": "https://example-login.com/login",
        "severity": 65
      },
      {
        "event_id": "EVT-003",
        "timestamp": "2026-08-09T10:17:00",
        "source": "endpoint",
        "event_type": "powershell",
        "user": "user01",
        "source_ip": "192.168.1.20",
        "domain": "example-login.com",
        "file_hash": "abc123",
        "severity": 80
      },
      {
        "event_id": "EVT-004",
        "timestamp": "2026-08-09T10:18:00",
        "source": "dns",
        "event_type": "suspicious_dns",
        "user": "user01",
        "source_ip": "192.168.1.20",
        "domain": "example-login.com",
        "severity": 70
      },
      {
        "event_id": "EVT-005",
        "timestamp": "2026-08-09T10:19:00",
        "source": "ad_controller",
        "event_type": "credential_login",
        "user": "user01",
        "source_ip": "192.168.1.20",
        "severity": 85
      }
    ]
    print(f"Loaded {len(raw_events)} mock threat events.")

    # 3. Process events through ingestion and correlation engine
    print("\n[Step 3] Processing events through normalizer & campaign correlation engine...")
    db = SessionLocal()
    campaign_engine = CampaignEngine()
    
    for raw in raw_events:
        # Normalize (assigns MITRE techniques and stages)
        normalized = normalize_raw_log(raw)
        
        # Save to DB
        db_event = DBEvent(
            event_id=normalized.event_id,
            timestamp=normalized.timestamp,
            source=normalized.source,
            event_type=normalized.event_type,
            user=normalized.user,
            source_ip=normalized.source_ip,
            domain=normalized.domain,
            url=normalized.url,
            file_hash=normalized.file_hash,
            severity=normalized.severity,
            security_status=normalized.security_status,
            mitre_technique=normalized.mitre_technique,
            mitre_stage=normalized.mitre_stage
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
        
        # Correlate campaign
        campaign_engine.correlate_event(normalized)
        print(f"Processed: {normalized.event_id} ({normalized.event_type}) -> MITRE: {normalized.mitre_technique} ({normalized.mitre_stage})")
        
    db.close()

    # 4. Verify Campaigns and Dynamic Risk Scores in database
    print("\n[Step 4] Querying database for correlated campaigns & dynamic risk scores...")
    db = SessionLocal()
    campaigns = db.query(DBCampaign).all()
    events = db.query(DBEvent).all()
    
    print(f"Total campaigns detected: {len(campaigns)}")
    assert len(campaigns) == 1, "Verification Failed: Expected exactly 1 campaign!"
    
    campaign = campaigns[0]
    print("\nCampaign Details:")
    print(f"  Campaign ID: {campaign.campaign_id}")
    print(f"  Target Entity: {campaign.target}")
    print(f"  Attack Type: {campaign.attack_type}")
    print(f"  Kill-Chain Stage Progression: {campaign.stage}")
    print(f"  Risk Classification: {campaign.risk}")
    print(f"  Numeric Risk Score: {campaign.risk_score} / 100")
    print(f"  Confidence: {campaign.confidence * 100:.1f}%")
    
    # Assertions
    assert campaign.target == "user01", f"Expected target 'user01', got '{campaign.target}'"
    assert "Initial Access" in campaign.stage, "Expected 'Initial Access' in stage"
    assert "Execution" in campaign.stage, "Expected 'Execution' in stage"
    assert "Credential Access" in campaign.stage, "Expected 'Credential Access' in stage"
    assert "Command & Control" in campaign.stage, "Expected 'Command & Control' in stage"
    assert campaign.risk == "HIGH", f"Expected 'HIGH' risk, got '{campaign.risk}'"
    assert campaign.risk_score > 70, f"Expected elevated risk score, got {campaign.risk_score}"
    
    print("\nCampaign events linked in database with MITRE tags:")
    for e in events:
        print(f"  - Event: {e.event_id} | Type: {e.event_type} | MITRE: {e.mitre_technique} | Stage: {e.mitre_stage} | Campaign: {e.campaign_id}")
        assert e.campaign_id == campaign.campaign_id, f"Event {e.event_id} not linked to correct campaign!"

    # 5. Verify SHAP Explainability
    print("\n[Step 5] Computing SHAP explainability values...")
    predictor = AttackPredictor()
    explainer = SHAPExplainer(predictor)
    
    # Construct feature vectors
    features = {
        "num_events": len(events),
        "avg_severity": sum(e.severity for e in events) / len(events),
        "max_severity": max(e.severity for e in events),
        "has_execution": 1,
        "has_credential_access": 1,
        "has_c2": 1
    }
    
    explanations = explainer.explain_campaign(features)
    print("\nSHAP Feature Importance (Impact on HIGH Risk prediction):")
    for exp in explanations:
        sign = "+" if exp["shap_value"] > 0 else ""
        print(f"  Feature: {exp['feature']:<25} | Value: {exp['value']:<5} | SHAP Impact: {sign}{exp['shap_value']:.4f} ({exp['impact'].upper()})")

    # 6. Verify Phase 2 Enhanced Features (Risk Trends, Stage Prediction, Dashboard Stats)
    print("\n[Step 6] Verifying Phase 2 Enhanced Features...")
    
    # Check Risk Trend calculation
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    risk_trend = []
    for i in range(len(sorted_events)):
        sub_events = sorted_events[:i+1]
        step_analysis = RiskEngine.get_risk_analysis(sub_events)
        risk_trend.append(step_analysis["score"])
        
    print(f"  Calculated Risk Trend: {' -> '.join(map(str, risk_trend))}")
    assert len(risk_trend) == 5, "Expected risk trend containing 5 entries"
    assert risk_trend[-1] == campaign.risk_score, "End of risk trend should match final campaign risk score"

    # Check Next Stage Predictions
    current_stages = list({e.mitre_stage for e in events if e.mitre_stage})
    next_stage_predictions = predictor.predict_next_stages(current_stages)
    print("  Predicted Next Stages:")
    for pred in next_stage_predictions:
        print(f"    - {pred['stage']}: {pred['probability'] * 100:.1f}%")
        
    assert len(next_stage_predictions) > 0, "Expected at least one next stage prediction"
    
    # Check Dashboard Stats
    total_campaigns = len(campaigns)
    total_events = len(events)
    correlated_events = sum(1 for e in events if e.campaign_id is not None)
    
    critical_count = sum(1 for c in campaigns if c.risk_score >= 85)
    high_count = sum(1 for c in campaigns if 70 <= c.risk_score < 85)
    medium_count = sum(1 for c in campaigns if 40 <= c.risk_score < 70)
    low_count = sum(1 for c in campaigns if c.risk_score < 40)
    
    print("\n  Dashboard Stats Summary:")
    print(f"    Active Campaigns: {total_campaigns}")
    print(f"    Critical:         {critical_count}")
    print(f"    High:             {high_count}")
    print(f"    Medium:           {medium_count}")
    print(f"    Low:              {low_count}")
    print(f"    Alerts Received:  {total_events}")
    print(f"    Correlated:       {correlated_events}")
    
    assert total_campaigns == 1, "Expected 1 active campaign in stats"
    assert total_events == 5, "Expected 5 alerts received in stats"
    assert correlated_events == 5, "Expected all 5 alerts to be correlated"

    print("\n=== Verification Successful: All Phase 2 checks passed! ===")
    db.close()

if __name__ == "__main__":
    run_verification()
