"""
CAIP Phase F — Live End-to-End Synthetic Telemetry Demonstration
================================================================
Demonstrates a multi-stage attack campaign progressing through 5 stages:
  Step 1: Initial Access      (Phishing Email)
  Step 2: Download            (Attachment Download)
  Step 3: Execution           (PowerShell Execution)
  Step 4: Credential Access   (Mimikatz Credential Dumping) -> DIGITAL TWIN ACTIVATION
  Step 5: Command & Control   (DNS C2 Beaconing)
"""

import sys, os
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.normpath(os.path.join(_HERE, "backend"))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# pyrefly: ignore [missing-import]
from app.ingestion.normalizer import normalize_raw_log
# pyrefly: ignore [missing-import]
from app.intelligence.risk_engine import RiskEngine
# pyrefly: ignore [missing-import]
from app.intelligence.attack_predictor import AttackPredictor
# pyrefly: ignore [missing-import]
from app.xai.explainer import SHAPExplainer
# pyrefly: ignore [missing-import]
from app.intelligence.digital_twin import DigitalTwin

def run_demo():
    print("=" * 80)
    print("  CAIP LIVE END-TO-END SYNTHETIC TELEMETRY DEMONSTRATION")
    print("=" * 80)

    now = datetime.now(timezone.utc)
    predictor = AttackPredictor()
    explainer = SHAPExplainer(predictor)
    twin = DigitalTwin()

    campaign_events = []

    steps = [
        {
            "step": 1,
            "stage_name": "Initial Access",
            "log": {
                "event_id": "EVT-DEMO-01",
                "timestamp": now.isoformat(),
                "source": "Phishing Filter",
                "user": "victim_user@corp.com",
                "source_ip": "192.168.1.105",
                "domain": "phish-bank.com",
                "event_type": "phishing_email",
                "severity": 35,
            }
        },
        {
            "step": 2,
            "stage_name": "Download",
            "log": {
                "event_id": "EVT-DEMO-02",
                "timestamp": (now + timedelta(minutes=5)).isoformat(),
                "source": "Web Proxy",
                "user": "victim_user@corp.com",
                "source_ip": "192.168.1.105",
                "domain": "malicious-payload.net",
                "url": "http://malicious-payload.net/invoice.docm",
                "event_type": "attachment_download",
                "severity": 55,
            }
        },
        {
            "step": 3,
            "stage_name": "Execution",
            "log": {
                "event_id": "EVT-DEMO-03",
                "timestamp": (now + timedelta(minutes=10)).isoformat(),
                "source": "EDR Agent",
                "user": "victim_user@corp.com",
                "source_ip": "192.168.1.105",
                "device_id": "WORKSTATION-042",
                "process_name": "powershell.exe",
                "event_type": "powershell",
                "severity": 75,
            }
        },
        {
            "step": 4,
            "stage_name": "Credential Access",
            "log": {
                "event_id": "EVT-DEMO-04",
                "timestamp": (now + timedelta(minutes=18)).isoformat(),
                "source": "AD LSASS Monitor",
                "user": "victim_user@corp.com",
                "source_ip": "192.168.1.105",
                "device_id": "WORKSTATION-042",
                "process_name": "mimikatz.exe",
                "event_type": "mimikatz",
                "severity": 90,
            }
        },
        {
            "step": 5,
            "stage_name": "Command & Control (C2)",
            "log": {
                "event_id": "EVT-DEMO-05",
                "timestamp": (now + timedelta(minutes=25)).isoformat(),
                "source": "DNS Firewall",
                "user": "victim_user@corp.com",
                "source_ip": "192.168.1.105",
                "domain": "c2.evil-attacker-infra.com",
                "event_type": "suspicious_dns",
                "severity": 95,
            }
        },
    ]

    for item in steps:
        step_num = item["step"]
        stage_name = item["stage_name"]
        raw = item["log"]

        norm_event = normalize_raw_log(raw)
        campaign_events.append(norm_event)

        # Risk Engine Analysis
        # Convert Pydantic objects to dicts for predictor + risk engine compatibility
        dict_events = [e.model_dump() if hasattr(e, 'model_dump') else e.__dict__ for e in campaign_events]
        risk_res = RiskEngine.get_risk_analysis(campaign_events)
        score = risk_res["score"]

        # ML Stage Prediction
        preds = predictor.predict_next_stages_ml(dict_events)
        top1_stage = preds[0]["stage"] if preds else "Unknown"
        top1_prob  = preds[0]["probability"] if preds else 0.0

        print("\n" + "-" * 80)
        print(f"  [STEP {step_num}/5] OBSERVED STAGE: {stage_name} ({norm_event.event_type})")
        print("-" * 80)
        print(f"  Event ID          : {norm_event.event_id}")
        print(f"  Target User       : {norm_event.user}")
        print(f"  Device / Host     : {norm_event.device_id or '192.168.1.105'}")
        print(f"  Dynamic Risk Score: {score}/100 [{risk_res.get('risk_level', 'ACTIVE')}]")
        print(f"  Active Risk Factors: {', '.join(risk_res.get('risk_factors', []))}")
        print(f"  Next-Stage ML Pred: {top1_stage} (Prob: {top1_prob:.1%})")

        # Digital Twin Trigger (Risk >= 80)
        if score >= 80:
            print("\n  " + "*" * 76)
            print(f"  *** DIGITAL TWIN SIMULATION ACTIVATED (Risk = {score} >= 80) ***")
            print("  " + "*" * 76)

            campaign_mock = {
                "campaign_id": "CAMPAIGN-DEMO-LIVE",
                "attack_type": "Credential Theft / Ransomware",
                "risk_score": score,
            }

            twin_res = twin.simulate(campaign_mock, dict_events)
            blast = twin_res["blast_radius"]
            playbook = twin_res["playbook"]

            print(f"  Recommended Action : {twin_res['decision']}")
            print(f"  Verdict            : {twin_res['verdict']}")
            print(f"  Blast Radius       : {blast['total_entities']} entities affected "
                  f"(Users: {len(blast['affected_users'])}, IPs: {len(blast['affected_ips'])}, "
                  f"Devices: {len(blast['affected_devices'])}, Domains: {len(blast['affected_domains'])})")

            print("\n  Recommended Playbook Steps:")
            for action in playbook.get("actions", []):
                print(f"    Step {action['step']}: [{action['action']}] {action['detail']}")

            # SHAP Explanation
            print("\n  SHAP Feature Attribution (Top Drivers for Next-Stage Prediction):")
            shap_info = explainer.explain_campaign(dict_events)
            for feat in shap_info[:3]:
                name = feat.get("feature", "unknown")
                val = feat.get("value", 0)
                impact = feat.get("impact", "neutral")
                print(f"    - {name:<25}: value={val:<6} (Impact: {impact})")

    print("\n" + "=" * 80)
    print("  LIVE DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("=" * 80)

if __name__ == "__main__":
    run_demo()
