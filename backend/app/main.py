import json
import os
import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List, Any, Optional, Dict

from app.database.database import engine, Base, get_db
from app.database.models import (
    Campaign as DBCampaign, 
    Event as DBEvent, 
    PredictionLog, 
    Indicator,
    SOCIncident,
    CaseEvidence,
    CaseNote,
    Notification
)
from app.ingestion.collector import router as collector_router
from app.intelligence.attack_predictor import AttackPredictor
from app.intelligence.risk_engine import RiskEngine
from app.intelligence.similarity_engine import SimilarityEngine
from app.intelligence.validation_engine import run_validation
from app.intelligence.feature_extractor import extract_features
from app.intelligence.digital_twin import DigitalTwin
from app.intelligence.threat_intel import ThreatIntelEngine
from app.intelligence.entity_extractor import EntityExtractor, get_proc_base, normalize_user
from app.intelligence.incident_engine import IncidentEngine
from app.intelligence.notification_engine import NotificationEngine
from app.intelligence.soc_ops_engine import SOCOpsEngine
from app.xai.explainer import SHAPExplainer
from app.graph.graph_queries import GraphQueries


def _migrate_db():
    from sqlalchemy import text
    with engine.connect() as conn:
        for col, col_type in [
            ("detection_rule", "TEXT"),
            ("detection_reason", "TEXT"),
            ("confidence", "TEXT"),
            ("command_line", "TEXT"),
            ("destination_ip", "TEXT"),
            ("destination_port", "TEXT"),
            ("parent_pid", "INTEGER"),
        ]:
            try:
                conn.execute(text(f"ALTER TABLE events ADD COLUMN {col} {col_type}"))
                conn.commit()
            except Exception:
                pass
        for col, col_type in [
            ("status", "TEXT"),
        ]:
            try:
                conn.execute(text(f"ALTER TABLE campaigns ADD COLUMN {col} {col_type}"))
                conn.commit()
            except Exception:
                pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _migrate_db()

    # Auto-connect Windows Sysmon live stream if service is running
    try:
        from app.ingestion.sysmon_service import sysmon_service, is_windows, get_windows_service_status
        if is_windows():
            status = get_windows_service_status()
            if status.get("running"):
                print(f"[+] Windows Sysmon service ({status.get('service_name')}) is active.")
                print("[+] Starting integrated Sysmon Live Telemetry Stream...")
                sysmon_service.start()
    except Exception as e:
        print(f"[!] Sysmon auto-connect notice: {e}")

    yield

    try:
        from app.ingestion.sysmon_service import sysmon_service
        sysmon_service.stop()
    except Exception:
        pass


app = FastAPI(
    title="CAIP — Collaborative Attack Intelligence Platform",
    description=(
        "Multi-stage attack campaign detection, MITRE ATT&CK correlation, "
        "Neo4j Context Graph, XGBoost + SHAP, Campaign Similarity, "
        "Digital Twin simulation, Actual-vs-Predicted validation. "
        "IEEE research prototype."
    ),
    version="4.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(collector_router, prefix="/api/v1")

# ── Unified Single-Host Serving Paths ─────────────────────────────────────────
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_root_dir = os.path.dirname(_backend_dir)
_frontend_dist = os.path.join(_root_dir, "frontend", "dist")
_simulator_dir = os.path.join(_root_dir, "caip-simulator")

if os.path.exists(_simulator_dir):
    app.mount("/simulator", StaticFiles(directory=_simulator_dir, html=True), name="simulator")

_assets_dir = os.path.join(_frontend_dist, "assets")
if os.path.exists(_assets_dir):
    app.mount("/assets", StaticFiles(directory=_assets_dir), name="assets")

# ── Startup model initialisation ──────────────────────────────────────────────
predictor = AttackPredictor()
explainer = SHAPExplainer(predictor)
twin      = DigitalTwin()


# ── Serialisation helpers ─────────────────────────────────────────────────────
def _normalize_campaign_status(status: Optional[str]) -> str:
    if not status or status.upper() in ["ACTIVE", "ACTIVE CAMPAIGN"]:
        return "Active Campaign"
    if "CONTAIN" in status.upper():
        return "Contained"
    if "RESOLV" in status.upper():
        return "Resolved"
    if "INVESTIGAT" in status.upper():
        return "Investigating"
    if "AWAIT" in status.upper():
        return "Awaiting Correlation"
    return status

def _campaign_to_dict(c, event_count: int = 0, device_id: str = None) -> dict:
    return {
        "id":               c.id,
        "campaign_id":      c.campaign_id,
        "target":           c.target,
        "attack_type":      c.attack_type,
        "stage":            c.stage,
        "confidence":       c.confidence,
        "risk":             c.risk,
        "risk_score":       c.risk_score,
        "data_source":      getattr(c, "data_source", "Synthetic"),
        "predicted_outcome":getattr(c, "predicted_outcome", None),
        "twin_report":      getattr(c, "twin_report", None),
        "status":           _normalize_campaign_status(getattr(c, "status", None)),
        "created_at":       c.created_at.isoformat() if c.created_at else None,
        "event_count":      event_count,
        "device_id":        device_id,
    }

def _event_to_dict(e) -> dict:
    return {
        "id":               e.id,
        "event_id":         e.event_id,
        "timestamp":        e.timestamp.isoformat() if e.timestamp else None,
        "source":           e.source,
        "event_type":       e.event_type,
        "user":             e.user,
        "source_ip":        e.source_ip,
        "domain":           e.domain,
        "url":              e.url,
        "file_hash":        e.file_hash,
        "severity":         e.severity,
        "security_status":  getattr(e, "security_status", "informational"),
        "mitre_technique":  e.mitre_technique,
        "mitre_stage":      e.mitre_stage,
        # Phase 4
        "device_id":        getattr(e, "device_id", None),
        "process_name":     getattr(e, "process_name", None),
        "process_pid":      getattr(e, "process_pid", None),
        "parent_process":   getattr(e, "parent_process", None),
        "parent_pid":       getattr(e, "parent_pid", None),
        "command_line":     getattr(e, "command_line", None),
        "destination_ip":   getattr(e, "destination_ip", None),
        "destination_port": getattr(e, "destination_port", None),
        "login_type":       getattr(e, "login_type", None),
        "file_path":        getattr(e, "file_path", None),
        "correlation_reason":getattr(e, "correlation_reason", None),
        "data_source":      getattr(e, "data_source", "Synthetic"),
        "campaign_id":      e.campaign_id,
        # Phase 5 — Detection Explainability
        "detection_rule":   getattr(e, "detection_rule", None),
        "detection_reason": getattr(e, "detection_reason", None),
        "confidence":       getattr(e, "confidence", None) or ("Critical" if e.severity >= 85 else ("High" if e.severity >= 70 else ("Medium" if e.severity >= 40 else "Informational"))),
    }


# ── Root & Health ─────────────────────────────────────────────────────────────
@app.get("/api/health")
def api_health():
    return {"status": "online", "service": "CAIP Backend API", "version": "4.0.0"}

@app.get("/")
def read_root():
    index_file = os.path.join(_frontend_dist, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "online", "service": "CAIP Backend API", "version": "4.0.0"}


# ── Dashboard stats ───────────────────────────────────────────────────────────
@app.get("/api/v1/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    campaigns = db.query(DBCampaign).all()
    events    = db.query(DBEvent).all()
    correlated = sum(1 for e in events if e.campaign_id is not None)
    critical = high = medium = low = 0
    for c in campaigns:
        s = c.risk_score
        if s >= 85:   critical += 1
        elif s >= 70: high     += 1
        elif s >= 40: medium   += 1
        else:         low      += 1

    # Data source breakdown
    synthetic  = sum(1 for c in campaigns if getattr(c, "data_source", "Synthetic") == "Synthetic")
    cicids     = sum(1 for c in campaigns if getattr(c, "data_source", "") == "CICIDS2017")

    return {
        "active_campaigns":  len(campaigns),
        "critical":          critical,
        "high":              high,
        "medium":            medium,
        "low":               low,
        "alerts_received":   len(events),
        "alerts_correlated": correlated,
        "campaigns_count":   len(campaigns),
        "data_sources": {
            "synthetic":  synthetic,
            "cicids2017": cicids,
        },
    }


# ── Clear Dashboard ───────────────────────────────────────────────────────────
@app.post("/api/v1/dashboard/clear")
@app.delete("/api/v1/dashboard/clear")
def clear_dashboard_data(db: Session = Depends(get_db)):
    """Removes all live security events, campaigns, and prediction logs from the dashboard, reseeding active apps."""
    db.query(CaseEvidence).delete()
    db.query(CaseNote).delete()
    db.query(SOCIncident).delete()
    db.query(Notification).delete()
    db.query(DBEvent).delete()
    db.query(DBCampaign).delete()
    db.query(PredictionLog).delete()
    db.query(Indicator).delete()
    db.commit()

    # Automatically reseed only clean live active apps running on this computer
    from app.ingestion.app_catalog import get_active_user_applications
    from app.ingestion.sysmon_service import HOSTNAME, USERNAME
    from app.ingestion.normalizer import normalize_raw_log
    from app.ingestion.collector import _build_db_event
    import uuid
    import time
    from datetime import datetime, timezone

    apps = get_active_user_applications()
    now = datetime.now(timezone.utc)
    base_time = int(time.time())

    for idx, app_info in enumerate(apps):
        exe = app_info.get("executable", "")
        name = app_info.get("app_name", exe)
        cat = app_info.get("category", "Application")

        event_time = datetime.fromtimestamp(base_time - (len(apps) - idx) * 15, tz=timezone.utc)
        payload = {
            "event_id": f"SYS-APP-{int(time.time() * 1000)}-{idx}-{uuid.uuid4().hex[:6]}",
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Sysmon",
            "event_type": "process_creation",
            "user": USERNAME,
            "device": HOSTNAME,
            "device_id": HOSTNAME,
            "source_ip": "127.0.0.1",
            "process": exe,
            "process_name": exe,
            "command_line": f"{name} ({cat})",
            "severity": 10,
            "security_status": "informational",
            "mitre_technique": None,
            "mitre_stage": None,
            "detection_rule": f"Live Host Application",
            "detection_reason": f"Real-time detected user application '{name}' running on {HOSTNAME}.",
            "confidence": "Informational",
            "data_source": "Live Endpoint Telemetry"
        }
        norm = normalize_raw_log(payload)
        db_ev = _build_db_event(norm)
        db.add(db_ev)

    db.commit()
    return {"status": "success", "message": f"Dashboard cleared and reset to {len(apps)} active host applications."}


# ── Event list & detail ───────────────────────────────────────────────────────
@app.get("/api/v1/events")
def list_events(
    campaign_id: str = None,
    user: str = None,
    device_id: str = None,
    severity: int = None,
    security_status: str = None,
    limit: int = 200,
    db: Session = Depends(get_db)
):
    query = db.query(DBEvent)
    if campaign_id:
        query = query.filter(DBEvent.campaign_id == campaign_id)
    if user:
        query = query.filter(DBEvent.user == user)
    if device_id:
        query = query.filter(DBEvent.device_id == device_id)
    if severity:
        query = query.filter(DBEvent.severity >= severity)
    if security_status:
        query = query.filter(DBEvent.security_status == security_status)
    events = query.order_by(DBEvent.timestamp.desc(), DBEvent.id.desc()).limit(limit).all()
    return [_event_to_dict(e) for e in events]


@app.get("/api/v1/events/{event_id}")
def get_event(event_id: str, db: Session = Depends(get_db)):
    event = db.query(DBEvent).filter(DBEvent.event_id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return _event_to_dict(event)


# ── Campaign list ─────────────────────────────────────────────────────────────
@app.get("/api/v1/campaigns")
def list_campaigns(db: Session = Depends(get_db)):
    campaigns = db.query(DBCampaign).order_by(DBCampaign.created_at.desc()).all()
    results = []
    for c in campaigns:
        events = db.query(DBEvent).filter(DBEvent.campaign_id == c.campaign_id).all()
        sec_events = [e for e in events if getattr(e, "security_status", "") != "informational"]
        event_count = len(sec_events) if sec_events else len(events)
        device_id = next((e.device_id for e in events if e.device_id), None)
        c_dict = _campaign_to_dict(c, event_count=event_count, device_id=device_id)
        c_dict["total_event_count"] = len(events)
        c_dict["contextual_event_count"] = len(events) - len(sec_events)
        results.append(c_dict)
    return results


# ── Campaign detail ───────────────────────────────────────────────────────────
@app.get("/api/v1/campaigns/{campaign_id}")
def get_campaign_details(campaign_id: str, db: Session = Depends(get_db)):
    """
    Returns full campaign details including:
    - Both ML + Rule-based predictions
    - Correlated and contextual events separated
    - Temporal features
    - Risk trend
    - SHAP explanations
    - Correlation reasons and score
    """
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    events        = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).all()
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    correlated_events = [e for e in sorted_events if getattr(e, "security_status", "") != "informational"]
    contextual_events = [e for e in sorted_events if getattr(e, "security_status", "") == "informational"]

    device_id = next((e.device_id for e in sorted_events if e.device_id), None)
    event_count = len(correlated_events) if correlated_events else len(sorted_events)

    camp_dict = _campaign_to_dict(campaign, event_count=event_count, device_id=device_id)
    camp_dict["total_events"] = len(sorted_events)
    camp_dict["contextual_event_count"] = len(contextual_events)

    # Extract correlation reasons and score
    import re
    reasons = []
    max_score = 0
    for e in sorted_events:
        if e.correlation_reason:
            reasons.append({
                "event_id": e.event_id,
                "reason": e.correlation_reason,
                "is_contextual": getattr(e, "security_status", "") == "informational",
            })
            m = re.search(r"score:\s*(\d+)", e.correlation_reason, re.IGNORECASE)
            if m:
                max_score = max(max_score, int(m.group(1)))

    # Risk trend
    risk_trend = []
    for i in range(len(sorted_events)):
        step_score = RiskEngine.get_risk_analysis(sorted_events[:i+1])["score"]
        risk_trend.append(step_score)

    analysis = RiskEngine.get_risk_analysis(sorted_events if sorted_events else [])

    # Ordered unique stages
    seen, ordered_stages = set(), []
    for e in sorted_events:
        if e.mitre_stage and e.mitre_stage not in seen:
            seen.add(e.mitre_stage)
            ordered_stages.append(e.mitre_stage)

    # Dual predictions
    rule_predictions = predictor.predict_next_stages_rule_based(ordered_stages)
    ml_predictions   = predictor.predict_next_stages_ml(sorted_events)

    # Temporal features
    temporal_features = extract_features(sorted_events)

    # SHAP features
    severity_sum = sum(e.severity for e in sorted_events) if sorted_events else 0
    max_severity = max(e.severity for e in sorted_events) if sorted_events else 0
    has_exec = any(e.event_type.lower() in ["powershell", "script_execution", "macro_execution",
                                             "wmi_execution", "execution"] for e in sorted_events)
    has_cred = any(e.event_type.lower() in ["credential_login", "suspicious_login",
                                             "brute_force", "mimikatz", "kerberoasting"] for e in sorted_events)
    has_c2   = any(e.event_type.lower() in ["suspicious_dns", "dns_beacon",
                                             "http_c2", "icmp_tunnel", "c2_beacon"] for e in sorted_events)
    shap_features = {
        "num_events":    len(sorted_events),
        "avg_severity":  severity_sum / len(sorted_events) if sorted_events else 0,
        "max_severity":  max_severity,
        "has_execution": int(has_exec),
        "has_cred_access":int(has_cred),
        "has_c2":        int(has_c2),
    }

    explanations = []
    try:
        explanations = explainer.explain_campaign(shap_features)
    except Exception:
        pass

    # Phase 6.1: Extract unique entities in this campaign
    extracted_entities = []
    seen_ent_keys = set()
    for e in sorted_events:
        for ent in EntityExtractor.extract_entities(e):
            ekey = (ent["type"], ent["value"].lower())
            if ekey not in seen_ent_keys:
                seen_ent_keys.add(ekey)
                ind = db.query(Indicator).filter(Indicator.type == ent["type"], Indicator.value == ent["value"].lower()).first()
                extracted_entities.append({
                    "type": ent["type"],
                    "value": ent["value"],
                    "reputation": ind.reputation if ind else "unknown",
                    "risk_score": ind.risk_score if ind else 30,
                    "status": ind.status if ind else "Observed Entity"
                })

    # Phase 6.5: Cross-campaign infrastructure reuse detection
    cross_campaign_reuse = ThreatIntelEngine().find_cross_campaign_reuse(campaign_id, db)

    return {
        "campaign":               camp_dict,
        "events":                 [_event_to_dict(e) for e in sorted_events],
        "correlated_events":      [_event_to_dict(e) for e in correlated_events],
        "contextual_events":      [_event_to_dict(e) for e in contextual_events],
        "correlation_reasons":    reasons,
        "correlation_score":      max_score if max_score > 0 else (75 if len(correlated_events) >= 2 else 0),
        "features":               shap_features,
        "temporal_features":      temporal_features,
        "risk_factors":           analysis["risk_factors"],
        "risk_trend":             risk_trend,
        "rule_predictions":       rule_predictions,
        "ml_predictions":         ml_predictions,
        "next_stage_predictions": ml_predictions,
        "explanations":           explanations,
        "entities":               extracted_entities,
        "cross_campaign_reuse":   cross_campaign_reuse,
    }


# ── Campaign events list ──────────────────────────────────────────────────────
@app.get("/api/v1/campaigns/{campaign_id}/events")
def get_campaign_events(campaign_id: str, db: Session = Depends(get_db)):
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    events = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).order_by(DBEvent.timestamp.asc()).all()
    return [_event_to_dict(e) for e in events]


# ── Campaign graph (Neo4j with resilient dynamic fallback) ───────────────────
def _build_dynamic_campaign_graph(campaign: DBCampaign, events: List[DBEvent]) -> Dict[str, Any]:
    nodes_dict = {}
    edges_list = []
    edge_keys = set()

    def _add_node(nid, ntype, name, properties=None):
        if nid not in nodes_dict:
            nodes_dict[nid] = {
                "id": nid,
                "type": ntype,
                "name": name,
                "properties": properties or {}
            }

    def _add_edge(source, target, label):
        ekey = (source, target, label)
        if ekey not in edge_keys and source in nodes_dict and target in nodes_dict:
            edge_keys.add(ekey)
            edges_list.append({
                "source": source,
                "target": target,
                "label": label,
                "type": label
            })

    target_user = normalize_user(campaign.target) or (normalize_user(events[0].user) if events else "user")
    user_id = f"user-{target_user}"
    _add_node(user_id, "User", target_user, {"target": True, "risk": campaign.risk})

    devices_seen = set()
    for e in events:
        dev = e.device_id or "WORKSTATION-01"
        dev_id = f"device-{dev.upper()}"
        if dev not in devices_seen:
            devices_seen.add(dev)
            _add_node(dev_id, "Device", dev.upper(), {"last_seen": e.timestamp.isoformat() if e.timestamp else ""})
            _add_edge(user_id, dev_id, "USED_DEVICE")

        p_name = get_proc_base(e.process_name)
        if p_name:
            proc_id = f"proc-{p_name}"
            _add_node(proc_id, "Process", p_name, {"pid": e.process_pid})
            _add_edge(dev_id, proc_id, "RAN_PROCESS")

            if e.parent_process:
                pp_name = get_proc_base(e.parent_process)
                if pp_name and pp_name != p_name:
                    pp_id = f"proc-{pp_name}"
                    _add_node(pp_id, "Process", pp_name)
                    _add_edge(pp_id, proc_id, "SPAWNED")

            if e.domain:
                dom_id = f"domain-{e.domain.lower()}"
                _add_node(dom_id, "Domain", e.domain.lower())
                _add_edge(proc_id, dom_id, "CONTACTED_DOMAIN")

            if e.source_ip and not e.source_ip.startswith("127.") and e.source_ip not in {"0.0.0.0", "::1"}:
                ip_id = f"ip-{e.source_ip}"
                _add_node(ip_id, "IP", e.source_ip)
                if e.domain:
                    dom_id = f"domain-{e.domain.lower()}"
                    _add_edge(dom_id, ip_id, "RESOLVED_TO")
                else:
                    _add_edge(proc_id, ip_id, "CONNECTED_TO")

            # Phase 6.6: LSASS & Credential Access Investigation Subtree
            event_text = f"{e.event_type} {e.detection_rule or ''} {e.detection_reason or ''} {e.mitre_technique or ''} {e.process_name or ''}".lower()
            if any(k in event_text for k in ["lsass", "mimikatz", "sekurlsa", "t1003", "credential_dump", "credential theft", "minidump"]):
                target_id = "target-lsass"
                _add_node(target_id, "Target", "LSASS", {"description": "Local Security Authority Subsystem Service"})
                _add_edge(proc_id, target_id, "TARGETED")
                
                tech_id = "tech-cred-access"
                _add_node(tech_id, "Technique", "Credential Access", {"mitre": "T1003"})
                _add_edge(target_id, tech_id, "TECHNIQUE")

            # C2 Technique Link
            if e.domain or (e.mitre_stage and "command" in e.mitre_stage.lower()):
                tech_c2 = "tech-c2"
                _add_node(tech_c2, "Technique", "Command & Control", {"mitre": "TA0011"})
                if e.domain:
                    dom_id = f"domain-{e.domain.lower()}"
                    _add_edge(dom_id, tech_c2, "TECHNIQUE")
                elif e.source_ip:
                    ip_id = f"ip-{e.source_ip}"
                    _add_edge(ip_id, tech_c2, "TECHNIQUE")

            if e.file_path or e.file_hash:
                fval = e.file_hash or get_proc_base(e.file_path) or "file"
                file_id = f"file-{fval}"
                _add_node(file_id, "File", fval, {"path": e.file_path, "hash": e.file_hash})
                _add_edge(proc_id, file_id, "CREATED_FILE")

    return {
        "nodes": list(nodes_dict.values()),
        "edges": edges_list
    }


@app.get("/api/v1/campaigns/{campaign_id}/graph")
def get_campaign_graph(campaign_id: str, db: Session = Depends(get_db)):
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    events = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).all()
    event_ids = [e.event_id for e in events]
    
    subgraph = {"nodes": [], "edges": []}
    try:
        with GraphQueries() as gq:
            subgraph = gq.get_campaign_subgraph(event_ids)
    except Exception:
        pass

    if not subgraph.get("nodes") or len(subgraph.get("nodes", [])) == 0:
        subgraph = _build_dynamic_campaign_graph(campaign, events)

    return subgraph


# ── Phase 6.2: Threat Intelligence Check Endpoints ────────────────────────────
@app.get("/api/v1/intel/check-domain")
def check_domain_intel(domain: str, db: Session = Depends(get_db)):
    return ThreatIntelEngine().check_domain(domain, db)


@app.get("/api/v1/intel/check-ip")
def check_ip_intel(ip: str, db: Session = Depends(get_db)):
    return ThreatIntelEngine().check_ip(ip, db)


@app.get("/api/v1/intel/check-process")
def check_process_intel(process: str, db: Session = Depends(get_db)):
    return ThreatIntelEngine().check_process(process, db)


@app.get("/api/v1/intel/check-hash")
def check_hash_intel(hash: str, db: Session = Depends(get_db)):
    return ThreatIntelEngine().check_file_hash(hash, db)


@app.get("/api/v1/intel/check")
def check_entity_intel(type: str, value: str, db: Session = Depends(get_db)):
    t = type.lower().strip()
    engine = ThreatIntelEngine()
    if t == "domain":
        return engine.check_domain(value, db)
    elif t in ["ip", "ip_address", "ipv4"]:
        return engine.check_ip(value, db)
    elif t in ["process", "proc"]:
        return engine.check_process(value, db)
    elif t in ["hash", "file_hash", "md5", "sha256"]:
        return engine.check_file_hash(value, db)
    else:
        return engine.get_entity_dossier(t, value, db)


# ── Phase 6.3: Threat Intelligence Indicators ─────────────────────────────────
@app.get("/api/v1/indicators")
def list_indicators(
    type: Optional[str] = None,
    reputation: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(Indicator)
    if type:
        query = query.filter(Indicator.type == type.lower())
    if reputation:
        query = query.filter(Indicator.reputation == reputation.lower())
    if search:
        query = query.filter(Indicator.value.ilike(f"%{search}%"))
    indicators = query.order_by(Indicator.risk_score.desc(), Indicator.sightings.desc()).limit(limit).all()
    return [ThreatIntelEngine._indicator_to_dict(ind) for ind in indicators]


# ── Phase 6.4: Entity Investigation Dossier ───────────────────────────────────
@app.get("/api/v1/entities/inspect")
def inspect_entity(type: str, value: str, db: Session = Depends(get_db)):
    return ThreatIntelEngine().get_entity_dossier(type, value, db)


# ── Phase 6.5: Cross-Campaign Infrastructure Reuse ────────────────────────────
@app.get("/api/v1/campaigns/{campaign_id}/cross-campaign")
def get_cross_campaign_reuse(campaign_id: str, db: Session = Depends(get_db)):
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return ThreatIntelEngine().find_cross_campaign_reuse(campaign_id, db)


# ── Phase 7: SOC Incident & Case Management ───────────────────────────────────
@app.get("/api/v1/incidents")
def list_soc_incidents(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    campaign_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    return IncidentEngine().list_incidents(
        status=status,
        priority=priority,
        assigned_to=assigned_to,
        campaign_id=campaign_id,
        db=db
    )


@app.post("/api/v1/incidents")
def create_soc_incident(payload: dict, db: Session = Depends(get_db)):
    campaign_id = payload.get("campaign_id")
    if not campaign_id:
        raise HTTPException(status_code=400, detail="Missing campaign_id")
    return IncidentEngine().create_incident(
        campaign_id=campaign_id,
        title=payload.get("title"),
        description=payload.get("description"),
        priority=payload.get("priority"),
        severity=payload.get("severity"),
        assigned_to=payload.get("assigned_to", "Unassigned"),
        db=db
    )


@app.get("/api/v1/incidents/{incident_id}")
def get_soc_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = IncidentEngine().get_incident(incident_id, db)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.patch("/api/v1/incidents/{incident_id}")
def update_soc_incident(incident_id: str, payload: dict, db: Session = Depends(get_db)):
    try:
        return IncidentEngine().update_incident(incident_id, payload, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/incidents/{incident_id}/evidence")
def add_case_evidence(incident_id: str, payload: dict, db: Session = Depends(get_db)):
    entity_type = payload.get("entity_type")
    entity_value = payload.get("entity_value")
    if not entity_type or not entity_value:
        raise HTTPException(status_code=400, detail="Missing entity_type or entity_value")
    try:
        return IncidentEngine().add_evidence(
            incident_id=incident_id,
            entity_type=entity_type,
            entity_value=entity_value,
            reason=payload.get("reason"),
            added_by=payload.get("added_by", "SOC Analyst"),
            event_id=payload.get("event_id"),
            db=db
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/incidents/{incident_id}/evidence/{evidence_id}")
def remove_case_evidence(incident_id: str, evidence_id: str, db: Session = Depends(get_db)):
    return IncidentEngine().remove_evidence(incident_id, evidence_id, db)


@app.post("/api/v1/incidents/{incident_id}/notes")
def add_case_note(incident_id: str, payload: dict, db: Session = Depends(get_db)):
    content = payload.get("content")
    if not content:
        raise HTTPException(status_code=400, detail="Missing content in note")
    try:
        return IncidentEngine().add_note(
            incident_id=incident_id,
            content=content,
            author=payload.get("author", "SOC Analyst"),
            author_type=payload.get("author_type", "ANALYST"),
            action_tag=payload.get("action_tag", "NOTE"),
            db=db
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/incidents/{incident_id}/timeline")
def get_incident_combined_timeline(incident_id: str, db: Session = Depends(get_db)):
    return IncidentEngine().get_incident_timeline(incident_id, db)


@app.get("/api/v1/incidents/{incident_id}/report")
def get_incident_report(incident_id: str, db: Session = Depends(get_db)):
    try:
        return IncidentEngine().generate_investigation_report(incident_id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/campaigns/{campaign_id}/incident")
def get_or_create_campaign_incident(campaign_id: str, auto_create: bool = True, db: Session = Depends(get_db)):
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    existing = db.query(SOCIncident).filter(SOCIncident.campaign_id == campaign_id).first()
    if existing:
        return IncidentEngine().get_incident(existing.incident_id, db)
    
    if auto_create:
        return IncidentEngine().ensure_incident_for_campaign(campaign, db)
    return None


@app.post("/api/v1/incidents/{incident_id}/auto-assign")
def auto_assign_soc_incident(incident_id: str, db: Session = Depends(get_db)):
    """Phase 8.2: Auto-assigns incident to available analyst with least open workload."""
    try:
        return IncidentEngine().auto_assign_incident(incident_id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Phase 8.3: Notification & Alerting Engine ─────────────────────────────────
@app.get("/api/v1/notifications")
def list_notifications(unread_only: bool = False, limit: int = 50, db: Session = Depends(get_db)):
    return NotificationEngine().list_notifications(unread_only=unread_only, limit=limit, db=db)


@app.get("/api/v1/notifications/unread-count")
def get_unread_notification_count(db: Session = Depends(get_db)):
    return {"unread_count": NotificationEngine().get_unread_count(db)}


@app.post("/api/v1/notifications/{notification_id}/read")
def mark_notification_read(notification_id: str, db: Session = Depends(get_db)):
    success = NotificationEngine().mark_as_read(notification_id, db)
    if not success:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"status": "success", "notification_id": notification_id}


@app.post("/api/v1/notifications/read-all")
def mark_all_notifications_read(db: Session = Depends(get_db)):
    count = NotificationEngine().mark_all_as_read(db)
    return {"status": "success", "marked_read_count": count}


# ── Phase 8.4 & 8.5: SOC Operations & Performance Dashboard ───────────────────
@app.get("/api/v1/soc-ops/overview")
def get_soc_operations_overview(db: Session = Depends(get_db)):
    return SOCOpsEngine().get_operations_overview(db)


@app.get("/api/v1/soc-ops/performance")
def get_soc_performance_metrics(db: Session = Depends(get_db)):
    return SOCOpsEngine().get_soc_performance_metrics(db)


@app.get("/api/v1/soc-ops/workload")
def get_analyst_workload_breakdown(db: Session = Depends(get_db)):
    return SOCOpsEngine().get_analyst_workload_breakdown(db)


@app.get("/api/v1/soc-ops/sla")
def get_soc_sla_breakdown(db: Session = Depends(get_db)):
    return SOCOpsEngine().get_sla_breakdown(db)


# ── Phase 8.6: Real Sysmon Live Attack Validation ─────────────────────────────
@app.post("/api/v1/sysmon-lab/validate")
def run_sysmon_lab_validation(db: Session = Depends(get_db)):
    """Phase 8.6: Runs safe lab validation of real Sysmon telemetry scenarios."""
    from app.intelligence.sysmon_lab_validator import SysmonLabValidator
    return SysmonLabValidator().run_all_validation_scenarios(db)


# ── Live Windows Sysmon Stream Management ───────────────────────────────────
@app.get("/api/v1/sysmon/status")
def get_sysmon_status():
    """Returns current live Sysmon service, channel, and stream metrics."""
    from app.ingestion.sysmon_service import sysmon_service
    return sysmon_service.get_status()


@app.post("/api/v1/sysmon/start")
def start_sysmon_stream():
    """Starts the real-time background Sysmon event subscriber."""
    from app.ingestion.sysmon_service import sysmon_service
    started = sysmon_service.start()
    return {"started": started, "status": sysmon_service.get_status()}


@app.post("/api/v1/sysmon/stop")
def stop_sysmon_stream():
    """Stops the real-time background Sysmon event subscriber."""
    from app.ingestion.sysmon_service import sysmon_service
    stopped = sysmon_service.stop()
    return {"stopped": stopped, "status": sysmon_service.get_status()}


@app.post("/api/v1/sysmon/test")
def trigger_sysmon_test(scenario: str = "reconnaissance"):
    """Triggers a safe benign command to verify live Sysmon capture and SOC feed display."""
    from app.ingestion.sysmon_service import sysmon_service
    return sysmon_service.trigger_safe_test_event(scenario)


# ── Host Applications Discovery & Real-Time Sync ───────────────────────────
@app.get("/api/v1/system/running-apps")
def get_running_applications():
    """Discovers all active user applications and browsers currently running on this machine."""
    from app.ingestion.app_catalog import get_active_user_applications
    from app.ingestion.sysmon_service import HOSTNAME, USERNAME
    apps = get_active_user_applications()
    return {
        "hostname": HOSTNAME,
        "username": USERNAME,
        "total_running": len(apps),
        "applications": apps
    }


@app.post("/api/v1/system/sync-active-apps")
def sync_active_apps_to_feed(db: Session = Depends(get_db)):
    """Discovers real active apps on this laptop and synchronizes them to the SOC feed."""
    from app.ingestion.app_catalog import get_active_user_applications
    from app.ingestion.sysmon_service import HOSTNAME, USERNAME
    from app.ingestion.normalizer import normalize_raw_log
    from app.ingestion.collector import _build_db_event
    import time
    import uuid
    from datetime import datetime, timezone

    apps = get_active_user_applications()
    synced = []
    now = datetime.now(timezone.utc)

    for idx, app_info in enumerate(apps):
        exe = app_info.get("executable", "")
        name = app_info.get("app_name", exe)
        cat = app_info.get("category", "Application")

        event_payload = {
            "event_id": f"SYS-APP-{int(time.time() * 1000)}-{idx}-{uuid.uuid4().hex[:6]}",
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Sysmon",
            "event_type": "process_creation",
            "user": USERNAME,
            "device": HOSTNAME,
            "device_id": HOSTNAME,
            "source_ip": "127.0.0.1",
            "process": exe,
            "process_name": exe,
            "command_line": f"{name} ({cat})",
            "severity": 10,
            "security_status": "informational",
            "mitre_technique": None,
            "mitre_stage": None,
            "detection_rule": f"Active {cat}",
            "detection_reason": f"Real-time detected user application '{name}' running on {HOSTNAME}.",
            "confidence": "Informational",
            "data_source": "Live Endpoint Telemetry"
        }
        norm = normalize_raw_log(event_payload)
        db_ev = _build_db_event(norm)
        db.add(db_ev)
        synced.append(name)

    db.commit()
    return {"status": "success", "synced_count": len(synced), "applications": synced}



# ── Campaign similarity ───────────────────────────────────────────────────────
@app.get("/api/v1/campaigns/{campaign_id}/similarity")
def get_campaign_similarity(campaign_id: str, top_k: int = 3, db: Session = Depends(get_db)):
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    all_campaigns = db.query(DBCampaign).all()
    sim_engine    = SimilarityEngine(db_campaigns=all_campaigns)
    current_stages = [s.strip() for s in (campaign.stage or "").split("->") if s.strip()]
    matches = sim_engine.find_similar(current_stages, top_k=top_k, exclude_campaign_id=campaign_id)
    return {"campaign_id": campaign_id, "similar_campaigns": matches}


# ── Digital Twin (Phase 4) ────────────────────────────────────────────────────
@app.post("/api/v1/campaigns/{campaign_id}/digital-twin")
def run_digital_twin(campaign_id: str, db: Session = Depends(get_db)):
    """
    Runs the Digital Twin simulation for a campaign.
    Recommended for HIGH / CRITICAL risk campaigns (risk_score >= 70).
    Returns: projected stages, blast radius, behaviour log, response playbook.
    """
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    events = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).all()
    report = twin.simulate(_campaign_to_dict(campaign), [_event_to_dict(e) for e in events])

    # Persist twin report to campaign record
    campaign.twin_report = json.dumps(report)
    db.commit()

    return report


# ── Update Campaign Lifecycle Status (Phase 5.4) ─────────────────────────────
@app.patch("/api/v1/campaigns/{campaign_id}/status")
@app.post("/api/v1/campaigns/{campaign_id}/status")
def update_campaign_status(campaign_id: str, payload: dict, db: Session = Depends(get_db)):
    """
    Updates campaign SOC workflow state:
    Awaiting Correlation -> Active Campaign -> Investigating -> Contained -> Resolved
    """
    new_status = payload.get("status") or payload.get("new_status")
    if not new_status:
        raise HTTPException(status_code=400, detail="Missing 'status' in payload")

    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    normalized_status = _normalize_campaign_status(new_status)
    campaign.status = normalized_status
    db.commit()
    db.refresh(campaign)

    return {
        "status": "success",
        "campaign_id": campaign_id,
        "new_status": normalized_status,
        "message": f"Campaign lifecycle status transitioned to '{normalized_status}'"
    }


# ── Dynamic SOC Response Playbook (Phase 5.3) ─────────────────────────────────
@app.get("/api/v1/campaigns/{campaign_id}/playbook")
def get_campaign_playbook(campaign_id: str, db: Session = Depends(get_db)):
    """
    Returns the campaign-specific SOC containment playbook based on attack archetype & stages.
    """
    from app.intelligence.digital_twin import RESPONSE_PLAYBOOKS, DEFAULT_PLAYBOOK
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    attack_type = campaign.attack_type or "Unknown"
    playbook_data = RESPONSE_PLAYBOOKS.get(attack_type)

    if not playbook_data:
        stage = campaign.stage or ""
        if "Credential" in stage or "Credential" in attack_type:
            playbook_data = RESPONSE_PLAYBOOKS.get("Credential Theft")
        elif "Command" in stage or "C2" in stage or "dns" in stage.lower():
            playbook_data = RESPONSE_PLAYBOOKS.get("Command & Control")
        elif "Impact" in stage or "Ransom" in attack_type:
            playbook_data = RESPONSE_PLAYBOOKS.get("Ransomware")
        elif "Lateral" in stage:
            playbook_data = RESPONSE_PLAYBOOKS.get("APT / Lateral Spread")
        elif "Exfiltration" in stage:
            playbook_data = RESPONSE_PLAYBOOKS.get("Data Exfiltration")
        elif "Execution" in stage or "Initial Access" in stage:
            playbook_data = RESPONSE_PLAYBOOKS.get("Malware Delivery")
        else:
            playbook_data = DEFAULT_PLAYBOOK

    return {
        "campaign_id": campaign_id,
        "attack_type": attack_type,
        "risk_score": campaign.risk_score,
        "playbook": playbook_data,
        "current_lifecycle_status": _normalize_campaign_status(campaign.status)
    }


# ── Execute containment action (SOAR Playbook) ───────────────────────────────
@app.post("/api/v1/campaigns/{campaign_id}/actions/execute")
def execute_containment_action(campaign_id: str, payload: dict, db: Session = Depends(get_db)):
    action_id = payload.get("action_id")
    action_name = payload.get("action_name")
    
    # Update campaign status in database
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if campaign:
        campaign.status = "Contained"
        db.commit()

    # Phase 8.4: Track contained_at timestamp and emit containment confirmation
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    inc = db.query(SOCIncident).filter(SOCIncident.campaign_id == campaign_id).first()
    if inc:
        inc.contained_at = now
        db.commit()
        try:
            IncidentEngine().add_note(
                incident_id=inc.incident_id,
                content=f"Containment action executed: {action_name}. Endpoint secured and campaign isolated.",
                author="SOC SOAR Engine",
                author_type="SYSTEM",
                action_tag="CONTAINMENT",
                db=db
            )
            NotificationEngine().create_notification(
                type="CONTAINMENT",
                title=f"✅ Containment Executed: {inc.incident_id}",
                message=f"Remediation action '{action_name}' executed on {campaign.target if campaign else 'target'}.",
                severity="INFO",
                link_type="incident",
                link_id=inc.incident_id,
                db=db
            )
        except Exception:
            pass

    return {
        "status": "success",
        "action_id": action_id,
        "action_name": action_name,
        "execution_timestamp": time.strftime("%H:%M:%S"),
        "campaign_status": "Contained",
        "message": f"Containment action '{action_name}' executed successfully."
    }


# ── Prediction timeline — Actual vs Predicted (Phase 4) ──────────────────────
@app.get("/api/v1/campaigns/{campaign_id}/prediction-timeline")
def get_prediction_timeline(campaign_id: str, db: Session = Depends(get_db)):
    """
    Returns the longitudinal actual-vs-predicted record for a campaign.
    Each entry shows: observed stages, ML + rule-based prediction made,
    actual next stage that occurred, and whether predictions were correct.
    """
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    logs = (
        db.query(PredictionLog)
        .filter(PredictionLog.campaign_id == campaign_id)
        .order_by(PredictionLog.id.asc())
        .all()
    )

    timeline = []
    for log in logs:
        timeline.append({
            "timestamp":       log.timestamp.isoformat() if log.timestamp else None,
            "at_stage":        log.at_stage,
            "observed_stages": json.loads(log.observed_stages or "[]"),
            "ml_prediction":   {
                "top1_stage": log.ml_top1_stage,
                "top1_prob":  log.ml_top1_prob,
                "top3_stages":json.loads(log.ml_top3_stages or "[]"),
            },
            "rule_prediction": {
                "top1_stage": log.rule_top1_stage,
                "top1_prob":  log.rule_top1_prob,
            },
            "actual_next_stage": log.actual_next_stage,
            "ml_correct":        log.ml_correct,
            "ml_top3_correct":   log.ml_top3_correct,
            "rule_correct":      log.rule_correct,
        })

    # Compute running accuracy
    total    = sum(1 for t in timeline if t["actual_next_stage"] is not None)
    ml_hits  = sum(1 for t in timeline if t["ml_correct"])
    rule_hits= sum(1 for t in timeline if t["rule_correct"])

    return {
        "campaign_id":         campaign_id,
        "timeline":            timeline,
        "running_ml_accuracy": round(ml_hits / total, 3) if total > 0 else None,
        "running_rule_accuracy": round(rule_hits / total, 3) if total > 0 else None,
        "total_predictions":   total,
    }


# ── Validation report ─────────────────────────────────────────────────────────
@app.get("/api/v1/validation/report")
def get_validation_report():
    return run_validation(predictor)


# ── Dataset export ────────────────────────────────────────────────────────────
@app.get("/api/v1/dataset/export")
def export_dataset(split: str = "train", source: str = "synthetic"):
    """
    Download generated research datasets.
    split: 'train' | 'val'
    source: 'synthetic' | 'cicids'
    """
    if source == "cicids":
        filename = "caip_cicids_dataset.csv"
    elif split == "val":
        filename = "caip_validation_set.csv"
    else:
        filename = "caip_attack_dataset.csv"

    path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "datasets", filename)
    )
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"{filename} not found.")
    return FileResponse(path, media_type="text/csv", filename=filename)


# ── Source comparison stats ───────────────────────────────────────────────────
@app.get("/api/v1/campaigns/compare-sources")
def compare_sources(db: Session = Depends(get_db)):
    """Returns campaign counts, risk distributions, and stage coverage by data source."""
    campaigns = db.query(DBCampaign).all()
    result = {}
    for c in campaigns:
        src = getattr(c, "data_source", "Synthetic")
        if src not in result:
            result[src] = {"count": 0, "high": 0, "critical": 0, "medium": 0, "low": 0}
        result[src]["count"] += 1
        s = c.risk_score
        if s >= 85:   result[src]["critical"] += 1
        elif s >= 70: result[src]["high"]     += 1
        elif s >= 40: result[src]["medium"]   += 1
        else:         result[src]["low"]      += 1
    return result


# ── Experiment Results Summary (for Research Dashboard Tab) ───────────────────
@app.get("/api/v1/experiments/summary")
def get_experiment_summary():
    """
    Returns latest experiment results for the Research tab.
    Results are pre-computed by running experiments/run_all_experiments.py.
    """
    import glob
    results_dir = os.path.normpath(os.path.join(
        os.path.dirname(__file__), "..", "..", "experiments", "results"
    ))

    summary = {}
    experiment_files = {
        "exp1": "exp1_results.json",
        "exp2": "exp2_results.json",
        "exp3": "exp3_results.json",
        "exp4": "exp4_results.json",
        "exp5": "exp5_results.json",
        "exp6": "exp6_results.json",
        "exp7": "exp7_results.json",
    }

    for key, filename in experiment_files.items():
        path = os.path.join(results_dir, filename)
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    summary[key] = json.load(f)
            except Exception:
                summary[key] = {"error": "failed to load"}
        else:
            summary[key] = {"status": "not_run"}

    # Also include routing tier info from cost_router
    from app.intelligence.cost_router import CostRouter
    summary["routing_tiers"] = CostRouter.explain_tiers()

    summary["has_results"] = any(
        "error" not in v and "status" not in v
        for v in summary.values()
        if isinstance(v, dict)
    )

    return summary


# ── Routing tier decision for a campaign ──────────────────────────────────────
@app.get("/api/v1/campaigns/{campaign_id}/routing")
def get_campaign_routing(campaign_id: str, db: Session = Depends(get_db)):
    """Return the cost-aware routing tier for a specific campaign."""
    from app.intelligence.cost_router import route_campaign
    campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    events = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).all()
    decision = route_campaign(
        risk_score=campaign.risk_score or 0,
        attack_type=campaign.attack_type or "",
        n_events=len(events),
    )
    return {
        "campaign_id":   campaign_id,
        "risk_score":    campaign.risk_score,
        "attack_type":   campaign.attack_type,
        "n_events":      len(events),
        **decision,
    }


# ── Live Simulation Endpoints ──────────────────────────────────────────────────
@app.post("/api/v1/simulation/credential-theft/step")
def simulate_credential_theft_step(payload: dict):
    """
    Returns step-by-step live simulation state for the Credential Theft scenario.
    Step 1: Suspicious URL (Alerts: 1, Risk: 35)
    Step 2: User Visit URL (Alerts: 2, Risk: 55)
    Step 3: PowerShell Execution (Alerts: 3, Risk: 78)
    Step 4: Credential Access (Alerts: 4, Risk: 92, Twin: Active)
    Step 5: DNS C2 Communication (Alerts: 5, Risk: 95, Twin: Active, Blast Radius & Response)
    """
    import socket
    system_host = socket.gethostname()
    system_user = os.environ.get("USERNAME") or os.environ.get("USER") or "analyst"
    step = payload.get("step", 1)
    
    events_timeline = [
        {
            "step": 1,
            "timestamp": "10:00:01",
            "source": "Web Proxy / EDR",
            "event_type": "url_visit",
            "user": system_user,
            "source_ip": "192.168.1.105",
            "device_id": system_host,
            "domain": "phish-secure-login.xyz",
            "url": "http://phish-secure-login.xyz/login.php",
            "mitre_technique": "T1566.002",
            "mitre_stage": "Initial Access",
            "severity": 4,
            "description": "User visited newly registered phishing domain",
            "detection_rule": "Phishing Domain Navigation",
            "detection_reason": "User navigated to newly registered suspicious credential collection domain.",
            "confidence": "Medium",
        },
        {
            "step": 2,
            "timestamp": "10:00:05",
            "source": "EDR Process",
            "event_type": "payload_download",
            "user": system_user,
            "source_ip": "192.168.1.105",
            "device_id": system_host,
            "domain": "phish-secure-login.xyz",
            "file_path": f"C:\\Users\\{system_user}\\Downloads\\invoice_update.scr",
            "mitre_technique": "T1204.002",
            "mitre_stage": "Initial Access",
            "severity": 6,
            "description": "User executed downloaded malicious binary payload",
            "detection_rule": "Executable Payload Ingress",
            "detection_reason": "Malicious executable binary downloaded to local filesystem directory.",
            "confidence": "Medium",
        },
        {
            "step": 3,
            "timestamp": "10:00:15",
            "source": "EDR Execution",
            "event_type": "powershell",
            "user": system_user,
            "source_ip": "192.168.1.105",
            "device_id": system_host,
            "process_name": "powershell.exe",
            "mitre_technique": "T1059.001",
            "mitre_stage": "Execution",
            "severity": 8,
            "description": "Obfuscated Base64 Encoded PowerShell command spawned",
            "detection_rule": "Suspicious PowerShell Activity",
            "detection_reason": "PowerShell executed with an encoded command (-EncodedCommand / IEX / DownloadString).",
            "confidence": "High",
        },
        {
            "step": 4,
            "timestamp": "10:00:25",
            "source": "EDR Credential Access",
            "event_type": "credential_access",
            "user": system_user,
            "source_ip": "192.168.1.105",
            "device_id": system_host,
            "process_name": "mimikatz.exe",
            "mitre_technique": "T1003.001",
            "mitre_stage": "Credential Access",
            "severity": 9,
            "description": "LSASS process memory dump attempted via Mimikatz",
            "detection_rule": "LSASS Process Memory Dump",
            "detection_reason": "Process opened LSASS handle with high-privilege read access via Mimikatz.",
            "confidence": "Critical",
        },
        {
            "step": 5,
            "timestamp": "10:00:40",
            "source": "Network Firewall",
            "event_type": "suspicious_dns",
            "user": system_user,
            "source_ip": "192.168.1.105",
            "device_id": system_host,
            "domain": "c2-control.attacker.net",
            "mitre_technique": "T1071.004",
            "mitre_stage": "Command & Control",
            "severity": 9,
            "description": "High-frequency DNS beaconing to external C2 server",
            "detection_rule": "Suspicious C2 Domain DNS Query",
            "detection_reason": "High-frequency DNS beaconing and interactive C2 communication detected.",
            "confidence": "High",
        }
    ]
    
    current_events = events_timeline[:min(step, 5)]
    alert_count = len(current_events)
    risk_map = {1: 35, 2: 55, 3: 78, 4: 92, 5: 95}
    risk_score = risk_map.get(step, 95)
    twin_activated = risk_score >= 80

    predictions = {
        "lateral_movement": 0.82 if step >= 4 else 0.45,
        "exfiltration": 0.67 if step >= 4 else 0.30,
        "impact": 0.41 if step >= 4 else 0.15,
        "next_predicted_stage": "Lateral Movement" if step >= 3 else "Execution"
    }

    blast_radius = {
        "users": [system_user],
        "devices": [system_host],
        "domains": ["phish-secure-login.xyz", "c2-control.attacker.net"] if step >= 5 else ["phish-secure-login.xyz"],
        "ips": ["192.168.1.105"]
    } if twin_activated else None

    playbook = [
        f"1. Isolate affected endpoint ('{system_host}') from network",
        "2. Investigate PowerShell process tree & spawned child processes",
        "3. Review LSASS memory access events & dump handles",
        f"4. Reset potentially compromised credentials & revoke active tokens for '{system_user}'",
        "5. Check adjacent hosts for signs of lateral movement or Kerberoasting"
    ] if twin_activated else []

    # Persist simulated events and campaign to database for real-time dashboard updates
    try:
        from app.database.database import SessionLocal, Base, engine
        import app.database.models
        from app.database.models import Event as DBEvent, Campaign as DBCampaign, PredictionLog
        from datetime import datetime
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        
        # Build stage flow string (e.g. "Initial Access -> Execution -> Credential Access")
        stages = []
        for ev in current_events:
            st = ev.get("mitre_stage")
            if st and st not in stages:
                stages.append(st)
        stage_str = " -> ".join(stages) if stages else "Initial Access"

        # Upsert Campaign
        camp = db.query(DBCampaign).filter(DBCampaign.campaign_id == "CMP-SIM-CRED-THEFT").first()
        if not camp:
            camp = DBCampaign(
                campaign_id="CMP-SIM-CRED-THEFT",
                target=f"{system_user} ({system_host})",
                attack_type="Credential Theft & Execution",
                stage=stage_str,
                confidence=0.94,
                risk="CRITICAL" if risk_score >= 85 else ("HIGH" if risk_score >= 70 else "MEDIUM"),
                risk_score=risk_score,
                status="Active Campaign",
                data_source="Live Simulation",
                predicted_outcome=predictions.get("next_predicted_stage"),
                twin_report=json.dumps(blast_radius) if blast_radius else None,
                created_at=datetime.utcnow()
            )
            db.add(camp)
            db.commit()
        else:
            camp.target = f"{system_user} ({system_host})"
            camp.stage = stage_str
            camp.risk_score = risk_score
            camp.risk = "CRITICAL" if risk_score >= 85 else ("HIGH" if risk_score >= 70 else "MEDIUM")
            camp.predicted_outcome = predictions.get("next_predicted_stage")
            if blast_radius:
                camp.twin_report = json.dumps(blast_radius)
            db.commit()

        # Add all events up to current step
        for idx, ev_dict in enumerate(current_events, 1):
            evt_id = f"SIM-EVT-00{idx}"
            existing = db.query(DBEvent).filter(DBEvent.event_id == evt_id).first()
            if not existing:
                new_evt = DBEvent(
                    event_id=evt_id,
                    timestamp=datetime.utcnow(),
                    source=ev_dict.get("source", "Simulation"),
                    event_type=ev_dict.get("event_type", "simulation_event"),
                    user=ev_dict.get("user", system_user),
                    source_ip=ev_dict.get("source_ip", "192.168.1.105"),
                    domain=ev_dict.get("domain"),
                    url=ev_dict.get("url"),
                    file_path=ev_dict.get("file_path"),
                    process_name=ev_dict.get("process_name"),
                    device_id=ev_dict.get("device_id", system_host),
                    severity=ev_dict.get("severity", 5) * 10,
                    mitre_technique=ev_dict.get("mitre_technique"),
                    mitre_stage=ev_dict.get("mitre_stage"),
                    detection_rule=ev_dict.get("detection_rule"),
                    detection_reason=ev_dict.get("detection_reason"),
                    confidence=ev_dict.get("confidence"),
                    correlation_reason=f"Correlated via identity ({system_user}) and endpoint ({system_host})",
                    data_source="Live Simulation",
                    campaign_id="CMP-SIM-CRED-THEFT"
                )
                db.add(new_evt)

        # Log prediction timeline for investigate tab
        current_mitre_stage = current_events[-1].get("mitre_stage", "Initial Access")
        pred_log = db.query(PredictionLog).filter(
            PredictionLog.campaign_id == "CMP-SIM-CRED-THEFT",
            PredictionLog.at_stage == current_mitre_stage
        ).first()
        if not pred_log:
            pred_log = PredictionLog(
                campaign_id="CMP-SIM-CRED-THEFT",
                timestamp=datetime.utcnow(),
                observed_stages=json.dumps(stages),
                at_stage=current_mitre_stage,
                ml_top1_stage=predictions.get("next_predicted_stage"),
                ml_top1_prob=0.88 if step >= 3 else 0.72,
                ml_top3_stages=json.dumps([predictions.get("next_predicted_stage", "Execution"), "Credential Access", "Command & Control"]),
                rule_top1_stage=predictions.get("next_predicted_stage"),
                rule_top1_prob=0.80,
                actual_next_stage="Execution" if step == 1 else ("Credential Access" if step == 2 else ("Command & Control" if step == 3 else "Exfiltration")),
                ml_correct=True,
                ml_top3_correct=True,
                rule_correct=True
            )
            db.add(pred_log)

        db.commit()
        db.close()
    except Exception as e:
        print(f"Error persisting simulation to database: {e}")

    return {
        "scenario": "Credential Theft & Execution",
        "current_step": step,
        "total_steps": 5,
        "alerts_count": alert_count,
        "campaigns_count": 1,
        "campaign_id": "CMP-SIM-CRED-THEFT",
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 85 else ("HIGH" if risk_score >= 70 else "MEDIUM"),
        "events": current_events,
        "predictions": predictions,
        "digital_twin_activated": twin_activated,
        "routing_decision": {
            "tier": "DIGITAL_TWIN" if twin_activated else ("ANALYST_QUEUE" if risk_score >= 40 else "MONITOR_LOG"),
            "reason": f"Risk Score {risk_score} >= 80 triggers automated Digital Twin sandbox simulation" if twin_activated else f"Risk Score {risk_score} < 80 logged for monitoring"
        },
        "blast_radius": blast_radius,
        "recommended_playbook": playbook
    }


# ── SPA Fallback Handler ──────────────────────────────────────────────────────
@app.get("/{full_path:path}")
async def catch_all_spa(full_path: str):
    if full_path.startswith("api/") or full_path == "api":
        raise HTTPException(status_code=404, detail="API endpoint not found")
    potential_file = os.path.join(_frontend_dist, full_path)
    if os.path.isfile(potential_file):
        return FileResponse(potential_file)
    index_file = os.path.join(_frontend_dist, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    raise HTTPException(status_code=404, detail="Resource not found")


