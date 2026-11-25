from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from app.database.database import get_db
from app.database.models import Event as DBEvent
from app.ingestion.normalizer import normalize_raw_log, NormalizedEvent

router = APIRouter(prefix="/events", tags=["Ingestion"])


def _build_db_event(event_data: NormalizedEvent) -> DBEvent:
    """Construct a DBEvent from a NormalizedEvent, including Phase 4 and Phase 5 fields."""
    return DBEvent(
        event_id       = event_data.event_id,
        timestamp      = event_data.timestamp,
        source         = event_data.source,
        event_type     = event_data.event_type,
        user           = event_data.user,
        source_ip      = event_data.source_ip,
        domain         = event_data.domain,
        url            = event_data.url,
        file_hash      = event_data.file_hash,
        severity       = event_data.severity,
        security_status= event_data.security_status,
        mitre_technique= event_data.mitre_technique,
        mitre_stage    = event_data.mitre_stage,
        # Phase 4 expanded fields
        device_id      = event_data.device_id,
        process_name   = event_data.process_name,
        process_pid    = event_data.process_pid,
        parent_process = event_data.parent_process,
        parent_pid     = event_data.parent_pid,
        command_line   = event_data.command_line,
        destination_ip = event_data.destination_ip,
        destination_port = event_data.destination_port,
        login_type     = event_data.login_type,
        file_path      = event_data.file_path,
        data_source    = event_data.data_source,
        # Phase 5 explainability fields
        detection_rule = event_data.detection_rule,
        detection_reason= event_data.detection_reason,
        confidence     = event_data.confidence,
    )


INTELLIGENCE_STATUSES = {
    "review",
    "suspicious",
    "high_risk",
    "critical"
}


@router.post("/ingest", response_model=NormalizedEvent)
def ingest_event(
    raw_log: Dict[str, Any],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    try:
        event_data = normalize_raw_log(raw_log)
        db_event = _build_db_event(event_data)
        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        # Phase 6.1 & 6.3: Extract entities & build internal threat intelligence memory
        try:
            from app.intelligence.threat_intel import ThreatIntelEngine
            ThreatIntelEngine().record_event_telemetry(db_event, db)
        except Exception as te_err:
            print(f"Threat intel recording error: {te_err}")

        if event_data.security_status in INTELLIGENCE_STATUSES:
            background_tasks.add_task(process_ingested_event, event_data)

        return event_data
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Log ingestion failed: {str(e)}")


@router.post("/ingest/batch", response_model=List[NormalizedEvent])
def ingest_events_batch(
    raw_logs: List[Dict[str, Any]],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    normalized_events = []
    db_events = []
    try:
        for raw_log in raw_logs:
            event_data = normalize_raw_log(raw_log)
            db_ev = _build_db_event(event_data)
            db.add(db_ev)
            db_events.append(db_ev)
            normalized_events.append(event_data)
        db.commit()

        # Phase 6.1 & 6.3: Record threat intelligence telemetry
        try:
            from app.intelligence.threat_intel import ThreatIntelEngine
            ti_engine = ThreatIntelEngine()
            for dev in db_events:
                ti_engine.record_event_telemetry(dev, db)
        except Exception as te_err:
            print(f"Batch threat intel recording error: {te_err}")

        for ev in normalized_events:
            if ev.security_status in INTELLIGENCE_STATUSES:
                background_tasks.add_task(process_ingested_event, ev)
        return normalized_events
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Batch log ingestion failed: {str(e)}")


def process_ingested_event(event: NormalizedEvent):
    """Run Campaign correlation engine immediately, then update Neo4j context graph and Threat Intel."""
    from app.intelligence.campaign_engine import CampaignEngine

    try:
        CampaignEngine().correlate_event(event)
    except Exception as e:
        print(f"Campaign correlation failed for event {event.event_id}: {str(e)}")

    # Update threat intel with any campaign links
    try:
        from app.database.database import SessionLocal
        from app.database.models import Event as DBEvent
        from app.intelligence.threat_intel import ThreatIntelEngine
        with SessionLocal() as db_session:
            db_ev = db_session.query(DBEvent).filter(DBEvent.event_id == event.event_id).first()
            if db_ev:
                ThreatIntelEngine().record_event_telemetry(db_ev, db_session)
    except Exception as e:
        pass

    try:
        from app.graph.graph_builder import GraphBuilder
        with GraphBuilder() as gb:
            if gb.driver:
                gb.add_event(event)
    except Exception as e:
        pass

