from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey, Float, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base

class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    target: Mapped[str] = mapped_column(String, index=True)
    attack_type: Mapped[str] = mapped_column(String)
    stage: Mapped[str] = mapped_column(String)  # Initial Access -> Execution -> ...
    confidence: Mapped[float] = mapped_column(Float)
    risk: Mapped[str] = mapped_column(String)       # HIGH, MEDIUM, LOW
    risk_score: Mapped[int] = mapped_column(Integer, default=0)  # 0–100
    data_source: Mapped[str] = mapped_column(String, default="Synthetic")  # Synthetic | CICIDS2017
    predicted_outcome: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # next stage ML prediction
    twin_report: Mapped[Optional[str]] = mapped_column(Text, nullable=True)          # JSON blob from digital twin
    status: Mapped[Optional[str]] = mapped_column(String, nullable=True, default=None) # SOAR status: CONTAINED | None
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    events: Mapped[List["Event"]] = relationship("Event", back_populates="campaign")
    prediction_logs: Mapped[List["PredictionLog"]] = relationship("PredictionLog", back_populates="campaign")
    incidents: Mapped[List["SOCIncident"]] = relationship("SOCIncident", back_populates="campaign")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = mapped_column(String, index=True)
    event_type: Mapped[str] = mapped_column(String, index=True)
    user: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    domain: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    severity: Mapped[int] = mapped_column(Integer)
    security_status: Mapped[str] = mapped_column(
        String,
        default="informational",
        index=True
    )

    # MITRE ATT&CK
    mitre_technique: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    mitre_stage: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)

    # Phase 4 — Expanded context fields
    device_id: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    process_name: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    process_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_process: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    parent_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    destination_port: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    login_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # interactive, network, service
    file_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    data_source: Mapped[str] = mapped_column(String, default="Synthetic")
    correlation_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # why it was correlated
    # Phase 5 — Detection Explainability
    detection_rule: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    detection_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    campaign_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("campaigns.campaign_id"), nullable=True)
    campaign: Mapped[Optional["Campaign"]] = relationship("Campaign", back_populates="events")


class PredictionLog(Base):
    """
    Longitudinal Actual vs Predicted record.
    One row per prediction event — stored whenever the ML predictor is called
    at a stage boundary. Enables post-hoc comparison of predicted vs actual
    next stage across a campaign's full timeline.
    """
    __tablename__ = "prediction_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String, ForeignKey("campaigns.campaign_id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # State at prediction time
    observed_stages: Mapped[str] = mapped_column(String)        # JSON list
    at_stage: Mapped[str] = mapped_column(String)               # stage when prediction was made

    # Prediction (ML)
    ml_top1_stage: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ml_top1_prob: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ml_top3_stages: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # JSON list

    # Prediction (Rule-based baseline)
    rule_top1_stage: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    rule_top1_prob: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Ground truth (filled in when next event arrives)
    actual_next_stage: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ml_correct: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    ml_top3_correct: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    rule_correct: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="prediction_logs")


class Indicator(Base):
    """
    Phase 6.3 — Internal Threat Intelligence Indicator Table.
    Maintains persistent memory of all observed IOCs and entities across telemetry.
    """
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    type: Mapped[str] = mapped_column(String, index=True)  # domain, ip, process, user, device, file, hash
    value: Mapped[str] = mapped_column(String, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    sightings: Mapped[int] = mapped_column(Integer, default=1)
    affected_devices: Mapped[int] = mapped_column(Integer, default=1)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    reputation: Mapped[str] = mapped_column(String, default="unknown")  # benign | suspicious | malicious | unknown
    status: Mapped[str] = mapped_column(String, default="Active Internal Indicator")

    # Associated relationships stored as JSON strings
    associated_devices: Mapped[str] = mapped_column(Text, default="[]")
    associated_processes: Mapped[str] = mapped_column(Text, default="[]")
    associated_campaigns: Mapped[str] = mapped_column(Text, default="[]")
    associated_users: Mapped[str] = mapped_column(Text, default="[]")


class SOCIncident(Base):
    """
    Phase 7.1 — SOC Incident / Case Management.
    Separates automatically detected attack campaigns from human-managed SOC cases.
    """
    __tablename__ = "soc_incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    campaign_id: Mapped[str] = mapped_column(String, ForeignKey("campaigns.campaign_id"), index=True)
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")

    severity: Mapped[str] = mapped_column(String, default="HIGH")       # CRITICAL | HIGH | MEDIUM | LOW
    priority: Mapped[str] = mapped_column(String, default="P2 - High")  # P1 - Critical | P2 - High | P3 - Medium | P4 - Low
    status: Mapped[str] = mapped_column(String, default="New")          # New -> Assigned -> Investigating -> Awaiting Action -> Closed

    assigned_to: Mapped[str] = mapped_column(String, default="Unassigned") # Unassigned | SOC Analyst A | SOC Analyst B | SOC Lead

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    triage_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    contained_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    sla_due_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_status: Mapped[str] = mapped_column(String, default="Within SLA")  # Within SLA | At Risk | Breached

    resolution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="incidents")
    evidence: Mapped[List["CaseEvidence"]] = relationship("CaseEvidence", back_populates="incident", cascade="all, delete-orphan")
    notes: Mapped[List["CaseNote"]] = relationship("CaseNote", back_populates="incident", cascade="all, delete-orphan")


class CaseEvidence(Base):
    """
    Phase 7.2 — Evidence Management.
    Enables analysts to mark critical IOCs, processes, domains, hashes, and events as case evidence.
    """
    __tablename__ = "case_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("soc_incidents.incident_id"), index=True)

    entity_type: Mapped[str] = mapped_column(String, index=True)  # process | domain | ip | file | hash | user | device | event
    entity_value: Mapped[str] = mapped_column(String)
    event_id: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)

    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    added_by: Mapped[str] = mapped_column(String, default="SOC Analyst")
    reason: Mapped[str] = mapped_column(Text, default="Identified during campaign evidence review")

    incident: Mapped["SOCIncident"] = relationship("SOCIncident", back_populates="evidence")


class CaseNote(Base):
    """
    Phase 7.3 — Analyst Notes & Audit Timeline.
    Stores timeline actions, status transitions, containment notes, and analyst findings.
    """
    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    note_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("soc_incidents.incident_id"), index=True)

    author: Mapped[str] = mapped_column(String, default="SOC Analyst")
    author_type: Mapped[str] = mapped_column(String, default="ANALYST") # SYSTEM | ANALYST
    content: Mapped[str] = mapped_column(Text)
    action_tag: Mapped[Optional[str]] = mapped_column(String, nullable=True) # ESCALATION | INVESTIGATION | CONTAINMENT | STATUS_CHANGE | NOTE

    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["SOCIncident"] = relationship("SOCIncident", back_populates="notes")


class Notification(Base):
    """
    Phase 8.3 — Notification & Alerting Engine.
    Stores alerts for critical incidents, high-risk campaigns, case assignments,
    SLA breach warnings, and containment confirmations.
    """
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    notification_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    type: Mapped[str] = mapped_column(String, index=True)  # CRITICAL_INCIDENT | HIGH_RISK_CAMPAIGN | CASE_ASSIGNMENT | SLA_BREACH | CONTAINMENT
    title: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String, default="HIGH")  # CRITICAL | HIGH | MEDIUM | INFO
    link_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # incident | campaign
    link_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
