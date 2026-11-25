"""
CAIP SOC Incident & Case Management Engine — Phase 7
====================================================
Separates automatically detected attack campaigns from human-managed SOC cases.
Manages:
  • 7.1 SOC Incident lifecycle (New -> Assigned -> Investigating -> Awaiting Action -> Closed)
  • 7.2 Case Evidence management (marking processes, domains, hashes, and events as formal evidence)
  • 7.3 Analyst Notes & Audit Timeline (combining automated events, analyst actions, status transitions)
  • 7.4 Analyst Assignment & Priority Ownership (P1-Critical to P4-Low)
  • 7.5 Distinct Campaign Status vs Incident Status Workflows
  • 7.6 Structured Incident Investigation Report Generation (Markdown & JSON export)
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.database.models import (
    SOCIncident,
    CaseEvidence,
    CaseNote,
    Campaign as DBCampaign,
    Event as DBEvent,
    Indicator,
    Notification
)
from app.intelligence.entity_extractor import EntityExtractor, get_proc_base


ANALYST_ROSTER = [
    "Unassigned",
    "SOC Analyst A",
    "SOC Analyst B",
    "SOC Lead"
]

INCIDENT_STATUSES = [
    "New",
    "Assigned",
    "Investigating",
    "Awaiting Action",
    "Closed"
]

PRIORITY_LEVELS = [
    "P1 - Critical",
    "P2 - High",
    "P3 - Medium",
    "P4 - Low"
]


class IncidentEngine:
    """
    Core engine for managing human SOC cases, evidence curation,
    analyst collaboration notes, SLA tracking, and automated assignment.
    """

    def get_analyst_workloads(self, db: Session) -> Dict[str, int]:
        """
        Phase 8.5: Returns active open case counts per analyst.
        """
        active_analysts = ["SOC Analyst A", "SOC Analyst B", "SOC Lead"]
        workloads = {a: 0 for a in active_analysts}
        
        incidents = db.query(SOCIncident).filter(
            SOCIncident.status != "Closed",
            SOCIncident.assigned_to.in_(active_analysts)
        ).all()
        
        for inc in incidents:
            if inc.assigned_to in workloads:
                workloads[inc.assigned_to] += 1
        return workloads

    def auto_assign_incident(self, incident_id: str, db: Session) -> Dict[str, Any]:
        """
        Phase 8.2: Automated Incident Assignment.
        Selects the analyst with the lowest open workload and dispatches the case.
        """
        inc = db.query(SOCIncident).filter(SOCIncident.incident_id == incident_id).first()
        if not inc:
            raise ValueError(f"Incident {incident_id} not found")

        workloads = self.get_analyst_workloads(db)
        tier1 = ["SOC Analyst A", "SOC Analyst B"]
        tier1_workloads = {a: workloads.get(a, 0) for a in tier1}
        min_load = min(tier1_workloads.values())
        candidate_analysts = [a for a, load in tier1_workloads.items() if load == min_load]
        selected_analyst = candidate_analysts[0]

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        inc.assigned_to = selected_analyst
        if inc.status == "New":
            inc.status = "Assigned"
            inc.triage_at = now

        inc.updated_at = now

        # Add audit note
        note = CaseNote(
            note_id=f"NOTE-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            author="SOC Orchestration Engine",
            author_type="SYSTEM",
            content=f"Automatically assigned to {selected_analyst} based on workload balance ({min_load} open cases).",
            action_tag="STATUS_CHANGE",
            timestamp=now
        )
        db.add(note)
        db.commit()

        # Emit notification
        try:
            from app.intelligence.notification_engine import NotificationEngine
            NotificationEngine().create_notification(
                type="CASE_ASSIGNMENT",
                title=f"👤 Case Assigned: {incident_id}",
                message=f"{inc.title} auto-assigned to {selected_analyst} ({inc.priority}, {min_load} active cases).",
                severity=inc.severity,
                link_type="incident",
                link_id=incident_id,
                db=db
            )
        except Exception:
            pass

        return self.get_incident(incident_id, db)

    def create_incident(
        self,
        campaign_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        priority: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: str = "Unassigned",
        auto_assign: bool = True,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Creates a new formal SOC Incident case linked to a campaign.
        """
        campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        year = now.strftime("%Y")
        
        inc_count = db.query(SOCIncident).count() + 1
        incident_id = f"INC-{year}-{inc_count:04d}"

        # Derive title and severity from campaign if not provided
        if not title:
            target = campaign.target if campaign else "Endpoint"
            attack = campaign.attack_type if campaign else "Suspicious Activity"
            title = f"{attack} on {target}"

        if not severity:
            severity = campaign.risk if campaign else "HIGH"

        if not priority:
            if severity == "CRITICAL" or (campaign and campaign.risk_score >= 85):
                priority = "P1 - Critical"
            elif severity == "HIGH" or (campaign and campaign.risk_score >= 70):
                priority = "P2 - High"
            elif severity == "MEDIUM":
                priority = "P3 - Medium"
            else:
                priority = "P4 - Low"

        if not description and campaign:
            description = (
                f"Multi-stage attack campaign {campaign.campaign_id} detected. "
                f"Target: {campaign.target}, Stage: {campaign.stage}, Risk Score: {campaign.risk_score}/100."
            )

        # SLA hours
        sla_hours = 4 if "P1" in priority else 8 if "P2" in priority else 24
        sla_due_at = now + timedelta(hours=sla_hours)

        incident = SOCIncident(
            incident_id=incident_id,
            campaign_id=campaign_id,
            title=title,
            description=description or "",
            severity=severity,
            priority=priority,
            status="New" if assigned_to == "Unassigned" else "Assigned",
            assigned_to=assigned_to,
            created_at=now,
            updated_at=now,
            sla_due_at=sla_due_at,
            sla_status="Within SLA"
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        # Initial automated system note
        init_note = CaseNote(
            note_id=f"NOTE-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            author="SYSTEM",
            author_type="SYSTEM",
            content=f"SOC Incident opened for campaign {campaign_id}. Severity: {severity}, Priority: {priority}, SLA Target: {sla_hours}h.",
            action_tag="ESCALATION",
            timestamp=now
        )
        db.add(init_note)

        # Emit Critical Incident Notification
        try:
            from app.intelligence.notification_engine import NotificationEngine
            if severity == "CRITICAL" or "P1" in priority:
                NotificationEngine().create_notification(
                    type="CRITICAL_INCIDENT",
                    title=f"🔴 Critical Incident Opened: {incident_id}",
                    message=f"{title} (Target: {campaign.target if campaign else 'Host'}). Immediate triage required within {sla_hours}h SLA.",
                    severity="CRITICAL",
                    link_type="incident",
                    link_id=incident_id,
                    db=db
                )
        except Exception:
            pass

        # Phase 8.2: Auto-assign if requested and unassigned
        if assigned_to == "Unassigned" and auto_assign:
            self.auto_assign_incident(incident_id, db)

        # Pre-seed initial key evidence from campaign if available
        if campaign:
            events = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).all()
            evidence_seen = set()
            for ev in events:
                if ev.security_status in ["high_risk", "critical"]:
                    if ev.process_name and ("process", ev.process_name.lower()) not in evidence_seen:
                        evidence_seen.add(("process", ev.process_name.lower()))
                        self._add_evidence_internal(
                            incident_id=incident_id,
                            entity_type="process",
                            entity_value=get_proc_base(ev.process_name),
                            reason=f"High-severity process involved in {ev.event_type} ({ev.detection_rule or 'Suspicious execution'})",
                            added_by="SYSTEM (Initial Triage)",
                            event_id=ev.event_id,
                            db=db
                        )
                    if ev.domain and ("domain", ev.domain.lower()) not in evidence_seen:
                        evidence_seen.add(("domain", ev.domain.lower()))
                        self._add_evidence_internal(
                            incident_id=incident_id,
                            entity_type="domain",
                            entity_value=ev.domain.lower(),
                            reason=f"Adversary C2 or external domain referenced in {ev.event_id}",
                            added_by="SYSTEM (Initial Triage)",
                            event_id=ev.event_id,
                            db=db
                        )

        db.commit()
        return self.get_incident(incident_id, db)

    def ensure_incident_for_campaign(self, campaign: DBCampaign, db: Session) -> Dict[str, Any]:
        """
        Idempotently returns existing incident or auto-creates one for a campaign.
        """
        existing = db.query(SOCIncident).filter(SOCIncident.campaign_id == campaign.campaign_id).first()
        if existing:
            return self.get_incident(existing.incident_id, db)
        return self.create_incident(campaign_id=campaign.campaign_id, db=db)

    def get_incident(self, incident_id: str, db: Session) -> Optional[Dict[str, Any]]:
        """
        Retrieves full incident details including evidence, notes, and campaign context.
        """
        inc = db.query(SOCIncident).filter(SOCIncident.incident_id == incident_id).first()
        if not inc:
            return None

        campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == inc.campaign_id).first()

        evidence_list = [
            {
                "evidence_id": e.evidence_id,
                "entity_type": e.entity_type,
                "entity_value": e.entity_value,
                "event_id": e.event_id,
                "added_at": e.added_at.isoformat() if e.added_at else "",
                "added_by": e.added_by,
                "reason": e.reason
            }
            for e in sorted(inc.evidence, key=lambda x: x.added_at, reverse=True)
        ]

        notes_list = [
            {
                "note_id": n.note_id,
                "author": n.author,
                "author_type": n.author_type,
                "content": n.content,
                "action_tag": n.action_tag or "NOTE",
                "timestamp": n.timestamp.isoformat() if n.timestamp else ""
            }
            for n in sorted(inc.notes, key=lambda x: x.timestamp, reverse=True)
        ]

        return {
            "incident_id": inc.incident_id,
            "campaign_id": inc.campaign_id,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "priority": inc.priority,
            "status": inc.status,
            "assigned_to": inc.assigned_to,
            "created_at": inc.created_at.isoformat() if inc.created_at else "",
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else "",
            "triage_at": inc.triage_at.isoformat() if inc.triage_at else None,
            "contained_at": inc.contained_at.isoformat() if inc.contained_at else None,
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
            "sla_due_at": inc.sla_due_at.isoformat() if inc.sla_due_at else None,
            "sla_status": inc.sla_status or "Within SLA",
            "resolution_summary": inc.resolution_summary,
            "evidence_count": len(evidence_list),
            "evidence": evidence_list,
            "notes_count": len(notes_list),
            "notes": notes_list,
            "campaign": {
                "campaign_id": campaign.campaign_id if campaign else inc.campaign_id,
                "target": campaign.target if campaign else "Unknown",
                "attack_type": campaign.attack_type if campaign else "Unknown",
                "stage": campaign.stage if campaign else "Initial Access",
                "risk_score": campaign.risk_score if campaign else 0,
                "risk": campaign.risk if campaign else "UNKNOWN",
                "status": campaign.status if campaign else "Active Campaign"
            } if campaign else None
        }

    def list_incidents(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assigned_to: Optional[str] = None,
        campaign_id: Optional[str] = None,
        db: Optional[Session] = None
    ) -> List[Dict[str, Any]]:
        """
        Lists incidents matching filters.
        """
        query = db.query(SOCIncident)
        if status:
            query = query.filter(SOCIncident.status == status)
        if priority:
            query = query.filter(SOCIncident.priority == priority)
        if assigned_to:
            query = query.filter(SOCIncident.assigned_to == assigned_to)
        if campaign_id:
            query = query.filter(SOCIncident.campaign_id == campaign_id)

        incidents = query.order_by(SOCIncident.created_at.desc()).all()
        results = []
        for inc in incidents:
            results.append({
                "incident_id": inc.incident_id,
                "campaign_id": inc.campaign_id,
                "title": inc.title,
                "severity": inc.severity,
                "priority": inc.priority,
                "status": inc.status,
                "assigned_to": inc.assigned_to,
                "created_at": inc.created_at.isoformat() if inc.created_at else "",
                "updated_at": inc.updated_at.isoformat() if inc.updated_at else "",
                "sla_due_at": inc.sla_due_at.isoformat() if inc.sla_due_at else None,
                "sla_status": inc.sla_status or "Within SLA",
                "evidence_count": len(inc.evidence),
                "notes_count": len(inc.notes)
            })
        return results

    def update_incident(
        self,
        incident_id: str,
        payload: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """
        Updates incident workflow attributes (status, priority, assigned_to, resolution_summary).
        Logs automatic audit notes for traceability.
        """
        inc = db.query(SOCIncident).filter(SOCIncident.incident_id == incident_id).first()
        if not inc:
            raise ValueError(f"Incident {incident_id} not found")

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        audit_messages = []

        if "assigned_to" in payload and payload["assigned_to"] != inc.assigned_to:
            old_assignee = inc.assigned_to
            inc.assigned_to = payload["assigned_to"]
            if inc.status == "New" and inc.assigned_to != "Unassigned":
                inc.status = "Assigned"
            audit_messages.append(f"Assignment changed from '{old_assignee}' to '{inc.assigned_to}'")

        if "priority" in payload and payload["priority"] != inc.priority:
            old_prio = inc.priority
            inc.priority = payload["priority"]
            audit_messages.append(f"Priority changed from '{old_prio}' to '{inc.priority}'")

        if "status" in payload and payload["status"] != inc.status:
            old_status = inc.status
            inc.status = payload["status"]
            if inc.status == "Closed":
                inc.resolved_at = now
                if "resolution_summary" in payload:
                    inc.resolution_summary = payload["resolution_summary"]
            audit_messages.append(f"Case status transitioned: '{old_status}' → '{inc.status}'")

        if "resolution_summary" in payload and payload["resolution_summary"]:
            inc.resolution_summary = payload["resolution_summary"]

        if "title" in payload and payload["title"]:
            inc.title = payload["title"]

        inc.updated_at = now

        # Add audit notes for each transition
        for msg in audit_messages:
            note = CaseNote(
                note_id=f"NOTE-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                author=payload.get("updated_by", "SOC Analyst"),
                author_type="ANALYST",
                content=msg,
                action_tag="STATUS_CHANGE",
                timestamp=now
            )
            db.add(note)

        db.commit()
        return self.get_incident(incident_id, db)

    def add_evidence(
        self,
        incident_id: str,
        entity_type: str,
        entity_value: str,
        reason: Optional[str] = None,
        added_by: str = "SOC Analyst",
        event_id: Optional[str] = None,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Phase 7.2: Formal evidence recording.
        """
        inc = db.query(SOCIncident).filter(SOCIncident.incident_id == incident_id).first()
        if not inc:
            raise ValueError(f"Incident {incident_id} not found")

        ev_id = self._add_evidence_internal(
            incident_id=incident_id,
            entity_type=entity_type,
            entity_value=entity_value,
            reason=reason or f"Marked as evidence by {added_by}",
            added_by=added_by,
            event_id=event_id,
            db=db
        )

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        inc.updated_at = now

        # Log case note
        note = CaseNote(
            note_id=f"NOTE-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            author=added_by,
            author_type="ANALYST",
            content=f"Added Case Evidence: [{entity_type.upper()}] {entity_value}. Reason: {reason or 'Evidence verification'}",
            action_tag="INVESTIGATION",
            timestamp=now
        )
        db.add(note)
        db.commit()

        return self.get_incident(incident_id, db)

    def _add_evidence_internal(
        self,
        incident_id: str,
        entity_type: str,
        entity_value: str,
        reason: str,
        added_by: str,
        event_id: Optional[str],
        db: Session
    ) -> str:
        # Check duplicate
        existing = db.query(CaseEvidence).filter(
            CaseEvidence.incident_id == incident_id,
            CaseEvidence.entity_type == entity_type.lower(),
            CaseEvidence.entity_value == entity_value
        ).first()
        if existing:
            return existing.evidence_id

        evidence_id = f"EVD-{uuid.uuid4().hex[:6].upper()}"
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        evidence = CaseEvidence(
            evidence_id=evidence_id,
            incident_id=incident_id,
            entity_type=entity_type.lower(),
            entity_value=entity_value,
            event_id=event_id,
            added_at=now,
            added_by=added_by,
            reason=reason
        )
        db.add(evidence)
        return evidence_id

    def remove_evidence(self, incident_id: str, evidence_id: str, db: Session) -> Dict[str, Any]:
        """Remove an item from case evidence."""
        ev = db.query(CaseEvidence).filter(
            CaseEvidence.incident_id == incident_id,
            CaseEvidence.evidence_id == evidence_id
        ).first()
        if ev:
            db.delete(ev)
            db.commit()
        return self.get_incident(incident_id, db)

    def add_note(
        self,
        incident_id: str,
        content: str,
        author: str = "SOC Analyst",
        author_type: str = "ANALYST",
        action_tag: str = "NOTE",
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Phase 7.3: Add analyst notes & investigation actions.
        """
        inc = db.query(SOCIncident).filter(SOCIncident.incident_id == incident_id).first()
        if not inc:
            raise ValueError(f"Incident {incident_id} not found")

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        note = CaseNote(
            note_id=f"NOTE-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            author=author,
            author_type=author_type,
            content=content,
            action_tag=action_tag,
            timestamp=now
        )
        db.add(note)
        inc.updated_at = now
        db.commit()

        return self.get_incident(incident_id, db)

    def get_incident_timeline(self, incident_id: str, db: Session) -> List[Dict[str, Any]]:
        """
        Phase 7.3: Combined Investigation Timeline
        Merges:
          • AUTOMATED EVENTS (Sysmon, detection rules, MITRE stages)
          • ANALYST ACTIONS & NOTES (Containment decisions, triage observations)
          • STATUS CHANGES (Audit log)
        """
        inc = db.query(SOCIncident).filter(SOCIncident.incident_id == incident_id).first()
        if not inc:
            return []

        timeline_items = []

        # 1. Add Campaign Telemetry Events
        events = db.query(DBEvent).filter(DBEvent.campaign_id == inc.campaign_id).all()
        for e in events:
            timeline_items.append({
                "type": "TELEMETRY_EVENT",
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "time_display": e.timestamp.strftime("%I:%M %p") if e.timestamp else "",
                "title": f"{e.event_type.replace('_', ' ').title()}",
                "description": e.detection_reason or f"Telemetry observed from {e.source} (PID: {e.process_pid or 'N/A'})",
                "source": e.source,
                "mitre_stage": e.mitre_stage or "Execution",
                "severity": e.severity,
                "entity": e.process_name or e.domain or e.source_ip,
                "author": "SYSTEM (Telemetry)",
                "badge": "Automated Event",
                "badge_color": "purple"
            })

        # 2. Add Analyst Notes & Actions
        for n in inc.notes:
            timeline_items.append({
                "type": "ANALYST_ACTION" if n.author_type == "ANALYST" else "SYSTEM_LOG",
                "timestamp": n.timestamp.isoformat() if n.timestamp else "",
                "time_display": n.timestamp.strftime("%I:%M %p") if n.timestamp else "",
                "title": f"{n.action_tag or 'ANALYST NOTE'}: {n.author}",
                "description": n.content,
                "author": n.author,
                "action_tag": n.action_tag,
                "badge": n.action_tag or "Analyst Action",
                "badge_color": "cyan" if n.author_type == "ANALYST" else "amber"
            })

        # Sort combined timeline chronologically
        timeline_items.sort(key=lambda x: x["timestamp"] or "")
        return timeline_items

    def generate_investigation_report(self, incident_id: str, db: Session) -> Dict[str, Any]:
        """
        Phase 7.6: Investigation Report Generation.
        Synthesizes all evidence, timeline, indicators, correlation factors, response actions,
        and analyst notes into a structured report (both JSON and Markdown).
        """
        inc_data = self.get_incident(incident_id, db)
        if not inc_data:
            raise ValueError(f"Incident {incident_id} not found")

        inc = db.query(SOCIncident).filter(SOCIncident.incident_id == incident_id).first()
        campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == inc.campaign_id).first()
        events = db.query(DBEvent).filter(DBEvent.campaign_id == inc.campaign_id).order_by(DBEvent.timestamp.asc()).all()

        # Grouping reasons and indicators
        domains = sorted(list({e.domain for e in events if e.domain}))
        processes = sorted(list({get_proc_base(e.process_name) for e in events if e.process_name}))
        devices = sorted(list({e.device_id for e in events if e.device_id}))
        ips = sorted(list({e.source_ip for e in events if e.source_ip and not e.source_ip.startswith("127.")}))
        hashes = sorted(list({e.file_hash for e in events if e.file_hash}))

        # Formulate executive summary (WHAT HAPPENED)
        target = campaign.target if campaign else "the system"
        attack_type = campaign.attack_type if campaign else "Attack Campaign"
        what_happened = (
            f"An intrusion campaign classified as '{attack_type}' was detected targeting {target}. "
            f"Adversary activity progressed through stages: {campaign.stage if campaign else 'Execution'}. "
            f"Initial activity commenced with {processes[0] if processes else 'an executable'} and "
            f"communicated with external infrastructure ({', '.join(domains) if domains else 'direct network sockets'})."
        )
        if any("lsass" in str(e.process_name).lower() or "lsass" in str(e.detection_reason).lower() or "t1003" in str(e.mitre_technique).lower() for e in events):
            what_happened += " Suspicious credential-access behavior involving LSASS memory extraction was confirmed."

        # Timeline entries
        attack_timeline = []
        for e in events:
            time_str = e.timestamp.strftime("%I:%M %p") if e.timestamp else "N/A"
            stage_desc = e.mitre_stage or e.event_type.replace("_", " ").title()
            rule_desc = e.detection_rule or e.event_type
            attack_timeline.append(f"• {time_str} — {rule_desc} ({stage_desc})")

        # Response actions
        response_actions = []
        if campaign and campaign.status and "CONTAIN" in campaign.status.upper():
            response_actions.append("✓ Endpoint isolated from corporate network")
            response_actions.append("✓ Malicious process trees terminated")
            response_actions.append("✓ Compromised credential reset requested")
        else:
            response_actions.append("• Endpoint isolation recommended")
            response_actions.append("• Active C2 domain/IP blacklisting initiated")
            response_actions.append("• SOC Analyst case active in investigating queue")

        # Analyst Notes
        notes_text = []
        for n in inc.notes:
            time_str = n.timestamp.strftime("%I:%M %p") if n.timestamp else ""
            notes_text.append(f"[{time_str}] {n.author} ({n.action_tag or 'NOTE'}): {n.content}")

        # Build Markdown Document matching Phase 7.6 format
        md_lines = [
            "# CAIP INCIDENT INVESTIGATION REPORT",
            "",
            f"**Incident ID**: `{inc.incident_id}`  ",
            f"**Linked Campaign**: `{inc.campaign_id}`  ",
            f"**Attack Type**: {campaign.attack_type if campaign else 'Multi-Stage Intrusion'}  ",
            f"**Severity / Risk**: {inc.severity} ({campaign.risk_score if campaign else 80}/100)  ",
            f"**Priority**: {inc.priority}  ",
            f"**Case Status**: {inc.status}  ",
            f"**Assigned Analyst**: {inc.assigned_to}  ",
            f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "",
            "---",
            "",
            "## WHAT HAPPENED",
            "",
            what_happened,
            "",
            "---",
            "",
            "## ATTACK TIMELINE",
            "",
        ]
        md_lines.extend(attack_timeline if attack_timeline else ["• No timeline events recorded."])
        md_lines.extend([
            "",
            "---",
            "",
            "## THREAT INDICATORS",
            "",
            f"- **Domains**: {', '.join(domains) if domains else 'None'}",
            f"- **Processes**: {', '.join(processes) if processes else 'None'}",
            f"- **Target Devices**: {', '.join(devices) if devices else 'None'}",
            f"- **External IPs**: {', '.join(ips) if ips else 'None'}",
            f"- **File Hashes**: {', '.join(hashes) if hashes else 'None'}",
            "",
            "---",
            "",
            "## CORRELATION EXPLANATION",
            "",
            f"**Correlation Score**: {campaign.risk_score if campaign else 85}/100",
            "",
            "• **Process Lineage**: Connected execution ancestors and child payloads  ",
            "• **Shared Device**: Activity localized to verified host asset  ",
            "• **Shared User**: Executed within the target user's authenticated context  ",
            "• **Temporal Proximity**: Rapid sequential execution within correlation time-decay window  ",
            "• **MITRE Progression**: Logical progression across standard MITRE ATT&CK kill-chain stages  ",
            "",
            "---",
            "",
            "## RESPONSE & CONTAINMENT ACTIONS",
            "",
        ])
        md_lines.extend(response_actions)
        md_lines.extend([
            "",
            "---",
            "",
            "## CASE EVIDENCE",
            "",
        ])
        if inc.evidence:
            for ev in inc.evidence:
                md_lines.append(f"- **[{ev.entity_type.upper()}]** `{ev.entity_value}` — *{ev.reason}* (Added by {ev.added_by})")
        else:
            md_lines.append("• No formal evidence marked yet.")

        md_lines.extend([
            "",
            "---",
            "",
            "## ANALYST NOTES & DECISIONS",
            "",
        ])
        md_lines.extend(notes_text if notes_text else ["• No analyst notes entered."])

        markdown_report = "\n".join(md_lines)

        return {
            "incident_id": inc.incident_id,
            "campaign_id": inc.campaign_id,
            "title": inc.title,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_markdown": markdown_report,
            "structured_data": {
                "what_happened": what_happened,
                "timeline": attack_timeline,
                "indicators": {
                    "domains": domains,
                    "processes": processes,
                    "devices": devices,
                    "ips": ips,
                    "hashes": hashes
                },
                "correlation_score": campaign.risk_score if campaign else 85,
                "response_actions": response_actions,
                "analyst_notes": notes_text,
                "evidence_count": len(inc.evidence)
            }
        }
