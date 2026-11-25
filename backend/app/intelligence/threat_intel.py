"""
CAIP Threat Intelligence Engine — Phase 6.2 & 6.3
=================================================
Builds internal threat intelligence and persistent memory from security telemetry.
Enriches indicators (domains, IPs, processes, hashes, files, users, devices)
with reputation scoring, sightings tracking, relationship binding, and cross-campaign
infrastructure reuse detection.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.database.models import Indicator, Event as DBEvent, Campaign as DBCampaign
from app.intelligence.entity_extractor import EntityExtractor, get_proc_base, normalize_user

# Known high-risk or LOLBAS utilities
SUSPICIOUS_PROCESSES = {
    "vssadmin.exe": ("Ransomware shadow copy deletion tool", 90, "malicious"),
    "powershell.exe": ("Script execution engine / potential cradle", 65, "suspicious"),
    "whoami.exe": ("Discovery & reconnaissance utility", 60, "suspicious"),
    "reg.exe": ("Registry manipulation tool", 70, "suspicious"),
    "certutil.exe": ("LOLBAS ingress tool / file downloader", 80, "suspicious"),
    "mimikatz.exe": ("Credential harvesting utility", 95, "malicious"),
    "bcdedit.exe": ("Boot configuration / shadow recovery disabling", 85, "malicious"),
    "cmd.exe": ("Command interpreter", 50, "suspicious"),
    "psexec.exe": ("Lateral movement tool", 85, "malicious"),
    "net.exe": ("Account / share reconnaissance", 60, "suspicious"),
    "nltest.exe": ("Domain trust discovery", 65, "suspicious"),
}

KNOWN_BENIGN_DOMAINS = {
    "google.com",
    "www.google.com",
    "microsoft.com",
    "windowsupdate.com",
    "github.com",
    "internal.portal",
    "corp.local"
}

KNOWN_BENIGN_PROCESSES = {
    "notepad.exe",
    "chrome.exe",
    "explorer.exe",
    "taskmgr.exe",
    "svchost.exe",
    "runtimebroker.exe",
    "searchindexer.exe"
}


class ThreatIntelEngine:
    """
    Core engine for internal threat intelligence, indicator management,
    reputation scoring, and cross-campaign correlation.
    """

    def record_event_telemetry(self, event: Any, db: Session) -> List[Dict[str, Any]]:
        """
        Extracts all entities from an event and updates the internal Indicator table.
        This gives CAIP persistent memory of every IOC and system entity observed.
        """
        extracted = EntityExtractor.extract_entities(event)
        updated_indicators = []

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        event_status = getattr(event, "security_status", "informational")
        event_severity = getattr(event, "severity", 10)
        event_device = getattr(event, "device_id", None)
        event_process = get_proc_base(getattr(event, "process_name", None))
        event_user = normalize_user(getattr(event, "user", None))
        event_campaign = getattr(event, "campaign_id", None)

        for ent in extracted:
            etype = ent["type"]
            evalue = ent["value"]

            # Query existing indicator or create new
            ind = db.query(Indicator).filter(
                Indicator.type == etype,
                Indicator.value == evalue
            ).first()

            if not ind:
                ind = Indicator(
                    indicator_id=f"IND-{uuid.uuid4().hex[:6].upper()}",
                    type=etype,
                    value=evalue,
                    first_seen=now,
                    last_seen=now,
                    sightings=1,
                    affected_devices=1 if event_device else 0,
                    risk_score=0,
                    reputation="unknown",
                    status="Internal Indicator",
                    associated_devices=json.dumps([event_device] if event_device else []),
                    associated_processes=json.dumps([event_process] if event_process else []),
                    associated_campaigns=json.dumps([event_campaign] if event_campaign else []),
                    associated_users=json.dumps([event_user] if event_user else [])
                )
                db.add(ind)
            else:
                # Update existing indicator
                ind.sightings += 1
                ind.last_seen = now

                # Merge devices
                devices = set(json.loads(ind.associated_devices or "[]"))
                if event_device:
                    devices.add(event_device)
                ind.associated_devices = json.dumps(list(devices))
                ind.affected_devices = max(1, len(devices))

                # Merge processes
                procs = set(json.loads(ind.associated_processes or "[]"))
                if event_process:
                    procs.add(event_process)
                ind.associated_processes = json.dumps(list(procs))

                # Merge campaigns
                camps = set(json.loads(ind.associated_campaigns or "[]"))
                if event_campaign:
                    camps.add(event_campaign)
                ind.associated_campaigns = json.dumps(list(camps))

                # Merge users
                users = set(json.loads(ind.associated_users or "[]"))
                if event_user:
                    users.add(event_user)
                ind.associated_users = json.dumps(list(users))

            # Calculate dynamic reputation and risk
            risk, rep, status = self.calculate_reputation(
                etype=etype,
                value=evalue,
                sightings=ind.sightings,
                devices_count=ind.affected_devices,
                campaigns_count=len(json.loads(ind.associated_campaigns or "[]")),
                severity=event_severity,
                security_status=event_status
            )
            ind.risk_score = risk
            ind.reputation = rep
            ind.status = status

            updated_indicators.append({
                "indicator_id": ind.indicator_id,
                "type": ind.type,
                "value": ind.value,
                "reputation": ind.reputation,
                "risk_score": ind.risk_score,
                "sightings": ind.sightings
            })

        db.commit()
        return updated_indicators

    def calculate_reputation(
        self,
        etype: str,
        value: str,
        sightings: int,
        devices_count: int,
        campaigns_count: int,
        severity: int,
        security_status: str
    ) -> Tuple[int, str, str]:
        """
        Dynamically calculates (risk_score, reputation, status) using CAIP telemetry heuristics.
        """
        val_lower = value.lower()

        # Check known benign baselines
        if (etype == "domain" and val_lower in KNOWN_BENIGN_DOMAINS) or \
           (etype == "process" and val_lower in KNOWN_BENIGN_PROCESSES):
            return 10, "benign", "Benign Internal Baseline"

        # Check known malicious/suspicious utilities
        if etype == "process" and val_lower in SUSPICIOUS_PROCESSES:
            desc, base_risk, rep = SUSPICIOUS_PROCESSES[val_lower]
            risk = min(100, base_risk + (10 if campaigns_count > 0 else 0) + min(15, (devices_count - 1) * 5))
            status = "High Risk Threat Indicator" if risk >= 80 else "Suspicious Internal Indicator"
            return risk, rep, status

        # Inherent scoring from telemetry context
        score = 20  # baseline for unseen entity
        if security_status in ["high_risk", "critical"]:
            score = max(score, severity, 80)
        elif security_status == "review":
            score = max(score, 60)
        elif security_status == "informational":
            score = min(score, 30)

        # Bonus risk for multi-campaign or multi-device spread
        if campaigns_count > 0:
            score = min(100, score + 20)
        if devices_count >= 2:
            score = min(100, score + 10)

        # Classify reputation string
        if score >= 75:
            reputation = "malicious"
            status = "High Risk Threat Indicator"
        elif score >= 50:
            reputation = "suspicious"
            status = "Suspicious Internal Indicator"
        elif score <= 25:
            reputation = "benign"
            status = "Benign Internal Indicator"
        else:
            reputation = "unknown"
            status = "Active Internal Indicator"

        return score, reputation, status

    def check_domain(self, domain: str, db: Session) -> Dict[str, Any]:
        """Check domain reputation, telemetry associations, and return threat intelligence summary."""
        d_lower = str(domain).strip().lower()
        ind = db.query(Indicator).filter(Indicator.type == "domain", Indicator.value == d_lower).first()
        if not ind:
            ev = db.query(DBEvent).filter(DBEvent.domain.ilike(f"%{d_lower}%")).first()
            if ev:
                self.record_event_telemetry(ev, db)
                ind = db.query(Indicator).filter(Indicator.type == "domain", Indicator.value == d_lower).first()
        if ind:
            return self._indicator_to_dict(ind)
        # Default assessment for unobserved domain
        risk, rep, st = self.calculate_reputation("domain", d_lower, 0, 0, 0, 20, "informational")
        return {
            "indicator_id": None,
            "type": "domain",
            "value": d_lower,
            "risk_score": risk,
            "reputation": rep.capitalize(),
            "status": st,
            "sightings": 0,
            "detection_count": 0,
            "affected_devices": 0,
            "first_seen": "",
            "last_seen": "",
            "first_observed": "Not yet observed in CAIP",
            "threat_intelligence": [
                "• First observed in CAIP: Not yet observed in telemetry",
                "• Seen on: 0 devices",
                "• Associated processes: None",
                "• Associated campaign: None",
                "• Detection count: 0"
            ],
            "associated_devices": [],
            "associated_processes": [],
            "associated_campaigns": [],
            "associated_users": []
        }

    def check_ip(self, ip: str, db: Session) -> Dict[str, Any]:
        """Check IP reputation, telemetry associations, and return threat intelligence summary."""
        ip_clean = str(ip).strip()
        ind = db.query(Indicator).filter(Indicator.type == "ip", Indicator.value == ip_clean).first()
        if not ind:
            ev = db.query(DBEvent).filter(DBEvent.source_ip == ip_clean).first()
            if ev:
                self.record_event_telemetry(ev, db)
                ind = db.query(Indicator).filter(Indicator.type == "ip", Indicator.value == ip_clean).first()
        if ind:
            return self._indicator_to_dict(ind)
        risk, rep, st = self.calculate_reputation("ip", ip_clean, 0, 0, 0, 20, "informational")
        return {
            "indicator_id": None,
            "type": "ip",
            "value": ip_clean,
            "risk_score": risk,
            "reputation": rep.capitalize(),
            "status": st,
            "sightings": 0,
            "detection_count": 0,
            "affected_devices": 0,
            "first_seen": "",
            "last_seen": "",
            "first_observed": "Not yet observed in CAIP",
            "threat_intelligence": [
                "• First observed in CAIP: Not yet observed in telemetry",
                "• Seen on: 0 devices",
                "• Associated processes: None",
                "• Associated campaign: None",
                "• Detection count: 0"
            ],
            "associated_devices": [],
            "associated_processes": [],
            "associated_campaigns": [],
            "associated_users": []
        }

    def check_file_hash(self, hash_val: str, db: Session) -> Dict[str, Any]:
        """Check hash reputation, telemetry associations, and return threat intelligence summary."""
        h_clean = str(hash_val).strip().lower()
        ind = db.query(Indicator).filter(Indicator.type == "hash", Indicator.value == h_clean).first()
        if not ind:
            ev = db.query(DBEvent).filter(DBEvent.file_hash.ilike(f"%{h_clean}%")).first()
            if ev:
                self.record_event_telemetry(ev, db)
                ind = db.query(Indicator).filter(Indicator.type == "hash", Indicator.value == h_clean).first()
        if ind:
            return self._indicator_to_dict(ind)
        risk, rep, st = self.calculate_reputation("hash", h_clean, 0, 0, 0, 40, "informational")
        return {
            "indicator_id": None,
            "type": "hash",
            "value": h_clean,
            "risk_score": risk,
            "reputation": rep.capitalize(),
            "status": st,
            "sightings": 0,
            "detection_count": 0,
            "affected_devices": 0,
            "first_seen": "",
            "last_seen": "",
            "first_observed": "Not yet observed in CAIP",
            "threat_intelligence": [
                "• First observed in CAIP: Not yet observed in telemetry",
                "• Seen on: 0 devices",
                "• Associated processes: None",
                "• Associated campaign: None",
                "• Detection count: 0"
            ],
            "associated_devices": [],
            "associated_processes": [],
            "associated_campaigns": [],
            "associated_users": []
        }

    def check_process(self, process_name: str, db: Session) -> Dict[str, Any]:
        """Check process reputation, telemetry associations, and return threat intelligence summary."""
        p_base = get_proc_base(process_name)
        ind = db.query(Indicator).filter(Indicator.type == "process", Indicator.value == p_base).first()
        if not ind:
            ev = db.query(DBEvent).filter(
                (DBEvent.process_name.ilike(f"%{p_base}%")) | (DBEvent.parent_process.ilike(f"%{p_base}%"))
            ).first()
            if ev:
                self.record_event_telemetry(ev, db)
                ind = db.query(Indicator).filter(Indicator.type == "process", Indicator.value == p_base).first()
        if ind:
            return self._indicator_to_dict(ind)
        risk, rep, st = self.calculate_reputation("process", p_base, 0, 0, 0, 30, "informational")
        return {
            "indicator_id": None,
            "type": "process",
            "value": p_base,
            "risk_score": risk,
            "reputation": rep.capitalize(),
            "status": st,
            "sightings": 0,
            "detection_count": 0,
            "affected_devices": 0,
            "first_seen": "",
            "last_seen": "",
            "first_observed": "Not yet observed in CAIP",
            "threat_intelligence": [
                "• First observed in CAIP: Not yet observed in telemetry",
                "• Seen on: 0 devices",
                "• Associated processes: None",
                "• Associated campaign: None",
                "• Detection count: 0"
            ],
            "associated_devices": [],
            "associated_processes": [],
            "associated_campaigns": [],
            "associated_users": []
        }

    def get_entity_dossier(self, entity_type: str, entity_value: str, db: Session) -> Dict[str, Any]:
        """
        Phase 6.4: Full 360-degree investigation dossier for an entity.
        Returns reputation, sightings, related processes/devices/users/campaigns, and timeline.
        """
        etype = entity_type.strip().lower()
        evalue = entity_value.strip()
        if etype in ["domain", "hash", "process", "user"]:
            evalue = evalue.lower()
        if etype == "device":
            evalue = evalue.upper()

        ind = db.query(Indicator).filter(
            Indicator.type == etype,
            Indicator.value == evalue
        ).first()

        # Query all events matching this entity
        query = db.query(DBEvent)
        if etype == "domain":
            query = query.filter(DBEvent.domain.ilike(f"%{evalue}%"))
        elif etype == "ip":
            query = query.filter(DBEvent.source_ip == evalue)
        elif etype == "process":
            query = query.filter((DBEvent.process_name.ilike(f"%{evalue}%")) | (DBEvent.parent_process.ilike(f"%{evalue}%")))
        elif etype == "user":
            query = query.filter(DBEvent.user.ilike(f"%{evalue}%"))
        elif etype == "device":
            query = query.filter(DBEvent.device_id.ilike(f"%{evalue}%"))
        elif etype == "hash":
            query = query.filter(DBEvent.file_hash.ilike(f"%{evalue}%"))
        elif etype == "file":
            query = query.filter(DBEvent.file_path.ilike(f"%{evalue}%"))

        matched_events = query.order_by(DBEvent.timestamp.asc()).all()

        # Aggregate related entities from actual events
        devices = set()
        users = set()
        processes = set()
        campaign_ids = set()
        timeline = []

        for ev in matched_events:
            if ev.device_id:
                devices.add(ev.device_id)
            if ev.user:
                users.add(normalize_user(ev.user))
            if ev.process_name:
                processes.add(get_proc_base(ev.process_name))
            if ev.parent_process:
                processes.add(get_proc_base(ev.parent_process))
            if ev.campaign_id:
                campaign_ids.add(ev.campaign_id)

            timeline.append({
                "event_id": ev.event_id,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
                "event_type": ev.event_type,
                "source": ev.source,
                "security_status": ev.security_status,
                "severity": ev.severity,
                "detection_rule": ev.detection_rule or "General Event",
                "detection_reason": ev.detection_reason or "",
                "mitre_stage": ev.mitre_stage or "",
                "campaign_id": ev.campaign_id,
                "device_id": ev.device_id,
                "user": ev.user,
                "process_name": ev.process_name,
                "source_ip": ev.source_ip,
                "domain": ev.domain
            })

        # Fetch related campaign details
        related_campaigns = []
        if campaign_ids:
            camps = db.query(DBCampaign).filter(DBCampaign.campaign_id.in_(list(campaign_ids))).all()
            for c in camps:
                related_campaigns.append({
                    "campaign_id": c.campaign_id,
                    "target": c.target,
                    "attack_type": c.attack_type,
                    "stage": c.stage,
                    "risk_score": c.risk_score,
                    "risk": c.risk,
                    "status": c.status or "Active Campaign",
                    "created_at": c.created_at.isoformat() if c.created_at else ""
                })

        # Use indicator values if available, else derive from events
        risk_score = ind.risk_score if ind else (80 if any(e["security_status"] in ["high_risk", "critical"] for e in timeline) else 30)
        reputation = ind.reputation if ind else ("malicious" if risk_score >= 75 else "suspicious" if risk_score >= 50 else "informational")
        status = ind.status if ind else "Observed Entity"
        sightings = max(ind.sightings if ind else 0, len(matched_events))
        first_seen = ind.first_seen.isoformat() if (ind and ind.first_seen) else (timeline[0]["timestamp"] if timeline else "")
        last_seen = ind.last_seen.isoformat() if (ind and ind.last_seen) else (timeline[-1]["timestamp"] if timeline else "")

        return {
            "entity": {
                "type": etype,
                "value": evalue,
                "reputation": reputation,
                "risk_score": risk_score,
                "status": status,
                "indicator_id": ind.indicator_id if ind else f"IND-{uuid.uuid4().hex[:6].upper()}",
                "first_seen": first_seen,
                "last_seen": last_seen,
                "sightings": sightings,
            },
            "metrics": {
                "campaigns_count": len(related_campaigns),
                "events_count": len(matched_events),
                "devices_count": len(devices),
                "users_count": len(users),
            },
            "related_processes": sorted(list(processes)),
            "related_devices": sorted(list(devices)),
            "related_users": sorted(list(users)),
            "related_campaigns": related_campaigns,
            "timeline": timeline
        }

    def find_cross_campaign_reuse(self, campaign_id: str, db: Session) -> Dict[str, Any]:
        """
        Phase 6.5: Cross-Campaign Correlation
        Detects if this campaign shares infrastructure (domain, external IP, file hash, tool)
        with other campaigns.
        """
        # Fetch events of the target campaign
        events = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).all()
        if not events:
            return {"has_reuse": False, "reuse_alert": None, "reused_entities": []}

        # Collect candidate IOCs from this campaign
        candidate_domains = {e.domain.lower() for e in events if e.domain and e.domain.lower() not in KNOWN_BENIGN_DOMAINS}
        candidate_ips = {e.source_ip for e in events if e.source_ip and not e.source_ip.startswith("127.") and e.source_ip not in {"0.0.0.0", "::1"}}
        candidate_hashes = {e.file_hash.lower() for e in events if e.file_hash}

        reused_items = []

        # Check domains across other campaigns
        for d in candidate_domains:
            other_events = db.query(DBEvent).filter(
                DBEvent.domain == d,
                DBEvent.campaign_id.isnot(None),
                DBEvent.campaign_id != campaign_id
            ).all()
            if other_events:
                shared_camps = sorted(list({ev.campaign_id for ev in other_events}))
                shared_devices = sorted(list({ev.device_id for ev in other_events if ev.device_id}))
                shared_procs = sorted(list({get_proc_base(ev.process_name) for ev in other_events if ev.process_name}))
                reused_items.append({
                    "type": "domain",
                    "value": d,
                    "shared_campaigns": shared_camps,
                    "devices": shared_devices,
                    "processes": shared_procs,
                    "risk_assessment": "Adversary Domain / C2 Infrastructure Reuse"
                })

        # Check external IPs across other campaigns
        for ip in candidate_ips:
            other_events = db.query(DBEvent).filter(
                DBEvent.source_ip == ip,
                DBEvent.campaign_id.isnot(None),
                DBEvent.campaign_id != campaign_id
            ).all()
            if other_events:
                shared_camps = sorted(list({ev.campaign_id for ev in other_events}))
                shared_devices = sorted(list({ev.device_id for ev in other_events if ev.device_id}))
                shared_procs = sorted(list({get_proc_base(ev.process_name) for ev in other_events if ev.process_name}))
                reused_items.append({
                    "type": "ip",
                    "value": ip,
                    "shared_campaigns": shared_camps,
                    "devices": shared_devices,
                    "processes": shared_procs,
                    "risk_assessment": "Shared External C2 / Ingress Host"
                })

        # Check hashes across other campaigns
        for h in candidate_hashes:
            other_events = db.query(DBEvent).filter(
                DBEvent.file_hash == h,
                DBEvent.campaign_id.isnot(None),
                DBEvent.campaign_id != campaign_id
            ).all()
            if other_events:
                shared_camps = sorted(list({ev.campaign_id for ev in other_events}))
                shared_devices = sorted(list({ev.device_id for ev in other_events if ev.device_id}))
                shared_procs = sorted(list({get_proc_base(ev.process_name) for ev in other_events if ev.process_name}))
                reused_items.append({
                    "type": "hash",
                    "value": h,
                    "shared_campaigns": shared_camps,
                    "devices": shared_devices,
                    "processes": shared_procs,
                    "risk_assessment": "Shared Payload / Malware Binary Hash"
                })

        has_reuse = len(reused_items) > 0
        return {
            "has_reuse": has_reuse,
            "reuse_alert": "⚠️ Potential cross-campaign infrastructure reuse detected." if has_reuse else None,
            "reused_entities": reused_items
        }

    @staticmethod
    def _indicator_to_dict(ind: Indicator) -> Dict[str, Any]:
        devices = json.loads(ind.associated_devices or "[]")
        processes = json.loads(ind.associated_processes or "[]")
        campaigns = json.loads(ind.associated_campaigns or "[]")
        users = json.loads(ind.associated_users or "[]")

        first_obs = ind.first_seen.strftime("%I:%M %p") if ind.first_seen else "N/A"
        dev_count = ind.affected_devices or max(1, len(devices))
        proc_str = ", ".join(processes) if processes else "None"
        camp_str = ", ".join(campaigns) if campaigns else "None"

        summary_bullets = [
            f"• First observed in CAIP: {first_obs}",
            f"• Seen on: {dev_count} device{'s' if dev_count != 1 else ''}",
            f"• Associated processes: {proc_str}",
            f"• Associated campaign: {camp_str}",
            f"• Detection count: {ind.sightings}"
        ]

        return {
            "indicator_id": ind.indicator_id,
            "type": ind.type,
            "value": ind.value,
            "risk_score": ind.risk_score,
            "reputation": ind.reputation.capitalize() if ind.reputation else "Unknown",
            "status": ind.status,
            "sightings": ind.sightings,
            "detection_count": ind.sightings,
            "affected_devices": dev_count,
            "first_seen": ind.first_seen.isoformat() if ind.first_seen else "",
            "last_seen": ind.last_seen.isoformat() if ind.last_seen else "",
            "first_observed": first_obs,
            "threat_intelligence": summary_bullets,
            "associated_devices": devices,
            "associated_processes": processes,
            "associated_campaigns": campaigns,
            "associated_users": users
        }
