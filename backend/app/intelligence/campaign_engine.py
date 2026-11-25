"""
CAIP Campaign Correlation Engine — Refactored for Real Windows Sysmon Telemetry
================================================================================
Correlates security events into multi-stage attack campaigns using a multi-factor
correlation scoring model, noise entity filtering, and retrospective contextual
telemetry binding.

Key Enhancements:
  1. Multi-factor Correlation Scoring: Evaluates PID, process lineage, parent process,
     user, device, domain, IP, time proximity, and MITRE kill-chain progression.
  2. Noise Entity Filtering: Ignores generic Windows accounts (SYSTEM, LOCAL SERVICE,
     NETWORK SERVICE) and generic IPs (127.0.0.1, 0.0.0.0, ::1) from independent correlation.
  3. Single-event Protection: Single alerts remain uncorrelated candidates until sufficient
     corroborating evidence exists (score >= 50).
  4. Retrospective Contextual Telemetry: Pulls relevant informational Sysmon events into
     campaigns to complete the attack narrative without burdening the pipeline.
  5. Explainable Composite Reasons: Stores human-readable evidence strings with scores.
  6. Preserved ML & Risk Integration: AttackPredictor, RiskEngine, feature extraction,
     and PredictionLog remain fully integrated.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple, List
from sqlalchemy.orm import Session

from app.database.database import SessionLocal
from app.database.models import Event as DBEvent, Campaign as DBCampaign, PredictionLog
from app.ingestion.normalizer import NormalizedEvent
from app.intelligence.attack_predictor import AttackPredictor
from app.intelligence.feature_extractor import extract_features
from app.intelligence.risk_engine import RiskEngine

# ── Generic/Noise Entities to ignore for independent correlation ─────────────
GENERIC_USERS = {
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "none",
    "null",
    "",
}

GENERIC_IPS = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "localhost",
    "none",
    "null",
    "",
}

STAGE_KILL_CHAIN_INDEX = {
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 7,
    "Lateral Movement": 8,
    "Collection": 9,
    "Command & Control": 10,
    "Command and Control": 10,
    "Exfiltration": 11,
    "Impact": 12,
}


def _to_dt(ts: Any) -> datetime:
    """Robust conversion to naive UTC datetime."""
    if isinstance(ts, datetime):
        if ts.tzinfo is not None:
            return ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts
    if isinstance(ts, str):
        cleaned = ts.replace("Z", "").split("+")[0]
        for fmt in (
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S.%f",
        ):
            try:
                return datetime.strptime(cleaned, fmt)
            except ValueError:
                pass
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalize_user(user: Optional[str]) -> str:
    """Normalize user string: strips domain prefix or @domain suffix and lowercases."""
    if not user:
        return ""
    u = str(user).strip().lower()
    if "\\" in u:
        u = u.split("\\")[-1].strip()
    if "@" in u:
        u = u.split("@")[0].strip()
    return u


def is_generic_user(user: Optional[str]) -> bool:
    """Check if the user is a generic Windows/system account."""
    if not user:
        return True
    u_raw = str(user).strip().lower()
    if u_raw in GENERIC_USERS:
        return True
    u_norm = normalize_user(user)
    return u_norm in GENERIC_USERS or not u_norm


def is_generic_ip(ip: Optional[str]) -> bool:
    """Check if IP is loopback, broadcast, or generic placeholder."""
    if not ip:
        return True
    cleaned = str(ip).strip().lower()
    return cleaned in GENERIC_IPS or cleaned.startswith("127.") or cleaned == "::1"


def get_proc_base(proc_name: Optional[str]) -> str:
    """Extract lowercase executable base filename from a path."""
    if not proc_name:
        return ""
    cleaned = str(proc_name).strip().replace("\\", "/").lower()
    return cleaned.split("/")[-1]


class CorrelationConfig:
    """Configurable scoring weights and correlation thresholds."""
    WEIGHT_PROCESS_LINEAGE: int   = 40
    WEIGHT_PID: int               = 35
    WEIGHT_PARENT_PROCESS: int    = 25
    WEIGHT_USER: int              = 15
    WEIGHT_DOMAIN: int            = 15
    WEIGHT_DEVICE: int            = 10
    WEIGHT_SOURCE_IP: int         = 10
    WEIGHT_CLOSE_TIME: int        = 20
    WEIGHT_ATTACK_PROGRESSION: int = 20

    THRESHOLD_UNRELATED: int = 30
    THRESHOLD_CANDIDATE: int = 50
    THRESHOLD_CAMPAIGN: int  = 50

    WINDOW_HOURS: int           = 6
    CLOSE_TIME_MINUTES: int     = 30
    PROXIMITY_TIME_MINUTES: int = 120


def score_event_pair(ev1: Any, ev2: Any, config: Optional[CorrelationConfig] = None) -> Tuple[int, str]:
    """
    Computes a multi-factor correlation score between two events.
    Returns (score, explanation_string).
    """
    if config is None:
        config = CorrelationConfig()

    score = 0
    reasons = []

    def _val(ev, key):
        if isinstance(ev, dict):
            return ev.get(key)
        return getattr(ev, key, None)

    # 1. Process PID (must be > 0)
    pid1 = _val(ev1, "process_pid")
    pid2 = _val(ev2, "process_pid")
    if pid1 is not None and pid2 is not None:
        try:
            p1_int, p2_int = int(pid1), int(pid2)
            if p1_int > 0 and p2_int > 0 and p1_int == p2_int:
                score += config.WEIGHT_PID
                reasons.append(f"Same PID ({p1_int})")
        except (ValueError, TypeError):
            pass

    # 2. Process Name & Lineage
    p1_base = get_proc_base(_val(ev1, "process_name"))
    p2_base = get_proc_base(_val(ev2, "process_name"))
    pp1_base = get_proc_base(_val(ev1, "parent_process"))
    pp2_base = get_proc_base(_val(ev2, "parent_process"))

    if p1_base and p2_base and p1_base == p2_base:
        score += config.WEIGHT_PROCESS_LINEAGE
        reasons.append(f"Same process '{p1_base}'")
    elif (pp1_base and p2_base and pp1_base == p2_base) or (pp2_base and p1_base and pp2_base == p1_base):
        score += config.WEIGHT_PROCESS_LINEAGE
        reasons.append(f"Process lineage ('{pp1_base or pp2_base}' -> '{p1_base or p2_base}')")

    # 3. Parent Process
    if pp1_base and pp2_base and pp1_base == pp2_base:
        score += config.WEIGHT_PARENT_PROCESS
        reasons.append(f"Same parent process '{pp1_base}'")

    # 4. User (ignoring generic service accounts)
    u1_raw = _val(ev1, "user")
    u2_raw = _val(ev2, "user")
    if not is_generic_user(u1_raw) and not is_generic_user(u2_raw):
        u1 = normalize_user(u1_raw)
        u2 = normalize_user(u2_raw)
        if u1 and u2 and u1 == u2:
            score += config.WEIGHT_USER
            reasons.append(f"Same user '{u1}'")

    # 5. Device
    d1 = str(_val(ev1, "device_id") or "").strip().lower()
    d2 = str(_val(ev2, "device_id") or "").strip().lower()
    if d1 and d2 and d1 == d2:
        score += config.WEIGHT_DEVICE
        reasons.append(f"Same device '{_val(ev1, 'device_id')}'")

    # 6. Domain
    dom1 = str(_val(ev1, "domain") or "").strip().lower()
    dom2 = str(_val(ev2, "domain") or "").strip().lower()
    if dom1 and dom2 and dom1 == dom2:
        score += config.WEIGHT_DOMAIN
        reasons.append(f"Same domain '{dom1}'")

    # 7. Source IP (ignoring loopback / generic)
    ip1 = _val(ev1, "source_ip")
    ip2 = _val(ev2, "source_ip")
    if not is_generic_ip(ip1) and not is_generic_ip(ip2):
        ip1_str = str(ip1).strip()
        ip2_str = str(ip2).strip()
        if ip1_str and ip2_str and ip1_str == ip2_str:
            score += config.WEIGHT_SOURCE_IP
            reasons.append(f"Same source IP '{ip1_str}'")

    # 8. Time Proximity
    dt1 = _to_dt(_val(ev1, "timestamp"))
    dt2 = _to_dt(_val(ev2, "timestamp"))
    diff_sec = abs((dt1 - dt2).total_seconds())
    if diff_sec <= config.CLOSE_TIME_MINUTES * 60:
        score += config.WEIGHT_CLOSE_TIME
        reasons.append(f"Close time ({diff_sec/60.0:.1f}m)")
    elif diff_sec <= config.PROXIMITY_TIME_MINUTES * 60:
        score += int(config.WEIGHT_CLOSE_TIME / 2)
        reasons.append(f"Temporal proximity ({diff_sec/60.0:.1f}m)")

    # 9. Logical MITRE ATT&CK progression
    s1 = _val(ev1, "mitre_stage")
    s2 = _val(ev2, "mitre_stage")
    if s1 and s2:
        idx1 = STAGE_KILL_CHAIN_INDEX.get(s1, 99)
        idx2 = STAGE_KILL_CHAIN_INDEX.get(s2, 99)
        if s1 != s2 and idx1 != 99 and idx2 != 99:
            first_s, second_s = (s1, s2) if dt1 <= dt2 else (s2, s1)
            idx_first = STAGE_KILL_CHAIN_INDEX.get(first_s, 99)
            idx_second = STAGE_KILL_CHAIN_INDEX.get(second_s, 99)
            if idx_first <= idx_second:
                score += config.WEIGHT_ATTACK_PROGRESSION
                reasons.append(f"Logical attack progression ({first_s} -> {second_s})")
            else:
                score += int(config.WEIGHT_ATTACK_PROGRESSION / 2)
                reasons.append(f"Attack progression ({first_s} -> {second_s})")
        elif s1 == s2 and idx1 != 99:
            score += int(config.WEIGHT_ATTACK_PROGRESSION / 2)
            reasons.append(f"Shared stage ({s1})")

    reason_str = " + ".join(reasons) if reasons else "No corroborating signals"
    return score, f"{reason_str} (score: {score})"


class CampaignEngine:
    def __init__(self, config: Optional[CorrelationConfig] = None):
        self.config = config or CorrelationConfig()
        self.predictor = AttackPredictor()

    def correlate_event(self, event: NormalizedEvent):
        """
        Processes a newly normalized event:
        1. Scores event against active campaigns and uncorrelated security events.
        2. Correlates into a campaign only if score meets THRESHOLD_CAMPAIGN.
        3. Pulls contextual informational telemetry to build full attack story.
        4. Updates ML and Risk predictions.
        """
        db: Session = SessionLocal()
        try:
            db_event = db.query(DBEvent).filter(DBEvent.event_id == event.event_id).first()

            campaign_id, correlation_reason, is_new, matched_events = self._find_or_create_campaign(db, event)

            if db_event:
                db_event.correlation_reason = correlation_reason
                if campaign_id:
                    db_event.campaign_id = campaign_id
                db.commit()

            if campaign_id:
                # ── Retrospectively link informational context ────────────────
                campaign_events = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).all()
                self._retrieve_contextual_events(db, campaign_id, campaign_events)

                # Re-fetch all campaign events and update campaign stats
                campaign_events = db.query(DBEvent).filter(DBEvent.campaign_id == campaign_id).all()
                self._update_campaign(db, campaign_id, campaign_events)

        except Exception as e:
            db.rollback()
            raise e
        finally:
            db.close()

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _find_or_create_campaign(
        self, db: Session, event: NormalizedEvent
    ) -> Tuple[Optional[str], str, bool, List[DBEvent]]:
        """
        Calculates correlation score against active campaigns and uncorrelated events.
        Returns (campaign_id, correlation_reason, is_new, matched_events).
        """
        event_dt = _to_dt(event.timestamp)
        window_start = event_dt - timedelta(hours=self.config.WINDOW_HOURS)
        window_end = event_dt + timedelta(hours=self.config.WINDOW_HOURS)

        # ── 1. Check against active campaigns ────────────────────────────────
        active_campaigns = (
            db.query(DBCampaign)
            .order_by(DBCampaign.created_at.desc())
            .all()
        )

        best_campaign = None
        best_campaign_score = 0
        best_campaign_reason = ""

        for camp in active_campaigns:
            camp_events = db.query(DBEvent).filter(DBEvent.campaign_id == camp.campaign_id).all()
            for ce in camp_events:
                score, reason = score_event_pair(event, ce, self.config)
                if score > best_campaign_score:
                    best_campaign_score = score
                    best_campaign_reason = reason
                    best_campaign = camp

        if best_campaign and best_campaign_score >= self.config.THRESHOLD_CAMPAIGN:
            return best_campaign.campaign_id, best_campaign_reason, False, []

        # ── 2. Check against existing uncorrelated security events ────────────
        uncorrelated_events = (
            db.query(DBEvent)
            .filter(
                DBEvent.campaign_id == None,
                DBEvent.event_id != event.event_id,
                DBEvent.timestamp >= window_start,
                DBEvent.timestamp <= window_end,
                (DBEvent.security_status != "informational") | (DBEvent.mitre_stage != None),
            )
            .order_by(DBEvent.timestamp.desc())
            .all()
        )

        best_cand_ev = None
        best_cand_score = 0
        best_cand_reason = ""

        for cand in uncorrelated_events:
            score, reason = score_event_pair(event, cand, self.config)
            if score > best_cand_score:
                best_cand_score = score
                best_cand_reason = reason
                best_cand_ev = cand

        if best_cand_ev and best_cand_score >= self.config.THRESHOLD_CAMPAIGN:
            # Create a new campaign linking both events
            campaign_id = f"CAMPAIGN-{uuid.uuid4().hex[:6].upper()}"
            target_val = (
                (event.user if event.user and not is_generic_user(event.user) else None)
                or (best_cand_ev.user if best_cand_ev.user and not is_generic_user(best_cand_ev.user) else None)
                or (event.source_ip if event.source_ip and not is_generic_ip(event.source_ip) else None)
                or event.device_id
                or best_cand_ev.device_id
                or "unknown"
            )

            new_campaign = DBCampaign(
                campaign_id      = campaign_id,
                target           = target_val,
                attack_type      = "Observed Incidents",
                stage            = "Detection",
                confidence       = 0.5,
                risk             = "LOW",
                risk_score       = 0,
                data_source      = event.data_source or best_cand_ev.data_source or "Sysmon",
                predicted_outcome= None,
                created_at       = datetime.now(timezone.utc).replace(tzinfo=None),
            )
            db.add(new_campaign)

            # Link the existing candidate event
            best_cand_ev.campaign_id = campaign_id
            best_cand_ev.correlation_reason = f"Correlated with {event.event_id}: {best_cand_reason}"
            db.commit()
            db.refresh(new_campaign)

            return campaign_id, best_cand_reason, True, [best_cand_ev]

        # ── 3. Insufficient evidence for campaign creation ────────────────────
        highest_score = max(best_campaign_score, best_cand_score)
        if highest_score >= self.config.THRESHOLD_UNRELATED:
            reason = best_cand_reason or best_campaign_reason or f"score {highest_score}"
            return None, f"Investigation candidate (score {highest_score}) — awaiting corroborating evidence: {reason}", False, []

        return None, f"Single event — pending correlation (score {highest_score})", False, []

    def _retrieve_contextual_events(self, db: Session, campaign_id: str, campaign_events: list) -> list:
        """
        Retrospectively finds recent informational events matching the campaign's context
        (same device, user, domain, process, or source IP) and links them as supporting telemetry.
        """
        if not campaign_events:
            return []

        dts = [_to_dt(e.timestamp) for e in campaign_events]
        min_dt = min(dts) - timedelta(minutes=60)
        max_dt = max(dts) + timedelta(minutes=15)

        users = {normalize_user(e.user) for e in campaign_events if e.user and not is_generic_user(e.user)}
        devices = {str(e.device_id).lower() for e in campaign_events if e.device_id}
        procs = {get_proc_base(e.process_name) for e in campaign_events if e.process_name}
        parent_procs = {get_proc_base(e.parent_process) for e in campaign_events if e.parent_process}
        all_procs = procs | parent_procs
        domains = {str(e.domain).lower() for e in campaign_events if e.domain}
        ips = {str(e.source_ip) for e in campaign_events if e.source_ip and not is_generic_ip(e.source_ip)}

        candidates = (
            db.query(DBEvent)
            .filter(
                DBEvent.campaign_id == None,
                DBEvent.security_status == "informational",
                DBEvent.timestamp >= min_dt,
                DBEvent.timestamp <= max_dt,
            )
            .all()
        )

        attached = []
        for cand in candidates:
            cand_user = normalize_user(cand.user)
            cand_device = str(cand.device_id or "").lower()
            cand_proc = get_proc_base(cand.process_name)
            cand_parent = get_proc_base(cand.parent_process)
            cand_dom = str(cand.domain or "").lower()
            cand_ip = str(cand.source_ip or "")

            is_relevant = False
            reasons = []
            if devices and cand_device in devices:
                if all_procs and ((cand_proc and cand_proc in all_procs) or (cand_parent and cand_parent in all_procs)):
                    is_relevant = True
                    reasons.append(f"process '{cand_proc or cand_parent}'")
                elif users and cand_user and cand_user in users:
                    is_relevant = True
                    reasons.append(f"user '{cand.user}'")
                elif domains and cand_dom and cand_dom in domains:
                    is_relevant = True
                    reasons.append(f"domain '{cand.domain}'")
                elif ips and cand_ip and cand_ip in ips:
                    is_relevant = True
                    reasons.append(f"source IP '{cand_ip}'")

            if is_relevant:
                cand.campaign_id = campaign_id
                cand.correlation_reason = f"Contextual telemetry: matched {', '.join(reasons)} on device '{cand.device_id}'"
                attached.append(cand)

        if attached:
            db.commit()

        return attached

    def _update_campaign(self, db: Session, campaign_id: str, events: list):
        """Recomputes campaign properties after events or contextual items are attached."""
        if not events:
            return

        campaign = db.query(DBCampaign).filter(DBCampaign.campaign_id == campaign_id).first()
        if not campaign:
            return

        # ── Stage extraction (ordered + deduplicated by MITRE stage) ─────────
        stage_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command & Control", "Command and Control", "Exfiltration", "Impact",
        ]
        sorted_events = sorted(events, key=lambda e: _to_dt(e.timestamp))
        seen, ordered_stages = set(), []
        for e in sorted_events:
            if e.mitre_stage and e.mitre_stage not in seen:
                seen.add(e.mitre_stage)
                ordered_stages.append(e.mitre_stage)

        # Sort stages by kill-chain order
        ordered_stages.sort(key=lambda s: stage_order.index(s) if s in stage_order else 99)
        stage_str = " -> ".join(ordered_stages) if ordered_stages else "Observation"

        # ── Attack type classification ────────────────────────────────────────
        stage_set = set(ordered_stages)
        etypes = {e.event_type.lower() for e in events}

        if {"exfil_https", "exfil_ftp", "dns_exfil"} & etypes:
            attack_type = "Data Exfiltration"
        elif {"ransomware_encrypt", "disk_wipe"} & etypes:
            attack_type = "Ransomware"
        elif {"dos_flood", "ddos_flood"} & etypes:
            attack_type = "DoS/DDoS"
        elif "Lateral Movement" in stage_set:
            attack_type = "APT / Lateral Spread"
        elif "Credential Access" in stage_set:
            attack_type = "Credential Theft"
        elif "Initial Access" in stage_set and "Execution" in stage_set:
            attack_type = "Malware Delivery"
        elif "Initial Access" in stage_set:
            attack_type = "Phishing Campaign"
        else:
            attack_type = "Observed Host Activity"

        # ── ML Prediction ─────────────────────────────────────────────────────
        feats = extract_features(events)
        confidence, risk = self.predictor.predict(feats)
        risk_score = RiskEngine.get_risk_analysis(events)["score"]

        # ML next stage
        ml_preds = self.predictor.predict_next_stages_ml(events)
        rule_preds = self.predictor.predict_next_stages_rule_based(ordered_stages)

        predicted_outcome = ml_preds[0]["stage"] if ml_preds else None

        # ── Log prediction at this stage boundary ─────────────────────────────
        last_log = (
            db.query(PredictionLog)
            .filter(PredictionLog.campaign_id == campaign_id)
            .order_by(PredictionLog.id.desc())
            .first()
        )
        if not last_log or last_log.at_stage != (ordered_stages[-1] if ordered_stages else ""):
            log_entry = PredictionLog(
                campaign_id     = campaign_id,
                timestamp       = datetime.now(timezone.utc).replace(tzinfo=None),
                observed_stages = json.dumps(ordered_stages),
                at_stage        = ordered_stages[-1] if ordered_stages else "",
                ml_top1_stage   = ml_preds[0]["stage"] if ml_preds else None,
                ml_top1_prob    = ml_preds[0]["probability"] if ml_preds else None,
                ml_top3_stages  = json.dumps([p["stage"] for p in ml_preds[:3]]),
                rule_top1_stage = rule_preds[0]["stage"] if rule_preds else None,
                rule_top1_prob  = rule_preds[0]["probability"] if rule_preds else None,
            )
            db.add(log_entry)

        # ── Update PredictionLog entries with actual_next_stage ───────────────
        if len(ordered_stages) >= 2 and last_log and last_log.actual_next_stage is None:
            actual_new_stage = ordered_stages[-1]
            last_log.actual_next_stage = actual_new_stage
            last_log.ml_correct = (last_log.ml_top1_stage == actual_new_stage)
            last_log.rule_correct = (last_log.rule_top1_stage == actual_new_stage)
            top3 = json.loads(last_log.ml_top3_stages or "[]")
            last_log.ml_top3_correct = actual_new_stage in top3

        # ── Update campaign record ────────────────────────────────────────────
        campaign.attack_type      = attack_type
        campaign.stage            = stage_str
        campaign.confidence       = confidence
        campaign.risk             = risk
        campaign.risk_score       = risk_score
        campaign.predicted_outcome= predicted_outcome
        db.commit()

        # ── Phase 7: Automatically open or update SOC Incident Case ──────────
        try:
            from app.intelligence.incident_engine import IncidentEngine
            if risk in ["HIGH", "CRITICAL"] or risk_score >= 70:
                IncidentEngine().ensure_incident_for_campaign(campaign, db)
        except Exception:
            pass
