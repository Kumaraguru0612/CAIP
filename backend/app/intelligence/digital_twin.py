"""
CAIP Digital Twin — Phase 4
==============================
The Digital Twin is a safe sandboxed simulation of a HIGH-risk campaign.

For a given HIGH-risk campaign it:
  1. Replays existing events in isolated trace context
  2. Projects the next 3 attack stages using the ML predictor
  3. Estimates blast radius (users, IPs, devices, domains at risk)
  4. Generates a timestamped behaviour log (projected events)
  5. Recommends a targeted response playbook

This provides the research flow:
  HIGH Risk → Digital Twin → Safe Analysis → Behaviour Logs → Final Decision

Academic scope: The "twin" is a probabilistic simulation, not a VM/hypervisor.
This is the standard approach in academic security twin literature (e.g., DARPA CHASE).
"""

import json
from datetime import datetime, timedelta
from typing import Any

from app.intelligence.attack_predictor import AttackPredictor
from app.intelligence.feature_extractor import extract_features


# ── Response playbooks by attack archetype ───────────────────────────────────
RESPONSE_PLAYBOOKS: dict[str, dict] = {
    "Credential Theft": {
        "priority": "CRITICAL",
        "actions": [
            {"step": 1, "action": "ISOLATE_HOST",            "detail": "1. Isolate affected endpoint from network to prevent lateral spread"},
            {"step": 2, "action": "INVESTIGATE_PROCESS_TREE","detail": "2. Investigate PowerShell & spawned child process tree"},
            {"step": 3, "action": "REVIEW_LSASS_ACCESS",     "detail": "3. Review LSASS memory access events and memory handle requests"},
            {"step": 4, "action": "RESET_USER_CREDENTIALS",  "detail": "4. Reset potentially compromised credentials & revoke active tokens"},
            {"step": 5, "action": "CHECK_LATERAL_MOVEMENT",  "detail": "5. Check adjacent hosts for signs of lateral movement or Kerberoasting"},
        ],
        "decision": "Isolate Endpoint + Credential Reset",
    },
    "Credential Access": {
        "priority": "CRITICAL",
        "actions": [
            {"step": 1, "action": "ISOLATE_HOST",            "detail": "1. Isolate affected endpoint from network to prevent lateral spread"},
            {"step": 2, "action": "INVESTIGATE_PROCESS_TREE","detail": "2. Investigate PowerShell & spawned child process tree"},
            {"step": 3, "action": "REVIEW_LSASS_ACCESS",     "detail": "3. Review LSASS memory access events and memory handle requests"},
            {"step": 4, "action": "RESET_USER_CREDENTIALS",  "detail": "4. Reset potentially compromised credentials & revoke active tokens"},
            {"step": 5, "action": "CHECK_LATERAL_MOVEMENT",  "detail": "5. Check adjacent hosts for signs of lateral movement or Kerberoasting"},
        ],
        "decision": "Isolate Endpoint + Credential Reset",
    },
    "Command & Control": {
        "priority": "HIGH",
        "actions": [
            {"step": 1, "action": "BLOCK_C2_DOMAIN_IP",      "detail": "1. Block suspicious domain & C2 destination IP at perimeter firewall / DNS sinkhole"},
            {"step": 2, "action": "INSPECT_OUTBOUND_CONN",   "detail": "2. Inspect outbound network connections and beaconing frequency from host"},
            {"step": 3, "action": "REVIEW_DNS_HISTORY",      "detail": "3. Review endpoint DNS resolution history for domain generation algorithms (DGA)"},
            {"step": 4, "action": "SWEEP_OTHER_ENDPOINTS",   "detail": "4. Search other enterprise endpoints for connection attempts to the same domain/IP"},
            {"step": 5, "action": "TERMINATE_C2_PROCESS",    "detail": "5. Terminate initiating process and quarantine payload binary"},
        ],
        "decision": "Block Domain/IP + Fleet IOC Sweep",
    },
    "C2 Beaconing": {
        "priority": "HIGH",
        "actions": [
            {"step": 1, "action": "BLOCK_C2_DOMAIN_IP",      "detail": "1. Block suspicious domain & C2 destination IP at perimeter firewall / DNS sinkhole"},
            {"step": 2, "action": "INSPECT_OUTBOUND_CONN",   "detail": "2. Inspect outbound network connections and beaconing frequency from host"},
            {"step": 3, "action": "REVIEW_DNS_HISTORY",      "detail": "3. Review endpoint DNS resolution history for domain generation algorithms (DGA)"},
            {"step": 4, "action": "SWEEP_OTHER_ENDPOINTS",   "detail": "4. Search other enterprise endpoints for connection attempts to the same domain/IP"},
            {"step": 5, "action": "TERMINATE_C2_PROCESS",    "detail": "5. Terminate initiating process and quarantine payload binary"},
        ],
        "decision": "Block Domain/IP + Fleet IOC Sweep",
    },
    "Ransomware": {
        "priority": "CRITICAL",
        "actions": [
            {"step": 1, "action": "ISOLATE_HOST",            "detail": "1. Quarantine affected endpoints immediately to prevent encryption spread"},
            {"step": 2, "action": "KILL_RANSOMWARE_PROCESS", "detail": "2. Forcibly terminate active encryption, vssadmin, and shadow-copy destruction processes"},
            {"step": 3, "action": "BLOCK_C2_IPS",            "detail": "3. Block all C2 IPs and staging domains at perimeter firewall"},
            {"step": 4, "action": "SNAPSHOT_VOLUMES",        "detail": "4. Preserve live memory & take forensic snapshot before rebooting"},
            {"step": 5, "action": "RESTORE_FROM_BACKUP",     "detail": "5. Initiate clean restoration from immutable offline backups"},
        ],
        "decision": "Emergency Isolation + Kill Process",
    },
    "Data Exfiltration": {
        "priority": "CRITICAL",
        "actions": [
            {"step": 1, "action": "DLP_BLOCK_OUTBOUND",       "detail": "1. Enable strict outbound DLP block on network perimeter"},
            {"step": 2, "action": "REVOKE_CREDENTIALS",       "detail": "2. Invalidate all active user sessions and API access tokens"},
            {"step": 3, "action": "BLOCK_EXFIL_DOMAINS",      "detail": "3. Blacklist destination IP and DNS tunnel endpoints"},
            {"step": 4, "action": "PRESERVE_LOGS",            "detail": "4. Archive network flow logs and staging directories for forensics"},
            {"step": 5, "action": "NOTIFY_DATA_OWNER",        "detail": "5. Alert security officer and legal compliance team"},
        ],
        "decision": "Block Outbound + Session Revocation",
    },
    "APT / Lateral Spread": {
        "priority": "HIGH",
        "actions": [
            {"step": 1, "action": "SEGMENT_NETWORK",          "detail": "1. Isolate compromised subnet / VLAN immediately"},
            {"step": 2, "action": "RESET_ADMIN_CREDS",        "detail": "2. Rotate all Domain Admin and service account passwords"},
            {"step": 3, "action": "SCAN_LATERAL_HOSTS",       "detail": "3. Perform live IOC sweep on adjacent workstations and servers"},
            {"step": 4, "action": "ENABLE_MFA",               "detail": "4. Enforce mandatory MFA for all remote and internal RDP/SSH sessions"},
            {"step": 5, "action": "OPEN_INCIDENT_TICKET",     "detail": "5. Escalate to P1 Incident Response team with full timeline"},
        ],
        "decision": "Segment Subnet + Credential Rotation",
    },
    "Malware Delivery": {
        "priority": "HIGH",
        "actions": [
            {"step": 1, "action": "QUARANTINE_FILE",          "detail": "1. Quarantine dropped files and script artifacts in temp/startup folders"},
            {"step": 2, "action": "KILL_PROCESS",             "detail": "2. Terminate malicious process trees on affected endpoints"},
            {"step": 3, "action": "BLOCK_DOWNLOAD_URL",       "detail": "3. Block delivery URL and payload hash across web gateway"},
            {"step": 4, "action": "SCAN_ENDPOINTS",           "detail": "4. Trigger comprehensive EDR / AV scan across endpoint group"},
        ],
        "decision": "Quarantine File + Terminate Process",
    },
    "Phishing Campaign": {
        "priority": "MEDIUM",
        "actions": [
            {"step": 1, "action": "BLOCK_PHISH_URL",          "detail": "1. Blacklist phishing URL and sender domain on email gateway"},
            {"step": 2, "action": "PURGE_MAILBOXES",          "detail": "2. Retrospectively purge malicious email from all employee inboxes"},
            {"step": 3, "action": "AUDIT_CLICKTHROUGHS",      "detail": "3. Review telemetry for users who clicked the link or submitted credentials"},
            {"step": 4, "action": "USER_AWARENESS_ALERT",     "detail": "4. Issue targeted security awareness alert to staff"},
        ],
        "decision": "Block Phish URL + Inbox Purge",
    },
    "DoS/DDoS": {
        "priority": "HIGH",
        "actions": [
            {"step": 1, "action": "RATE_LIMIT",               "detail": "1. Apply rate limiting and DDoS scrubbing at load balancer"},
            {"step": 2, "action": "ACTIVATE_CDN_WAF",         "detail": "2. Enable aggressive WAF mitigation and challenge rules"},
            {"step": 3, "action": "BLOCK_SOURCE_RANGES",      "detail": "3. Block attacking source IP subnets at upstream provider"},
            {"step": 4, "action": "SCALE_SERVICES",           "detail": "4. Dynamically scale backend capacity to sustain legitimate traffic"},
        ],
        "decision": "Rate Limit + Scrub Traffic",
    },
}

DEFAULT_PLAYBOOK = {
    "priority": "MEDIUM",
    "actions": [
        {"step": 1, "action": "INCREASE_MONITORING",      "detail": "1. Enable enhanced verbose telemetry logging for involved entities"},
        {"step": 2, "action": "REVIEW_ALERTS",            "detail": "2. Initiate Level-2 SOC analyst manual review of correlated events"},
        {"step": 3, "action": "CHECK_ENDPOINT_HEALTH",    "detail": "3. Check endpoint security agent health and policy compliance"},
    ],
    "decision": "Monitor + Analyst Review",
}


class DigitalTwin:
    """
    Safe sandbox simulation of a HIGH-risk attack campaign.
    """

    def __init__(self):
        self.predictor = AttackPredictor()

    def simulate(self, campaign: Any, events: list[Any]) -> dict:
        """
        Parameters
        ----------
        campaign : Campaign ORM object or dict
        events   : list of Event ORM objects or dicts

        Returns
        -------
        dict — full twin report including:
          projected_stages, blast_radius, behaviour_log, playbook, decision
        """
        # ── Helpers to access either ORM or dict ──────────────────────────────
        def _get(obj, key):
            if isinstance(obj, dict):
                return obj.get(key)
            return getattr(obj, key, None)

        campaign_id  = _get(campaign, "campaign_id")
        attack_type  = _get(campaign, "attack_type") or "Unknown"
        risk_score   = int(_get(campaign, "risk_score") or 0)

        # ── Current state ──────────────────────────────────────────────────────
        sorted_events = sorted(events, key=lambda e: _get(e, "timestamp") or "")
        current_stages = []
        seen = set()
        for e in sorted_events:
            s = _get(e, "mitre_stage") or ""
            if s and s not in seen:
                seen.add(s)
                current_stages.append(s)

        # ── Project next stages (ML) ───────────────────────────────────────────
        ml_preds = self.predictor.predict_next_stages_ml(events)
        projected = [{"stage": p["stage"], "probability": p["probability"]} for p in ml_preds[:3]]

        # ── Blast radius estimation ────────────────────────────────────────────
        users   = list({_get(e, "user") for e in events if _get(e, "user")})
        ips     = list({_get(e, "source_ip") for e in events if _get(e, "source_ip")})
        domains = list({_get(e, "domain") for e in events if _get(e, "domain")})
        devices = list({_get(e, "device_id") for e in events if _get(e, "device_id")})

        blast_radius = {
            "affected_users":   users,
            "affected_ips":     ips,
            "affected_domains": domains,
            "affected_devices": devices,
            "total_entities":   len(users) + len(ips) + len(domains) + len(devices),
        }

        # ── Behaviour log — replay + projection ───────────────────────────────
        behaviour_log = []

        # Replay actual events
        for e in sorted_events:
            behaviour_log.append({
                "type":       "observed",
                "timestamp":  str(_get(e, "timestamp")),
                "event_type": _get(e, "event_type"),
                "stage":      _get(e, "mitre_stage"),
                "severity":   _get(e, "severity"),
                "user":       _get(e, "user"),
                "source_ip":  _get(e, "source_ip"),
            })

        # Project future events based on predicted stages
        if sorted_events:
            last_ts_raw = _get(sorted_events[-1], "timestamp")
            if isinstance(last_ts_raw, datetime):
                last_ts = last_ts_raw
            else:
                try:
                    last_ts = datetime.fromisoformat(str(last_ts_raw))
                except Exception:
                    last_ts = datetime.utcnow()
        else:
            last_ts = datetime.utcnow()

        stage_to_event = {
            "Lateral Movement":   "lateral_rdp",
            "Collection":         "data_staged",
            "Exfiltration":       "exfil_https",
            "Command & Control":  "dns_beacon",
            "Privilege Escalation":"uac_bypass",
            "Impact":             "ransomware_encrypt",
            "Persistence":        "scheduled_task",
            "Discovery":          "network_scan",
        }

        for i, pred in enumerate(projected):
            projected_ts = last_ts + timedelta(minutes=(i + 1) * 12)
            behaviour_log.append({
                "type":       "projected",
                "timestamp":  projected_ts.strftime("%Y-%m-%dT%H:%M:%S"),
                "event_type": stage_to_event.get(pred["stage"], "unknown"),
                "stage":      pred["stage"],
                "probability":round(pred["probability"] * 100, 1),
                "severity":   min(risk_score + (i * 8), 100),
                "user":       users[0] if users else "unknown",
                "source_ip":  ips[0] if ips else "unknown",
            })

        # ── Select response playbook ───────────────────────────────────────────
        playbook = RESPONSE_PLAYBOOKS.get(attack_type, DEFAULT_PLAYBOOK)

        # ── Risk verdict ───────────────────────────────────────────────────────
        if risk_score >= 85:
            verdict = "CRITICAL — Immediate containment required"
        elif risk_score >= 70:
            verdict = "HIGH — Block and investigate"
        elif risk_score >= 40:
            verdict = "MEDIUM — Monitor with elevated alerting"
        else:
            verdict = "LOW — Log and observe"

        return {
            "campaign_id":     campaign_id,
            "twin_timestamp":  datetime.utcnow().isoformat(),
            "risk_score":      risk_score,
            "current_stages":  current_stages,
            "attack_type":     attack_type,
            "projected_stages":projected,
            "blast_radius":    blast_radius,
            "behaviour_log":   behaviour_log,
            "playbook":        playbook,
            "verdict":         verdict,
            "decision":        playbook.get("decision", "Monitor"),
        }
