from typing import List
from app.database.models import Event as DBEvent

class RiskEngine:
    @staticmethod
    def calculate_base_risk(events: List[DBEvent]) -> float:
        """
        Calculates a risk score from 0 to 100 based on event severities and quantity indicators.
        """
        if not events:
            return 0.0

        # Base risk matches the maximum severity in the event collection
        max_sev = max(e.severity for e in events)
        
        # Add dynamic boost for multi-event sequences (alert fatigue/pivoting indicator)
        event_count = len(events)
        boost = min(event_count * 2.5, 20.0)  # max 20 point boost
        
        # Add boost if we cross critical infrastructure domains or files
        critical_boost = 0.0
        for e in events:
            # Check critical event names or severities
            if e.event_type.lower() in ["powershell", "credential_login", "brute_force"]:
                critical_boost += 5.0
                
        critical_boost = min(critical_boost, 15.0) # max 15 point critical boost

        return min(max_sev + boost + critical_boost, 100.0)

    @staticmethod
    def get_risk_analysis(events: List[DBEvent]) -> dict:
        """
        Computes numeric risk score (0-100) and returns a checklist of active risk factors.
        """
        if not events:
            return {"score": 0, "risk_factors": []}

        score = int(RiskEngine.calculate_base_risk(events))
        factors = []
        
        # Check specific threat patterns
        has_powershell = any(e.event_type.lower() in ["powershell", "powershell_execution"] for e in events)
        has_cred = any(e.event_type.lower() in ["credential_login", "suspicious_login", "brute_force"] for e in events)
        has_c2 = any(e.event_type.lower() in ["suspicious_dns", "dns_beacon", "c2_beacon"] for e in events)
        
        stages = {e.mitre_stage for e in events if e.mitre_stage}
        unique_ips = {e.source_ip for e in events if e.source_ip}
        unique_users = {e.user for e in events if e.user}
        unique_domains = {e.domain for e in events if e.domain}

        if has_cred:
            factors.append("Credential access")
        if has_powershell:
            factors.append("PowerShell execution")
        if has_c2:
            factors.append("C2 communication")
        if len(events) >= 4:
            factors.append("Multiple related events")
        if len(stages) >= 3:
            factors.append("Attack progression")
        if len(unique_ips) > 1 or len(unique_users) > 1 or len(unique_domains) > 1:
            factors.append("Multiple affected entities")

        return {
            "score": score,
            "risk_factors": factors
        }
