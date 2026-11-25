"""
CAIP Cost-Aware Router
========================
Implements the 3-tier routing decision that determines how much
computational resource to allocate to each campaign.

Tiers:
  MONITOR     — Risk < 50  — log only, no ML inference
  INVESTIGATE — Risk 50-79 — ML prediction + rule analysis
  TWIN        — Risk >= 80 — Full Digital Twin simulation

This module is used by:
  - campaign_engine.py (after risk scoring)
  - main.py  (campaign detail endpoint)
  - Experiment 6 (cost analysis)

IEEE paper section: "Cost-Aware Campaign Processing"
"""

from typing import Literal

# Routing tier type
RoutingTier = Literal["monitor", "investigate", "twin"]

# Cost estimates per tier (approximate, profiled on dev machine)
TIER_COST_MS = {
    "monitor":     0.3,    # normalisation only
    "investigate": 3.5,    # ML inference + rule evaluation
    "twin":        18.0,   # full simulation + playbook generation
}

TIER_RAM_MB = {
    "monitor":     1.0,
    "investigate": 14.0,
    "twin":        52.0,
}


class CostRouter:
    """
    Determines the processing tier for a campaign based on risk score
    and optional override signals.

    Usage:
        router = CostRouter()
        decision = router.route(campaign_risk_score=85, attack_type="ransomware")
        # → {"tier": "twin", "reason": "risk >= 80", ...}
    """

    # Attack types that always escalate to TWIN regardless of score
    ALWAYS_TWIN = {"ransomware", "apt_full_chain", "apt_exfiltration"}

    # Attack types that cap at INVESTIGATE (never auto-twin)
    CAP_INVESTIGATE = {"port_scan", "dos_ddos"}

    def __init__(
        self,
        monitor_threshold: int = 50,
        twin_threshold: int = 80,
    ):
        self.monitor_threshold    = monitor_threshold
        self.twin_threshold       = twin_threshold

    def route(
        self,
        campaign_risk_score: int,
        attack_type: str = "",
        n_events: int = 1,
    ) -> dict:
        """
        Determine routing tier for a campaign.

        Args:
            campaign_risk_score: integer 0-100 from RiskEngine
            attack_type: campaign archetype (optional, for override logic)
            n_events: number of events in campaign (high event count = escalate)

        Returns:
            {
              "tier":         "monitor"|"investigate"|"twin",
              "reason":       str,
              "est_cpu_ms":   float,
              "est_ram_mb":   float,
              "escalated":    bool,
            }
        """
        attack_type_lower = (attack_type or "").lower().replace(" ", "_")

        # ── Override: always twin for critical attack types ───────────────────
        if attack_type_lower in self.ALWAYS_TWIN:
            return self._decision("twin", f"attack type '{attack_type}' always requires twin", True)

        # ── Override: cap at investigate for low-risk types ──────────────────
        if attack_type_lower in self.CAP_INVESTIGATE and campaign_risk_score < self.twin_threshold:
            return self._decision("investigate", f"attack type '{attack_type}' capped at investigate", False)

        # ── Volume escalation: many events → at least investigate ────────────
        if n_events >= 8 and campaign_risk_score < self.monitor_threshold:
            return self._decision("investigate", f"event volume ({n_events}) escalates from monitor", True)

        # ── Standard threshold routing ────────────────────────────────────────
        if campaign_risk_score >= self.twin_threshold:
            return self._decision("twin", f"risk score {campaign_risk_score} >= {self.twin_threshold}", False)
        elif campaign_risk_score >= self.monitor_threshold:
            return self._decision("investigate", f"risk score {campaign_risk_score} in investigate range", False)
        else:
            return self._decision("monitor", f"risk score {campaign_risk_score} < {self.monitor_threshold}", False)

    def _decision(self, tier: RoutingTier, reason: str, escalated: bool) -> dict:
        return {
            "tier":       tier,
            "reason":     reason,
            "est_cpu_ms": TIER_COST_MS[tier],
            "est_ram_mb": TIER_RAM_MB[tier],
            "escalated":  escalated,
            "label":      {
                "monitor":     "MONITOR",
                "investigate": "INVESTIGATE",
                "twin":        "DIGITAL TWIN",
            }[tier],
        }

    def get_tier_label(self, risk_score: int, attack_type: str = "") -> str:
        """Quick label lookup for API responses."""
        return self.route(risk_score, attack_type)["tier"]

    @staticmethod
    def explain_tiers() -> dict:
        """Return human-readable tier explanations for documentation."""
        return {
            "monitor": {
                "threshold":   "risk < 50",
                "action":      "Log and flag for periodic review",
                "cost_cpu":    f"~{TIER_COST_MS['monitor']}ms",
                "cost_ram":    f"~{TIER_RAM_MB['monitor']}MB",
                "description": "Low-confidence or low-severity events. Minimal processing.",
            },
            "investigate": {
                "threshold":   "risk 50–79",
                "action":      "Run ML prediction + rule analysis",
                "cost_cpu":    f"~{TIER_COST_MS['investigate']}ms",
                "cost_ram":    f"~{TIER_RAM_MB['investigate']}MB",
                "description": "Medium-risk campaigns. Predict next stage and issue alert.",
            },
            "twin": {
                "threshold":   "risk >= 80",
                "action":      "Full Digital Twin simulation + response playbook",
                "cost_cpu":    f"~{TIER_COST_MS['twin']}ms",
                "cost_ram":    f"~{TIER_RAM_MB['twin']}MB",
                "description": "High-risk campaigns. Project behavior, estimate blast radius, generate playbook.",
            },
        }


# Module-level singleton for import convenience
_router = None

def get_router() -> CostRouter:
    global _router
    if _router is None:
        _router = CostRouter()
    return _router


def route_campaign(risk_score: int, attack_type: str = "", n_events: int = 1) -> dict:
    """Convenience function — route a campaign and return tier decision."""
    return get_router().route(risk_score, attack_type, n_events)
