"""Explainable Risk Assessment Engine for AGENT SHIELD.

AVISHKAR'26 Problem Statement 9 Compliance:
- Produces a deterministic 0–100 risk score and human-readable reasons for every request.
- Explicitly decomposes contributions from:
  1. Resource & action sensitivity
  2. Policy / permission & prompt-injection checks
  3. Deterministic behavioural indicators (volume, unique records, off-hours, unseen resources, failures)
  4. Isolation Forest ML anomaly detection
- Explicitly distinguishes operational risk score (0–100) from calibrated attack probability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from backend.behaviour_monitor import BehaviourAssessment
from backend.config import ACTION_SENSITIVITY, PAYMENT_APPROVAL_THRESHOLD, RESOURCE_SENSITIVITY
from backend.policy_engine import PolicyEvaluation

RISK_SCORE_DISCLAIMER = (
    "Explainable operational risk index (0-100) combining policy, resource sensitivity, "
    "deterministic behaviour indicators, and Isolation Forest outlier signals — NOT a calibrated attack probability."
)


@dataclass
class RiskAssessment:
    score: float
    level: str  # LOW, MEDIUM, HIGH, CRITICAL
    factors: List[str] = field(default_factory=list)
    breakdown: Dict[str, float] = field(default_factory=dict)
    disclaimer: str = RISK_SCORE_DISCLAIMER


class RiskAssessmentEngine:
    """Calculates transparent, explainable 0-100 risk scores with component breakdown."""

    def assess(
        self,
        *,
        authenticated: bool,
        resource: str,
        action: str,
        arguments: Dict[str, Any],
        policy: PolicyEvaluation,
        behaviour: BehaviourAssessment,
    ) -> RiskAssessment:
        if not authenticated:
            return RiskAssessment(
                score=95.0,
                level="CRITICAL",
                factors=["Unauthenticated or invalid agent credential (+95.0)"],
                breakdown={
                    "resource_action_sensitivity": 0.0,
                    "policy_and_injection": 95.0,
                    "behaviour_rules": 0.0,
                    "ml_isolation_forest": 0.0,
                },
            )

        factors: List[str] = []

        # 1. Resource & action sensitivity
        res_base = float(RESOURCE_SENSITIVITY.get(resource, 50))
        act_mod = float(ACTION_SENSITIVITY.get(action, 15))
        sensitivity_pts = round(res_base * 0.30 + act_mod * 0.45, 1)
        factors.append(f"Resource/action sensitivity ({resource}:{action}): +{sensitivity_pts}")

        # 2. Policy & prompt injection
        policy_pts = 0.0
        if policy.injection_detected:
            policy_pts += 70.0
            factors.append("Prompt-injection / privilege escalation pattern detected (+70.0)")
        if not policy.allowed:
            policy_pts += 45.0
            factors.append("Permission Registry denied request (+45.0)")
        if policy.requires_approval:
            policy_pts += 22.0
            factors.append("Sensitive operation meets administrator approval threshold (+22.0)")
        if resource == "payments" and action == "execute":
            try:
                amt = float(arguments.get("amount", 0.0))
                if amt >= PAYMENT_APPROVAL_THRESHOLD:
                    policy_pts += 12.0
                    factors.append(f"High-value simulated payment ${amt:,.2f} (+12.0)")
            except (TypeError, ValueError):
                pass

        # 3. Deterministic behavioural indicators
        beh_rule_pts = 0.0
        if behaviour.status == "ANOMALOUS_BLOCK":
            beh_rule_pts += 40.0
            factors.append("Behaviour rules crossed hard anomaly block threshold (+40.0)")
        elif behaviour.rule_reasons:
            # Granular contribution for each triggered behavioural indicator
            if behaviour.metrics.get("off_hours_activity"):
                beh_rule_pts += 12.0
                factors.append("Off-hours activity outside agent trusted operating window (+12.0)")
            if behaviour.metrics.get("unseen_resource_category"):
                beh_rule_pts += 15.0
                factors.append("Access to previously unseen resource category (+15.0)")
            if behaviour.metrics.get("failed_authz_in_window", 0) >= 3:
                beh_rule_pts += 12.0
                factors.append("Repeated failed permission attempts in sliding window (+12.0)")
            if beh_rule_pts == 0.0:
                beh_rule_pts += 15.0
                factors.append("Elevated request velocity or record volume in sliding window (+15.0)")

        # 4. Isolation Forest ML anomaly contribution
        ml_pts = round(float(behaviour.ml_severity_points), 1)
        if behaviour.ml_is_anomaly and ml_pts > 0:
            factors.append(
                f"Isolation Forest outlier vs per-agent trusted baseline "
                f"(score={behaviour.anomaly_score}): +{ml_pts}"
            )

        raw_total = sensitivity_pts + policy_pts + beh_rule_pts + ml_pts
        final_score = round(min(100.0, max(0.0, raw_total)), 1)

        if final_score >= 80:
            level = "CRITICAL"
        elif final_score >= 60:
            level = "HIGH"
        elif final_score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        breakdown = {
            "resource_action_sensitivity": round(sensitivity_pts, 1),
            "policy_and_injection": round(policy_pts, 1),
            "behaviour_rules": round(beh_rule_pts, 1),
            "ml_isolation_forest": round(ml_pts, 1),
        }

        return RiskAssessment(
            score=final_score,
            level=level,
            factors=factors,
            breakdown=breakdown,
            disclaimer=RISK_SCORE_DISCLAIMER,
        )
