"""Enforcement Engine for AGENT SHIELD.

Implements the four mandatory enforcement outcomes with strict precedence and fail-closed logic:
1. BLOCK (highest precedence — never executes; NEVER overridden by a normal/low ML anomaly score)
2. REQUIRE_APPROVAL (sensitive permitted request — held pending admin approval; never executes early)
3. MONITOR (permitted request with behavioural/ML anomaly — executes with alert & audit log)
4. ALLOW (permitted normal request — executes cleanly)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from backend.auth import AuthResult
from backend.behaviour_monitor import BehaviourAssessment
from backend.policy_engine import PolicyEvaluation
from backend.risk_engine import RiskAssessment


@dataclass
class EnforcementDecision:
    decision: str  # ALLOW, BLOCK, MONITOR, REQUIRE_APPROVAL
    should_execute: bool
    create_alert: bool
    alert_severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    reasons: List[str] = field(default_factory=list)


class EnforcementEngine:
    """Combines auth, policy, behaviour, and risk assessments into a single enforcement decision.

    Hard Security Invariant: An ML anomaly score (normal or anomalous) can NEVER override
    an explicit permission denial, authentication failure, or prompt-injection block.
    """

    def decide(
        self,
        *,
        auth: AuthResult,
        validation_ok: bool,
        validation_reason: str,
        policy: PolicyEvaluation,
        behaviour: BehaviourAssessment,
        risk: RiskAssessment,
    ) -> EnforcementDecision:
        reasons: List[str] = []

        # 1. Fail-closed on auth failure or error
        if not auth.authenticated or auth.error:
            return EnforcementDecision(
                decision="BLOCK",
                should_execute=False,
                create_alert=True,
                alert_severity="CRITICAL",
                reasons=[auth.reason],
            )

        # 2. Fail-closed on invalid tool or arguments
        if not validation_ok:
            return EnforcementDecision(
                decision="BLOCK",
                should_execute=False,
                create_alert=True,
                alert_severity="HIGH",
                reasons=[validation_reason],
            )

        # 3. Fail-closed on policy engine error, prompt injection, or unauthorized permission.
        #    NOTE: Checked strictly BEFORE behaviour/ML so ML can NEVER override a policy denial.
        if policy.error or policy.injection_detected or not policy.allowed:
            reasons.append(policy.reason)
            if behaviour.reasons:
                reasons.extend(behaviour.reasons)
            return EnforcementDecision(
                decision="BLOCK",
                should_execute=False,
                create_alert=True,
                alert_severity="CRITICAL" if policy.injection_detected or policy.error else "HIGH",
                reasons=reasons,
            )

        # 4. Behaviour hard-block threshold overrides ALLOW/MONITOR/APPROVAL
        if behaviour.status == "ANOMALOUS_BLOCK":
            reasons.extend(behaviour.reasons)
            return EnforcementDecision(
                decision="BLOCK",
                should_execute=False,
                create_alert=True,
                alert_severity="CRITICAL",
                reasons=reasons,
            )

        # 5. Sensitive operation requiring administrator approval (must NOT execute early)
        if policy.requires_approval:
            reasons.append(policy.reason)
            if behaviour.reasons:
                reasons.extend(behaviour.reasons)
            return EnforcementDecision(
                decision="REQUIRE_APPROVAL",
                should_execute=False,
                create_alert=True,
                alert_severity="MEDIUM" if risk.score < 70 else "HIGH",
                reasons=reasons,
            )

        # 6. Permitted request with behavioural or Isolation Forest anomaly alert
        if behaviour.status == "MONITOR":
            reasons.extend(behaviour.reasons)
            return EnforcementDecision(
                decision="MONITOR",
                should_execute=True,
                create_alert=True,
                alert_severity="MEDIUM" if risk.score < 60 else "HIGH",
                reasons=reasons,
            )

        # 7. Cleanly authorized request
        return EnforcementDecision(
            decision="ALLOW",
            should_execute=True,
            create_alert=False,
            alert_severity="LOW",
            reasons=[policy.reason],
        )
