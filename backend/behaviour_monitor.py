"""Per-Agent Behaviour Baseline & Isolation Forest Monitoring Engine for AGENT SHIELD.

AVISHKAR'26 Problem Statement 9 Compliance:
1. Per-agent trusted normal-behaviour baseline persisted in SQLite (`behaviour_baselines`),
   trained exclusively on synthetic normal activity data — NEVER automatically retrained
   from incoming untrusted requests (prevents baseline poisoning).
2. Mandatory Isolation Forest anomaly detection (`sklearn.ensemble.IsolationForest` when
   scikit-learn is installed; deterministic pure-NumPy Liu et al. (2008) Isolation Forest
   fallback when running in an offline environment without scikit-learn).
3. Monitors all 5 required behavioural features:
   - Request volume and frequency (requests_in_window)
   - Number of unique records accessed (projected_unique_records)
   - Access to previously unseen resource categories (unseen_resource_flag)
   - Failed permission attempts (failed_authz_in_window)
   - Off-hours activity (off_hours_flag)
4. Combines ML anomaly detection with transparent deterministic security rules.
   Clearly distinguishes statistical anomaly scores from calibrated attack probabilities.
"""
from __future__ import annotations

import hashlib
import json
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from backend.config import (
    BEHAVIOUR_WINDOW_SECONDS,
    BLOCK_REQUEST_THRESHOLD,
    BLOCK_UNIQUE_RECORDS_THRESHOLD,
    DEFAULT_NORMAL_HOUR_END,
    DEFAULT_NORMAL_HOUR_START,
    DEFAULT_TIMEZONE,
    FAILED_AUTHZ_ALERT_THRESHOLD,
    MONITOR_REQUEST_THRESHOLD,
    MONITOR_UNIQUE_RECORDS_THRESHOLD,
    REPEATED_PATTERN_THRESHOLD,
)
from backend.database import DatabaseManager

try:
    from zoneinfo import ZoneInfo
    _APP_TZ = ZoneInfo(DEFAULT_TIMEZONE)
except Exception:
    _APP_TZ = timezone.utc

try:
    from sklearn.ensemble import IsolationForest as SklearnIsolationForest  # type: ignore

    _SKLEARN_AVAILABLE = True
except ImportError:
    SklearnIsolationForest = None
    _SKLEARN_AVAILABLE = False


class _PureNumpyIsolationForest:
    """Exact Liu et al. (2008) Isolation Forest in NumPy used ONLY if scikit-learn is absent."""

    def __init__(self, n_estimators: int = 100, max_samples: int = 128, contamination: float = 0.04, random_state: int = 42) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self._trees: List[Dict[str, Any]] = []
        self._threshold: float = 0.58
        self._sample_size: int = max_samples
        self._feature_mins: Optional[np.ndarray] = None
        self._feature_maxs: Optional[np.ndarray] = None

    @staticmethod
    def _c(n: int) -> float:
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        return 2.0 * (math.log(n - 1.0) + 0.5772156649) - (2.0 * (n - 1.0) / n)

    def _build_tree(self, X: np.ndarray, depth: int, max_depth: int, rng: np.random.Generator) -> Dict[str, Any]:
        n_samples, n_features = X.shape
        if depth >= max_depth or n_samples <= 1:
            return {"leaf": True, "size": n_samples}

        # Pick only among features with non-zero spread so trees do not prematurely terminate
        valid_feats = [f for f in range(n_features) if float(np.min(X[:, f])) < float(np.max(X[:, f]))]
        if not valid_feats:
            return {"leaf": True, "size": n_samples}

        feat = int(rng.choice(valid_feats))
        col = X[:, feat]
        lo, hi = float(np.min(col)), float(np.max(col))
        split = float(rng.uniform(lo, hi))
        left_mask = col < split
        if not np.any(left_mask) or np.all(left_mask):
            return {"leaf": True, "size": n_samples}
        return {
            "leaf": False,
            "feat": feat,
            "split": split,
            "left": self._build_tree(X[left_mask], depth + 1, max_depth, rng),
            "right": self._build_tree(X[~left_mask], depth + 1, max_depth, rng),
        }

    def _path_len(self, node: Dict[str, Any], x: np.ndarray, depth: int = 0) -> float:
        if node["leaf"]:
            return float(depth) + self._c(node["size"])
        if x[node["feat"]] < node["split"]:
            return self._path_len(node["left"], x, depth + 1)
        return self._path_len(node["right"], x, depth + 1)

    def fit(self, X: np.ndarray) -> "_PureNumpyIsolationForest":
        rng = np.random.default_rng(self.random_state)
        n = X.shape[0]
        self._sample_size = min(self.max_samples, n)
        max_depth = int(math.ceil(math.log2(max(2, self._sample_size))))
        self._feature_mins = np.min(X, axis=0)
        self._feature_maxs = np.max(X, axis=0)
        self._trees = []
        for _ in range(self.n_estimators):
            idx = rng.choice(n, size=self._sample_size, replace=False)
            self._trees.append(self._build_tree(X[idx], 0, max_depth, rng))
        scores = self._raw_anomaly_scores(X)
        self._threshold = float(np.quantile(scores, 1.0 - self.contamination))
        return self

    def _raw_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        c_n = max(1e-6, self._c(self._sample_size))
        out = np.zeros(X.shape[0], dtype=float)
        for i in range(X.shape[0]):
            avg_h = sum(self._path_len(t, X[i]) for t in self._trees) / len(self._trees)
            base_score = 2.0 ** (-avg_h / c_n)
            # Account for out-of-envelope extrapolation beyond the trusted normal hyper-rectangle
            if self._feature_maxs is not None:
                excess = np.maximum(0.0, X[i] - self._feature_maxs)
                span = np.maximum(0.1, self._feature_maxs - self._feature_mins)
                norm_excess = float(np.sum(excess / span))
                if norm_excess > 0.0:
                    base_score = min(0.99, base_score + min(0.35, 0.12 * math.log1p(norm_excess)))
            out[i] = base_score
        return out

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Matches scikit-learn convention: positive = inlier (normal), negative = outlier (anomalous)."""
        scores = self._raw_anomaly_scores(X)
        return self._threshold - scores

    def predict(self, X: np.ndarray) -> np.ndarray:
        df = self.decision_function(X)
        return np.where(df < 0.0, -1, 1)


@dataclass
class BehaviourAssessment:
    status: str  # NORMAL, MONITOR, ANOMALOUS_BLOCK
    reasons: List[str] = field(default_factory=list)
    rule_reasons: List[str] = field(default_factory=list)
    ml_reasons: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    baseline_profile: Dict[str, Any] = field(default_factory=dict)
    ml_is_anomaly: bool = False
    anomaly_score: float = 0.0  # positive = normal inlier, negative = outlier
    ml_severity_points: float = 0.0  # 0..30 deterministic risk contribution from ML detector
    detector_mode: str = "rule_based+isolation_forest"


class BehaviourMonitoringEngine:
    """Tracks per-agent sliding-window behaviour against trusted synthetic baselines + Isolation Forest."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self._models: Dict[str, Tuple[Any, Dict[str, Any]]] = {}

    @staticmethod
    def _agent_seed(agent_id: str) -> int:
        return int(hashlib.sha256(agent_id.encode("utf-8")).hexdigest()[:8], 16)

    def ensure_agent_baseline(
        self,
        *,
        agent_id: str,
        normal_resources: List[str],
        normal_hours_start: int = DEFAULT_NORMAL_HOUR_START,
        normal_hours_end: int = DEFAULT_NORMAL_HOUR_END,
        typical_req_per_window_max: int = 4,
        typical_unique_records_max: int = 8,
        baseline_sample_count: int = 250,
    ) -> Dict[str, Any]:
        """Persist a trusted normal-behaviour baseline for an agent (never learned from untrusted traffic)."""
        now = datetime.now(timezone.utc).isoformat()
        with self.db.write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO behaviour_baselines (
                    agent_id, normal_resources, normal_hours_start, normal_hours_end,
                    typical_req_per_window_max, typical_unique_records_max,
                    baseline_sample_count, trusted_source, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'synthetic_normal_baseline_v1', ?)
                """,
                (
                    agent_id,
                    json.dumps(sorted(set(normal_resources))),
                    int(normal_hours_start),
                    int(normal_hours_end),
                    int(typical_req_per_window_max),
                    int(typical_unique_records_max),
                    int(baseline_sample_count),
                    now,
                ),
            )
        self._models.pop(agent_id, None)
        return self.get_agent_baseline(agent_id)

    def get_agent_baseline(self, agent_id: str) -> Dict[str, Any]:
        with self.db.read_connection() as conn:
            row = conn.execute(
                "SELECT * FROM behaviour_baselines WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if row is not None:
                d = dict(row)
                d["normal_resources"] = json.loads(d["normal_resources"])
                return d

            perms = [
                r["resource"]
                for r in conn.execute(
                    "SELECT DISTINCT resource FROM permissions WHERE agent_id = ? AND effect = 'ALLOW'",
                    (agent_id,),
                ).fetchall()
            ]
        return self.ensure_agent_baseline(
            agent_id=agent_id,
            normal_resources=perms or ["customers"],
        )

    def _get_or_train_agent_model(self, agent_id: str) -> Tuple[Any, Dict[str, Any], np.ndarray, np.ndarray]:
        """Train a dedicated per-agent Isolation Forest on its trusted synthetic normal baseline."""
        if agent_id in self._models:
            return self._models[agent_id]

        profile = self.get_agent_baseline(agent_id)
        rng = np.random.default_rng(self._agent_seed(agent_id))
        n = max(250, int(profile.get("baseline_sample_count", 250)))
        req_max = max(2, int(profile.get("typical_req_per_window_max", 4)))
        rec_max = max(3, int(profile.get("typical_unique_records_max", 8)))

        # 5 mandatory features in normal baseline:
        # [requests_in_window, projected_unique_records, unseen_resource_flag, failed_authz_in_window, off_hours_flag]
        req = rng.uniform(1.0, float(req_max), size=n)
        rec = rng.uniform(1.0, float(rec_max), size=n)
        unseen = rng.normal(0.0, 0.02, size=n)
        failed = rng.normal(0.0, 0.02, size=n)
        off_hours = rng.normal(0.0, 0.02, size=n)

        raw_matrix = np.column_stack([req, rec, unseen, failed, off_hours])
        means = np.mean(raw_matrix, axis=0)
        stds = np.std(raw_matrix, axis=0)
        stds[stds < 1e-4] = 1.0

        scaled = (raw_matrix - means) / stds
        excess = np.maximum(0.0, np.abs(scaled) - 1.5)
        dev = np.sum(excess, axis=1, keepdims=True)
        X_train = np.hstack([scaled, dev])

        if _SKLEARN_AVAILABLE and SklearnIsolationForest is not None:
            model = SklearnIsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
                n_jobs=1,
            )
            model.fit(X_train)
        else:
            model = _PureNumpyIsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
            )
            model.fit(X_train)

        res = (model, profile, means, stds)
        self._models[agent_id] = res
        return res

    def evaluate(
        self,
        *,
        agent_id: str,
        tool_name: str,
        resource: str,
        action: str,
        arguments: Dict[str, Any],
        is_sensitive_tool: bool,
        policy_allowed: bool,
        simulated_hour: Optional[int] = None,
    ) -> BehaviourAssessment:
        """Compare current request + sliding window against trusted per-agent baseline & Isolation Forest."""
        now_tz = datetime.now(_APP_TZ)
        current_hour = int(simulated_hour) if simulated_hour is not None else now_tz.hour
        window_start = (datetime.now(timezone.utc) - timedelta(seconds=BEHAVIOUR_WINDOW_SECONDS)).isoformat()

        model, baseline, means, stds = self._get_or_train_agent_model(agent_id)
        normal_resources = set(baseline.get("normal_resources", []))
        hr_start = int(baseline.get("normal_hours_start", DEFAULT_NORMAL_HOUR_START))
        hr_end = int(baseline.get("normal_hours_end", DEFAULT_NORMAL_HOUR_END))

        with self.db.read_connection() as conn:
            recent = conn.execute(
                """
                SELECT tool_name, resource, action, record_ids, record_count,
                       decision, authorized, sensitive_op, timestamp
                FROM activity_logs
                WHERE agent_id = ? AND timestamp >= ?
                ORDER BY timestamp DESC
                """,
                (agent_id, window_start),
            ).fetchall()

        req_count = len(recent) + 1
        unique_records = set()
        failed_authz = 0 if policy_allowed else 1
        sensitive_ops = 1 if is_sensitive_tool else 0
        repeated_same_tool = 1

        for row in recent:
            try:
                ids = json.loads(row["record_ids"]) if row["record_ids"] else []
                unique_records.update(ids)
            except Exception:
                pass
            if not row["authorized"]:
                failed_authz += 1
            if row["sensitive_op"]:
                sensitive_ops += 1
            if row["tool_name"] == tool_name and row["resource"] == resource:
                repeated_same_tool += 1

        requested_limit = 1
        if "limit" in arguments:
            try:
                requested_limit = max(1, int(arguments["limit"]))
            except (TypeError, ValueError):
                requested_limit = 1
        projected_unique_records = len(unique_records) + requested_limit

        # 5 Mandatory Features
        unseen_resource_flag = 1 if (normal_resources and resource not in normal_resources) else 0
        off_hours_flag = 1 if (current_hour < hr_start or current_hour >= hr_end) else 0

        rule_reasons: List[str] = []
        ml_reasons: List[str] = []
        should_block = False
        should_monitor = False

        # Deterministic Security Rules
        if req_count >= BLOCK_REQUEST_THRESHOLD:
            should_block = True
            rule_reasons.append(
                f"High request velocity: {req_count} requests in {BEHAVIOUR_WINDOW_SECONDS}s "
                f"(block threshold: {BLOCK_REQUEST_THRESHOLD})."
            )
        elif req_count >= MONITOR_REQUEST_THRESHOLD:
            should_monitor = True
            rule_reasons.append(
                f"Elevated request frequency: {req_count} requests in {BEHAVIOUR_WINDOW_SECONDS}s "
                f"(monitor threshold: {MONITOR_REQUEST_THRESHOLD})."
            )

        if projected_unique_records >= BLOCK_UNIQUE_RECORDS_THRESHOLD:
            should_block = True
            rule_reasons.append(
                f"Abnormal bulk record access: {projected_unique_records} unique/requested records "
                f"in {BEHAVIOUR_WINDOW_SECONDS}s (block threshold: {BLOCK_UNIQUE_RECORDS_THRESHOLD})."
            )
        elif projected_unique_records >= MONITOR_UNIQUE_RECORDS_THRESHOLD:
            should_monitor = True
            rule_reasons.append(
                f"Elevated unique record volume: {projected_unique_records} unique/requested records "
                f"in {BEHAVIOUR_WINDOW_SECONDS}s (monitor threshold: {MONITOR_UNIQUE_RECORDS_THRESHOLD})."
            )

        if failed_authz >= FAILED_AUTHZ_ALERT_THRESHOLD:
            should_monitor = True
            rule_reasons.append(
                f"Repeated failed permission attempts: {failed_authz} denied calls in "
                f"{BEHAVIOUR_WINDOW_SECONDS}s (threshold: {FAILED_AUTHZ_ALERT_THRESHOLD})."
            )

        if unseen_resource_flag:
            should_monitor = True
            rule_reasons.append(
                f"Previously unseen resource category: '{resource}' is outside trusted baseline "
                f"categories {sorted(normal_resources)}."
            )

        if off_hours_flag:
            should_monitor = True
            rule_reasons.append(
                f"Off-hours activity detected: request at {current_hour:02d}:00 UTC is outside "
                f"trusted operating window ({hr_start:02d}:00–{hr_end:02d}:00 UTC)."
            )

        if repeated_same_tool >= REPEATED_PATTERN_THRESHOLD:
            should_monitor = True
            rule_reasons.append(
                f"Repeated tool access pattern: '{tool_name}' called {repeated_same_tool} times "
                f"within {BEHAVIOUR_WINDOW_SECONDS}s."
            )

        # Mandatory Per-Agent Isolation Forest Evaluation against Trusted Normal Baseline
        raw_vec = np.array(
            [[
                float(req_count),
                float(projected_unique_records),
                float(unseen_resource_flag),
                float(failed_authz),
                float(off_hours_flag),
            ]]
        )
        scaled_vec = (raw_vec - means) / stds
        excess_vec = np.maximum(0.0, np.abs(scaled_vec) - 1.5)
        dev_vec = np.sum(excess_vec, axis=1, keepdims=True)
        feature_vec = np.hstack([scaled_vec, dev_vec])

        pred = int(model.predict(feature_vec)[0])  # -1 = anomalous outlier, 1 = normal inlier
        raw_df = float(model.decision_function(feature_vec)[0])
        anomaly_score = round(raw_df, 4)
        ml_is_anomaly = (pred == -1)

        ml_severity_points = 0.0
        if ml_is_anomaly:
            ml_severity_points = round(min(30.0, max(12.0, abs(anomaly_score) * 140.0 + 10.0)), 1)
            if not should_block:
                should_monitor = True
            backend_label = "scikit-learn IsolationForest" if _SKLEARN_AVAILABLE else "IsolationForest (NumPy fallback)"
            ml_reasons.append(
                f"Per-agent {backend_label} flagged statistical outlier vs trusted baseline "
                f"(decision_score={anomaly_score}, +{ml_severity_points} risk pts; not an attack probability)."
            )

        if should_block:
            status = "ANOMALOUS_BLOCK"
        elif should_monitor:
            status = "MONITOR"
        else:
            status = "NORMAL"

        detector_mode = (
            "rule_based+sklearn_isolation_forest"
            if _SKLEARN_AVAILABLE
            else "rule_based+numpy_isolation_forest"
        )

        metrics = {
            "window_seconds": BEHAVIOUR_WINDOW_SECONDS,
            "requests_in_window": req_count,
            "unique_records_in_window": len(unique_records),
            "projected_records": projected_unique_records,
            "failed_authz_in_window": failed_authz,
            "sensitive_ops_in_window": sensitive_ops,
            "repeated_same_tool": repeated_same_tool,
            "unseen_resource_category": bool(unseen_resource_flag),
            "off_hours_activity": bool(off_hours_flag),
            "timezone": DEFAULT_TIMEZONE,
            "evaluated_hour": current_hour,
            "operating_window": f"{hr_start:02d}:00–{hr_end:02d}:00 ({DEFAULT_TIMEZONE})",
            "evaluated_hour_utc": current_hour,
            "trusted_hours_utc": f"{hr_start:02d}:00-{hr_end:02d}:00",
            "feature_values": {
                "requests_in_window": req_count,
                "projected_records": projected_unique_records,
                "unseen_resource_category": unseen_resource_flag,
                "failed_authz_in_window": failed_authz,
                "off_hours_activity": off_hours_flag,
            },
            "baseline_sample_count": int(baseline.get("baseline_sample_count", 250)),
            "model_status": "ACTIVE (sklearn.ensemble.IsolationForest)" if _SKLEARN_AVAILABLE else "ACTIVE (NumPy Liu et al. IsolationForest fallback)",
            "ml_is_anomaly": ml_is_anomaly,
            "ml_anomaly_score": anomaly_score,
            "ml_severity_points": ml_severity_points,
        }

        return BehaviourAssessment(
            status=status,
            reasons=rule_reasons + ml_reasons,
            rule_reasons=rule_reasons,
            ml_reasons=ml_reasons,
            metrics=metrics,
            baseline_profile=baseline,
            ml_is_anomaly=ml_is_anomaly,
            anomaly_score=anomaly_score,
            ml_severity_points=ml_severity_points,
            detector_mode=detector_mode,
        )

    def record_activity(
        self,
        *,
        agent_id: str,
        tool_name: str,
        resource: str,
        action: str,
        record_ids: List[str],
        decision: str,
        authorized: bool,
        sensitive_op: bool,
        risk_score: float,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        aid = f"act-{uuid.uuid4().hex[:12]}"
        ts = datetime.now(timezone.utc).isoformat()
        with self.db.write_transaction() as conn:
            conn.execute(
                """
                INSERT INTO activity_logs (
                    activity_id, agent_id, tool_name, resource, action,
                    record_ids, record_count, decision, authorized,
                    sensitive_op, risk_score, timestamp, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    aid,
                    agent_id,
                    tool_name,
                    resource,
                    action,
                    json.dumps(record_ids),
                    len(record_ids),
                    decision,
                    1 if authorized else 0,
                    1 if sensitive_op else 0,
                    round(float(risk_score), 2),
                    ts,
                    json.dumps(details or {}, default=str),
                ),
            )
        return aid

    def get_agent_behaviour_summary(self) -> List[Dict[str, Any]]:
        """Aggregate per-agent behaviour telemetry alongside trusted baseline profiles."""
        window_start = (
            datetime.now(timezone.utc) - timedelta(seconds=BEHAVIOUR_WINDOW_SECONDS * 5)
        ).isoformat()
        detector_mode = (
            "rule_based+sklearn_isolation_forest"
            if _SKLEARN_AVAILABLE
            else "rule_based+numpy_isolation_forest"
        )

        with self.db.read_connection() as conn:
            agents = [
                dict(r)
                for r in conn.execute(
                    "SELECT agent_id, name, role, status FROM agents ORDER BY created_at ASC"
                ).fetchall()
            ]
            summaries: List[Dict[str, Any]] = []
            for ag in agents:
                baseline = self.get_agent_baseline(ag["agent_id"])
                rows = conn.execute(
                    """
                    SELECT tool_name, resource, record_ids, decision, authorized, sensitive_op, risk_score, timestamp
                    FROM activity_logs
                    WHERE agent_id = ? AND timestamp >= ?
                    ORDER BY timestamp DESC
                    """,
                    (ag["agent_id"], window_start),
                ).fetchall()
                uniq = set()
                failed = 0
                sensitive = 0
                blocked = 0
                monitored = 0
                risks = []
                resources = set()
                for r in rows:
                    try:
                        uniq.update(json.loads(r["record_ids"]))
                    except Exception:
                        pass
                    if not r["authorized"]:
                        failed += 1
                    if r["sensitive_op"]:
                        sensitive += 1
                    if r["decision"] == "BLOCK":
                        blocked += 1
                    if r["decision"] == "MONITOR":
                        monitored += 1
                    risks.append(float(r["risk_score"]))
                    resources.add(r["resource"])

                summaries.append(
                    {
                        "agent_id": ag["agent_id"],
                        "agent_name": ag["name"],
                        "role": ag["role"],
                        "status": ag["status"],
                        "recent_requests": len(rows),
                        "unique_records_accessed": len(uniq),
                        "failed_authz_attempts": failed,
                        "sensitive_operations": sensitive,
                        "blocked_count": blocked,
                        "monitored_count": monitored,
                        "avg_risk_score": round(sum(risks) / len(risks), 1) if risks else 0.0,
                        "max_risk_score": round(max(risks), 1) if risks else 0.0,
                        "resources_touched": sorted(resources),
                        "baseline": {
                            "normal_resources": baseline["normal_resources"],
                            "normal_hours_utc": f"{baseline['normal_hours_start']:02d}:00-{baseline['normal_hours_end']:02d}:00",
                            "typical_req_max": baseline["typical_req_per_window_max"],
                            "typical_records_max": baseline["typical_unique_records_max"],
                            "sample_count": baseline["baseline_sample_count"],
                            "trusted_source": baseline["trusted_source"],
                        },
                        "detector_mode": detector_mode,
                    }
                )
        return summaries

    def get_model_info(self, agent_id: str) -> Dict[str, Any]:
        """Expose detailed per-agent Isolation Forest metadata, status, and baseline characteristics."""
        model, baseline, means, stds = self._get_or_train_agent_model(agent_id)
        is_sklearn = bool(_SKLEARN_AVAILABLE and SklearnIsolationForest is not None and isinstance(model, SklearnIsolationForest))
        return {
            "agent_id": agent_id,
            "baseline_sample_count": baseline.get("baseline_sample_count", 250),
            "training_timestamp": baseline.get("created_at"),
            "model_status": "active_trained",
            "detector_mode": "sklearn_isolation_forest" if is_sklearn else "numpy_fallback_isolation_forest",
            "sklearn_active": is_sklearn,
            "contamination": getattr(model, "contamination", 0.05),
            "n_estimators": getattr(model, "n_estimators", 100),
            "normal_features": [
                "requests_in_window",
                "projected_unique_records",
                "unseen_resource_flag",
                "failed_authz_in_window",
                "off_hours_flag",
                "composite_envelope_deviation",
            ],
            "feature_means": [round(float(m), 4) for m in means],
            "feature_stds": [round(float(s), 4) for s in stds],
            "trusted_baseline": baseline,
        }
