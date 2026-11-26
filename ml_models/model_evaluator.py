"""Model Evaluator and Explainable Risk Contributor for AGENT SHIELD."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
import numpy as np


class AnomalyEvaluator:
    """Translates raw Isolation Forest output into calibrated explainable risk factors."""

    @staticmethod
    def evaluate(
        model: Any,
        feature_vec: np.ndarray,
    ) -> Tuple[bool, float, float, List[str]]:
        """Evaluate inference vector against Isolation Forest.
        
        Returns:
            (is_anomaly, anomaly_score, ml_severity_points, explainable_reasons)
        """
        pred = int(model.predict(feature_vec)[0])  # -1 = anomaly, 1 = normal
        raw_df = float(model.decision_function(feature_vec)[0])
        anomaly_score = round(raw_df, 4)
        is_anomaly = (pred == -1)

        ml_severity_points = 0.0
        reasons: List[str] = []

        if is_anomaly:
            # Deterministic, non-probabilistic 0-30 risk score contribution
            ml_severity_points = round(min(30.0, max(12.0, abs(anomaly_score) * 140.0 + 10.0)), 1)
            reasons.append(
                f"Per-agent Scikit-learn Isolation Forest flagged statistical anomaly "
                f"(decision_score={anomaly_score}, +{ml_severity_points} risk points; operational index, not attack probability)."
            )

        return is_anomaly, anomaly_score, ml_severity_points, reasons
