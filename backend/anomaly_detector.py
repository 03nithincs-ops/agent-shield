"""Anomaly Detector wrapper linking backend security gateway with ml_models."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from ml_models.isolation_forest import AgentIsolationForest, _SKLEARN_AVAILABLE
from ml_models.baseline_generator import generate_normal_baseline, agent_seed
from ml_models.feature_pipeline import BehaviourFeaturePipeline
from ml_models.model_evaluator import AnomalyEvaluator


class AnomalyDetector:
    """Interface connecting backend behaviour telemetry to the per-agent Isolation Forest."""

    def __init__(self, agent_id: str, baseline_sample_count: int = 250, req_max: int = 4, rec_max: int = 8) -> None:
        self.agent_id = agent_id
        self.baseline_sample_count = baseline_sample_count
        self.req_max = req_max
        self.rec_max = rec_max
        
        # Train per-agent model on trusted baseline
        X_train, self.means, self.stds = generate_normal_baseline(
            agent_id=self.agent_id,
            req_max=self.req_max,
            rec_max=self.rec_max,
            sample_count=self.baseline_sample_count,
        )
        self.model = AgentIsolationForest(contamination=0.05, random_state=42)
        self.model.fit(X_train)

    def evaluate_vector(self, raw_vec: np.ndarray) -> Tuple[bool, float, float, List[str]]:
        """Normalize feature vector and evaluate using Isolation Forest."""
        feat_vec = BehaviourFeaturePipeline.transform_vector(raw_vec, self.means, self.stds)
        return AnomalyEvaluator.evaluate(self.model, feat_vec)

    @property
    def is_sklearn(self) -> bool:
        return self.model.is_sklearn
