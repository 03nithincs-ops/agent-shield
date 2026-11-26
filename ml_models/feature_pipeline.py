"""Feature Extraction and Normalization Pipeline for AGENT SHIELD Behaviour Telemetry."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import numpy as np


class BehaviourFeaturePipeline:
    """Extracts and normalizes the 5 required behavioural features:
    1. Request volume and frequency
    2. Number of unique records accessed
    3. Previously unseen resource categories
    4. Failed permission attempts
    5. Off-hours activity
    """

    FEATURE_NAMES = [
        "requests_in_window",
        "projected_unique_records",
        "unseen_resource_flag",
        "failed_authz_in_window",
        "off_hours_flag",
        "composite_envelope_deviation",
    ]

    @staticmethod
    def transform_vector(
        raw_vec: np.ndarray,
        means: np.ndarray,
        stds: np.ndarray,
    ) -> np.ndarray:
        """Standardize raw feature vector and compute envelope deviation consistently."""
        scaled_vec = (raw_vec - means) / stds
        excess_vec = np.maximum(0.0, np.abs(scaled_vec) - 1.5)
        dev_vec = np.sum(excess_vec, axis=1, keepdims=True)
        return np.hstack([scaled_vec, dev_vec])
