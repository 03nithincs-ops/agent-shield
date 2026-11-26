"""
Feature Engineering and Preprocessing Pipeline for Agent Shield Isolation Forest ML.
Ensures strict identical feature ordering and transformation across training and inference.
"""
from typing import List, Dict, Any
import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "api_request_frequency",
    "denied_requests_count",
    "failed_operations_count",
    "sensitive_operations_ratio",
    "permission_violations_count",
    "unusual_access_time",
    "average_risk_score",
    "tool_calls_count"
]

def extract_feature_vector(features_dict: Dict[str, Any]) -> List[float]:
    """
    Extracts features in exact strict order required by the model.
    """
    return [
        float(features_dict.get("api_request_frequency", 1.0)),
        float(features_dict.get("denied_requests_count", 0.0)),
        float(features_dict.get("failed_operations_count", 0.0)),
        float(features_dict.get("sensitive_operations_ratio", 0.0)),
        float(features_dict.get("permission_violations_count", 0.0)),
        float(features_dict.get("unusual_access_time", 0.0)),
        float(features_dict.get("average_risk_score", 20.0)),
        float(features_dict.get("tool_calls_count", 1.0))
    ]

def features_to_dataframe(feature_vectors: List[List[float]]) -> pd.DataFrame:
    """
    Converts list of feature vectors into named DataFrame.
    """
    return pd.DataFrame(feature_vectors, columns=FEATURE_NAMES)
