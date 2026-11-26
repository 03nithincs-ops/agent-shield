"""
Isolation Forest Model Wrapper & Prediction Engine
"""
import os
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, Any, Tuple
from .preprocessing import FEATURE_NAMES, extract_feature_vector
from .training import train_isolation_forest

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_FILE = os.path.join(MODEL_DIR, "isolation_forest.joblib")

class IsolationForestService:
    def __init__(self):
        self.model = None
        self.metadata = {}
        self.load_or_train()

    def load_or_train(self):
        """Loads saved Joblib model or trains a new baseline."""
        if os.path.exists(MODEL_FILE):
            try:
                data = joblib.load(MODEL_FILE)
                self.model = data["model"]
                self.metadata = {k: v for k, v in data.items() if k != "model"}
                print(f"[ML Service] Loaded Isolation Forest model from {MODEL_FILE}")
                return
            except Exception as e:
                print(f"[ML Service] Error loading saved model ({e}). Retraining...")

        print("[ML Service] No saved model found. Training initial Isolation Forest baseline...")
        self.model = train_isolation_forest(model_save_path=MODEL_FILE)
        self.metadata = {
            "n_estimators": 100,
            "contamination": 0.08,
            "training_sample_count": 1500,
            "data_source": "synthetic_representative_baseline",
            "trained_at": datetime.utcnow().isoformat()
        }

    def predict_single(self, features_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs Isolation Forest prediction on a single feature vector.
        """
        if self.model is None:
            self.load_or_train()

        vec = extract_feature_vector(features_dict)
        X = pd.DataFrame([vec], columns=FEATURE_NAMES)

        # Scikit-learn prediction: 1 for inlier (nominal), -1 for outlier (anomaly)
        pred = int(self.model.predict(X)[0])
        is_anomaly = bool(pred == -1)

        # Decision score: negative for anomaly, positive for normal
        raw_score = float(self.model.decision_function(X)[0])

        # Normalize score into [0.0, 1.0] range (0 = very normal, 1 = extreme anomaly)
        # Logistic sigmoid transformation centered near boundary
        normalized_score = float(1.0 / (1.0 + np.exp(raw_score * 8.0)))
        normalized_score = max(0.0, min(1.0, round(normalized_score, 4)))

        # Generate explainable breakdown
        reasons = []
        if features_dict.get("api_request_frequency", 0) > 15:
            reasons.append(f"Excessive API rate ({features_dict['api_request_frequency']} req/m)")
        if features_dict.get("denied_requests_count", 0) >= 3:
            reasons.append(f"Multiple denials ({features_dict['denied_requests_count']} in window)")
        if features_dict.get("sensitive_operations_ratio", 0) > 0.5:
            reasons.append(f"High sensitive resource ratio ({features_dict['sensitive_operations_ratio']:.1%})")
        if features_dict.get("unusual_access_time", 0) == 1.0:
            reasons.append("Off-hours operation (22:00-06:00)")
        if features_dict.get("average_risk_score", 0) >= 60:
            reasons.append(f"Elevated historical risk score ({features_dict['average_risk_score']})")

        explanation = "; ".join(reasons) if reasons else ("Behavior strictly aligns with learned baseline" if not is_anomaly else "Subtle multivariate deviation in tool/frequency pattern")

        return {
            "is_anomaly": is_anomaly,
            "prediction": pred,
            "anomaly_score": normalized_score,
            "raw_decision_score": round(raw_score, 4),
            "explanation": explanation,
            "input_features": {k: float(v) for k, v in zip(FEATURE_NAMES, vec)}
        }

    def get_info(self) -> Dict[str, Any]:
        return {
            "model_name": "AgentShield_IsolationForest",
            "model_version": "1.0.0",
            "algorithm": "scikit-learn IsolationForest",
            "n_estimators": self.metadata.get("n_estimators", 100),
            "contamination": self.metadata.get("contamination", 0.08),
            "feature_names": FEATURE_NAMES,
            "training_sample_count": self.metadata.get("training_sample_count", 1500),
            "data_source": self.metadata.get("data_source", "synthetic_representative_baseline"),
            "last_trained": self.metadata.get("trained_at", datetime.utcnow().isoformat())
        }

# Global singleton
service_instance = IsolationForestService()
