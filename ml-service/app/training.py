"""
Model Training & Synthetic Baseline Dataset Generator
"""
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
import joblib
import os
from .preprocessing import FEATURE_NAMES

def generate_synthetic_training_data(n_samples: int = 1500, random_state: int = 42) -> pd.DataFrame:
    """
    Generates representative baseline behavior telemetry for AI agents.
    Clearly documented as synthetic training baseline.
    """
    np.random.seed(random_state)
    
    # 92% Nominal agent traffic patterns
    n_nominal = int(n_samples * 0.92)
    nominal_api_freq = np.random.gamma(shape=2.0, scale=2.5, size=n_nominal) # ~5 req/min
    nominal_denials = np.random.poisson(lam=0.1, size=n_nominal)
    nominal_failed = np.random.poisson(lam=0.15, size=n_nominal)
    nominal_sensitive = np.random.beta(a=0.5, b=5.0, size=n_nominal)
    nominal_violations = np.random.poisson(lam=0.05, size=n_nominal)
    nominal_off_hours = np.random.binomial(n=1, p=0.08, size=n_nominal)
    nominal_risk = np.random.normal(loc=18.0, scale=8.0, size=n_nominal)
    nominal_risk = np.clip(nominal_risk, 0.0, 45.0)
    nominal_tools = np.random.gamma(shape=2.0, scale=3.0, size=n_nominal)

    # 8% Anomalous traffic patterns (injections, runaway loops, privilege escalation)
    n_anomalies = n_samples - n_nominal
    anom_api_freq = np.random.uniform(22.0, 60.0, size=n_anomalies)
    anom_denials = np.random.poisson(lam=4.5, size=n_anomalies)
    anom_failed = np.random.poisson(lam=5.0, size=n_anomalies)
    anom_sensitive = np.random.uniform(0.6, 1.0, size=n_anomalies)
    anom_violations = np.random.poisson(lam=3.5, size=n_anomalies)
    anom_off_hours = np.random.binomial(n=1, p=0.65, size=n_anomalies)
    anom_risk = np.random.normal(loc=72.0, scale=12.0, size=n_anomalies)
    anom_risk = np.clip(anom_risk, 50.0, 100.0)
    anom_tools = np.random.uniform(15.0, 45.0, size=n_anomalies)

    df = pd.DataFrame({
        "api_request_frequency": np.concatenate([nominal_api_freq, anom_api_freq]),
        "denied_requests_count": np.concatenate([nominal_denials, anom_denials]),
        "failed_operations_count": np.concatenate([nominal_failed, anom_failed]),
        "sensitive_operations_ratio": np.concatenate([nominal_sensitive, anom_sensitive]),
        "permission_violations_count": np.concatenate([nominal_violations, anom_violations]),
        "unusual_access_time": np.concatenate([nominal_off_hours, anom_off_hours]),
        "average_risk_score": np.concatenate([nominal_risk, anom_risk]),
        "tool_calls_count": np.concatenate([nominal_tools, anom_tools])
    })

    return df[FEATURE_NAMES]

def train_isolation_forest(
    data: pd.DataFrame = None,
    n_estimators: int = 100,
    contamination: float = 0.08,
    random_state: int = 42,
    model_save_path: str = None
) -> IsolationForest:
    """
    Fits scikit-learn Isolation Forest on baseline activity data.
    """
    if data is None:
        data = generate_synthetic_training_data(n_samples=1500, random_state=random_state)
        data_source = "synthetic_representative_baseline"
    else:
        data_source = "provided_dataset"

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(data[FEATURE_NAMES])

    if model_save_path:
        os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
        joblib.dump({
            "model": model,
            "feature_names": FEATURE_NAMES,
            "n_estimators": n_estimators,
            "contamination": contamination,
            "training_sample_count": len(data),
            "data_source": data_source,
            "trained_at": datetime.utcnow().isoformat()
        }, model_save_path)

    return model
