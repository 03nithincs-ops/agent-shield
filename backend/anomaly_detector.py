"""
AGENT SHIELD - Isolation Forest Anomaly Detector
Detects unusual AI agent behaviour using Scikit-learn Isolation Forest.
"""

import numpy as np
import logging
import pickle
import os
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "isolation_forest.pkl")

FEATURE_NAMES = [
    "requests_per_minute",
    "resources_accessed",
    "failed_attempts",
    "access_frequency",
    "unique_resources",
    "off_hours_requests",
    "sensitive_resource_access"
]

_model = None
_scaler = None
_model_metadata: Dict[str, Any] = {}
_model_loaded = False


def _generate_training_data(n_samples: int = 2500) -> np.ndarray:
    """
    Generate synthetic normal agent behaviour training data.
    Simulates expected baseline activities across various agent types:
    - Customer Support: Low RPM, read-focused, minimal failures
    - Analytics: Medium bursts, report-focused, rare failures
    - Financial: Steady, transaction-focused, strictly bounded
    """
    np.random.seed(42)
    
    # 70% standard daytime normal activity
    n_standard = int(n_samples * 0.70)
    standard_rpm = np.random.exponential(scale=4.0, size=n_standard).clip(0.1, 20.0)
    standard_res = np.random.randint(1, 6, size=n_standard).astype(float)
    standard_fails = np.random.poisson(lam=0.3, size=n_standard).clip(0, 3).astype(float)
    standard_freq = np.random.exponential(scale=2.5, size=n_standard).clip(0.1, 15.0)
    standard_uniq = np.random.randint(1, 4, size=n_standard).astype(float)
    standard_off = np.random.poisson(lam=0.2, size=n_standard).clip(0, 2).astype(float)
    standard_sens = np.random.binomial(n=1, p=0.15, size=n_standard).astype(float)
    
    # 25% active batch / scheduled normal jobs (higher volume, still normal)
    n_batch = int(n_samples * 0.25)
    batch_rpm = np.random.normal(loc=12.0, scale=3.0, size=n_batch).clip(4.0, 22.0)
    batch_res = np.random.randint(2, 8, size=n_batch).astype(float)
    batch_fails = np.random.poisson(lam=0.5, size=n_batch).clip(0, 4).astype(float)
    batch_freq = np.random.normal(loc=10.0, scale=2.5, size=n_batch).clip(3.0, 18.0)
    batch_uniq = np.random.randint(2, 5, size=n_batch).astype(float)
    batch_off = np.random.poisson(lam=0.8, size=n_batch).clip(0, 4).astype(float)
    batch_sens = np.random.binomial(n=1, p=0.25, size=n_batch).astype(float)
    
    # 5% slight variations
    n_var = n_samples - n_standard - n_batch
    var_rpm = np.random.exponential(scale=6.0, size=n_var).clip(0.5, 24.0)
    var_res = np.random.randint(1, 7, size=n_var).astype(float)
    var_fails = np.random.poisson(lam=0.8, size=n_var).clip(0, 4).astype(float)
    var_freq = np.random.exponential(scale=4.0, size=n_var).clip(0.5, 18.0)
    var_uniq = np.random.randint(1, 5, size=n_var).astype(float)
    var_off = np.random.poisson(lam=1.5, size=n_var).clip(0, 5).astype(float)
    var_sens = np.random.binomial(n=1, p=0.30, size=n_var).astype(float)
    
    rpm = np.concatenate([standard_rpm, batch_rpm, var_rpm])
    res = np.concatenate([standard_res, batch_res, var_res])
    fails = np.concatenate([standard_fails, batch_fails, var_fails])
    freq = np.concatenate([standard_freq, batch_freq, var_freq])
    uniq = np.concatenate([standard_uniq, batch_uniq, var_uniq])
    off = np.concatenate([standard_off, batch_off, var_off])
    sens = np.concatenate([standard_sens, batch_sens, var_sens])
    
    return np.column_stack([rpm, res, fails, freq, uniq, off, sens])


def train_model(
    n_samples: int = 2500,
    contamination: float = 0.08,
    n_estimators: int = 200
) -> bool:
    """Train and persist the Isolation Forest model."""
    global _model, _scaler, _model_loaded, _model_metadata
    
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import sklearn
        
        logger.info(f"Training Isolation Forest model (samples={n_samples}, contamination={contamination}, estimators={n_estimators})...")
        training_data = _generate_training_data(n_samples)
        
        _scaler = StandardScaler()
        scaled_data = _scaler.fit_transform(training_data)
        
        _model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        _model.fit(scaled_data)
        
        _model_metadata = {
            "n_samples": n_samples,
            "contamination": contamination,
            "n_estimators": n_estimators,
            "features": FEATURE_NAMES,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "sklearn_version": sklearn.__version__,
            "model_type": "IsolationForest"
        }
        
        _model_loaded = True
        
        # Persist model and metadata
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump({
                "model": _model,
                "scaler": _scaler,
                "metadata": _model_metadata
            }, f)
        
        logger.info("Isolation Forest model trained and successfully saved.")
        return True
    
    except Exception as e:
        logger.error(f"Model training error: {e}", exc_info=True)
        _model_loaded = False
        return False


def load_model() -> bool:
    """Load persisted model from disk."""
    global _model, _scaler, _model_loaded, _model_metadata
    
    if _model_loaded and _model is not None:
        return True
    
    try:
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                data = pickle.load(f)
                _model = data["model"]
                _scaler = data["scaler"]
                _model_metadata = data.get("metadata", {
                    "model_type": "IsolationForest",
                    "features": FEATURE_NAMES
                })
                _model_loaded = True
                logger.info("Isolation Forest model loaded from disk.")
                return True
    except Exception as e:
        logger.warning(f"Could not load model from disk: {e}")
    
    # Train fresh if loading fails
    return train_model()


def detect_anomaly(
    requests_per_minute: float,
    resources_accessed: int,
    failed_attempts: int,
    access_frequency: float,
    unique_resources: int,
    off_hours_requests: int = 0,
    sensitive_resource_access: int = 0
) -> Dict[str, Any]:
    """
    Classify activity as NORMAL or ANOMALOUS using Isolation Forest.
    
    Returns dict with:
    - classification: NORMAL | ANOMALOUS | UNAVAILABLE
    - anomaly_score: float (-1 to 1; lower = more anomalous)
    - explanation: human-readable explanation
    - features_used: dict of input features
    """
    features = {
        "requests_per_minute": float(requests_per_minute),
        "resources_accessed": int(resources_accessed),
        "failed_attempts": int(failed_attempts),
        "access_frequency": float(access_frequency),
        "unique_resources": int(unique_resources),
        "off_hours_requests": int(off_hours_requests),
        "sensitive_resource_access": int(sensitive_resource_access)
    }
    
    try:
        if not _model_loaded or _model is None or _scaler is None:
            if not load_model():
                return {
                    "classification": "UNAVAILABLE",
                    "anomaly_score": 0.0,
                    "explanation": "Anomaly detection model unavailable. Authorization decisions are unaffected.",
                    "features_used": features
                }
        
        feature_array = np.array([[
            features["requests_per_minute"],
            features["resources_accessed"],
            features["failed_attempts"],
            features["access_frequency"],
            features["unique_resources"],
            features["off_hours_requests"],
            features["sensitive_resource_access"]
        ]])
        
        scaled = _scaler.transform(feature_array)
        prediction = _model.predict(scaled)[0]  # 1=normal, -1=anomalous
        raw_score = _model.score_samples(scaled)[0]  # Lower = more anomalous
        
        is_anomalous = (prediction == -1)
        
        # Build explainable contributing factors
        anomaly_flags = []
        if requests_per_minute > 25.0:
            anomaly_flags.append(f"Elevated request rate ({requests_per_minute:.1f} req/min)")
        if failed_attempts > 5:
            anomaly_flags.append(f"Repeated authorization failures ({failed_attempts} denials)")
        if resources_accessed > 10:
            anomaly_flags.append(f"Broad resource footprint ({resources_accessed} resources)")
        if unique_resources > 6:
            anomaly_flags.append(f"High resource variety ({unique_resources} unique targets)")
        if off_hours_requests > 8:
            anomaly_flags.append(f"Unusual temporal activity ({off_hours_requests} off-hours events)")
        if sensitive_resource_access > 2:
            anomaly_flags.append(f"Access targeting restricted simulated resources ({sensitive_resource_access} attempts)")
        
        if is_anomalous:
            if anomaly_flags:
                explanation = "ANOMALOUS behaviour detected. Contributing factors: " + "; ".join(anomaly_flags)
            else:
                explanation = "ANOMALOUS behaviour detected based on combined multivariate divergence from normal profile."
        else:
            explanation = "Activity appears NORMAL based on current activity profile."
            if anomaly_flags:
                explanation += " Note: some elevated indicators observed: " + "; ".join(anomaly_flags)
        
        return {
            "classification": "ANOMALOUS" if is_anomalous else "NORMAL",
            "anomaly_score": round(float(raw_score), 4),
            "explanation": explanation,
            "features_used": features
        }
    
    except Exception as e:
        logger.error(f"Anomaly detection error: {e}", exc_info=True)
        return {
            "classification": "UNAVAILABLE",
            "anomaly_score": 0.0,
            "explanation": "Anomaly detection temporarily unavailable. Authorization decisions are independent and unaffected.",
            "features_used": features
        }


def evaluate_model() -> Dict[str, Any]:
    """
    Evaluate the loaded model on synthetic validation datasets:
    - Normal baseline test cases
    - Extreme anomalous test cases
    Returns validation performance summary metrics.
    """
    if not _model_loaded:
        load_model()
        
    np.random.seed(101)
    
    # 200 normal test cases
    normal_test = np.column_stack([
        np.random.exponential(scale=4.0, size=200).clip(0.1, 15.0),
        np.random.randint(1, 5, size=200).astype(float),
        np.random.poisson(lam=0.2, size=200).clip(0, 2).astype(float),
        np.random.exponential(scale=2.5, size=200).clip(0.1, 12.0),
        np.random.randint(1, 4, size=200).astype(float),
        np.random.poisson(lam=0.3, size=200).clip(0, 2).astype(float),
        np.random.binomial(n=1, p=0.10, size=200).astype(float)
    ])
    
    # 100 outlier test cases (severe anomalies)
    anomaly_test = np.column_stack([
        np.random.uniform(50.0, 120.0, size=100),
        np.random.uniform(20.0, 50.0, size=100),
        np.random.uniform(15.0, 45.0, size=100),
        np.random.uniform(40.0, 100.0, size=100),
        np.random.uniform(10.0, 25.0, size=100),
        np.random.uniform(15.0, 50.0, size=100),
        np.random.uniform(8.0, 20.0, size=100)
    ])
    
    norm_scaled = _scaler.transform(normal_test)
    anom_scaled = _scaler.transform(anomaly_test)
    
    norm_preds = _model.predict(norm_scaled)  # 1 = normal
    anom_preds = _model.predict(anom_scaled)  # -1 = anomaly
    
    norm_acc = float(np.mean(norm_preds == 1))
    anom_detect_rate = float(np.mean(anom_preds == -1))
    
    avg_norm_score = float(np.mean(_model.score_samples(norm_scaled)))
    avg_anom_score = float(np.mean(_model.score_samples(anom_scaled)))
    
    return {
        "normal_accuracy": round(norm_acc, 4),
        "anomaly_detection_rate": round(anom_detect_rate, 4),
        "avg_normal_score": round(avg_norm_score, 4),
        "avg_anomaly_score": round(avg_anom_score, 4),
        "samples_evaluated": 300
    }


def get_model_status() -> dict:
    """Return current model status and training metadata."""
    return {
        "loaded": _model_loaded,
        "model_path": MODEL_PATH,
        "model_exists_on_disk": os.path.exists(MODEL_PATH),
        "model_type": _model_metadata.get("model_type", "IsolationForest" if _model_loaded else "Not loaded"),
        "features": FEATURE_NAMES,
        "metadata": _model_metadata
    }
