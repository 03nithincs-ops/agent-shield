"""
Unit and Integration Test for Isolation Forest ML Service
"""
import os
import sys

# Ensure parent directory is on python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.model import service_instance, MODEL_FILE
from app.training import train_isolation_forest, generate_synthetic_training_data
from app.preprocessing import extract_feature_vector, FEATURE_NAMES

def test_ml_pipeline():
    print("--- [1/5] Testing Synthetic Training Data Generator ---")
    data = generate_synthetic_training_data(n_samples=200)
    assert len(data) == 200
    assert list(data.columns) == FEATURE_NAMES
    print(f"  -> Generated {len(data)} training rows with features: {FEATURE_NAMES}")

    print("\n--- [2/5] Testing Model Training & Joblib Save ---")
    model = train_isolation_forest(data=data, n_estimators=50, model_save_path=MODEL_FILE)
    assert os.path.exists(MODEL_FILE), "Joblib model file was not saved!"
    print(f"  -> Successfully trained and verified model saved at {MODEL_FILE}")

    print("\n--- [3/5] Testing Model Info ---")
    info = service_instance.get_info()
    print("  -> Model metadata:", info)
    assert info["algorithm"] == "scikit-learn IsolationForest"

    print("\n--- [4/5] Testing Normal Behavior Prediction ---")
    normal_features = {
        "api_request_frequency": 3.0,
        "denied_requests_count": 0.0,
        "failed_operations_count": 0.0,
        "sensitive_operations_ratio": 0.05,
        "permission_violations_count": 0.0,
        "unusual_access_time": 0.0,
        "average_risk_score": 15.0,
        "tool_calls_count": 2.0
    }
    pred_normal = service_instance.predict_single(normal_features)
    print("  -> Normal prediction output:", pred_normal)
    assert pred_normal["is_anomaly"] is False
    assert pred_normal["anomaly_score"] < 0.5

    print("\n--- [5/5] Testing Extreme Anomalous Behavior Prediction ---")
    anom_features = {
        "api_request_frequency": 48.0,
        "denied_requests_count": 8.0,
        "failed_operations_count": 7.0,
        "sensitive_operations_ratio": 0.95,
        "permission_violations_count": 6.0,
        "unusual_access_time": 1.0,
        "average_risk_score": 88.0,
        "tool_calls_count": 50.0
    }
    pred_anom = service_instance.predict_single(anom_features)
    print("  -> Anomaly prediction output:", pred_anom)
    assert pred_anom["is_anomaly"] is True
    assert pred_anom["anomaly_score"] >= 0.5
    assert len(pred_anom["explanation"]) > 0

    print("\n>>> ALL ML PIPELINE TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    test_ml_pipeline()
