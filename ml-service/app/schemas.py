from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class ActivityFeatures(BaseModel):
    api_request_frequency: float = Field(default=1.0, ge=0.0, description="Requests per minute window")
    denied_requests_count: float = Field(default=0.0, ge=0.0, description="Count of denied requests in last 5m")
    failed_operations_count: float = Field(default=0.0, ge=0.0, description="Failed operational calls")
    sensitive_operations_ratio: float = Field(default=0.0, ge=0.0, le=1.0, description="Ratio of sensitive operations")
    permission_violations_count: float = Field(default=0.0, ge=0.0, description="Permission violations recorded")
    unusual_access_time: float = Field(default=0.0, ge=0.0, le=1.0, description="1.0 if outside 06:00-22:00, else 0.0")
    average_risk_score: float = Field(default=20.0, ge=0.0, le=100.0, description="Average historical risk score")
    tool_calls_count: float = Field(default=1.0, ge=0.0, description="Total tool invocations")

class PredictionResponse(BaseModel):
    is_anomaly: bool = Field(description="True if classified as an anomaly, False if nominal")
    prediction: int = Field(description="-1 for anomaly, 1 for nominal")
    anomaly_score: float = Field(description="Normalized anomaly score between 0.0 (normal) and 1.0 (anomalous)")
    raw_decision_score: float = Field(description="Raw scikit-learn decision function score")
    explanation: str = Field(description="Human-readable breakdown of anomaly indicators")
    input_features: Dict[str, float]

class BatchPredictionRequest(BaseModel):
    records: List[ActivityFeatures]

class BatchPredictionResponse(BaseModel):
    count: int
    predictions: List[PredictionResponse]

class ModelTrainingRequest(BaseModel):
    n_estimators: Optional[int] = Field(default=100, ge=10, le=500)
    contamination: Optional[float] = Field(default=0.08, ge=0.01, le=0.4)
    random_state: Optional[int] = Field(default=42)
    use_synthetic_data: Optional[bool] = Field(default=True, description="Generate synthetic baseline if no real data")

class ModelInfoResponse(BaseModel):
    model_name: str
    model_version: str
    algorithm: str
    n_estimators: int
    contamination: float
    feature_names: List[str]
    training_sample_count: int
    data_source: str
    last_trained: str
