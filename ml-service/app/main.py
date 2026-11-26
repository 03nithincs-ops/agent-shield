"""
FastAPI Microservice for Isolation Forest Anomaly Detection
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uvicorn
import os

from .schemas import (
    ActivityFeatures,
    PredictionResponse,
    BatchPredictionRequest,
    BatchPredictionResponse,
    ModelTrainingRequest,
    ModelInfoResponse
)
from .model import service_instance, MODEL_FILE
from .training import train_isolation_forest

app = FastAPI(
    title="Agent Shield ML Anomaly Detection Service",
    description="Isolation Forest ML inference & training engine for autonomous AI agent cybersecurity monitoring",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    """Health check endpoint verified by Node.js backend."""
    return {
        "status": "healthy",
        "service": "Agent Shield Isolation Forest ML Service",
        "model_loaded": service_instance.model is not None,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/model-info", response_model=ModelInfoResponse)
def get_model_info():
    """Retrieve active model parameters and training provenance."""
    return service_instance.get_info()

@app.post("/predict", response_model=PredictionResponse)
def predict_anomaly(features: ActivityFeatures):
    """
    Run Isolation Forest anomaly detection on activity feature vector.
    Returns anomaly prediction, normalized score (0-1), and explainable breakdown.
    """
    try:
        result = service_instance.predict_single(features.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@app.post("/batch-predict", response_model=BatchPredictionResponse)
def batch_predict(batch: BatchPredictionRequest):
    """Batch anomaly prediction across multiple activity vectors."""
    try:
        results = [service_instance.predict_single(f.dict()) for f in batch.records]
        return {
            "count": len(results),
            "predictions": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch prediction failed: {str(e)}")

@app.post("/train")
def train_model(req: ModelTrainingRequest):
    """
    Trigger Isolation Forest model training and save via Joblib.
    """
    try:
        model = train_isolation_forest(
            n_estimators=req.n_estimators,
            contamination=req.contamination,
            random_state=req.random_state,
            model_save_path=MODEL_FILE
        )
        service_instance.load_or_train()
        return {
            "success": True,
            "message": "Isolation Forest model retrained and loaded successfully.",
            "info": service_instance.get_info()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model training failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8001, reload=False)
