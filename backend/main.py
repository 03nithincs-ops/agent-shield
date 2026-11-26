"""
AGENT SHIELD - FastAPI Main Application
"""

import logging
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .database import init_database
from .anomaly_detector import load_model
from .routes.agents import router as agents_router
from .routes.authorization import router as auth_router
from .routes.analytics import router as analytics_router
from .routes.testing import router as testing_router
from .routes.chat import router as chat_router

# Initialize FastAPI app
app = FastAPI(
    title="Agent Shield API",
    description="AI Agent Authorization Monitoring and Permission Enforcement System",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS for Streamlit frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please check server logs."}
    )

# Request size limit middleware
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    max_size = 1_048_576  # 1MB
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_size:
        return JSONResponse(status_code=413, content={"detail": "Request too large."})
    return await call_next(request)


# Include routers
app.include_router(agents_router)
app.include_router(auth_router)
app.include_router(analytics_router)
app.include_router(testing_router)
app.include_router(chat_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database and ML model on startup."""
    logger.info("=" * 60)
    logger.info("AGENT SHIELD - Starting up...")
    logger.info("=" * 60)
    
    try:
        init_database()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
    
    try:
        success = load_model()
        if success:
            logger.info("✅ Isolation Forest model loaded")
        else:
            logger.warning("⚠️  ML model not loaded - anomaly detection unavailable")
    except Exception as e:
        logger.warning(f"⚠️  ML model loading failed: {e}")
    
    logger.info("🛡️  Agent Shield API is ready!")


@app.get("/")
async def root():
    return {
        "name": "Agent Shield API",
        "tagline": "Every Agent. Every Action. Under Control.",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    from .database import get_dashboard_stats
    from .anomaly_detector import get_model_status
    
    try:
        stats = get_dashboard_stats()
        db_ok = True
    except Exception:
        stats = {}
        db_ok = False
    
    model_status = get_model_status()
    
    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "error",
        "ml_model": "loaded" if model_status["loaded"] else "not_loaded",
        "stats": stats
    }


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
