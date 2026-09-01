"""FastAPI entry point. Run: uvicorn main:app --reload --port 8000"""
from __future__ import annotations
import time
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from src.models.log_models import LogBundle
from src.models.alert_models import AnalysisResponse
from src.pipeline import run_pipeline

app = FastAPI(
    title="Threat Pipeline API",
    description="Zeek log threat detection and incident correlation service.",
    version="1.0.0",
)


@app.middleware("http")
async def add_process_time(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Process-Time-Ms"] = f"{(time.perf_counter()-start)*1000:.2f}"
    return response


@app.exception_handler(Exception)
async def global_exc(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": str(exc), "type": type(exc).__name__, "path": str(request.url)},
    )


@app.get("/", tags=["Ops"])
async def root():
    return {
        "service": "Threat Pipeline API",
        "version": "1.0.0",
        "status": "online",
        "docs": "/docs",
        "health": "/health",
        "analyze": "POST /analyze"
    }


@app.get("/health", tags=["Ops"])
async def health():
    return {"status": "ok", "service": "threat-pipeline", "version": "1.0.0"}


@app.post("/analyze", response_model=AnalysisResponse, tags=["Analysis"])
async def analyze(bundle: LogBundle) -> AnalysisResponse:
    """Submit Zeek log records → get alerts + correlated incidents."""
    return run_pipeline(bundle)
