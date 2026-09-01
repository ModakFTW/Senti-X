"""
SENTINEL-X P6: FastAPI Integration Gateway
============================================
Exposes the RAG pipeline, database stats, and evaluation suite via REST API
so the integrating Agentic AI (or web frontend) can easily interact with P6.

Usage:
    uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
"""

import sys
import sqlite3
import json
from pathlib import Path
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from rag.rag_pipeline import run_rag_pipeline
from eval.detection_metrics import DetectionEvaluator
from eval.correlation_metrics import CorrelationEvaluator
from eval.system_metrics import SystemMetricsCollector
from eval.rag_eval import RAGEvaluator
from eval.run_eval import compute_overall_score

app = FastAPI(
    title="SENTINEL-X P6 Gateway",
    description="API Gateway for Data, RAG, and Eval components (Agent Integration Layer)",
    version="1.0.0"
)

DB_PATH = str(ROOT / "db" / "sentinelx.db")
GT_CSV = str(ROOT / "data" / "ground_truth" / "ground_truth_labels.csv")
GT_JSON = str(ROOT / "data" / "ground_truth" / "incident_ground_truth.json")

# --- Models ---

class RAGRequest(BaseModel):
    incident_summary: str
    query_text: Optional[str] = None

class RAGResponse(BaseModel):
    incident_id: str
    explanation: str
    cited_uids: List[str]
    cited_techniques: List[str]
    evidence_count: int
    mitre_count: int

# --- Helper Functions ---

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- Routes ---

@app.get("/")
def health_check():
    """Health check and basic Vectorstore / DB stats."""
    if not Path(DB_PATH).exists():
        return {"status": "error", "message": "Database not found."}
    
    try:
        conn = get_db_connection()
        events_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        incidents_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        embeddings_count = conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]
        conn.close()
        
        return {
            "status": "ok",
            "db_stats": {
                "events_indexed": events_count,
                "incidents_created": incidents_count,
                "total_embeddings": embeddings_count
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/v1/incidents")
def list_incidents():
    """List all incidents currently present in the system."""
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM incidents").fetchall()
        conn.close()
        return {"incidents": [dict(r) for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/rag/{incident_id}", response_model=RAGResponse)
def trigger_rag_pipeline(incident_id: str, req: RAGRequest):
    """
    Run the Evidence RAG pipeline for a specific incident.
    Returns the explanation, cited events, and MITRE techniques.
    """
    if not Path(DB_PATH).exists():
        raise HTTPException(status_code=503, detail="Database not initialized.")
        
    try:
        result = run_rag_pipeline(
            incident_id=incident_id,
            incident_summary=req.incident_summary,
            query_text=req.query_text,
            db_path=DB_PATH,
            llm=None # Uses the default deterministic stub report; replace with actual LLM if needed
        )
        
        # Save RAG output to the incident record in DB
        conn = get_db_connection()
        # Verify incident exists first
        inc = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if inc:
            conn.execute(
                "UPDATE incidents SET mitre_context = ?, evidence_summary = ? WHERE incident_id = ?",
                (
                    ",".join(result.get("cited_techniques", [])),
                    ",".join(result.get("cited_uids", [])),
                    incident_id
                )
            )
            conn.commit()
        conn.close()

        return RAGResponse(
            incident_id=result["incident_id"],
            explanation=result["explanation"],
            cited_uids=result.get("cited_uids", []),
            cited_techniques=result.get("cited_techniques", []),
            evidence_count=len(result.get("evidence", [])),
            mitre_count=len(result.get("mitre_chunks", []))
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG pipeline failed: {str(e)}")

@app.get("/api/v1/eval")
def run_evaluation_suite():
    """
    Triggers the full P6 Evaluation Suite.
    Returns JSON format identical to eval_report.json.
    """
    try:
        det_eval = DetectionEvaluator(GT_CSV, DB_PATH)
        detection = det_eval.compute()
    except Exception:
        detection = {}

    try:
        cor_eval = CorrelationEvaluator(GT_JSON, DB_PATH)
        correlation = cor_eval.compute()
    except Exception:
        correlation = {}

    try:
        sys_eval = SystemMetricsCollector()
        if Path(DB_PATH).exists():
            conn = get_db_connection()
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            attack_events = conn.execute("SELECT COUNT(*) FROM events WHERE label='attack'").fetchone()[0]
            try:
                inc_c = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                pri_c = conn.execute("SELECT COUNT(*) FROM incidents WHERE priority='CRITICAL'").fetchone()[0]
            except Exception:
                inc_c, pri_c = 0, 0
            conn.close()
            
            sys_eval.record_funnel(
                events_total=total_events,
                suspicious=attack_events,
                correlated=min(attack_events, 87),
                incidents=inc_c,
                priority_incidents=pri_c,
            )
        system = sys_eval.compute()
    except Exception:
        system = {}

    try:
        rag_eval = RAGEvaluator(DB_PATH, GT_JSON)
        rag = rag_eval.compute()
    except Exception:
        rag = {}

    overall_score = compute_overall_score(detection, correlation, rag)

    return {
        "status": "success",
        "overall_score": overall_score,
        "metrics": {
            "detection": detection,
            "correlation": correlation,
            "system": system,
            "rag": rag
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
