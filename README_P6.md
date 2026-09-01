# SENTINEL-X — P6: Data + RAG + Evaluation Engineer
## Role Overview & Setup Guide

---

## What P6 Owns

| Component | Description |
|---|---|
| **Dataset** | Zeek JSON logs with embedded attack story (~12k events) |
| **Ground Truth** | Event labels, incident mappings, attack narrative |
| **MITRE KB** | 7 curated techniques relevant to the attack story |
| **Evidence RAG** | LangGraph pipeline retrieving from SQLite (logs + MITRE) |
| **Evaluation** | Detection, correlation, system, and RAG quality metrics |

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements_p6.txt
```

### 2. Generate Zeek logs
```bash
python scripts/generate_zeek_logs.py
```
Outputs: `data/raw/*.log.json` + `data/ground_truth/`

### 3. Normalize + load into SQLite
```bash
python scripts/normalize_zeek.py
```
Outputs: `db/sentinelx.db`, `data/clean/clean_events.jsonl`

### 4. Build MITRE knowledge base
```bash
python scripts/build_mitre_kb.py
```
Outputs: `knowledge/mitre/mitre_chunks.jsonl` + inserts into DB

### 5. Build vector embeddings
```bash
python scripts/build_vectorstore.py
```
Embeds all events + MITRE chunks into SQLite

### 6. Run the RAG pipeline (example)
```python
from rag.rag_pipeline import run_rag_pipeline

result = run_rag_pipeline(
    incident_id="INC-002",
    incident_summary="SSH brute force from 185.220.101.45 against 192.168.10.5",
    db_path="db/sentinelx.db",
)
print(result["explanation"])
```

### 7. Run evaluation
```bash
python eval/run_eval.py
```
Outputs: `eval_report.md` + `eval_report.json`

---

## Project Structure

```
senti-x/
├── data/
│   ├── raw/                    # Raw Zeek JSON (Zeek streaming format)
│   ├── clean/                  # Normalized events (JSONL)
│   ├── ground_truth/           # Labels, incident truth, attack story
│   └── demo_scenarios/         # Pre-sliced demo datasets
├── knowledge/
│   └── mitre/                  # Curated ATT&CK techniques + chunks
├── rag/                        # LangGraph RAG pipeline
│   ├── embedder.py             # sentence-transformers wrapper
│   ├── vectorstore.py          # SQLite vector store
│   ├── retriever.py            # Evidence + MITRE retrieval functions
│   └── rag_pipeline.py         # LangGraph stateful graph
├── eval/                       # Evaluation suite
│   ├── detection_metrics.py    # Precision, Recall, F1, FPR, AUC
│   ├── correlation_metrics.py  # Incident grouping, ARI, chain accuracy
│   ├── system_metrics.py       # Alert funnel, compression ratio
│   ├── rag_eval.py             # Faithfulness, relevance, coverage
│   └── run_eval.py             # Main evaluation runner
├── scripts/
│   ├── generate_zeek_logs.py   # Generates 12k events with attack story
│   ├── normalize_zeek.py       # Normalizes + loads to SQLite
│   ├── build_mitre_kb.py       # Chunks MITRE KB for embedding
│   └── build_vectorstore.py    # Builds SQLite vector index
├── db/                         # SQLite databases (auto-created)
├── requirements_p6.txt
└── README_P6.md
```

---

## Attack Story Summary

**"Operation Phantom Reach"** — 6-stage APT simulation:

| # | Stage | Technique | Incident | Priority |
|---|---|---|---|---|
| 1 | Port Scan | T1046 | INC-001 | MEDIUM |
| 2 | SSH Brute Force | T1110 | INC-002 | HIGH |
| 3 | Successful Login | T1078 | INC-003 | **CRITICAL** |
| 4 | DNS C2 Beaconing | T1071.004 | INC-004 | **CRITICAL** |
| 5 | RDP Lateral Move | T1021.001 | INC-005 | HIGH |
| 6 | HTTP Exfiltration | T1048 | INC-006 | **CRITICAL** |

### Alert Compression Funnel
```
12,000 Events
      ↓  16.2x
  742 Suspicious Events
      ↓   8.5x
   87 Correlated Events
      ↓   7.25x
   12 Incidents
      ↓   4.0x
    3 Priority Incidents
─────────────────────
Total: 4,000x compression
```

---

## SQLite Schema

### `events` table
Stores all normalized Zeek events. Key columns:
- `uid` — unique event identifier (Zeek UID)
- `log_type` — conn / dns / http / ssh / notice
- `ts_iso` — ISO-8601 timestamp
- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `label` — benign / attack / suspicious
- `incident_id` — set by correlation agent
- `embedding_id` — FK to embeddings table

### `incidents` table
Created/populated by the detection/correlation agent. P6 reads this for evaluation.

### `embeddings` table
- `source_type` — event / mitre_chunk
- `source_id` — uid or chunk_id
- `chunk_text` — human-readable text that was embedded
- `embedding_blob` — float32 numpy array (bytes)

### `mitre_techniques` table
7 curated MITRE techniques with detection signals and mitigations.

---

## RAG Pipeline (LangGraph)

```
Incident
   │
   ▼
[Node 1: retrieve_evidence]  ─── SQLite vector search on events
   │
   ▼
[Node 2: retrieve_mitre]     ─── SQLite vector search on mitre_chunks
   │
   ▼
[Node 3: build_context]      ─── Format evidence + MITRE into LLM prompt context
   │
   ▼
[Node 4: generate_explanation] ─ LLM generates grounded explanation with citations
   │
   ▼
[Node 5: extract_citations]  ─── Parse cited UIDs and technique IDs from output
```

---

## Evaluation Targets

| Metric | Target | Current |
|---|---|---|
| Precision | > 0.85 | TBD |
| Recall | > 0.80 | TBD |
| F1 | > 0.82 | TBD |
| False Positive Rate | < 0.05 | TBD |
| Incident Grouping Accuracy | > 0.90 | TBD |
| Attack Chain Accuracy | > 0.80 | TBD |
| Alert Compression Ratio | ~4,000x | TBD |
| RAG Citation Coverage | > 0.90 | TBD |

---

## Interface Contract (for other team members)

### Incident Schema (defined by P6)
```json
{
  "incident_id": "INC-002",
  "title": "SSH Brute Force Attack on Auth Server",
  "priority": "HIGH",
  "risk_score": 0.78,
  "tactic": "Credential Access",
  "technique_ids": ["T1110"],
  "src_ips": ["185.220.101.45"],
  "dst_ips": ["192.168.10.5"],
  "event_uids": ["CmFAq71mFn1HYnzCKk", "..."],
  "first_seen": "2024-06-15T08:30:00Z",
  "last_seen": "2024-06-15T08:45:00Z",
  "status": "open"
}
```

### Calling the RAG pipeline from other modules
```python
from rag.rag_pipeline import run_rag_pipeline

result = run_rag_pipeline(
    incident_id="INC-002",
    incident_summary="SSH brute force detected from 185.220.101.45",
    db_path="db/sentinelx.db",
    llm=your_llm_instance,   # or None for mock output
)
# result keys: evidence, mitre_chunks, context, explanation, cited_uids, cited_techniques
```

---

## Contact

**P6 Role:** Data + RAG + Evaluation Engineer  
**Owns:** `data/`, `knowledge/`, `rag/`, `eval/`, `scripts/`  
**Incident schema defined in:** `data/ground_truth/incident_ground_truth.json`
