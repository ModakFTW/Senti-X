"""
rag/rag_pipeline.py
-------------------
SENTINEL-X LangGraph RAG pipeline.

Implements a stateful directed graph that:
  1. Retrieves relevant log-event evidence from SQLite
  2. Retrieves relevant MITRE ATT&CK technique chunks
  3. Formats a structured context string
  4. Generates an AI explanation (or a rich stub when no LLM is attached)
  5. Extracts cited UIDs and technique IDs from the explanation

Entry point:
    run_rag_pipeline(incident_id, incident_summary, db_path, llm=None)
"""

from __future__ import annotations

import re
import textwrap
from typing import Any, Optional

from typing_extensions import TypedDict
from langgraph.graph import StateGraph, END

from rag.retriever import retrieve_evidence, retrieve_mitre


# ---------------------------------------------------------------------------
# State schema
# ---------------------------------------------------------------------------


class RAGState(TypedDict):
    """Typed state passed between LangGraph nodes.

    Fields
    ------
    incident_id:
        Identifier of the active incident (used to filter events).
    incident_summary:
        Brief human-readable description of the incident; fed to the
        MITRE retriever so the technique search is contextual.
    query_text:
        What we want the pipeline to explain (may be the same as or
        a refinement of *incident_summary*).
    db_path:
        Absolute path to the SENTINEL-X SQLite database.
    evidence:
        Log-event records returned by :func:`retrieve_evidence`.
    mitre_chunks:
        MITRE ATT&CK chunk records returned by :func:`retrieve_mitre`.
    context:
        Formatted context string assembled by ``build_context_node``.
    explanation:
        LLM (or stub) output describing what happened.
    cited_uids:
        Event UIDs explicitly cited in ``explanation``.
    cited_techniques:
        ATT&CK technique IDs cited in ``explanation``.
    """

    incident_id: str
    incident_summary: str
    query_text: str
    db_path: str
    evidence: list[dict]
    mitre_chunks: list[dict]
    context: str
    explanation: str
    cited_uids: list[str]
    cited_techniques: list[str]


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------


def retrieve_evidence_node(state: RAGState) -> dict:
    """Node 1 -- retrieve relevant log-event evidence.

    Uses :func:`rag.retriever.retrieve_evidence` to fetch the top-10
    most semantically similar event embeddings for the incident.
    """
    evidence = retrieve_evidence(
        incident_id=state["incident_id"],
        query_text=state["query_text"],
        db_path=state["db_path"],
        top_k=10,
    )
    return {"evidence": evidence}


def retrieve_mitre_node(state: RAGState) -> dict:
    """Node 2 -- retrieve relevant MITRE ATT&CK technique chunks.

    Uses the *incident_summary* (not the raw query_text) so that the
    MITRE search reflects the broader incident context.
    """
    mitre_chunks = retrieve_mitre(
        query_text=state["incident_summary"],
        db_path=state["db_path"],
        top_k=3,
    )
    return {"mitre_chunks": mitre_chunks}


def build_context_node(state: RAGState) -> dict:
    """Node 3 -- format evidence + MITRE chunks into a context string.

    Produces a clearly sectioned block that is injected into the LLM
    prompt (or consumed by the stub generator).

    Format::

        === EVIDENCE (Log Events) ===
        [1] uid=CXX... log_type=conn ts=2024-... src=192.168.1.5 dst=10.0.0.1 | ...

        === MITRE ATT&CK CONTEXT ===
        [1] T1110 Brute Force (Detection): Multiple failed auth attempts ...
    """
    lines: list[str] = []

    # -- Evidence section -------------------------------------------------
    lines.append("=== EVIDENCE (Log Events) ===")
    evidence = state.get("evidence") or []
    if not evidence:
        lines.append("  (no indexed evidence found for this incident)")
    else:
        for i, rec in enumerate(evidence, start=1):
            uid      = rec.get("uid", "N/A")
            log_type = rec.get("log_type", "N/A")
            ts_iso   = rec.get("ts_iso", "N/A")
            src_ip   = rec.get("src_ip", "N/A")
            dst_ip   = rec.get("dst_ip", "N/A")
            chunk    = rec.get("chunk_text", "")
            score    = rec.get("similarity_score", 0.0)
            lines.append(
                f"[{i}] uid={uid} log_type={log_type} ts={ts_iso} "
                f"src={src_ip} dst={dst_ip} (sim={score:.3f}) | {chunk}"
            )

    lines.append("")

    # -- MITRE section ----------------------------------------------------
    lines.append("=== MITRE ATT&CK CONTEXT ===")
    mitre_chunks = state.get("mitre_chunks") or []
    if not mitre_chunks:
        lines.append("  (no MITRE technique chunks found)")
    else:
        for i, rec in enumerate(mitre_chunks, start=1):
            tid    = rec.get("technique_id", "N/A")
            name   = rec.get("technique_name", "")
            tactic = rec.get("tactic", "")
            section = rec.get("section", "")
            chunk  = rec.get("chunk_text", "")
            score  = rec.get("similarity_score", 0.0)
            label  = f"{tid} {name}" if name else tid
            lines.append(
                f"[{i}] {label} ({section}) [tactic={tactic}] (sim={score:.3f}):\n"
                f"    {textwrap.shorten(chunk, width=300, placeholder='...')}"
            )

    context = "\n".join(lines)
    return {"context": context}


def generate_explanation_node(state: RAGState) -> dict:
    """Node 4 -- generate a human-readable incident explanation.

    If an LLM is attached (stored under ``state["_llm"]``), the full
    LangChain ChatPromptTemplate + LLM chain is invoked.  Otherwise a
    richly formatted stub explanation is returned so the pipeline
    produces meaningful output even in test/development environments.
    """
    llm = state.get("_llm")  # type: ignore[typeddict-item]
    context = state.get("context", "")
    incident_id = state.get("incident_id", "UNKNOWN")
    incident_summary = state.get("incident_summary", "")

    if llm is not None:
        explanation = _invoke_llm(llm, context, incident_id, incident_summary)
    else:
        explanation = _stub_explanation(
            context, incident_id, incident_summary,
            state.get("evidence") or [],
            state.get("mitre_chunks") or [],
        )

    return {"explanation": explanation}


def extract_citations_node(state: RAGState) -> dict:
    """Node 5 -- parse cited UIDs and technique IDs from the explanation.

    Scans for:
    * Event UIDs matching the Zeek UID pattern (capital letter(s) + alphanum)
    * MITRE technique IDs matching ``T\d{4}(\.\d{3})?``
    """
    explanation = state.get("explanation", "")

    uid_pattern = re.compile(r"\bC[a-zA-Z0-9]{10,}\b")
    tech_pattern = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

    cited_uids = sorted(set(uid_pattern.findall(explanation)))
    cited_techniques = sorted(set(tech_pattern.findall(explanation)))

    return {
        "cited_uids": cited_uids,
        "cited_techniques": cited_techniques,
    }


# ---------------------------------------------------------------------------
# LLM invocation helper
# ---------------------------------------------------------------------------


def _invoke_llm(
    llm: Any,
    context: str,
    incident_id: str,
    incident_summary: str,
) -> str:
    """Invoke a LangChain-compatible LLM with the RAG prompt.

    Parameters
    ----------
    llm:
        Any LangChain ``BaseChatModel`` or ``BaseLanguageModel``.
    context:
        Formatted context string from ``build_context_node``.
    incident_id:
        Active incident identifier.
    incident_summary:
        Brief description of the incident.

    Returns
    -------
    str
        Raw LLM output.
    """
    try:
        from langchain_core.prompts import ChatPromptTemplate  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "langchain-core is required for LLM invocation. "
            "Run: pip install langchain-core"
        ) from exc

    system_prompt = (
        "You are SENTINEL-X, an elite cybersecurity AI analyst. "
        "You receive structured evidence from network logs and MITRE ATT&CK "
        "knowledge. Your task is to produce a precise, actionable incident report.\n\n"
        "Instructions:\n"
        "1. Explain clearly what happened based on the provided log evidence.\n"
        "2. Map the observed behaviour to specific MITRE ATT&CK techniques "
        "   (cite technique IDs in the format T####).\n"
        "3. Recommend immediate response actions (containment, eradication, "
        "   recovery) with specifics.\n"
        "4. Cite the exact log UIDs that support each finding.\n"
        "5. Be concise and structured. Use sections: FINDINGS, MITRE MAPPING, "
        "   RESPONSE ACTIONS."
    )

    human_prompt = (
        "INCIDENT ID: {incident_id}\n"
        "SUMMARY: {incident_summary}\n\n"
        "{context}\n\n"
        "Produce the incident analysis report now."
    )

    prompt = ChatPromptTemplate.from_messages(
        [("system", system_prompt), ("human", human_prompt)]
    )
    chain = prompt | llm
    response = chain.invoke(
        {
            "incident_id": incident_id,
            "incident_summary": incident_summary,
            "context": context,
        }
    )

    # Support both AIMessage and str responses
    if hasattr(response, "content"):
        return str(response.content)
    return str(response)


# ---------------------------------------------------------------------------
# Stub explanation (no LLM)
# ---------------------------------------------------------------------------


def _stub_explanation(
    context: str,
    incident_id: str,
    incident_summary: str,
    evidence: list[dict],
    mitre_chunks: list[dict],
) -> str:
    """Generate a structured stub explanation when no LLM is configured.

    Pulls data directly from the retrieved records to produce a
    deterministic, readable report suitable for testing and development.
    """
    uid_list = ", ".join(r.get("uid", "") for r in evidence[:5] if r.get("uid"))
    tech_list = ", ".join(
        f"{r.get('technique_id', '')} {r.get('technique_name', '')}".strip()
        for r in mitre_chunks
        if r.get("technique_id")
    )

    top_src_ips = list(
        {r.get("src_ip", "") for r in evidence if r.get("src_ip")}
    )[:3]
    top_dst_ips = list(
        {r.get("dst_ip", "") for r in evidence if r.get("dst_ip")}
    )[:3]

    report_lines = [
        f"SENTINEL-X INCIDENT ANALYSIS REPORT",
        f"=====================================",
        f"Incident ID  : {incident_id}",
        f"Summary      : {incident_summary}",
        f"",
        f"--- FINDINGS ---",
        f"Analysis of {len(evidence)} log event(s) revealed suspicious activity "
        f"consistent with the reported incident.",
    ]

    if top_src_ips:
        report_lines.append(
            f"Source IP(s) involved : {', '.join(top_src_ips)}"
        )
    if top_dst_ips:
        report_lines.append(
            f"Target IP(s)          : {', '.join(top_dst_ips)}"
        )
    if uid_list:
        report_lines.append(f"Key event UIDs        : {uid_list}")

    if evidence:
        best = evidence[0]
        report_lines.append(
            f"\nHighest-confidence event: uid={best.get('uid')} "
            f"(score={best.get('similarity_score', 0):.3f})\n"
            f"  {best.get('chunk_text', '')}"
        )

    report_lines += [
        f"",
        f"--- MITRE MAPPING ---",
    ]
    if mitre_chunks:
        for rec in mitre_chunks:
            tid     = rec.get("technique_id", "")
            name    = rec.get("technique_name", "")
            tactic  = rec.get("tactic", "")
            section = rec.get("section", "")
            score   = rec.get("similarity_score", 0.0)
            report_lines.append(
                f"  {tid} - {name} [{tactic}] ({section}) sim={score:.3f}"
            )
    else:
        report_lines.append("  No MITRE techniques matched.")

    if tech_list:
        report_lines.append(f"\nReferenced techniques : {tech_list}")

    report_lines += [
        f"",
        f"--- RESPONSE ACTIONS ---",
        f"1. Isolate affected hosts identified in evidence.",
        f"2. Block source IPs at perimeter firewall if external.",
        f"3. Reset credentials for any accounts involved in the activity.",
        f"4. Enable enhanced logging on affected segments.",
        f"5. Conduct forensic analysis of the flagged event UIDs.",
        f"",
        f"[STUB] This report was generated without an LLM. "
        f"Attach a LangChain-compatible model via run_rag_pipeline(llm=...) "
        f"for AI-generated analysis.",
    ]

    return "\n".join(report_lines)


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def _build_graph() -> StateGraph:
    """Construct and compile the SENTINEL-X RAG LangGraph."""
    workflow = StateGraph(RAGState)

    # Register nodes
    workflow.add_node("retrieve_evidence_node", retrieve_evidence_node)
    workflow.add_node("retrieve_mitre_node", retrieve_mitre_node)
    workflow.add_node("build_context_node", build_context_node)
    workflow.add_node("generate_explanation_node", generate_explanation_node)
    workflow.add_node("extract_citations_node", extract_citations_node)

    # Linear edge chain
    workflow.set_entry_point("retrieve_evidence_node")
    workflow.add_edge("retrieve_evidence_node", "retrieve_mitre_node")
    workflow.add_edge("retrieve_mitre_node", "build_context_node")
    workflow.add_edge("build_context_node", "generate_explanation_node")
    workflow.add_edge("generate_explanation_node", "extract_citations_node")
    workflow.add_edge("extract_citations_node", END)

    return workflow.compile()


# Compile once at import time
_graph = _build_graph()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_rag_pipeline(
    incident_id: str,
    incident_summary: str,
    db_path: str,
    query_text: Optional[str] = None,
    llm: Optional[Any] = None,
) -> dict:
    """Run the full SENTINEL-X RAG pipeline for an incident.

    Parameters
    ----------
    incident_id:
        Identifier of the incident to analyse.
    incident_summary:
        Brief description of the incident (used for MITRE retrieval and
        displayed in the final report).
    db_path:
        Absolute path to the SENTINEL-X SQLite database.
    query_text:
        Optional override for the evidence retrieval query.  Defaults to
        ``incident_summary`` when not supplied.
    llm:
        Optional LangChain-compatible language model.  When ``None`` the
        pipeline produces a deterministic stub report.

    Returns
    -------
    dict
        The final :class:`RAGState` dictionary containing all intermediate
        and final fields: ``evidence``, ``mitre_chunks``, ``context``,
        ``explanation``, ``cited_uids``, ``cited_techniques``.
    """
    initial_state: dict = {
        "incident_id":      incident_id,
        "incident_summary": incident_summary,
        "query_text":       query_text or incident_summary,
        "db_path":          db_path,
        "evidence":         [],
        "mitre_chunks":     [],
        "context":          "",
        "explanation":      "",
        "cited_uids":       [],
        "cited_techniques": [],
        "_llm":             llm,  # passed through state, not part of schema
    }

    final_state: dict = _graph.invoke(initial_state)
    # Remove private key before returning
    final_state.pop("_llm", None)
    return final_state


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 3:
        print("Usage: python -m rag.rag_pipeline <db_path> <incident_id> [summary]")
        sys.exit(1)

    _db  = sys.argv[1]
    _inc = sys.argv[2]
    _sum = sys.argv[3] if len(sys.argv) > 3 else "Suspicious network activity detected"

    result = run_rag_pipeline(
        incident_id=_inc,
        incident_summary=_sum,
        db_path=_db,
    )

    print(result["explanation"])
    print(f"\ncited_uids       : {result['cited_uids']}")
    print(f"cited_techniques : {result['cited_techniques']}")