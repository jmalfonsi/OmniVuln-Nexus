from __future__ import annotations
from langgraph.graph import StateGraph, START, END
from orchestration.state import OmniState

# ----------------------------
# Nodes
# ----------------------------

def ingest_diff(state: OmniState) -> OmniState:
    """
    Inputs:
    - repo_path
    - diff_text
    - commit_sha
    Outputs:
    - diff_sha256
    - affected_functions
    """
    # 1. hash diff
    # 2. map changed files/lines
    # 3. extract affected functions via Tree-sitter/compile DB
    return state

def build_or_update_cpg(state: OmniState) -> OmniState:
    """
    Outputs:
    - cpg_snapshot_id
    """
    # Run Joern import/update.
    # Persist snapshot ID.
    return state

def extract_program_slices(state: OmniState) -> OmniState:
    """
    Outputs:
    - program_slices
    Each slice must include:
    - source node
    - sink node
    - dataflow path
    - guard candidates
    - changed lines overlap
    """
    return state

def triage_llm(state: OmniState) -> OmniState:
    """
    LLM consumes only structured slices.
    LLM emits FindingBatch JSON.
    """
    return state

def validate_hypotheses_schema(state: OmniState) -> OmniState:
    """
    Parse with Pydantic.
    Reject anything with:
    - unknown CPG node
    - invalid endpoint
    - sink line absent from vulnerable_lines
    - forbidden extra fields
    """
    return state

def render_harnesses(state: OmniState) -> OmniState:
    """
    Jinja2 template.
    No full from-scratch harness generation.
    """
    return state

def compile_harnesses(state: OmniState) -> OmniState:
    """
    clang++ -O0 -g -fsanitize=address,undefined,fuzzer
    Hard timeout: 15 seconds per harness.
    """
    return state

def repair_harness_once(state: OmniState) -> OmniState:
    """
    One retry only.
    LLM receives:
    - generated harness
    - compiler stderr
    - compile command
    - target signature
    """
    return state

def fuzz_timeboxed(state: OmniState) -> OmniState:
    """
    libFuzzer hard timeout:
    - Sprint 0: 60 sec
    - PR validated tier: configurable 5–10 min
    """
    return state

def parse_sanitizer_crashes(state: OmniState) -> OmniState:
    """
    Parse ASAN/UBSAN/MSAN.
    Match stacktrace frames to:
    - sink line
    - vulnerable_lines
    - target function
    - CPG node locations
    """
    return state

def classify_alerts(state: OmniState) -> OmniState:
    """
    Produces:
    - VALIDATED_FINDING if sanitizer crash matches JSON
    - SUSPICIOUS_PATH if CPG path valid but no crash
    - RESEARCH_QUEUE if high confidence and no crash
    """
    return state

def enqueue_klee(state: OmniState) -> OmniState:
    """
    Does not block PR path.
    Creates queue item for nightly symbolic execution.
    """
    return state

def emit_pr_report(state: OmniState) -> OmniState:
    """
    Writes Markdown/SARIF artifacts.
    Blocking only for VALIDATED_FINDING.
    """
    return state

def reject_invalid(state: OmniState) -> OmniState:
    """
    Terminal non-alert path for invalid JSON/hallucinated CPG nodes.
    """
    return state

# ----------------------------
# Routers
# ----------------------------

def route_after_schema(state: OmniState) -> str:
    valid = bool(state.get("hypotheses"))
    return "render_harnesses" if valid else "reject_invalid"

def route_after_compile(state: OmniState) -> str:
    compile_results = state.get("compile_results", {})
    attempts = state.get("compile_attempts", {})
    any_success = any(result["ok"] for result in compile_results.values())
    if any_success:
        return "fuzz_timeboxed"
    can_retry = any(count < 1 for count in attempts.values())
    if can_retry:
        return "repair_harness_once"
    return "classify_alerts"

def route_after_crash_parse(state: OmniState) -> str:
    fuzz_results = state.get("fuzz_results", {})
    hypotheses = state.get("hypotheses", [])
    crash_found = any(r.get("crash_found") for r in fuzz_results.values())
    if crash_found:
        return "classify_alerts"
    high_confidence = any(h.confidence_score >= 0.90 for h in hypotheses)
    if high_confidence:
        return "enqueue_klee"
    return "classify_alerts"

# ----------------------------
# Graph assembly
# ----------------------------

def build_graph():
    graph = StateGraph(OmniState)
    graph.add_node("ingest_diff", ingest_diff)
    graph.add_node("build_or_update_cpg", build_or_update_cpg)
    graph.add_node("extract_program_slices", extract_program_slices)
    graph.add_node("triage_llm", triage_llm)
    graph.add_node("validate_hypotheses_schema", validate_hypotheses_schema)
    graph.add_node("render_harnesses", render_harnesses)
    graph.add_node("compile_harnesses", compile_harnesses)
    graph.add_node("repair_harness_once", repair_harness_once)
    graph.add_node("fuzz_timeboxed", fuzz_timeboxed)
    graph.add_node("parse_sanitizer_crashes", parse_sanitizer_crashes)
    graph.add_node("classify_alerts", classify_alerts)
    graph.add_node("enqueue_klee", enqueue_klee)
    graph.add_node("emit_pr_report", emit_pr_report)
    graph.add_node("reject_invalid", reject_invalid)

    graph.add_edge(START, "ingest_diff")
    graph.add_edge("ingest_diff", "build_or_update_cpg")
    graph.add_edge("build_or_update_cpg", "extract_program_slices")
    graph.add_edge("extract_program_slices", "triage_llm")
    graph.add_edge("triage_llm", "validate_hypotheses_schema")

    graph.add_conditional_edges(
        "validate_hypotheses_schema",
        route_after_schema,
        {
            "render_harnesses": "render_harnesses",
            "reject_invalid": "reject_invalid",
        },
    )

    graph.add_edge("render_harnesses", "compile_harnesses")

    graph.add_conditional_edges(
        "compile_harnesses",
        route_after_compile,
        {
            "fuzz_timeboxed": "fuzz_timeboxed",
            "repair_harness_once": "repair_harness_once",
            "classify_alerts": "classify_alerts",
        },
    )

    graph.add_edge("repair_harness_once", "compile_harnesses")
    graph.add_edge("fuzz_timeboxed", "parse_sanitizer_crashes")

    graph.add_conditional_edges(
        "parse_sanitizer_crashes",
        route_after_crash_parse,
        {
            "classify_alerts": "classify_alerts",
            "enqueue_klee": "enqueue_klee",
        },
    )

    graph.add_edge("enqueue_klee", "classify_alerts")
    graph.add_edge("classify_alerts", "emit_pr_report")
    graph.add_edge("emit_pr_report", END)
    graph.add_edge("reject_invalid", END)

    return graph.compile()
