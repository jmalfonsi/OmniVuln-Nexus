from __future__ import annotations
from typing import TypedDict, NotRequired, Literal
from schemas.finding_hypothesis import FindingHypothesis, AlertClass

class CompileResult(TypedDict):
    ok: bool
    attempt: int
    compiler_stdout: str
    compiler_stderr: str
    binary_path: NotRequired[str]

class FuzzResult(TypedDict):
    executed: bool
    timeout_seconds: int
    crash_found: bool
    sanitizer: NotRequired[Literal["ASAN", "UBSAN", "MSAN"]]
    crash_log_path: NotRequired[str]
    reproducer_path: NotRequired[str]
    matched_cpg_lines: NotRequired[list[int]]

class KleeQueueItem(TypedDict):
    hypothesis_id: str
    priority: float
    timeout_seconds: int

class Alert(TypedDict):
    alert_class: AlertClass
    hypothesis_id: str
    blocking: bool
    markdown_report_path: NotRequired[str]
    sarif_path: NotRequired[str]

class OmniState(TypedDict):
    repo_path: str
    repository: str
    commit_sha: str
    diff_text: str
    diff_sha256: str
    cpg_snapshot_id: NotRequired[str]
    affected_functions: NotRequired[list[str]]
    program_slices: NotRequired[list[dict]]
    llm_raw_output: NotRequired[str]
    hypotheses: NotRequired[list[FindingHypothesis]]
    rejected_hypotheses: NotRequired[list[dict]]
    harness_sources: NotRequired[dict[str, str]]
    compile_results: NotRequired[dict[str, CompileResult]]
    compile_attempts: NotRequired[dict[str, int]]
    fuzz_results: NotRequired[dict[str, FuzzResult]]
    klee_queue: NotRequired[list[KleeQueueItem]]
    alerts: NotRequired[list[Alert]]
    audit_log: NotRequired[list[str]]
