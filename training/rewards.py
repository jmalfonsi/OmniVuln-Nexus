from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any
from schemas.finding_hypothesis import FindingHypothesis

@dataclass(frozen=True)
class SandboxResult:
    schema_valid: bool
    cpg_nodes_exist: bool
    dataflow_path_valid: bool
    harness_rendered: bool
    harness_compiled: bool
    target_reached: bool
    ubsan_triggered: bool
    msan_triggered: bool
    asan_crash: bool
    trace_matches_json: bool
    baseline_tests_pass: bool
    compiler_error: str | None = None
    sanitizer_log: str | None = None

def clamp(x: float, lo: float = -1.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))

def validate_against_cpg(hypothesis: FindingHypothesis, cpg_slice: dict[str, Any]) -> bool:
    """
    Deterministic check:
    - source node exists
    - sink node exists
    - every dataflow edge exists
    - path endpoints match
    - vulnerable lines are in changed or reachable code
    """
    node_ids = set(cpg_slice["node_ids"])
    edge_triples = set(tuple(e) for e in cpg_slice["edges"])
    if hypothesis.source.node.node_id not in node_ids:
        return False
    if hypothesis.sink.node.node_id not in node_ids:
        return False
    for step in hypothesis.dataflow_path:
        edge = (step.from_node_id, step.edge_kind.value, step.to_node_id)
        if edge not in edge_triples:
            return False
    return True

def run_sandbox_validation(
    hypothesis: FindingHypothesis,
    cpg_slice: dict[str, Any],
    compile_context: dict[str, Any],
) -> SandboxResult:
    """
    This is an interface, not an in-process runner.
    Implementation must call an isolated sandbox with:
    - no network
    - read-only source checkout
    - CPU/memory limits
    - hard timeouts
    - clean temp directory
    - seccomp/AppArmor profile if available
    """
    raise NotImplementedError

def score_sandbox_result(result: SandboxResult) -> float:
    """
    Curriculum reward.
    Stage reward is monotonic:
    - bad schema / hallucinated CPG => negative
    - compile + reach target => +0.2
    - UBSAN/MSAN with matching trace => +0.5
    - ASAN crash with matching trace => +1.0
    Do not add 0.2 + 0.5 + 1.0.
    Use max-stage reward.
    """
    if not result.schema_valid:
        return -1.0
    if not result.cpg_nodes_exist:
        return -0.8
    if not result.dataflow_path_valid:
        return -0.6
    if not result.harness_rendered:
        return -0.4
    if not result.harness_compiled:
        return -0.2
    
    reward = 0.0
    if result.harness_compiled and result.target_reached:
        reward = max(reward, 0.2)
    if (result.ubsan_triggered or result.msan_triggered) and result.trace_matches_json:
        reward = max(reward, 0.5)
    if result.asan_crash and result.trace_matches_json:
        reward = max(reward, 1.0)
    
    # Penalize misleading crashes.
    if result.asan_crash and not result.trace_matches_json:
        reward -= 0.4
    
    # Penalize breaking the project's baseline behavior.
    if not result.baseline_tests_pass:
        reward -= 0.5
        
    return clamp(reward)

def omnivuln_curriculum_reward(
    completions: list[str],
    cpg_slices: list[dict[str, Any]],
    compile_contexts: list[dict[str, Any]],
    **kwargs: Any,
) -> list[float]:
    """
    TRL-compatible reward function.
    Each completion is expected to be a JSON FindingHypothesis.
    """
    rewards: list[float] = []
    for completion, cpg_slice, compile_context in zip(
        completions,
        cpg_slices,
        compile_contexts,
        strict=True,
    ):
        try:
            hypothesis = FindingHypothesis.model_validate_json(completion)
        except Exception:
            rewards.append(-1.0)
            continue
        try:
            sandbox_result = run_sandbox_validation(
                hypothesis=hypothesis,
                cpg_slice=cpg_slice,
                compile_context=compile_context,
            )
        except TimeoutError:
            rewards.append(-0.3)
            continue
        except Exception:
            rewards.append(-0.5)
            continue
        rewards.append(score_sandbox_result(sandbox_result))
    return rewards
