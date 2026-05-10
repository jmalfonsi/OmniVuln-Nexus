from __future__ import annotations
from enum import Enum
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

# ----------------------------
# Base strict model
# ----------------------------
class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_assignment=True,
    )

NodeId = Annotated[
    str,
    Field(pattern=r"^cpg:[A-Za-z0-9_.:/@#-]+$")
]

Sha256 = Annotated[
    str,
    Field(pattern=r"^sha256:[a-fA-F0-9]{64}$")
]

LineNo = Annotated[int, Field(ge=1)]
ColumnNo = Annotated[int, Field(ge=1)]
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]

# ----------------------------
# Enums
# ----------------------------
class SupportedCWE(str, Enum):
    CWE_119 = "CWE-119"
    CWE_787 = "CWE-787"
    CWE_416 = "CWE-416"

class Language(str, Enum):
    C = "c"
    CPP = "cpp"

class CpgNodeKind(str, Enum):
    METHOD = "METHOD"
    METHOD_PARAMETER_IN = "METHOD_PARAMETER_IN"
    CALL = "CALL"
    IDENTIFIER = "IDENTIFIER"
    LOCAL = "LOCAL"
    LITERAL = "LITERAL"
    RETURN = "RETURN"
    BLOCK = "BLOCK"
    CONTROL_STRUCTURE = "CONTROL_STRUCTURE"
    FIELD_IDENTIFIER = "FIELD_IDENTIFIER"
    MEMBER = "MEMBER"
    TYPE_DECL = "TYPE_DECL"
    ALLOCATION = "ALLOCATION"
    FREE = "FREE"
    ARRAY_ACCESS = "ARRAY_ACCESS"
    POINTER_DEREF = "POINTER_DEREF"

class DataflowEdgeKind(str, Enum):
    REACHING_DEF = "REACHING_DEF"
    PARAMETER_LINK = "PARAMETER_LINK"
    ARGUMENT_LINK = "ARGUMENT_LINK"
    RETURN_VALUE = "RETURN_VALUE"
    FIELD_ACCESS = "FIELD_ACCESS"
    ARRAY_INDEX = "ARRAY_INDEX"
    POINTER_DEREF = "POINTER_DEREF"
    CONTROL_DEPENDENCE = "CONTROL_DEPENDENCE"
    CALL_TO_RETURN = "CALL_TO_RETURN"

class SourceKind(str, Enum):
    NETWORK_INPUT = "NETWORK_INPUT"
    FILE_INPUT = "FILE_INPUT"
    CLI_ARG = "CLI_ARG"
    ENV_VAR = "ENV_VAR"
    IPC_INPUT = "IPC_INPUT"
    FUZZER_INPUT = "FUZZER_INPUT"
    PUBLIC_API_PARAMETER = "PUBLIC_API_PARAMETER"

class SinkKind(str, Enum):
    MEMCPY = "MEMCPY"
    MEMMOVE = "MEMMOVE"
    MEMSET = "MEMSET"
    STRCPY = "STRCPY"
    STRNCPY = "STRNCPY"
    SPRINTF = "SPRINTF"
    SNPRINTF = "SNPRINTF"
    ARRAY_WRITE = "ARRAY_WRITE"
    ARRAY_READ = "ARRAY_READ"
    POINTER_WRITE = "POINTER_WRITE"
    POINTER_READ = "POINTER_READ"
    FREE = "FREE"
    DELETE = "DELETE"
    REALLOC = "REALLOC"
    VEC_INDEX = "VEC_INDEX"

class GuardKind(str, Enum):
    UPPER_BOUND_CHECK = "UPPER_BOUND_CHECK"
    LOWER_BOUND_CHECK = "LOWER_BOUND_CHECK"
    NON_NULL_CHECK = "NON_NULL_CHECK"
    LIFETIME_VALIDITY_CHECK = "LIFETIME_VALIDITY_CHECK"
    CAPACITY_MATCH_CHECK = "CAPACITY_MATCH_CHECK"
    INTEGER_OVERFLOW_CHECK = "INTEGER_OVERFLOW_CHECK"

class GuardStatus(str, Enum):
    MISSING = "MISSING"
    PRESENT_BUT_INSUFFICIENT = "PRESENT_BUT_INSUFFICIENT"
    PRESENT_BUT_NOT_DOMINATING = "PRESENT_BUT_NOT_DOMINATING"

class RelationOp(str, Enum):
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="
    EQ = "=="
    NE = "!="

class ValidationType(str, Enum):
    ASAN_LIBFUZZER = "asan_libfuzzer"
    UBSAN_LIBFUZZER = "ubsan_libfuzzer"
    MSAN_LIBFUZZER = "msan_libfuzzer"
    KLEE_SYMBOLIC = "klee_symbolic"

class Sanitizer(str, Enum):
    ADDRESS = "address"
    UNDEFINED = "undefined"
    MEMORY = "memory"

class AlertClass(str, Enum):
    VALIDATED_FINDING = "validated_finding"
    SUSPICIOUS_PATH = "suspicious_path"
    RESEARCH_QUEUE = "research_queue"

class InputMappingKind(str, Enum):
    RAW_BYTES = "RAW_BYTES"
    SIZE_T_LENGTH = "SIZE_T_LENGTH"
    NULL_TERMINATED_STRING = "NULL_TERMINATED_STRING"
    STRUCT_DESERIALIZATION = "STRUCT_DESERIALIZATION"
    ARRAY_OF_BYTES = "ARRAY_OF_BYTES"

# ----------------------------
# Core references
# ----------------------------
class SourceLocation(StrictModel):
    file_sha256: Sha256
    file_path: str
    line: LineNo
    column: ColumnNo | None = None

class CpgRef(StrictModel):
    node_id: NodeId
    kind: CpgNodeKind
    location: SourceLocation
    function_qualified_name: str
    symbol: str
    cpg_snapshot_id: Sha256

class SourceRef(StrictModel):
    source_kind: SourceKind
    node: CpgRef

class SinkRef(StrictModel):
    sink_kind: SinkKind
    node: CpgRef

class DataflowStep(StrictModel):
    from_node_id: NodeId
    to_node_id: NodeId
    edge_kind: DataflowEdgeKind

class GuardExpectation(StrictModel):
    guard_kind: GuardKind
    status: GuardStatus
    checked_value_node_id: NodeId
    relation: RelationOp
    # Example: size <= dst_capacity
    bound_node_id: NodeId | None = None
    # Present only if status is not MISSING.
    observed_guard_node_id: NodeId | None = None

    @model_validator(mode="after")
    def validate_guard_consistency(self) -> "GuardExpectation":
        if self.status != GuardStatus.MISSING and self.observed_guard_node_id is None:
            raise ValueError(
                "observed_guard_node_id is required when guard status is not MISSING"
            )
        return self

class HarnessInputMapping(StrictModel):
    parameter_node_id: NodeId
    mapping_kind: InputMappingKind
    max_bytes: Annotated[int, Field(ge=1, le=1_048_576)]

class HarnessSpec(StrictModel):
    target_function_node_id: NodeId
    target_function_qualified_name: str
    language: Language
    input_mappings: list[HarnessInputMapping] = Field(min_length=1, max_length=16)
    required_compile_commands_hash: Sha256

class ValidationPlan(StrictModel):
    validation_type: ValidationType
    sanitizers: list[Sanitizer] = Field(min_length=1, max_length=3)
    timeout_seconds: Annotated[int, Field(ge=10, le=7200)]
    harness: HarnessSpec

class FindingHypothesis(StrictModel):
    schema_version: Literal["omnivuln.finding.v1"] = "omnivuln.finding.v1"
    hypothesis_id: Sha256
    repository: str
    commit_sha: Annotated[str, Field(pattern=r"^[a-fA-F0-9]{40}$")]
    diff_sha256: Sha256
    language: Language
    cwe: SupportedCWE
    confidence_score: Confidence
    source: SourceRef
    sink: SinkRef
    dataflow_path: list[DataflowStep] = Field(min_length=1, max_length=128)
    guard_expectations: list[GuardExpectation] = Field(min_length=1, max_length=16)
    vulnerable_lines: list[LineNo] = Field(min_length=1, max_length=16)
    validation_plan: ValidationPlan

    @model_validator(mode="after")
    def validate_path_endpoints(self) -> "FindingHypothesis":
        first = self.dataflow_path[0]
        last = self.dataflow_path[-1]
        if first.from_node_id != self.source.node.node_id:
            raise ValueError("dataflow_path must start at source.node.node_id")
        if last.to_node_id != self.sink.node.node_id:
            raise ValueError("dataflow_path must end at sink.node.node_id")
        sink_line = self.sink.node.location.line
        if sink_line not in self.vulnerable_lines:
            raise ValueError("vulnerable_lines must include sink line")
        return self

class FindingBatch(StrictModel):
    schema_version: Literal["omnivuln.finding_batch.v1"] = "omnivuln.finding_batch.v1"
    findings: list[FindingHypothesis] = Field(max_length=32)

if __name__ == "__main__":
    import json
    schema = FindingHypothesis.model_json_schema()
    print(json.dumps(schema, indent=2))
