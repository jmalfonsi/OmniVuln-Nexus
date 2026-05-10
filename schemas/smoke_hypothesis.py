from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


LineNo = Annotated[int, Field(strict=True, ge=1)]
Confidence = Annotated[float, Field(strict=True, ge=0.0, le=1.0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )


class CWE(str, Enum):
    CWE_119 = "CWE-119"
    CWE_787 = "CWE-787"
    CWE_416 = "CWE-416"


class SinkSymbol(str, Enum):
    MEMCPY = "memcpy"
    MEMMOVE = "memmove"
    STRCPY = "strcpy"
    STRNCPY = "strncpy"
    ARRAY_WRITE = "array_write"
    POINTER_WRITE = "pointer_write"
    FREE = "free"


class ValidationType(str, Enum):
    ASAN_LIBFUZZER = "asan_libfuzzer"


class ExpectedBugType(str, Enum):
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
    USE_AFTER_FREE = "heap-use-after-free"
    GLOBAL_BUFFER_OVERFLOW = "global-buffer-overflow"


class SinkSpec(StrictModel):
    function: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]
    file: Annotated[str, Field(min_length=1)]
    line: LineNo
    symbol: SinkSymbol


class ValidationSpec(StrictModel):
    type: ValidationType
    expected_bug_type: ExpectedBugType


class SmokeHypothesis(StrictModel):
    schema_version: Literal["omnivuln.smoke_hypothesis.v1"] = "omnivuln.smoke_hypothesis.v1"

    hypothesis_id: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_.:-]+$")]
    cwe: CWE
    confidence_score: Confidence

    sink: SinkSpec
    validation: ValidationSpec