#!/usr/bin/env python3

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pydantic import ValidationError

from schemas.smoke_hypothesis import SmokeHypothesis


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def fail(reason: str, **extra) -> int:
    payload = {
        "matched": False,
        "reason": reason,
        **extra,
    }
    print(json.dumps(payload, indent=2))
    return 1


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} <hypothesis.json> <parsed_asan.json>",
            file=sys.stderr,
        )
        return 2

    hypothesis_path = Path(sys.argv[1])
    crash_path = Path(sys.argv[2])

    try:
        hypothesis = SmokeHypothesis.model_validate_json(
            hypothesis_path.read_text()
        )
    except ValidationError as e:
        return fail(
            "hypothesis_schema_validation_failed",
            errors=json.loads(e.json()),
        )

    try:
        crash = json.loads(crash_path.read_text())
    except json.JSONDecodeError as e:
        return fail(
            "parsed_asan_json_invalid",
            error=str(e),
        )

    if not crash.get("crash_found"):
        return fail("no_crash_found")

    expected_bug = hypothesis.validation.expected_bug_type.value
    actual_bug = crash.get("bug_type")

    if actual_bug != expected_bug:
        return fail(
            "bug_type_mismatch",
            expected=expected_bug,
            actual=actual_bug,
        )

    sink_file = normalize_path(hypothesis.sink.file)
    sink_line = hypothesis.sink.line
    sink_function = hypothesis.sink.function

    for frame in crash.get("frames", []):
        frame_file = normalize_path(frame["file"])

        file_matches = frame_file.endswith(sink_file)
        line_matches = frame["line"] == sink_line
        function_matches = frame["function"] == sink_function

        if file_matches and line_matches and function_matches:
            print(json.dumps({
                "matched": True,
                "alert_class": "validated_finding",
                "blocking": True,
                "hypothesis_id": hypothesis.hypothesis_id,
                "schema_version": hypothesis.schema_version,
                "cwe": hypothesis.cwe.value,
                "sanitizer": crash["sanitizer"],
                "bug_type": crash["bug_type"],
                "matched_frame": frame,
                "reproducer": crash.get("reproducer"),
                "base64": crash.get("base64"),
            }, indent=2))
            return 0

    return fail(
        "no_matching_stack_frame",
        expected={
            "function": sink_function,
            "file_suffix": sink_file,
            "line": sink_line,
        },
        actual_frames=crash.get("frames", []),
    )


if __name__ == "__main__":
    raise SystemExit(main())