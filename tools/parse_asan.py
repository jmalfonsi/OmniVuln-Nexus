#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path


def parse_asan_log(text: str) -> dict:
    result = {
        "sanitizer": None,
        "bug_type": None,
        "crash_found": False,
        "frames": [],
        "summary": None,
        "reproducer": None,
        "base64": None,
    }

    m = re.search(r"ERROR: AddressSanitizer: ([^\s]+)", text)
    if m:
        result["sanitizer"] = "ASAN"
        result["bug_type"] = m.group(1)
        result["crash_found"] = True

    frame_re = re.compile(
        r"#(?P<idx>\d+)\s+0x[0-9a-fA-F]+\s+in\s+"
        r"(?P<function>[^\s]+)\s+"
        r"(?P<file>/[^:\n]+):(?P<line>\d+):(?P<column>\d+)"
    )

    for m in frame_re.finditer(text):
        result["frames"].append({
            "index": int(m.group("idx")),
            "function": m.group("function"),
            "file": m.group("file"),
            "line": int(m.group("line")),
            "column": int(m.group("column")),
        })

    summary = re.search(r"SUMMARY: AddressSanitizer: ([^\n]+)", text)
    if summary:
        result["summary"] = summary.group(1).strip()

    repro = re.search(r"Test unit written to (\S+)", text)
    if repro:
        result["reproducer"] = repro.group(1)

    b64 = re.search(r"Base64:\s*([A-Za-z0-9+/=]+)", text)
    if b64:
        result["base64"] = b64.group(1)

    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <asan.log>", file=sys.stderr)
        sys.exit(2)

    log_path = Path(sys.argv[1])
    parsed = parse_asan_log(log_path.read_text(errors="replace"))

    print(json.dumps(parsed, indent=2))