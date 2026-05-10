#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    marker = "/omnivuln/"
    if marker in path:
        return path.split(marker, 1)[1]
    return path.lstrip("./")


def build_markdown(finding: dict) -> str:
    frame = finding["matched_frame"]
    file_path = normalize_path(frame["file"])
    line = frame["line"]
    column = frame.get("column", 1)

    reproducer = finding.get("reproducer") or "n/a"
    base64_input = finding.get("base64") or "n/a"

    lines = [
        "## 🔴 OmniVuln validated finding",
        "",
        "A memory-safety issue was reproduced by sanitizer-backed fuzzing.",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Alert class | `{finding['alert_class']}` |",
        f"| Blocking | `{finding['blocking']}` |",
        f"| CWE | `{finding['cwe']}` |",
        f"| Sanitizer | `{finding['sanitizer']}` |",
        f"| Bug type | `{finding['bug_type']}` |",
        f"| Function | `{frame['function']}` |",
        f"| Location | `{file_path}:{line}:{column}` |",
        f"| Hypothesis ID | `{finding['hypothesis_id']}` |",
        "",
        "### Evidence",
        "",
        "```text",
        f"{finding['sanitizer']} confirmed {finding['bug_type']} at {file_path}:{line}",
        f"Matched function: {frame['function']}",
        "```",
        "",
        "### Reproducer",
        "",
        "```text",
        str(reproducer),
        "```",
        "",
        "### Base64 input",
        "",
        "```text",
        str(base64_input),
        "```",
        "",
        "### Required action",
        "",
        "Patch the bounds/lifetime condition at the matched sink, then rerun:",
        "",
        "```bash",
        "make smoke-negative",
        "make test",
        "```",
        "",
    ]

    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} <finding.json> <output.md>",
            file=sys.stderr,
        )
        return 2

    finding_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    finding = json.loads(finding_path.read_text())

    if not finding.get("matched"):
        print(
            "finding is not matched; refusing to emit blocking PR comment",
            file=sys.stderr,
        )
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_markdown(finding) + "\n")

    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
