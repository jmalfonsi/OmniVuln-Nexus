#!/usr/bin/env python3

import json
import sys
from pathlib import Path


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    marker = "/omnivuln/"
    if marker in path:
        return path.split(marker, 1)[1]
    return path.lstrip("./")


def level_from_bug_type(bug_type: str) -> str:
    if bug_type in {
        "stack-buffer-overflow",
        "heap-buffer-overflow",
        "global-buffer-overflow",
        "heap-use-after-free",
    }:
        return "error"
    return "warning"


def build_sarif(finding: dict) -> dict:
    frame = finding["matched_frame"]

    file_uri = normalize_path(frame["file"])
    line = int(frame["line"])
    bug_type = finding["bug_type"]
    cwe = finding["cwe"]

    rule_id = f"omnivuln.{cwe}.{bug_type}"

    message = (
        f"{finding['alert_class']}: {cwe} confirmed by {finding['sanitizer']} "
        f"({bug_type}) in function {frame['function']}."
    )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OmniVuln-Nexus",
                        "informationUri": "https://github.com/jmalfonsi/omnivuln-nexus",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": f"{cwe}: {bug_type}",
                                "shortDescription": {
                                    "text": f"{cwe} confirmed by sanitizer"
                                },
                                "fullDescription": {
                                    "text": (
                                        "OmniVuln validated this finding with a sanitizer "
                                        "crash and matched the crash stack frame to the "
                                        "hypothesized vulnerable sink."
                                    )
                                },
                                "help": {
                                    "text": (
                                        "Review the matched sink, the sanitizer trace, and "
                                        "the generated reproducer. Do not suppress unless "
                                        "the reproducer is proven irrelevant."
                                    )
                                },
                                "properties": {
                                    "tags": [
                                        "security",
                                        "memory-corruption",
                                        cwe,
                                        finding["sanitizer"],
                                        bug_type,
                                    ],
                                    "precision": "very-high",
                                    "security-severity": "9.0",
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": level_from_bug_type(bug_type),
                        "message": {
                            "text": message
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": file_uri
                                    },
                                    "region": {
                                        "startLine": line,
                                        "startColumn": int(frame.get("column") or 1),
                                    },
                                }
                            }
                        ],
                        "partialFingerprints": {
                            "omnivulnHypothesisId": finding["hypothesis_id"],
                            "omnivulnLocation": f"{file_uri}:{line}:{frame['function']}",
                            "omnivulnBugType": bug_type,
                        },
                        "properties": {
                            "alert_class": finding["alert_class"],
                            "blocking": finding["blocking"],
                            "hypothesis_id": finding["hypothesis_id"],
                            "schema_version": finding.get("schema_version"),
                            "cwe": cwe,
                            "sanitizer": finding["sanitizer"],
                            "bug_type": bug_type,
                            "function": frame["function"],
                            "reproducer": finding.get("reproducer"),
                            "base64": finding.get("base64"),
                        },
                    }
                ],
            }
        ],
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} <finding.json> <output.sarif>",
            file=sys.stderr,
        )
        return 2

    finding_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    finding = json.loads(finding_path.read_text())

    if not finding.get("matched"):
        print("finding is not matched; refusing to emit blocking SARIF", file=sys.stderr)
        return 1

    sarif = build_sarif(finding)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif, indent=2))

    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())