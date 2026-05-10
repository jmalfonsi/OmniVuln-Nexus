import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)

    return subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
    )


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text())


def test_positive_pipeline_produces_validated_finding():
    result = run(["./tools/run_smoke_pipeline.sh"])

    assert result.returncode == 0, result.stdout + result.stderr

    finding = read_json("demo/out/finding.json")

    assert finding["matched"] is True
    assert finding["alert_class"] == "validated_finding"
    assert finding["blocking"] is True
    assert finding["hypothesis_id"] == "demo-001"
    assert finding["cwe"] == "CWE-787"
    assert finding["sanitizer"] == "ASAN"
    assert finding["bug_type"] == "stack-buffer-overflow"
    assert finding["matched_frame"]["function"] == "parse_packet"
    assert finding["matched_frame"]["line"] == 12
    assert finding["reproducer"] is not None


def test_negative_pipeline_patched_code_has_no_crash():
    result = run(["./tools/run_smoke_negative.sh"])

    assert result.returncode == 0, result.stdout + result.stderr

    finding = read_json("demo/out_negative/finding.json")

    assert finding["matched"] is False
    assert finding["reason"] == "no_crash_found"


def test_hallucinated_json_field_is_rejected():
    bad = {
        "schema_version": "omnivuln.smoke_hypothesis.v1",
        "hypothesis_id": "demo-evil",
        "cwe": "CWE-787",
        "confidence_score": 0.95,
        "sink": {
            "function": "parse_packet",
            "file": "demo/vuln.c",
            "line": 12,
            "symbol": "memcpy",
        },
        "validation": {
            "type": "asan_libfuzzer",
            "expected_bug_type": "stack-buffer-overflow",
        },
        "reasoning": "champ interdit",
    }

    path = ROOT / "demo/out/bad_hypothesis.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bad, indent=2))

    # Reuse existing parsed ASAN if present, otherwise generate it.
    run(["./tools/run_smoke_pipeline.sh"])

    result = run([
        "./tools/match_crash.py",
        str(path),
        "demo/out/parsed_asan.json",
    ])

    assert result.returncode == 1

    payload = json.loads(result.stdout)
    assert payload["matched"] is False
    assert payload["reason"] == "hypothesis_schema_validation_failed"

    error_types = {err["type"] for err in payload["errors"]}
    assert "extra_forbidden" in error_types


def test_wrong_sink_line_is_rejected():
    good = json.loads((ROOT / "demo/hypothesis.json").read_text())
    good["sink"]["line"] = 11

    path = ROOT / "demo/out/wrong_line_hypothesis.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(good, indent=2))

    run(["./tools/run_smoke_pipeline.sh"])

    result = run([
        "./tools/match_crash.py",
        str(path),
        "demo/out/parsed_asan.json",
    ])

    assert result.returncode == 1

    payload = json.loads(result.stdout)
    assert payload["matched"] is False
    assert payload["reason"] == "no_matching_stack_frame"

def test_positive_pipeline_emits_sarif():
    result = run(["./tools/run_smoke_pipeline.sh"])

    assert result.returncode == 0, result.stdout + result.stderr

    sarif = read_json("demo/out/omnivuln.sarif")

    assert sarif["version"] == "2.1.0"

    run0 = sarif["runs"][0]
    assert run0["tool"]["driver"]["name"] == "OmniVuln-Nexus"

    result0 = run0["results"][0]

    assert result0["ruleId"] == "omnivuln.CWE-787.stack-buffer-overflow"
    assert result0["level"] == "error"

    location = result0["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "demo/vuln.c"
    assert location["region"]["startLine"] == 12

    props = result0["properties"]
    assert props["alert_class"] == "validated_finding"
    assert props["blocking"] is True
    assert props["sanitizer"] == "ASAN"
    assert props["bug_type"] == "stack-buffer-overflow"

def test_positive_pipeline_emits_pr_markdown():
    result = run(["./tools/run_smoke_pipeline.sh"])

    assert result.returncode == 0, result.stdout + result.stderr

    md = (ROOT / "demo/out/pr_comment.md").read_text()

    assert "OmniVuln validated finding" in md
    assert "CWE-787" in md
    assert "stack-buffer-overflow" in md
    assert "demo/vuln.c:12" in md
    assert "make smoke-negative" in md