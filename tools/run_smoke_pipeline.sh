#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p demo/out

echo "[1/8] Render libFuzzer harness"
tools/render_harness.py \
  demo/hypothesis.json \
  demo/out/fuzz_generated.cpp

echo "[2/8] Compile C object"
clang \
  -O0 -g \
  -fsanitize=address,fuzzer-no-link \
  -c demo/vuln.c \
  -o demo/out/vuln.o

echo "[3/8] Link fuzz target"
clang++ \
  -O0 -g \
  -fsanitize=address,fuzzer \
  demo/out/vuln.o \
  demo/out/fuzz_generated.cpp \
  -o demo/out/fuzz_generated

echo "[4/8] Run libFuzzer"
set +e
timeout 60s demo/out/fuzz_generated > demo/out/asan.log 2>&1
FUZZ_EXIT=$?
set -e

echo "[5/8] Parse ASAN"
tools/parse_asan.py demo/out/asan.log > demo/out/parsed_asan.json

echo "[6/8] Match crash to hypothesis"
tools/match_crash.py \
  demo/hypothesis.json \
  demo/out/parsed_asan.json \
  > demo/out/finding.json

if grep -q '"matched": true' demo/out/finding.json; then
  echo "[7/8] Emit SARIF"
  tools/finding_to_sarif.py \
    demo/out/finding.json \
    demo/out/omnivuln.sarif

  echo "[8/8] Emit PR Markdown"
  tools/finding_to_markdown.py \
    demo/out/finding.json \
    demo/out/pr_comment.md

  echo "[OK] validated_finding"
  cat demo/out/finding.json
  echo "[OK] SARIF written to demo/out/omnivuln.sarif"
  echo "[OK] PR comment written to demo/out/pr_comment.md"
  exit 0
fi

echo "[FAIL] no validated finding"
cat demo/out/finding.json
exit 1