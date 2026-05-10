#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p demo/out_negative

echo "[1/6] Render libFuzzer harness"
tools/render_harness.py \
  demo/hypothesis.json \
  demo/out_negative/fuzz_generated.cpp

echo "[2/6] Compile patched C object"
clang \
  -O0 -g \
  -fsanitize=address,fuzzer-no-link \
  -c demo/vuln_patched.c \
  -o demo/out_negative/vuln.o

echo "[3/6] Link fuzz target"
clang++ \
  -O0 -g \
  -fsanitize=address,fuzzer \
  demo/out_negative/vuln.o \
  demo/out_negative/fuzz_generated.cpp \
  -o demo/out_negative/fuzz_generated

echo "[4/6] Run libFuzzer on patched code"
set +e
timeout 15s demo/out_negative/fuzz_generated > demo/out_negative/asan.log 2>&1
set -e

echo "[5/6] Parse ASAN"
tools/parse_asan.py demo/out_negative/asan.log > demo/out_negative/parsed_asan.json

echo "[6/6] Match crash to hypothesis"
set +e
tools/match_crash.py \
  demo/hypothesis.json \
  demo/out_negative/parsed_asan.json \
  > demo/out_negative/finding.json
MATCH_EXIT=$?
set -e

if grep -q '"reason": "no_crash_found"' demo/out_negative/finding.json; then
  echo "[OK] patched code produced no crash"
  cat demo/out_negative/finding.json
  exit 0
fi

echo "[FAIL] patched code still produced a finding or unexpected result"
cat demo/out_negative/finding.json
exit 1