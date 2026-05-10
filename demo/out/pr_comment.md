## 🔴 OmniVuln validated finding

A memory-safety issue was reproduced by sanitizer-backed fuzzing.

| Field | Value |
|---|---|
| Alert class | `validated_finding` |
| Blocking | `True` |
| CWE | `CWE-787` |
| Sanitizer | `ASAN` |
| Bug type | `stack-buffer-overflow` |
| Function | `parse_packet` |
| Location | `demo/vuln.c:12:5` |
| Hypothesis ID | `demo-001` |

### Evidence

```text
ASAN confirmed stack-buffer-overflow at demo/vuln.c:12
Matched function: parse_packet
```

### Reproducer

```text
./crash-65682de0b26fb1f3238a5865e4af5ee3394a78fd
```

### Base64 input

```text
TU1NTU1NTU0K
```

### Required action

Patch the bounds/lifetime condition at the matched sink, then rerun:

```bash
make smoke-negative
make test
```

