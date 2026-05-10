#!/usr/bin/env python3

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import ValidationError

from schemas.smoke_hypothesis import SmokeHypothesis


def derive_header_path(source_file: str) -> Path:
    source = Path(source_file)

    if source.suffix not in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError(f"unsupported source suffix: {source.suffix}")

    return source.with_suffix(".h")


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} <hypothesis.json> <output.cpp>",
            file=sys.stderr,
        )
        return 2

    hypothesis_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    try:
        hypothesis = SmokeHypothesis.model_validate_json(
            hypothesis_path.read_text()
        )
    except ValidationError as e:
        print(e.json(indent=2), file=sys.stderr)
        return 1

    source_file = hypothesis.sink.file
    header_path = derive_header_path(source_file)

    if not header_path.exists():
        print(f"header not found: {header_path}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Include path relative to generated harness location.
    header_include = os.path.relpath(header_path, output_path.parent)
    header_include = header_include.replace("\\", "/")

    env = Environment(
        loader=FileSystemLoader(PROJECT_ROOT / "harness" / "templates"),
        undefined=StrictUndefined,
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template("libfuzzer_c.j2")

    rendered = template.render(
        header_include=header_include,
        target_function=hypothesis.sink.function,
    )

    output_path.write_text(rendered)
    print(output_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())