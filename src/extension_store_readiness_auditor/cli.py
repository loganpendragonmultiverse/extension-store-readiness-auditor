from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

from .core import TARGETS, analyze, compare_reports, load_policy, render_json, render_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit a browser-extension package before store review."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("--target", action="append", choices=sorted(TARGETS), dest="targets")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy) if args.policy else None
        report = analyze(args.source, set(args.targets or TARGETS), policy)
        if args.baseline:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            if not isinstance(baseline, dict):
                raise TypeError("baseline report must contain an object")
            report["comparison"] = compare_reports(report, baseline)
        rendered = render_json(report) if args.format == "json" else render_markdown(report)
        if args.output:
            if args.output.exists():
                raise ValueError(f"output already exists: {args.output}")
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1 if report["summary"]["error"] else 0
