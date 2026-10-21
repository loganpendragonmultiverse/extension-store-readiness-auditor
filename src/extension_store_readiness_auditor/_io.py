from __future__ import annotations

import json
import math
import re
import stat
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 10 * 1024 * 1024
MAX_DEPTH = 128
MAX_INTEGER_DIGITS = 1000


def checked_path(path: Path) -> Path:
    absolute = path.absolute()
    if any(part.is_symlink() for part in (absolute, *absolute.parents)):
        raise ValueError("symlink paths are unsupported")
    return absolute


def read_bytes(path: Path, limit: int = MAX_JSON_BYTES) -> bytes:
    path = checked_path(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("input must be a regular file")
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"input exceeds the {limit}-byte limit")
    return raw


def validate_json(value: Any) -> None:
    pending: list[tuple[Any, int, frozenset[int]]] = [(value, 0, frozenset())]
    while pending:
        item, depth, ancestors = pending.pop()
        if isinstance(item, (dict, list)):
            if id(item) in ancestors:
                raise ValueError("cyclic values are not JSON")
            if depth >= MAX_DEPTH:
                raise ValueError(f"JSON nesting exceeds {MAX_DEPTH} levels")
            if isinstance(item, dict) and any(not isinstance(k, str) for k in item):
                raise TypeError("JSON object keys must be strings")
            children = item.values() if isinstance(item, dict) else item
            pending.extend((child, depth + 1, ancestors | {id(item)}) for child in children)
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("JSON numbers must be finite")
        elif isinstance(item, int) and not isinstance(item, bool):
            if item.bit_length() > 4000 or len(str(abs(item))) > MAX_INTEGER_DIGITS:
                raise ValueError(f"JSON integers exceed {MAX_INTEGER_DIGITS} digits")
        elif item is not None and not isinstance(item, (str, bool)):
            raise TypeError("value is not a JSON type")


def parse_json(raw: bytes) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON input exceeds the size limit")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("JSON contains a duplicate object key")
            result[key] = value
        return result

    def constant(value: str) -> Any:
        raise ValueError("JSON numbers must be finite")

    def number(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("JSON numbers must be finite")
        return result

    def integer(value: str) -> int:
        if len(value.lstrip("-")) > MAX_INTEGER_DIGITS:
            raise ValueError(f"JSON integers exceed {MAX_INTEGER_DIGITS} digits")
        return int(value)

    try:
        value = json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_float=number,
            parse_int=integer,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the parser limit") from exc
    validate_json(value)
    return value


def load_json(path: Path) -> Any:
    return parse_json(read_bytes(path, MAX_JSON_BYTES))


def preflight_output(path: Path) -> Path:
    path = checked_path(path)
    if path.exists() or path.is_symlink():
        raise ValueError(f"output already exists: {path}")
    if not path.parent.is_dir():
        raise ValueError("output parent must be an existing directory")
    return path


def write_new_text(path: Path, text: str) -> None:
    path = preflight_output(path)
    # The explicit symlink check also covers dangling links on Windows Python 3.10.
    if path.exists() or path.is_symlink():
        raise ValueError(f"output already exists: {path}")
    with path.open("x", encoding="utf-8", newline="") as handle:
        handle.write(text)


def code_span(value: str) -> str:
    value = value.replace("\r", " ").replace("\n", " ")
    fence = "`" * (1 + max((len(x) for x in re.findall(r"`+", value)), default=0))
    pad = " " if value.startswith(("`", " ")) or value.endswith(("`", " ")) else ""
    return fence + pad + value + pad + fence


def json_fence(text: str) -> str:
    fence = "`" * max(3, 1 + max((len(x) for x in re.findall(r"`+", text)), default=0))
    return fence + "json\n" + text.rstrip() + "\n" + fence
