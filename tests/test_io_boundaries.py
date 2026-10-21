import json
from pathlib import Path

import pytest

from extension_store_readiness_auditor import _io


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        b'{"x":1e400}',
        b'{"x":-1e400}',
        b"[" * 1100 + b"0" + b"]" * 1100,
    ],
    ids=["duplicate", "nan", "inf", "negative-inf", "overflow", "negative-overflow", "deep"],
)
def test_strict_json_refuses_ambiguous_or_nonfinite_input(tmp_path, raw):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    with pytest.raises((ValueError, TypeError)):
        _io.load_json(path)
    assert path.read_bytes() == raw


def test_json_limits_and_valid_unicode(tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    path.write_text('{"unicode":"é","fraction":1.25}', encoding="utf-8")
    assert b"\xc3\xa9" in path.read_bytes()
    assert _io.load_json(path) == {"unicode": "é", "fraction": 1.25}
    monkeypatch.setattr(_io, "MAX_JSON_BYTES", 8)
    with pytest.raises(ValueError, match="limit"):
        _io.load_json(path)
    with pytest.raises(ValueError, match="limit"):
        _io.parse_json(b" " * 9)


def test_json_depth_integer_cycles_and_library_types():
    with pytest.raises(ValueError, match="nesting"):
        _io.parse_json(b"[" * 129 + b"0" + b"]" * 129)
    with pytest.raises(ValueError, match="digits"):
        _io.parse_json(b"1" * 1001)
    assert _io.parse_json(b"1" * 1000) > 0
    cycle = []
    cycle.append(cycle)
    for bad in [cycle, {1: "bad"}, (1, 2), float("nan"), 10**1001, 10**1500]:
        with pytest.raises((ValueError, TypeError)):
            _io.validate_json(bad)


def test_input_and_output_symlinks_and_nonfiles(tmp_path):
    source = tmp_path / "source"
    source.write_text("{}")
    try:
        linked = tmp_path / "linked"
        linked.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symlink"):
        _io.load_json(linked)
    with pytest.raises(ValueError, match="regular"):
        _io.read_bytes(tmp_path)
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "absent")
    with pytest.raises(ValueError):
        _io.write_new_text(dangling, "bad")
    assert not (tmp_path / "absent").exists()
    directory = tmp_path / "directory"
    directory.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError):
        _io.write_new_text(alias / "output", "bad")
    assert not list(directory.iterdir())


def test_exclusive_output_preserves_existing_and_raced_files(tmp_path, monkeypatch):
    dest = tmp_path / "result"
    _io.write_new_text(dest, "first")
    with pytest.raises(ValueError):
        _io.write_new_text(dest, "second")
    assert dest.read_text() == "first"
    with pytest.raises(ValueError, match="parent"):
        _io.write_new_text(tmp_path / "missing" / "output", "bad")
    original = Path.open
    raced = tmp_path / "raced"

    def race(path, mode="r", *args, **kwargs):
        if path == raced and mode == "x":
            with original(path, "w") as handle:
                handle.write("racer")
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", race)
    with pytest.raises(FileExistsError):
        _io.write_new_text(raced, "bad")
    assert raced.read_text() == "racer"


def test_literal_markdown_delimiters():
    assert _io.code_span("simple") == "`simple`"
    assert _io.code_span("`a`\n").startswith("`` ")
    value = json.dumps({"x": "```\n<script>"})
    assert _io.json_fence(value).startswith("````json\n")
