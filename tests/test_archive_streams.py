import io
import json
import struct
import zipfile
import zlib

import pytest

from extension_store_readiness_auditor import core
from extension_store_readiness_auditor.cli import main

METHODS = [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA]
IDS = ["stored", "deflate", "bzip2", "lzma"]
if hasattr(zipfile, "ZIP_ZSTANDARD"):
    METHODS.append(zipfile.ZIP_ZSTANDARD)
    IDS.append("zstandard")
MARKER = b"XSYNTHETIC_TRAILING_MARKER"


def container(method, body=MARKER, name="worker.bin", manifest=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=method) as archive:
        archive.writestr(name, body)
        if manifest:
            archive.writestr(
                "manifest.json",
                json.dumps(
                    {
                        "manifest_version": 3,
                        "version": "1",
                        "name": "Fixture",
                        "description": "Fixture",
                    }
                ),
            )
    return bytearray(stream.getvalue())


def locations(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        member = archive.infolist()[0]
        local = member.header_offset
    name_size, extra_size = struct.unpack_from("<2H", data, local + 26)
    return local, local + 30 + name_size + extra_size, data.index(b"PK\x01\x02")


def patch_declared(data, *, size=None, crc=None, compressed_size=None):
    local, _, central = locations(data)
    for value, local_offset, central_offset in [
        (size, 22, 24),
        (crc, 14, 16),
        (compressed_size, 18, 20),
    ]:
        if value is not None:
            struct.pack_into("<I", data, local + local_offset, value)
            struct.pack_into("<I", data, central + central_offset, value)
    return data


def read(tmp_path, data):
    path = tmp_path / "fixture.zip"
    path.write_bytes(data)
    return core._read_package(path)[0]


@pytest.mark.parametrize("method", METHODS, ids=IDS)
def test_complete_large_and_empty_directory_streams_remain_supported(tmp_path, method):
    body = b"complete\n" * 80000
    data = container(method, body)
    with zipfile.ZipFile(io.BytesIO(data), "a", compression=method) as archive:
        # Build separately below: bytearray from a closed BytesIO is intentionally immutable here.
        assert archive.read("worker.bin") == body
    assert read(tmp_path, data)["worker.bin"] == body
    assert read(tmp_path, container(method, b"", "assets/")) == {}


@pytest.mark.parametrize("method", METHODS, ids=IDS)
def test_declared_prefix_cannot_hide_decoded_suffix(tmp_path, method):
    data = patch_declared(container(method), size=1, crc=zlib.crc32(b"X"))
    with pytest.raises(ValueError, match="ZIP"):
        read(tmp_path, data)


@pytest.mark.parametrize("method", METHODS, ids=IDS)
def test_complete_compressed_span_requires_end_marker_and_declared_size(tmp_path, method):
    data = container(method, b"X")
    local, _, _ = locations(data)
    compressed = struct.unpack_from("<I", data, local + 18)[0]
    patch_declared(data, compressed_size=compressed - 1)
    with pytest.raises(ValueError, match="ZIP"):
        read(tmp_path, data)


@pytest.mark.parametrize("method", METHODS, ids=IDS)
def test_compressed_span_cannot_contain_trailing_junk(tmp_path, method):
    data = container(method, b"X")
    local, start, central = locations(data)
    compressed = struct.unpack_from("<I", data, local + 18)[0]
    assert start + compressed == central
    suffix = b"TRAILING"
    data[central:central] = suffix
    new_central = central + len(suffix)
    struct.pack_into("<I", data, local + 18, compressed + len(suffix))
    struct.pack_into("<I", data, new_central + 20, compressed + len(suffix))
    end = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, end + 16, new_central)
    with pytest.raises(ValueError, match="ZIP"):
        read(tmp_path, data)


@pytest.mark.parametrize("method", METHODS, ids=IDS)
@pytest.mark.parametrize(
    "conceal_size", [False, True], ids=["declared-payload", "concealed-payload"]
)
def test_directory_members_must_decode_to_zero_bytes(tmp_path, method, conceal_size):
    data = container(method, MARKER, "assets/")
    if conceal_size:
        patch_declared(data, size=0, crc=0)
    with pytest.raises(ValueError, match="ZIP"):
        read(tmp_path, data)


@pytest.mark.parametrize("method", METHODS, ids=IDS)
def test_crc_covers_complete_decoded_content(tmp_path, method):
    data = patch_declared(container(method), crc=zlib.crc32(MARKER) ^ 1)
    with pytest.raises(ValueError, match="ZIP"):
        read(tmp_path, data)


@pytest.mark.parametrize("field", ["flags", "method"])
def test_local_and_central_flags_and_method_agree(tmp_path, field):
    data = container(zipfile.ZIP_STORED)
    local, _, _ = locations(data)
    struct.pack_into(
        "<H",
        data,
        local + (6 if field == "flags" else 8),
        0x800 if field == "flags" else zipfile.ZIP_DEFLATED,
    )
    with pytest.raises(ValueError, match="flags or method"):
        read(tmp_path, data)


@pytest.mark.parametrize(
    "damage",
    ["short", "properties-size", "properties-range", "dictionary-budget", "invalid-filter"],
)
def test_lzma_properties_are_bounded_and_validated(tmp_path, damage):
    data = container(zipfile.ZIP_LZMA)
    _, start, _ = locations(data)
    if damage == "short":
        patch_declared(data, compressed_size=4)
    elif damage == "properties-size":
        struct.pack_into("<H", data, start + 2, 4)
    elif damage == "properties-range":
        data[start + 4] = 255
    elif damage == "dictionary-budget":
        struct.pack_into("<I", data, start + 5, 1024 * 1024 * 1024)
    else:
        data[start + 4] = 44
    with pytest.raises(ValueError, match="ZIP"):
        read(tmp_path, data)


def test_optional_codec_unavailability_is_actionable(tmp_path, monkeypatch):
    from extension_store_readiness_auditor import _archive

    original = _archive.importlib.import_module

    def unavailable(name):
        if name == "bz2":
            raise ImportError("synthetic missing optional codec")
        return original(name)

    monkeypatch.setattr(_archive.importlib, "import_module", unavailable)
    with pytest.raises(ValueError, match="unavailable"):
        read(tmp_path, container(zipfile.ZIP_BZIP2))


@pytest.mark.parametrize("method", METHODS, ids=IDS)
def test_invalid_codec_bytes_are_actionable(tmp_path, method):
    data = container(method)
    _, start, _ = locations(data)
    # The ZIP-LZMA prefix contains version/properties, not compressed data.
    stream_start = start + 9 if method == zipfile.ZIP_LZMA else start
    data[stream_start] ^= 255
    with pytest.raises(ValueError, match="ZIP"):
        read(tmp_path, data)


def test_cli_prefix_refusal_preserves_input_and_creates_no_report(tmp_path, capsys):
    source = tmp_path / "package.zip"
    data = patch_declared(
        container(zipfile.ZIP_DEFLATED, manifest=True), size=1, crc=zlib.crc32(b"X")
    )
    source.write_bytes(data)
    output = tmp_path / "report.json"
    assert main([str(source), "--output", str(output)]) == 2
    assert source.read_bytes() == data and not output.exists()
    assert "Traceback" not in capsys.readouterr().err
