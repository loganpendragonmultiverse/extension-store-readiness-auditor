"""Bounded complete ZIP streams, independent of ZipExtFile's declared-size cutoff."""

from __future__ import annotations

import importlib
import struct
import zipfile
import zlib
from typing import IO, Any

CHUNK = 65536
MAX_CODEC_MEMORY = 512 * 1024 * 1024


def _decoder(
    source: IO[bytes], member: zipfile.ZipInfo, remaining: int
) -> tuple[Any, int, tuple[type[Exception], ...]]:
    method = member.compress_type
    if method == zipfile.ZIP_STORED:
        return None, remaining, ()
    if method == zipfile.ZIP_DEFLATED:
        return zlib.decompressobj(-15), remaining, (zlib.error,)
    if method == zipfile.ZIP_BZIP2:
        module = importlib.import_module("bz2")
        return module.BZ2Decompressor(), remaining, (OSError, EOFError)
    if method == zipfile.ZIP_LZMA:
        module = importlib.import_module("lzma")
        if remaining < 9:
            raise ValueError("ZIP LZMA properties are truncated")
        header = source.read(9)
        if len(header) != 9 or struct.unpack_from("<H", header, 2)[0] != 5:
            raise ValueError("ZIP LZMA properties are invalid")
        properties = header[4]
        dictionary = int.from_bytes(header[5:9], "little")
        if properties >= 225 or dictionary > MAX_CODEC_MEMORY:
            raise ValueError("ZIP LZMA properties exceed decoder limits")
        lc = properties % 9
        remainder = properties // 9
        filters = [
            {
                "id": module.FILTER_LZMA1,
                "dict_size": max(4096, dictionary),
                "lc": lc,
                "lp": remainder % 5,
                "pb": remainder // 5,
            }
        ]
        try:
            decoder = module.LZMADecompressor(format=module.FORMAT_RAW, filters=filters)
        except module.LZMAError as error:
            raise ValueError("ZIP LZMA properties are invalid") from error
        return decoder, remaining - 9, (module.LZMAError, EOFError)
    if method in {20, 93}:
        module = importlib.import_module("compression.zstd")
        decoder = module.ZstdDecompressor(
            options={module.DecompressionParameter.window_log_max: 29}
        )
        return decoder, remaining, (module.ZstdError, EOFError)
    raise NotImplementedError("unsupported ZIP compression method")


def read_member(
    archive: zipfile.ZipFile, member: zipfile.ZipInfo, limit: int, container_limit: int
) -> bytes:
    """Keep stdlib local-name/overlap checks; validate raw span, EOF, size and CRC."""
    with archive.open(member):
        pass
    source = archive.fp
    if source is None or not 0 <= member.compress_size <= container_limit:
        raise ValueError("ZIP compressed member extent exceeds the container limit")
    source.seek(member.header_offset)
    header = source.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ValueError("ZIP local member header is invalid")
    flags, method = struct.unpack_from("<2H", header, 6)
    if flags != member.flag_bits or method != member.compress_type:
        raise ValueError("ZIP local member flags or method differ from the central directory")
    name_size, extra_size = struct.unpack_from("<2H", header, 26)
    start = member.header_offset + 30 + name_size + extra_size
    if start < 0 or start + member.compress_size > archive.start_dir:
        raise ValueError("ZIP compressed member span overlaps the central directory")
    source.seek(start)
    try:
        decoder, remaining, errors = _decoder(source, member, member.compress_size)
    except ImportError as error:
        raise ValueError("ZIP compression codec is unavailable in this Python runtime") from error
    content = bytearray()
    while remaining:
        chunk = source.read(min(CHUNK, remaining))
        if not chunk:
            raise ValueError("ZIP member compressed stream is truncated")
        remaining -= len(chunk)
        pending = chunk
        while pending or decoder is not None and not getattr(decoder, "needs_input", True):
            allowance = min(CHUNK, limit - len(content) + 1)
            if decoder is None:
                decoded, pending = pending, b""
            else:
                try:
                    decoded = decoder.decompress(pending, allowance)
                except errors as error:
                    raise ValueError("ZIP member compression data is invalid") from error
                pending = decoder.unconsumed_tail if method == zipfile.ZIP_DEFLATED else b""
            content.extend(decoded)
            if len(content) > limit:
                raise ValueError("ZIP member exceeds declared size or decompression budget")
            if decoder is not None and decoder.eof:
                if decoder.unused_data or pending or remaining:
                    raise ValueError("ZIP member has trailing compressed data")
                break
    if decoder is not None and not decoder.eof:
        raise ValueError("ZIP member compressed stream is unfinished")
    if len(content) != member.file_size or zlib.crc32(content) & 0xFFFFFFFF != member.CRC:
        raise ValueError("ZIP complete member size or CRC differs from its declaration")
    return bytes(content)
