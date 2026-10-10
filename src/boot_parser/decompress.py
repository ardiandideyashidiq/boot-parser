"""Automatic detection and decompression for ramdisk archives."""

import bz2
import gzip
import io
import lzma
import shutil
import struct
import subprocess

import lz4.block
import lz4.frame
import zstandard

from boot_parser.exceptions import DecompressionError

GZIP_MAGIC = b"\x1f\x8b"
LZ4_FRAME_MAGIC = b"\x04\x22\x4d\x18"
LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
BZIP2_MAGIC = b"BZh"
CPIO_NEWC_MAGIC = b"070701"
CPIO_CRC_MAGIC = b"070702"

LZ4_LEGACY_MAX_BLOCK_SIZE = 8 * 1024 * 1024  # 8 MB


def detect_compression(data: bytes) -> str:
    """Identify compression type from data magic bytes."""
    if data.startswith(GZIP_MAGIC):
        return "gzip"
    if data.startswith(LZ4_FRAME_MAGIC):
        return "lz4"
    if data.startswith(LZ4_LEGACY_MAGIC):
        return "lz4_legacy"
    if data.startswith(XZ_MAGIC):
        return "xz"
    if data.startswith(ZSTD_MAGIC):
        return "zstd"
    if data.startswith(BZIP2_MAGIC):
        return "bzip2"
    if data.startswith((CPIO_NEWC_MAGIC, CPIO_CRC_MAGIC)):
        return "cpio"
    return "unknown"


def _decompress_lz4_legacy(data: bytes) -> bytes:
    """Decompress an LZ4 legacy frame (magic 0x184c2102)."""
    # If system lz4 is present, attempt fast external decompression
    lz4_path = shutil.which("lz4")
    if lz4_path:
        try:
            proc = subprocess.run(
                [lz4_path, "-dcq", "-"],
                input=data,
                capture_output=True,
                check=True,
            )
            if proc.stdout:
                return proc.stdout
        except (subprocess.CalledProcessError, OSError):
            pass

    # Pure Python / lz4.block fallback
    out = bytearray()
    offset = 4  # skip 4-byte magic
    data_len = len(data)

    while offset < data_len:
        if offset + 4 > data_len:
            break
        (block_size,) = struct.unpack("<I", data[offset : offset + 4])
        offset += 4
        if block_size == 0:
            break

        block_data = data[offset : offset + block_size]
        offset += block_size

        try:
            decomp = lz4.block.decompress(
                block_data, uncompressed_size=LZ4_LEGACY_MAX_BLOCK_SIZE
            )
        except lz4.block.LZ4BlockError:
            # Fallback size estimation if block buffer exceeds 8MB
            decomp = lz4.block.decompress(
                block_data,
                uncompressed_size=max(LZ4_LEGACY_MAX_BLOCK_SIZE, block_size * 4),
            )

        out.extend(decomp)

    return bytes(out)


def decompress_data(data: bytes) -> tuple[bytes, str]:
    """Decompress raw ramdisk bytes based on detected magic signature.

    Returns:
        Tuple of (decompressed_bytes, format_name)
    """
    comp_type = detect_compression(data)

    try:
        match comp_type:
            case "gzip":
                # Handle potential multi-member gzip streams
                chunks = []
                f = io.BytesIO(data)
                while True:
                    try:
                        with gzip.GzipFile(fileobj=f) as gz:
                            chunk = gz.read()
                            if not chunk:
                                break
                            chunks.append(chunk)
                    except (gzip.BadGzipFile, EOFError, OSError):
                        break
                if chunks:
                    return b"".join(chunks), "gzip"
                return gzip.decompress(data), "gzip"

            case "lz4":
                return lz4.frame.decompress(data), "lz4"

            case "lz4_legacy":
                return _decompress_lz4_legacy(data), "lz4"

            case "xz":
                return lzma.decompress(data), "xz"

            case "zstd":
                dctx = zstandard.ZstdDecompressor()
                return dctx.decompress(data, max_output_size=1024 * 1024 * 512), "zstd"

            case "bzip2":
                return bz2.decompress(data), "bzip2"

            case "cpio":
                return data, "cpio"

            case _:
                try:
                    return lzma.decompress(data), "lzma"
                except (lzma.LZMAError, OSError):
                    pass
                return data, "raw"

    except Exception as exc:
        raise DecompressionError(
            f"Failed to decompress {comp_type} ramdisk: {exc}"
        ) from exc
