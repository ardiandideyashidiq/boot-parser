"""Unit tests for clean-room boot-parser implementation."""

import struct
from io import BytesIO
from pathlib import Path

from boot_parser.constants import (
    BOOT_MAGIC,
    BOOT_V3_PAGE_SIZE,
    VENDOR_BOOT_MAGIC,
)
from boot_parser.cpio import extract_cpio
from boot_parser.decompress import decompress_data, detect_compression
from boot_parser.exceptions import MagicNotFoundError
from boot_parser.models import ImageType
from boot_parser.parser import BootImageParser, align_up, parse_os_version


def test_align_up() -> None:
    assert align_up(0, 4096) == 0
    assert align_up(1, 4096) == 4096
    assert align_up(4096, 4096) == 4096
    assert align_up(4097, 4096) == 8192


def test_parse_os_version() -> None:
    # A=12, B=0, C=0, Y=2024 (24), M=2
    # os_version = A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0]
    val = (12 << 25) | (0 << 18) | (0 << 11) | (24 << 4) | 2
    ver, patch = parse_os_version(val)
    assert ver == "12.0.0"
    assert patch == "2024-02"


def test_magic_not_found() -> None:
    buf = BytesIO(b"RANDOM_BYTES" * 100)
    parser = BootImageParser(buf)
    try:
        parser.parse()
    except MagicNotFoundError:
        pass
    else:
        raise AssertionError("Expected MagicNotFoundError was not raised")


def test_synthetic_boot_v3() -> None:
    buf = bytearray(8192)
    # Magic
    buf[0:8] = BOOT_MAGIC
    # kernel_size=1000, ramdisk_size=2000, os_version=0, header_size=1580, reserved (16 bytes), header_version=3
    struct.pack_into("<4I", buf, 8, 1000, 2000, 0, 1580)
    struct.pack_into("<I", buf, 40, 3)  # header_version
    cmdline = b"console=ttyS0"
    buf[44 : 44 + len(cmdline)] = cmdline

    parser = BootImageParser(BytesIO(buf))
    meta = parser.parse()
    assert meta.image_type == ImageType.BOOT
    assert meta.header_version == 3
    assert meta.page_size == BOOT_V3_PAGE_SIZE
    assert meta.cmdline == "console=ttyS0"
    assert len(meta.payloads) == 2
    assert meta.payloads[0].name == "kernel"
    assert meta.payloads[0].file_offset == 4096
    assert meta.payloads[0].size == 1000
    assert meta.payloads[1].name == "ramdisk"
    assert meta.payloads[1].file_offset == 8192
    assert meta.payloads[1].size == 2000


def test_synthetic_vendor_boot_v3() -> None:
    buf = bytearray(8192)
    buf[0:8] = VENDOR_BOOT_MAGIC
    # header_version=3, page_size=2048, kernel_addr=0x10008000, ramdisk_addr=0x11000000, vendor_ramdisk_size=500
    struct.pack_into("<5I", buf, 8, 3, 2048, 0x10008000, 0x11000000, 500)
    cmdline = b"bootopt=test"
    buf[28 : 28 + len(cmdline)] = cmdline
    # tags_addr=0x10000100, name="vendor", header_size=2112, dtb_size=300, dtb_addr=0x12000000
    struct.pack_into("<I", buf, 2076, 0x10000100)
    buf[2080 : 2080 + 6] = b"vendor"
    struct.pack_into("<IIQ", buf, 2096, 2112, 300, 0x12000000)

    parser = BootImageParser(BytesIO(buf))
    meta = parser.parse()
    assert meta.image_type == ImageType.VENDOR_BOOT
    assert meta.header_version == 3
    assert meta.page_size == 2048
    assert meta.cmdline == "bootopt=test"
    assert meta.base_address == 0x10000000
    assert meta.kernel_offset == 0x8000
    assert len(meta.payloads) == 2
    assert meta.payloads[0].name == "vendor_ramdisk"
    assert meta.payloads[0].size == 500
    assert meta.payloads[1].name == "dtb"
    assert meta.payloads[1].size == 300


def test_cpio_roundtrip(tmp_path: Path) -> None:
    import gzip

    # Generate small CPIO archive with one file
    name = b"test.txt"
    content = b"Hello, CPIO!"
    namesize = len(name) + 1
    filesize = len(content)

    # Header 110 bytes
    hdr = f"07070100000001000081a400000000000000000000000100000000{filesize:08x}00000000000000000000000000000000{namesize:08x}00000000".encode()
    pad_name = (4 - ((110 + namesize) % 4)) % 4
    pad_data = (4 - (filesize % 4)) % 4
    archive = (
        hdr + name + b"\x00" + (b"\x00" * pad_name) + content + (b"\x00" * pad_data)
    )

    # Trailer
    trailer_name = b"TRAILER!!!"
    t_namesize = len(trailer_name) + 1
    t_hdr = f"0707010000000000000000000000000000000000000001000000000000000000000000000000000000000000000000{t_namesize:08x}00000000".encode()
    t_pad_name = (4 - ((110 + t_namesize) % 4)) % 4
    archive += t_hdr + trailer_name + b"\x00" + (b"\x00" * t_pad_name)

    compressed = gzip.compress(archive)
    assert detect_compression(compressed) == "gzip"
    decomp, fmt = decompress_data(compressed)
    assert fmt == "gzip"

    extracted_count = extract_cpio(decomp, tmp_path)
    assert extracted_count == 1
    assert (tmp_path / "test.txt").read_bytes() == content


def test_real_vendor_boot_image() -> None:
    img_path = Path("/home/rd/tmp/android-image-kitchen-complete/vendor_boot.img")
    if not img_path.exists():
        return
    parser = BootImageParser.from_file(img_path)
    meta = parser.parse()
    assert meta.image_type == ImageType.VENDOR_BOOT
    assert meta.header_version == 4
    assert meta.header_size == 2128
    assert meta.page_size == 4096
    assert meta.base_address == 0x3FFF8000
    assert meta.kernel_offset == 0x8000
    assert meta.dtb_offset == 0x07C88000
    assert "bootopt=" in meta.cmdline
    assert len(meta.payloads) == 4
    assert len(meta.vendor_ramdisk_table) == 2


def test_real_boot_image() -> None:
    img_path = Path("/home/rd/tmp/android-image-kitchen-complete/boot.img")
    if not img_path.exists():
        return
    parser = BootImageParser.from_file(img_path)
    meta = parser.parse()
    assert meta.image_type == ImageType.BOOT
    assert meta.header_version == 2
    assert meta.page_size == 2048
    assert meta.os_version == "12.0.0"
    assert meta.os_patch_level == "2024-02"
    assert meta.base_address == 0x40078000
    assert len(meta.payloads) == 3


def test_cli_default_output_dir(tmp_path: Path, monkeypatch) -> None:
    from click.testing import CliRunner

    from boot_parser.cli import main

    img_path = Path("/home/rd/tmp/android-image-kitchen-complete/vendor_boot.img")
    if not img_path.exists():
        return

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, [str(img_path), "--no-unpack-ramdisk", "-q"])
    assert result.exit_code == 0
    expected_dir = tmp_path / "output" / f"{img_path.stem}_unpacked"
    assert expected_dir.is_dir()
    assert (expected_dir / "metadata.json").is_file()
