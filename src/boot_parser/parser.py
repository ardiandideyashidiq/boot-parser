"""Clean-room parser for Android Boot and Vendor Boot images."""

import struct
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Self

from boot_parser.constants import (
    BOOT_MAGIC,
    BOOT_V3_PAGE_SIZE,
    KERNEL_BASE_OFFSET,
    MAGIC_SEARCH_LIMIT,
    MAX_HEADER_VERSION,
    VENDOR_BOOT_MAGIC,
)
from boot_parser.exceptions import (
    CorruptImageError,
    MagicNotFoundError,
    UnsupportedHeaderVersionError,
)
from boot_parser.models import (
    BootImageMetadata,
    ImageType,
    PayloadEntry,
    RamdiskType,
    VendorRamdiskTableEntry,
)


def align_up(size: int, page_size: int) -> int:
    """Align size up to page_size boundary."""
    if page_size <= 0:
        return size
    return (size + page_size - 1) & ~(page_size - 1)


def parse_os_version(raw: int) -> tuple[str | None, str | None]:
    """Extract OS version (A.B.C) and security patch level (YYYY-MM)."""
    if raw == 0:
        return None, None

    os_version = raw >> 11
    os_patch_level = raw & 0x7FF

    a = (os_version >> 14) & 0x7F
    b = (os_version >> 7) & 0x7F
    c = os_version & 0x7F

    year = (os_patch_level >> 4) + 2000
    month = os_patch_level & 0xF

    if a < 128 and b < 128 and c < 128 and 2000 <= year < 2128 and 1 <= month <= 12:
        return f"{a}.{b}.{c}", f"{year}-{month:02d}"

    return None, None


def detect_hash_type(id_bytes: bytes) -> str:
    """Determine hash algorithm from id field."""
    # SHA-1 has zeroes in id[20] and higher (accommodating bootimg variants)
    for b in id_bytes[24:32]:
        if b != 0:
            return "sha256"
    return "sha1"


class BootImageParser:
    """Parser for Android boot and vendor_boot images."""

    def __init__(
        self, stream: BinaryIO, file_size: int | None = None, auto_close: bool = False
    ):
        self.stream = stream
        self.file_size = file_size
        self._auto_close = auto_close

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._auto_close and self.stream:
            self.stream.close()

    @classmethod
    def from_file(cls, path: Path | str) -> "BootImageParser":
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Image not found: {file_path}")
        f = file_path.open("rb")
        return cls(f, file_path.stat().st_size, auto_close=True)

    def parse(self) -> BootImageMetadata:
        """Scan for magic and parse image structure."""
        self.stream.seek(0)
        search_buf = self.stream.read(MAGIC_SEARCH_LIMIT)
        if not search_buf:
            raise CorruptImageError("Empty image file")

        magic_offset = -1
        image_type: ImageType | None = None

        boot_idx = search_buf.find(BOOT_MAGIC)
        vendor_idx = search_buf.find(VENDOR_BOOT_MAGIC)

        if boot_idx != -1 and (vendor_idx == -1 or boot_idx <= vendor_idx):
            magic_offset = boot_idx
            image_type = ImageType.BOOT
        elif vendor_idx != -1:
            magic_offset = vendor_idx
            image_type = ImageType.VENDOR_BOOT
        else:
            raise MagicNotFoundError(
                f"Neither {BOOT_MAGIC.decode()} nor {VENDOR_BOOT_MAGIC.decode()} magic found in first {MAGIC_SEARCH_LIMIT} bytes."
            )

        if image_type == ImageType.BOOT:
            return self._parse_boot_image(magic_offset)
        else:
            return self._parse_vendor_boot_image(magic_offset)

    def _parse_boot_image(self, magic_offset: int) -> BootImageMetadata:
        self.stream.seek(magic_offset)
        hdr_prefix = self.stream.read(44)
        if len(hdr_prefix) < 44:
            raise CorruptImageError("Truncated boot image header")

        (
            _kernel_size,
            _kernel_addr,
            _ramdisk_size,
            _ramdisk_addr,
            _second_size,
            _second_addr,
            _tags_addr,
            _page_size,
            ver_or_dt,
        ) = struct.unpack("<9I", hdr_prefix[8:44])

        if ver_or_dt in (3, 4):
            return self._parse_boot_v3_v4(magic_offset, ver_or_dt)
        else:
            return self._parse_boot_v0_v2(magic_offset, ver_or_dt)

    def _parse_boot_v0_v2(self, magic_offset: int, ver_or_dt: int) -> BootImageMetadata:
        # Full v2 header is 1660 bytes
        self.stream.seek(magic_offset)
        raw_hdr = self.stream.read(1660)
        if len(raw_hdr) < 1632:
            raise CorruptImageError("Truncated boot v0-v2 header")

        (
            _magic,
            kernel_size,
            kernel_addr,
            ramdisk_size,
            ramdisk_addr,
            second_size,
            second_addr,
            tags_addr,
            page_size,
            header_version,
            raw_os_version,
            raw_name,
            raw_cmdline,
            raw_id,
            raw_extra_cmdline,
        ) = struct.unpack("<8s7I2II16s512s32s1024s", raw_hdr[:1632])

        is_legacy_dt = header_version > MAX_HEADER_VERSION
        actual_header_version = 0 if is_legacy_dt else header_version
        dt_size = header_version if is_legacy_dt else 0

        recovery_dtbo_size = 0
        recovery_dtbo_offset = 0
        header_size = 1632
        dtb_size = 0
        dtb_addr = 0

        if actual_header_version >= 1 and len(raw_hdr) >= 1648:
            (recovery_dtbo_size, recovery_dtbo_offset, header_size) = struct.unpack(
                "<IQI", raw_hdr[1632:1648]
            )

        if actual_header_version >= 2 and len(raw_hdr) >= 1660:
            (dtb_size, dtb_addr) = struct.unpack("<IQ", raw_hdr[1648:1660])

        cmdline = raw_cmdline.rstrip(b"\x00").decode("utf-8", errors="replace")
        extra_cmdline = raw_extra_cmdline.rstrip(b"\x00").decode(
            "utf-8", errors="replace"
        )
        if extra_cmdline:
            cmdline = f"{cmdline} {extra_cmdline}".strip()

        board_name = raw_name.rstrip(b"\x00").decode("utf-8", errors="replace")
        os_ver, os_patch = parse_os_version(raw_os_version)
        hash_type = detect_hash_type(raw_id)

        base = kernel_addr - KERNEL_BASE_OFFSET

        # Layout offsets calculation
        # Header takes 1 page
        curr_offset = magic_offset + page_size
        payloads: list[PayloadEntry] = []

        if kernel_size > 0:
            padded = align_up(kernel_size, page_size)
            payloads.append(
                PayloadEntry("kernel", curr_offset, kernel_size, padded, "kernel")
            )
            curr_offset += padded

        if ramdisk_size > 0:
            padded = align_up(ramdisk_size, page_size)
            payloads.append(
                PayloadEntry(
                    "ramdisk", curr_offset, ramdisk_size, padded, "ramdisk.cpio"
                )
            )
            curr_offset += padded

        if second_size > 0:
            padded = align_up(second_size, page_size)
            payloads.append(
                PayloadEntry("second", curr_offset, second_size, padded, "second")
            )
            curr_offset += padded

        if actual_header_version == 0 and dt_size > 0:
            padded = align_up(dt_size, page_size)
            payloads.append(PayloadEntry("dt", curr_offset, dt_size, padded, "dt"))
            curr_offset += padded

        if actual_header_version >= 1 and recovery_dtbo_size > 0:
            padded = align_up(recovery_dtbo_size, page_size)
            rec_off = (
                magic_offset + recovery_dtbo_offset
                if recovery_dtbo_offset > 0
                else curr_offset
            )
            payloads.append(
                PayloadEntry(
                    "recovery_dtbo",
                    rec_off,
                    recovery_dtbo_size,
                    padded,
                    "recovery_dtbo",
                )
            )
            curr_offset = max(curr_offset, rec_off + padded)

        if actual_header_version >= 2 and dtb_size > 0:
            padded = align_up(dtb_size, page_size)
            payloads.append(PayloadEntry("dtb", curr_offset, dtb_size, padded, "dtb"))
            curr_offset += padded

        return BootImageMetadata(
            image_type=ImageType.BOOT,
            magic=BOOT_MAGIC.decode(),
            magic_offset=magic_offset,
            header_version=actual_header_version,
            header_size=header_size,
            page_size=page_size,
            cmdline=cmdline,
            board_name=board_name,
            base_address=base,
            kernel_offset=kernel_addr - base,
            ramdisk_offset=ramdisk_addr - base,
            second_offset=second_addr - base if second_size > 0 else None,
            tags_offset=tags_addr - base,
            dtb_offset=dtb_addr - base if dtb_size > 0 else None,
            recovery_dtbo_offset=recovery_dtbo_offset
            if recovery_dtbo_size > 0
            else None,
            os_version=os_ver,
            os_patch_level=os_patch,
            hash_type=hash_type,
            payloads=payloads,
            extra={"dt_size": dt_size} if dt_size > 0 else {},
        )

    def _parse_boot_v3_v4(self, magic_offset: int, version: int) -> BootImageMetadata:
        self.stream.seek(magic_offset)
        raw_hdr = self.stream.read(1584)
        if len(raw_hdr) < 1580:
            raise CorruptImageError("Truncated boot v3/v4 header")

        (
            _magic,
            kernel_size,
            ramdisk_size,
            raw_os_version,
            header_size,
            _res0,
            _res1,
            _res2,
            _res3,
            _header_version,
            raw_cmdline,
        ) = struct.unpack("<8s4I4II1536s", raw_hdr[:1580])

        signature_size = 0
        if version == 4 and len(raw_hdr) >= 1584:
            signature_size = struct.unpack("<I", raw_hdr[1580:1584])[0]

        cmdline = raw_cmdline.rstrip(b"\x00").decode("utf-8", errors="replace")
        os_ver, os_patch = parse_os_version(raw_os_version)

        page_size = BOOT_V3_PAGE_SIZE
        curr_offset = magic_offset + page_size
        payloads: list[PayloadEntry] = []

        if kernel_size > 0:
            padded = align_up(kernel_size, page_size)
            payloads.append(
                PayloadEntry("kernel", curr_offset, kernel_size, padded, "kernel")
            )
            curr_offset += padded

        if ramdisk_size > 0:
            padded = align_up(ramdisk_size, page_size)
            payloads.append(
                PayloadEntry(
                    "ramdisk", curr_offset, ramdisk_size, padded, "ramdisk.cpio"
                )
            )
            curr_offset += padded

        if version == 4 and signature_size > 0:
            padded = align_up(signature_size, page_size)
            payloads.append(
                PayloadEntry(
                    "boot_signature",
                    curr_offset,
                    signature_size,
                    padded,
                    "boot_signature",
                )
            )
            curr_offset += padded

        return BootImageMetadata(
            image_type=ImageType.BOOT,
            magic=BOOT_MAGIC.decode(),
            magic_offset=magic_offset,
            header_version=version,
            header_size=header_size,
            page_size=page_size,
            cmdline=cmdline,
            board_name="",
            os_version=os_ver,
            os_patch_level=os_patch,
            payloads=payloads,
            extra={"signature_size": signature_size} if signature_size > 0 else {},
        )

    def _parse_vendor_boot_image(self, magic_offset: int) -> BootImageMetadata:
        self.stream.seek(magic_offset)
        raw_hdr = self.stream.read(2128)
        if len(raw_hdr) < 2112:
            raise CorruptImageError("Truncated vendor boot header")

        (
            _magic,
            header_version,
            page_size,
            kernel_addr,
            ramdisk_addr,
            vendor_ramdisk_size,
            raw_cmdline,
            tags_addr,
            raw_name,
            header_size,
            dtb_size,
            dtb_addr,
        ) = struct.unpack("<8s5I2048sI16sIIQ", raw_hdr[:2112])

        if header_version not in (3, 4):
            raise UnsupportedHeaderVersionError(
                f"Unsupported vendor boot header version: {header_version}"
            )

        vendor_ramdisk_table_size = 0
        vendor_ramdisk_table_entry_num = 0
        bootconfig_size = 0

        if header_version == 4:
            if len(raw_hdr) < 2128:
                raise CorruptImageError("Truncated vendor boot v4 header")
            (
                vendor_ramdisk_table_size,
                vendor_ramdisk_table_entry_num,
                _vendor_ramdisk_table_entry_size,
                bootconfig_size,
            ) = struct.unpack("<4I", raw_hdr[2112:2128])

        cmdline = raw_cmdline.rstrip(b"\x00").decode("utf-8", errors="replace")
        board_name = raw_name.rstrip(b"\x00").decode("utf-8", errors="replace")
        base = kernel_addr - KERNEL_BASE_OFFSET

        # Layout sequence for vendor boot
        curr_offset = magic_offset + align_up(header_size, page_size)
        payloads: list[PayloadEntry] = []

        if vendor_ramdisk_size > 0:
            padded = align_up(vendor_ramdisk_size, page_size)
            payloads.append(
                PayloadEntry(
                    "vendor_ramdisk",
                    curr_offset,
                    vendor_ramdisk_size,
                    padded,
                    "vendor_ramdisk.cpio",
                )
            )
            curr_offset += padded

        if dtb_size > 0:
            padded = align_up(dtb_size, page_size)
            payloads.append(PayloadEntry("dtb", curr_offset, dtb_size, padded, "dtb"))
            curr_offset += padded

        vendor_table_entries: list[VendorRamdiskTableEntry] = []
        if header_version == 4:
            if vendor_ramdisk_table_size > 0:
                padded = align_up(vendor_ramdisk_table_size, page_size)
                payloads.append(
                    PayloadEntry(
                        "vendor_ramdisk_table",
                        curr_offset,
                        vendor_ramdisk_table_size,
                        padded,
                        "vendor_ramdisk_table",
                    )
                )

                # Parse the vendor ramdisk table entries if present
                self.stream.seek(curr_offset)
                table_bytes = self.stream.read(vendor_ramdisk_table_size)
                table_stream = BytesIO(table_bytes)
                entry_struct = "<3I32s16I"
                entry_len = struct.calcsize(entry_struct)  # 108 bytes

                for _ in range(vendor_ramdisk_table_entry_num):
                    if len(table_bytes) < entry_len:
                        break
                    chunk = table_stream.read(entry_len)
                    if len(chunk) < entry_len:
                        break
                    res = struct.unpack(entry_struct, chunk)
                    rd_size, rd_off, rd_type, rd_raw_name = (
                        res[0],
                        res[1],
                        res[2],
                        res[3],
                    )
                    board_ids = list(res[4:])
                    rd_name = rd_raw_name.rstrip(b"\x00").decode(
                        "utf-8", errors="replace"
                    )
                    vendor_table_entries.append(
                        VendorRamdiskTableEntry(
                            ramdisk_name=rd_name,
                            ramdisk_type=RamdiskType.from_int(rd_type).value,
                            ramdisk_size=rd_size,
                            ramdisk_offset=rd_off,
                            board_ids=board_ids,
                        )
                    )
                curr_offset += padded

            if bootconfig_size > 0:
                padded = align_up(bootconfig_size, page_size)
                payloads.append(
                    PayloadEntry(
                        "bootconfig", curr_offset, bootconfig_size, padded, "bootconfig"
                    )
                )
                curr_offset += padded

        return BootImageMetadata(
            image_type=ImageType.VENDOR_BOOT,
            magic=VENDOR_BOOT_MAGIC.decode(),
            magic_offset=magic_offset,
            header_version=header_version,
            header_size=header_size,
            page_size=page_size,
            cmdline=cmdline,
            board_name=board_name,
            base_address=base,
            kernel_offset=kernel_addr - base,
            ramdisk_offset=ramdisk_addr - base,
            tags_offset=tags_addr - base,
            dtb_offset=dtb_addr - base if dtb_size > 0 else None,
            payloads=payloads,
            vendor_ramdisk_table=vendor_table_entries,
            extra={
                "bootconfig_size": bootconfig_size,
                "vendor_ramdisk_table_size": vendor_ramdisk_table_size,
            }
            if header_version == 4
            else {},
        )
