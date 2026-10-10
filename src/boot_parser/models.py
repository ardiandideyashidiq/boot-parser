"""Data models representing parsed Android boot image structures and metadata."""

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ImageType(StrEnum):
    BOOT = "boot"
    VENDOR_BOOT = "vendor_boot"


class RamdiskType(StrEnum):
    NONE = "none"
    PLATFORM = "platform"
    RECOVERY = "recovery"
    DLKM = "dlkm"
    UNKNOWN = "unknown"

    @classmethod
    def from_int(cls, val: int) -> "RamdiskType":
        match val:
            case 0:
                return cls.NONE
            case 1:
                return cls.PLATFORM
            case 2:
                return cls.RECOVERY
            case 3:
                return cls.DLKM
            case _:
                return cls.UNKNOWN


@dataclass(slots=True)
class PayloadEntry:
    name: str
    file_offset: int
    size: int
    padded_size: int
    output_filename: str


@dataclass(slots=True)
class VendorRamdiskTableEntry:
    ramdisk_name: str
    ramdisk_type: str
    ramdisk_size: int
    ramdisk_offset: int
    board_ids: list[int] = field(default_factory=list)


@dataclass(slots=True)
class BootImageMetadata:
    image_type: ImageType
    magic: str
    magic_offset: int
    header_version: int
    header_size: int
    page_size: int
    cmdline: str
    board_name: str
    base_address: int | None = None
    kernel_offset: int | None = None
    ramdisk_offset: int | None = None
    second_offset: int | None = None
    tags_offset: int | None = None
    dtb_offset: int | None = None
    recovery_dtbo_offset: int | None = None
    os_version: str | None = None
    os_patch_level: str | None = None
    hash_type: str | None = None
    payloads: list[PayloadEntry] = field(default_factory=list)
    vendor_ramdisk_table: list[VendorRamdiskTableEntry] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to a serializable dictionary."""
        d = asdict(self)
        d["image_type"] = self.image_type.value
        return d
