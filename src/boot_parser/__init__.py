"""Android Boot and Vendor Boot image parser and unpacker."""

from boot_parser.cli import main
from boot_parser.extractor import BootImageExtractor
from boot_parser.models import (
    BootImageMetadata,
    ImageType,
    PayloadEntry,
    VendorRamdiskTableEntry,
)
from boot_parser.parser import BootImageParser

__version__ = "0.1.0"
__all__ = [
    "BootImageExtractor",
    "BootImageMetadata",
    "BootImageParser",
    "ImageType",
    "PayloadEntry",
    "VendorRamdiskTableEntry",
    "main",
]
