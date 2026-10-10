"""Custom exception classes for boot image parsing and extraction."""


class BootParserError(Exception):
    """Base exception for all boot-parser errors."""


class MagicNotFoundError(BootParserError):
    """Raised when neither ANDROID! nor VNDRBOOT magic is found within search window."""


class UnsupportedHeaderVersionError(BootParserError):
    """Raised when an unrecognized header version is encountered."""


class CorruptImageError(BootParserError):
    """Raised when an image is truncated or structure validation fails."""


class DecompressionError(BootParserError):
    """Raised when ramdisk decompression fails."""


class CpioExtractionError(BootParserError):
    """Raised when extracting CPIO archive fails or contains unsafe paths."""
