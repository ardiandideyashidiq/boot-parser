"""Constants and magic signatures for Android Boot and Vendor Boot images."""

# Magic signatures
BOOT_MAGIC = b"ANDROID!"
BOOT_MAGIC_SIZE = 8

VENDOR_BOOT_MAGIC = b"VNDRBOOT"
VENDOR_BOOT_MAGIC_SIZE = 8

# Maximum search window for magic signature (in bytes)
MAGIC_SEARCH_LIMIT = 65536

# Maximum header version threshold.
# Values greater than 8 in v0 header_version position indicate legacy dt_size.
MAX_HEADER_VERSION = 8

# Standard field buffer sizes
BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024
BOOT_V3_ARGS_SIZE = BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE  # 1536

VENDOR_BOOT_NAME_SIZE = 16
VENDOR_BOOT_ARGS_SIZE = 2048

# Fixed page size for v3/v4 boot.img
BOOT_V3_PAGE_SIZE = 4096

# Kernel base offset deduction constant (0x00008000)
KERNEL_BASE_OFFSET = 0x00008000

# Vendor Ramdisk v4 constants
VENDOR_RAMDISK_TYPE_NONE = 0
VENDOR_RAMDISK_TYPE_PLATFORM = 1
VENDOR_RAMDISK_TYPE_RECOVERY = 2
VENDOR_RAMDISK_TYPE_DLKM = 3

VENDOR_RAMDISK_NAME_SIZE = 32
VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE = 16  # 16 * 4 bytes = 64 bytes
