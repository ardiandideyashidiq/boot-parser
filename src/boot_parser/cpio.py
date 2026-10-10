"""Pure-Python SVR4 (newc / crc) CPIO archive parser and unpacker."""

import io
import os
import stat
from pathlib import Path
from typing import BinaryIO

from boot_parser.exceptions import CpioExtractionError

CPIO_HEADER_SIZE = 110
TRAILER = "TRAILER!!!"


def is_safe_path(base_dir: Path, path: Path) -> bool:
    """Ensure the path stays strictly within base_dir without following symlinks."""
    for part in path.parts:
        if part in ("..", "/", "\\"):
            return False
    return not path.is_absolute()


def extract_cpio(stream: BinaryIO | bytes, out_dir: Path) -> int:
    """Extract a SVR4 CPIO archive (supporting concatenated archives) into out_dir safely.

    Returns:
        Number of extracted entries.
    """
    if isinstance(stream, bytes):
        f = io.BytesIO(stream)
    else:
        f = stream

    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    while True:
        # Read next potential header or skip padding between concatenated archives
        hdr_bytes = f.read(CPIO_HEADER_SIZE)
        if len(hdr_bytes) < CPIO_HEADER_SIZE:
            break

        magic = hdr_bytes[:6]
        if magic not in (b"070701", b"070702"):
            # Check if there is padding preceding another CPIO header
            f.seek(-len(hdr_bytes), io.SEEK_CUR)
            chunk = f.read(512)
            if not chunk:
                break
            # Find next magic
            m1 = chunk.find(b"070701")
            m2 = chunk.find(b"070702")
            found = -1
            if m1 != -1 and (m2 == -1 or m1 <= m2):
                found = m1
            elif m2 != -1:
                found = m2

            if found != -1:
                f.seek(-len(chunk) + found, io.SEEK_CUR)
                continue
            else:
                # No more CPIO headers found
                break

        try:
            mode = int(hdr_bytes[14:22], 16)
            filesize = int(hdr_bytes[54:62], 16)
            namesize = int(hdr_bytes[94:102], 16)
        except ValueError as err:
            raise CpioExtractionError(f"Malformed CPIO header integer: {err}") from err

        raw_name = f.read(namesize)
        # SVR4 aligns header + namesize to 4-byte boundary
        pad_name = (4 - ((CPIO_HEADER_SIZE + namesize) % 4)) % 4
        if pad_name:
            f.read(pad_name)

        name = raw_name.rstrip(b"\x00").decode("utf-8", errors="replace")

        # Read payload data
        data = f.read(filesize)
        # SVR4 aligns filesize to 4-byte boundary
        pad_data = (4 - (filesize % 4)) % 4
        if pad_data:
            f.read(pad_data)

        if name == TRAILER:
            # Reached end of one archive member; check if more concatenated archives follow
            continue

        rel_path = Path(name)
        if not is_safe_path(out_dir, rel_path):
            raise CpioExtractionError(
                f"Insecure path traversal detected in CPIO: {name}"
            )

        target_path = out_dir / rel_path

        # If an existing symlink or file exists at target_path, unlink it first
        # so we do not follow an existing symlink outside the tree
        if target_path.is_symlink() or (
            target_path.exists() and not (stat.S_ISDIR(mode) and target_path.is_dir())
        ):
            try:
                target_path.unlink()
            except OSError:
                pass

        # Handle file types
        if stat.S_ISDIR(mode):
            target_path.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(target_path, stat.S_IMODE(mode))
            except OSError:
                pass
        elif stat.S_ISLNK(mode):
            target_path.parent.mkdir(parents=True, exist_ok=True)
            link_target = data.decode("utf-8", errors="replace")
            try:
                target_path.symlink_to(link_target)
            except OSError:
                # If symlink creation fails, write target text
                target_path.write_text(link_target, encoding="utf-8")
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(data)
            try:
                os.chmod(target_path, stat.S_IMODE(mode))
            except OSError:
                pass

        count += 1

    return count
