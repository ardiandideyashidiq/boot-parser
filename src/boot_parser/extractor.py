"""Payload extraction coordinator for Android boot and vendor_boot images."""

import json
from pathlib import Path

from loguru import logger

from boot_parser.cpio import extract_cpio
from boot_parser.decompress import decompress_data, detect_compression
from boot_parser.models import BootImageMetadata
from boot_parser.parser import BootImageParser


def get_compression_extension(comp_type: str) -> str:
    """Return standard file extension for compression type."""
    match comp_type:
        case "gzip":
            return ".gz"
        case "lz4" | "lz4_legacy":
            return ".lz4"
        case "xz":
            return ".xz"
        case "zstd":
            return ".zst"
        case "bzip2":
            return ".bz2"
        case "lzma":
            return ".lzma"
        case _:
            return ""


class BootImageExtractor:
    """Coordinates extraction of payloads, ramdisk decompression, and metadata serialization."""

    def __init__(
        self, parser: BootImageParser, out_dir: Path | str, unpack_ramdisk: bool = True
    ):
        self.parser = parser
        self.out_dir = Path(out_dir)
        self.unpack_ramdisk = unpack_ramdisk

    def extract(self) -> tuple[BootImageMetadata, dict[str, Path]]:
        """Extract all payloads, ramdisk contents, and save metadata.json.

        Returns:
            Tuple of (BootImageMetadata, dict of extracted artifact name -> Path)
        """
        self.out_dir.mkdir(parents=True, exist_ok=True)
        metadata = self.parser.parse()
        extracted_files: dict[str, Path] = {}

        logger.info(f"Extracting {metadata.image_type.value} image to {self.out_dir}")

        for payload in metadata.payloads:
            self.parser.stream.seek(payload.file_offset)
            raw_data = self.parser.stream.read(payload.size)

            if "ramdisk" in payload.name and not payload.name.endswith("table"):
                comp_type = detect_compression(raw_data)
                ext = get_compression_extension(comp_type)
                # Output filename with accurate extension
                archive_name = (
                    f"{payload.name}{ext}"
                    if not payload.name.endswith(".cpio")
                    else f"{payload.name[:-5]}.cpio{ext}"
                )
                target_path = self.out_dir / archive_name
                target_path.write_bytes(raw_data)
                extracted_files[payload.name] = target_path
                logger.debug(f"Saved {archive_name} ({len(raw_data)} bytes)")

                if self.unpack_ramdisk:
                    logger.info(
                        f"Decompressing and unpacking {payload.name} ({comp_type})..."
                    )
                    decomp_bytes, _detected_fmt = decompress_data(raw_data)
                    ramdisk_dir = self.out_dir / "ramdisk"
                    count = extract_cpio(decomp_bytes, ramdisk_dir)
                    extracted_files["ramdisk_dir"] = ramdisk_dir
                    logger.info(
                        f"Unpacked {count} files/directories into {ramdisk_dir}"
                    )

                # If vendor ramdisk table exists, also save individual table slices
                if metadata.vendor_ramdisk_table:
                    for entry in metadata.vendor_ramdisk_table:
                        sub_name = entry.ramdisk_name or entry.ramdisk_type
                        sub_raw = raw_data[
                            entry.ramdisk_offset : entry.ramdisk_offset
                            + entry.ramdisk_size
                        ]
                        sub_comp = detect_compression(sub_raw)
                        sub_ext = get_compression_extension(sub_comp)
                        sub_filename = f"vendor_ramdisk_{sub_name}.cpio{sub_ext}"
                        sub_path = self.out_dir / sub_filename
                        sub_path.write_bytes(sub_raw)
                        extracted_files[f"vendor_ramdisk_{sub_name}"] = sub_path
                        logger.debug(
                            f"Saved individual slice {sub_filename} ({len(sub_raw)} bytes)"
                        )

            else:
                target_path = self.out_dir / payload.output_filename
                target_path.write_bytes(raw_data)
                extracted_files[payload.name] = target_path
                logger.debug(f"Saved {payload.output_filename} ({len(raw_data)} bytes)")

        # Save metadata.json
        meta_json_path = self.out_dir / "metadata.json"
        meta_json_path.write_text(
            json.dumps(metadata.to_dict(), indent=2), encoding="utf-8"
        )
        extracted_files["metadata.json"] = meta_json_path
        logger.info(f"Saved metadata to {meta_json_path}")

        return metadata, extracted_files
