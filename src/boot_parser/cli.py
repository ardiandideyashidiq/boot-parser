"""Command-line interface for boot-parser using rich-click and rich."""

import json
import sys
from pathlib import Path

import rich_click as click
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from boot_parser.exceptions import BootParserError
from boot_parser.extractor import BootImageExtractor
from boot_parser.models import BootImageMetadata
from boot_parser.parser import BootImageParser

click.rich_click.TEXT_MARKUP = "rich"
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True

console = Console()


def format_size(size_bytes: int) -> str:
    """Format bytes into human-readable representation."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KiB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MiB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GiB"


def render_metadata_tables(metadata: BootImageMetadata) -> None:
    """Render beautiful Rich tables summarizing image structure."""
    header_table = Table(
        title=f"Android Image Header ({metadata.image_type.upper()})",
        show_header=True,
        header_style="bold cyan",
        title_style="bold magenta",
    )
    header_table.add_column("Property", style="bold yellow")
    header_table.add_column("Value", style="green")

    header_table.add_row(
        "Magic Signature", f"{metadata.magic} (offset: 0x{metadata.magic_offset:x})"
    )
    header_table.add_row("Header Version", str(metadata.header_version))
    header_table.add_row("Header Size", f"{metadata.header_size} bytes")
    header_table.add_row("Page Size", f"{metadata.page_size} bytes")

    if metadata.board_name:
        header_table.add_row("Board Name", metadata.board_name)
    if metadata.os_version:
        header_table.add_row("OS Version", metadata.os_version)
    if metadata.os_patch_level:
        header_table.add_row("OS Patch Level", metadata.os_patch_level)
    if metadata.hash_type:
        header_table.add_row("Hash Algorithm", metadata.hash_type)

    if metadata.base_address is not None:
        header_table.add_row("Base Address", f"0x{metadata.base_address:08x}")
    if metadata.kernel_offset is not None:
        header_table.add_row("Kernel Offset", f"0x{metadata.kernel_offset:08x}")
    if metadata.ramdisk_offset is not None:
        header_table.add_row("Ramdisk Offset", f"0x{metadata.ramdisk_offset:08x}")
    if metadata.second_offset is not None:
        header_table.add_row("Second Offset", f"0x{metadata.second_offset:08x}")
    if metadata.tags_offset is not None:
        header_table.add_row("Tags Offset", f"0x{metadata.tags_offset:08x}")
    if metadata.dtb_offset is not None:
        header_table.add_row("DTB Offset", f"0x{metadata.dtb_offset:08x}")
    if metadata.recovery_dtbo_offset is not None:
        header_table.add_row(
            "Recovery DTBO Offset", f"0x{metadata.recovery_dtbo_offset:08x}"
        )

    console.print(header_table)

    if metadata.cmdline:
        console.print(
            Panel(
                metadata.cmdline,
                title="[bold cyan]Kernel / Vendor Command Line[/bold cyan]",
                border_style="blue",
            )
        )

    # Payloads table
    if metadata.payloads:
        payload_table = Table(
            title="Image Payloads",
            show_header=True,
            header_style="bold cyan",
            title_style="bold magenta",
        )
        payload_table.add_column("Component", style="bold yellow")
        payload_table.add_column("File Offset", justify="right")
        payload_table.add_column("Size", justify="right", style="green")
        payload_table.add_column("Padded Size", justify="right")
        payload_table.add_column("Output File", style="cyan")

        for p in metadata.payloads:
            payload_table.add_row(
                p.name,
                f"0x{p.file_offset:x} ({p.file_offset})",
                f"{format_size(p.size)} ({p.size:,} B)",
                f"{format_size(p.padded_size)}",
                p.output_filename,
            )
        console.print(payload_table)

    # Vendor ramdisk table if present
    if metadata.vendor_ramdisk_table:
        v_table = Table(
            title="Vendor Ramdisk Table (v4)",
            show_header=True,
            header_style="bold cyan",
            title_style="bold magenta",
        )
        v_table.add_column("Name", style="bold yellow")
        v_table.add_column("Type", style="cyan")
        v_table.add_column("Offset", justify="right")
        v_table.add_column("Size", justify="right", style="green")

        for ventry in metadata.vendor_ramdisk_table:
            v_table.add_row(
                ventry.ramdisk_name or "(default)",
                ventry.ramdisk_type,
                f"{ventry.ramdisk_offset:,} B",
                f"{format_size(ventry.ramdisk_size)} ({ventry.ramdisk_size:,} B)",
            )
        console.print(v_table)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument(
    "image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "-o",
    "--output",
    "out_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory for extracted payloads and metadata (defaults to ./output/<image_name>_unpacked)",
)
@click.option(
    "--json",
    "emit_json",
    is_flag=True,
    default=False,
    help="Emit JSON metadata to standard output.",
)
@click.option(
    "--no-unpack-ramdisk",
    is_flag=True,
    default=False,
    help="Do not unpack CPIO ramdisk contents to a directory (only save compressed archive).",
)
@click.option(
    "-v",
    "--debug",
    is_flag=True,
    default=False,
    help="Enable verbose / debug logs.",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress table rendering (useful when writing scripts).",
)
def main(
    image_path: Path,
    out_dir: Path | None,
    emit_json: bool,
    no_unpack_ramdisk: bool,
    debug: bool,
    quiet: bool,
) -> None:
    """Android Boot and Vendor Boot image parser and unpacker.

    Supports AOSP boot.img (Header v0-v4) and vendor_boot.img (Header v3-v4).
    """
    logger.remove()
    if debug:
        logger.add(sys.stderr, level="DEBUG")
    else:
        logger.add(
            sys.stderr,
            level="INFO",
            format="<green>{time:HH:mm:ss}</green> | <level>{message}</level>",
        )

    if out_dir is None:
        stem = image_path.stem
        out_dir = Path.cwd() / "output" / f"{stem}_unpacked"

    try:
        with BootImageParser.from_file(image_path) as parser:
            extractor = BootImageExtractor(
                parser=parser,
                out_dir=out_dir,
                unpack_ramdisk=not no_unpack_ramdisk,
            )

            metadata, extracted_files = extractor.extract()

        if emit_json:
            click.echo(json.dumps(metadata.to_dict(), indent=2))
        elif not quiet:
            render_metadata_tables(metadata)
            console.print(
                Panel(
                    f"[bold green]Successfully extracted to:[/bold green] [bold cyan]{out_dir.resolve()}[/bold cyan]\n"
                    f"[bold yellow]Artifacts extracted:[/bold yellow] {len(extracted_files)} files/folders\n"
                    f"[bold yellow]Metadata saved:[/bold yellow] {out_dir / 'metadata.json'}",
                    title="[bold green]Extraction Complete[/bold green]",
                    border_style="green",
                )
            )

    except BootParserError as exc:
        if debug:
            logger.exception("Parser error")
        console.print(Panel(f"[bold red]Error:[/bold red] {exc}", border_style="red"))
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        if debug:
            logger.exception("Unexpected error")
        console.print(
            Panel(f"[bold red]Unexpected Failure:[/bold red] {exc}", border_style="red")
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
