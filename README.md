# boot-parser

Parse and unpack Android `boot.img` (v0–v4) and `vendor_boot.img` (v3–v4).

## Install

```bash
uv tool install https://github.com/ardiandideyashidiq/boot-parser
```

Or for local development:

```bash
uv sync
```

## Usage

```bash
# Unpack image (extracts payloads + ramdisk to ./<image>_unpacked)
boot-parser boot.img

# Extract to a specific folder
uv run boot-parser vendor_boot.img -o ./out

# Print JSON metadata only
uv run boot-parser vendor_boot.img --json
```

### Options

- `-o, --output <dir>`: Target folder (default: `./<image>_unpacked`)
- `--json`: Print metadata JSON to stdout
- `--no-unpack-ramdisk`: Save raw compressed ramdisk without unpacking files
- `-v, --debug`: Verbose logs
- `-q, --quiet`: Quiet mode

## Python API

```python
from boot_parser import BootImageParser, BootImageExtractor

with BootImageParser.from_file("boot.img") as parser:
    extractor = BootImageExtractor(parser, out_dir="./out")
    metadata, files = extractor.extract()
```

## Test

```bash
uv run pytest
```

## Credits

- **AOSP**: Android boot image format specifications and `bootimg.h`.
- **osm0sis @ xda-developers**: [Android Image Kitchen](https://github.com/osm0sis/Android-Image-Kitchen) and [mkbootimg](https://github.com/osm0sis/mkbootimg) reference tools.
