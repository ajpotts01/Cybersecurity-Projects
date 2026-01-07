# 🔒 Metadata Scrubber

A privacy-focused CLI tool that removes sensitive metadata (EXIF, GPS, author info) from image files. Perfect for protecting your privacy before sharing photos online.

[![Tests](https://github.com/Heritage-XioN/metadata-scrubber-tool/actions/workflows/test.yml/badge.svg)](https://github.com/Heritage-XioN/metadata-scrubber-tool/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## ✨ Features

- **Multi-format support** - JPEG, PNG (with PDF/Office planned)
- **Concurrent processing** - Process 1000+ files efficiently with ThreadPoolExecutor
- **Dry-run mode** - Preview what would be scrubbed without making changes
- **Smart format detection** - Uses Pillow's format detection, not just file extensions
- **Beautiful CLI** - Rich progress bars and formatted output
- **Privacy-first** - Removes GPS coordinates, camera info, timestamps, author data

## 🚀 Quick Start

### Installation

```bash
# Using uv (recommended)
uv pip install metadata-scrubber

# Or clone and install locally
git clone https://github.com/Heritage-XioN/metadata-scrubber-tool.git
cd metadata-scrubber-tool
uv sync
```

### Basic Usage

```bash
# Read metadata from a file
mst read photo.jpg

# Scrub metadata and save to output folder
mst scrub photo.jpg --output ./cleaned

# Batch process entire folder
mst scrub ./photos -r -ext jpg --output ./cleaned
```

## 📖 Commands

### `mst read` - View Metadata

```bash
mst read photo.jpg                      # Single file
mst read ./photos -r -ext jpg           # Directory (recursive)
```

### `mst scrub` - Remove Metadata

```bash
mst scrub photo.jpg --output ./out      # Single file
mst scrub ./photos -r -ext jpg -o ./out # Directory
mst scrub ./photos -r -ext jpg --dry-run # Preview only
mst scrub ./photos -r -ext jpg -w 8     # 8 concurrent workers
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-r`, `--recursive` | Process directories recursively |
| `-ext`, `--extension` | Filter by file extension (jpg, png) |
| `-o`, `--output` | Output directory for cleaned files |
| `-d`, `--dry-run` | Preview without making changes |
| `-w`, `--workers` | Number of concurrent workers |
| `-V`, `--verbose` | Show detailed debug logs |
| `-v`, `--version` | Show version |

## 🛠️ Development

### Setup

```bash
git clone https://github.com/Heritage-XioN/metadata-scrubber-tool.git
cd metadata-scrubber-tool

# Install with dev dependencies
uv sync --all-extras

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy src
```

### Project Structure

```
src/
├── main.py                 # CLI entry point (Typer app)
├── commands/
│   ├── read.py             # Read metadata command
│   └── scrub.py            # Scrub metadata command
├── services/
│   ├── metadata_factory.py # Factory for creating handlers
│   ├── image_handler.py    # JPEG/PNG handler
│   └── batch_processor.py  # Concurrent batch processing
└── core/
    ├── jpeg_metadata.py    # JPEG EXIF processor
    └── png_metadata.py     # PNG metadata processor
```

## ⚠️ Security Considerations

- **Original files are never modified** - processed copies are created
- **Use `--dry-run`** to preview changes before committing
- **GPS coordinates** are completely stripped for privacy
- **Always backup files** before scrubbing in production

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

Made with ❤️ for privacy
