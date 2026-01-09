"""
Pytest configuration and shared fixtures.

Provides cross-platform test file paths that work on both Windows and Linux (CI).
"""

from pathlib import Path

import pytest

# Get the tests directory (this file's parent)
TESTS_DIR = Path(__file__).parent
ASSETS_DIR = TESTS_DIR / "assets"
TEST_IMAGES_DIR = ASSETS_DIR / "test_images"
TEST_PDFS_DIR = ASSETS_DIR / "test_pdfs"


@pytest.fixture
def jpg_test_file() -> Path:
    """Return path to a JPG test file."""
    return TEST_IMAGES_DIR / "test_fuji.jpg"


@pytest.fixture
def png_test_file() -> Path:
    """Return path to a PNG test file."""
    return TEST_IMAGES_DIR / "generated_test_03.png"


@pytest.fixture
def test_images_dir() -> Path:
    """Return path to test images directory."""
    return TEST_IMAGES_DIR


# String versions for parametrize (which doesn't support fixtures directly)
def get_jpg_test_file() -> str:
    """Get JPG test file path as string."""
    return str(TEST_IMAGES_DIR / "test_fuji.jpg")


def get_png_test_file() -> str:
    """Get PNG test file path as string."""
    return str(TEST_IMAGES_DIR / "generated_test_03.png")


def get_test_images_dir() -> str:
    """Get test images directory path as string."""
    return str(TEST_IMAGES_DIR)


@pytest.fixture
def pdf_test_file() -> Path:
    """Return path to a PDF test file with metadata."""
    return TEST_PDFS_DIR / "sample.pdf"


@pytest.fixture
def test_pdfs_dir() -> Path:
    """Return path to test PDFs directory."""
    return TEST_PDFS_DIR


# String versions for parametrize (PDF)
def get_pdf_test_file() -> str:
    """Get PDF test file path as string."""
    return str(TEST_PDFS_DIR / "sample.pdf")


def get_large_pdf_test_file() -> str:
    """Get large PDF test file path as string."""
    return str(TEST_PDFS_DIR / "file-example_PDF_1MB.pdf")


def get_test_pdfs_dir() -> str:
    """Get test PDFs directory path as string."""
    return str(TEST_PDFS_DIR)
