"""
PDF metadata handler for PDF files.
Does not support encrypted files.

This module provides the PdfHandler class which implements the MetadataHandler
interface for PDF files. It delegates the actual metadata operations to
format-specific processors (PdfProcessor).
"""

import shutil
from pathlib import Path

from pypdf import PdfReader, PdfWriter

from src.services.metadata_handler import MetadataHandler
from src.utils.exceptions import (
    MetadataNotFoundError,
    MetadataReadingError,
    UnsupportedFormatError,
)


class PDFHandler(MetadataHandler):
    """
    PDF metadata handler for PDF files.
    """

    def __init__(self, filepath: str):
        """
        Initialize the pdf handler.

        Args:
            filepath: Path to the pdf file to process.
        """
        super().__init__(filepath)
        self.keys_to_delete: list[str] = []

    def _detect_format(self) -> str:
        """
        Detect actual pdf format using, not file extension.

        Returns:
            Normalized format string ('pdf').

        Raises:
            UnsupportedFormatError: If format is not supported or undetectable.
        """
        normalise = Path(self.filepath).suffix.lower()
        if normalise != ".pdf":
            raise UnsupportedFormatError(f"Unsupported format: {normalise}")

        return normalise[1:]

    def read(self):
        """
        Extract metadata from the file.

        Uses actual format detection to select the appropriate processor.
        """
        with PdfReader(Path(self.filepath)) as reader:
            if reader.is_encrypted:
                raise MetadataReadingError("File is encrypted.")

            if reader.metadata is None:
                raise MetadataNotFoundError("No metadata found in the file.")

            for key, value in reader.metadata.items():
                self.metadata[key] = value
                self.keys_to_delete.append(key)
        return self.metadata

    def wipe(self) -> None:
        """
        Remove metadata from PDF file.
        """
        with PdfReader(Path(self.filepath)) as reader:
            metadata = reader.metadata
            if metadata is None:
                raise MetadataNotFoundError("No metadata found in the file.")

            for key in list(metadata):
                if key in self.keys_to_delete:
                    del metadata[key]

            self.processed_metadata = metadata

    def save(self, output_path: str | Path | None = None) -> None:
        """
        Save the changes to a copy of the original file.
        """
        destination_file_path = Path(output_path) if output_path else None
        if not destination_file_path:
            raise ValueError("output_path is required")

        shutil.copy2(self.filepath, destination_file_path)
        with PdfReader(destination_file_path) as reader, PdfWriter() as writer:
            # Copy all pages
            for page in reader.pages:
                writer.add_page(page)

            writer.add_metadata(self.processed_metadata)
            writer.write(destination_file_path)
