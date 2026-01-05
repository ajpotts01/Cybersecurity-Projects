from typing import Any


def clean_value(value: Any) -> str:
    """
    Helper to make raw EXIF data human-readable.
    """
    # Decode bytes (e.g., b'samsung' -> 'samsung')
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8").strip()
        except UnicodeDecodeError:
            return str(value)

    # Format Tuples (e.g., (1, 50) -> '1/50')
    if isinstance(value, tuple) or isinstance(value, list):
        return "/".join(map(str, value))

    # Handle empty values
    if value == "":
        return "-"

    return str(value)
