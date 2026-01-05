from typing import Any, Dict

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.utils.formatter import clean_value

console = Console()


def print_metadata_table(metadata: Dict[str, Any]):
    """
    Displays metadata organized by logical groups.
    """

    # Define the groups using simple lists of keys
    groups = {
        "📸 Device Info": ["Make", "Model", "Software", "ExifVersion"],
        "⚙️ Exposure Settings": [
            "ExposureTime",
            "FNumber",
            "ISOSpeedRatings",
            "ShutterSpeedValue",
            "ApertureValue",
            "Flash",
            "FocalLength",
        ],
        "🖼️ Image Data": [
            "ImageWidth",
            "ImageLength",
            "PixelXDimension",
            "PixelYDimension",
            "Orientation",
            "ResolutionUnit",
        ],
        "📅 Dates": ["DateTime", "DateTimeOriginal", "DateTimeDigitized", "OffsetTime"],
    }

    # Create the main table
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    # Track which keys we have displayed to handle the "leftovers"
    displayed_keys = set()

    # Loop through the defined groups to create sections
    for section_name, keys in groups.items():
        # Check if we have any data for this section
        section_data = {k: metadata[k] for k in keys if k in metadata}

        if section_data:
            # Add a section row (acts as a sub-header)
            table.add_row(Text(section_name, style="bold yellow"), "")

            for key, val in section_data.items():
                table.add_row(f"  {key}", clean_value(val))
                displayed_keys.add(key)

            # Add a blank row for spacing
            table.add_section()

    # Handle "Other" (Any keys that isn't in the groups)
    leftovers = {
        k: v
        for k, v in metadata.items()
        if k not in displayed_keys and k != "JPEGInterchangeFormat"
    }  # skip binary blobs
    if leftovers:
        table.add_row(Text("📝 Other", style="bold yellow"), "")
        for key, val in leftovers.items():
            table.add_row(f"  {key}", clean_value(val))

    # Print nicely inside a panel
    console.print(
        Panel(table, title="Metadata Report", border_style="blue", expand=False)
    )
