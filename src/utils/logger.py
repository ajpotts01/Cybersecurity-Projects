import logging

from rich.logging import RichHandler


def setup_logging(verbose: bool = False):
    """
    - Default (Info): Shows main steps and errors.
    - Verbose (Debug): Shows file paths, extraction details, and raw values.
    """
    # Define the log level
    level = logging.DEBUG if verbose else logging.INFO

    # Configure the logger
    # remove existing handlers to avoid duplicate lines if the app restarts
    logging.getLogger().handlers.clear()

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True,  # Beautiful colorful stack traces
                markup=True,  # Allow [bold red] styles in logs
                show_path=False,  # Hide line number (cleaner for CLI tools)
            )
        ],
    )

    # Return the logger instance
    return logging.getLogger("metadata-scrubber")
