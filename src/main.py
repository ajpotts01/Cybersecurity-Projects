import logging

import typer

from src.commands.read import get_metadata
from src.utils.logger import setup_logging

# Initialize the app and the console
app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
log = logging.getLogger("metadata-scrubber")


# fmt: off
@app.callback()
def main(
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed debug logs for every file processed.",
    ),
):
    """
    Metadata Scrubber Tool - Clean your images privacy data.
    """
    # Initialize the logger based on the user's flag
    setup_logging(verbose)

    if verbose:
        log.debug("🐛 Verbose mode enabled. Detailed logs active.")
# fmt: on

# register commands
app.command(name="get-metadata")(get_metadata)

# run app
if __name__ == "__main__":
    app()
