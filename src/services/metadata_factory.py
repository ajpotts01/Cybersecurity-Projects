from pathlib import Path

from src.services.image_handler import ImageHandler


class MetadataFactory:
    @staticmethod
    def get_handler(filepath: str):
        ext = Path(filepath).suffix.lower()
        if Path(filepath).is_file():
            if ext in [".jpg", ".jpeg", ".png"]:
                return ImageHandler(filepath)

            # TODO: implement other handlers
            # elif ext == ".pdf":
            #     return PDFHandler(filepath)
            # elif ext == ".xlsx":
            #     return ExcelHandler(filepath)
            # elif ext == ".pptx":
            #     return PowerPointHandler(filepath)
            else:
                raise ValueError(f"No handler defined for {ext} files.")
        else:
            raise ValueError(
                f"{filepath} is not a file. if you want to process a directory, use the --recursive flag."
            )
