def get_target_files(input_path_str, ext: str):
    """Yields a list of files to process based on the input path. handles recursive searches"""
    # if input_path_str is a directory, yield all files with the specified extension
    if input_path_str.is_dir():
        yield from input_path_str.rglob(f"*.{ext}")
