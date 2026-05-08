"""File renaming based on detected archive format."""

from pathlib import Path
from typing import Optional
import re

from .detector import detect_with_tar_combo
from .split_detector import is_split_archive


def suggest_extension(filepath: str | Path) -> Optional[str]:
    """Determine the correct primary extension for an archive file.

    Returns the extension string (e.g. '.zip', '.rar', '.tar.gz'), or None if unknown.
    """
    info = detect_with_tar_combo(filepath)
    if info is None:
        return None
    return info.extensions[0]


def needs_rename(filepath: str | Path) -> bool:
    """Check if a file has an incorrect extension for its detected format.

    Split archives (.001, .part1.rar, .r00 etc.) are never renamed
    since their naming pattern is already correct for extraction.
    """
    path = Path(filepath)

    # Split archives have valid naming — don't touch them
    if is_split_archive(path):
        return False

    suggested = suggest_extension(path)
    if suggested is None:
        return False

    # If name already ends with the correct extension, no rename needed
    name_lower = path.name.lower()
    info = detect_with_tar_combo(path)
    if info is None:
        return False

    for ext in info.extensions:
        if name_lower.endswith(ext.lower()):
            return False

    return True


def get_correct_path(filepath: str | Path) -> Optional[Path]:
    """Get the path with the correct extension.

    Returns None if format can't be detected, extension is already correct,
    or the file is a split archive.
    """
    path = Path(filepath)

    # Split archives should not be renamed
    if is_split_archive(path):
        return None

    suggested = suggest_extension(path)
    if suggested is None:
        return None

    name_lower = path.name.lower()
    if name_lower.endswith(suggested.lower()):
        return None

    # Build new name: strip known extensions, then add correct one
    stem = path.name
    for test_ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst",
                     ".tgz", ".tbz2", ".txz",
                     ".gz", ".bz2", ".xz", ".zst", ".lz4",
                     ".zip", ".rar", ".7z", ".cab", ".iso",
                     ".arj", ".lzh", ".lha", ".gzip", ".bzip2", ".zstd",
                     ".tar", ".r00", ".r01"]:
        if stem.lower().endswith(test_ext):
            stem = stem[:-len(test_ext)]
            break

    # Strip .partN suffix if present
    stem = re.sub(r'\.part\d+$', '', stem, flags=re.IGNORECASE)

    new_name = stem + suggested
    return path.with_name(new_name)
