"""Archive format detection via magic bytes."""

from pathlib import Path
from typing import Optional

from .signatures import (
    SIGNATURES, FormatInfo,
    TAR_MAGIC_OFFSET, TAR_MAGICS,
    ISO_OFFSETS, ISO_MAGIC,
)


def detect(filepath: str | Path) -> Optional[FormatInfo]:
    """Detect archive format by reading magic bytes.

    Returns FormatInfo if recognized, None otherwise.
    """
    path = Path(filepath)
    if not path.is_file():
        return None

    size = path.stat().st_size
    if size < 2:
        return None

    try:
        with open(path, "rb") as f:
            header = f.read(512)
    except OSError:
        return None

    # Check standard signatures
    for magic, offset, info in SIGNATURES:
        end = offset + len(magic)
        if len(header) >= end and header[offset:end] == magic:
            return info

    # Check TAR (ustar at offset 257)
    if len(header) > TAR_MAGIC_OFFSET:
        for tm in TAR_MAGICS:
            end = TAR_MAGIC_OFFSET + len(tm)
            if len(header) >= end and header[TAR_MAGIC_OFFSET:end] == tm:
                return FormatInfo("TAR", [".tar"], "application/x-tar")

    # Check ISO 9660 (CD001 at deep offsets)
    if size >= max(ISO_OFFSETS) + 5:
        try:
            with open(path, "rb") as f:
                for off in ISO_OFFSETS:
                    f.seek(off)
                    if f.read(5) == ISO_MAGIC:
                        return FormatInfo("ISO", [".iso"], "application/x-iso9660-image")
        except OSError:
            pass

    return None


def is_archive(filepath: str | Path) -> bool:
    """Check if a file is a recognized archive."""
    return detect(filepath) is not None


def detect_with_tar_combo(filepath: str | Path) -> Optional[FormatInfo]:
    """Detect format, recognizing tar.* combinations (e.g. tar.gz -> TAR.GZ)."""
    path = Path(filepath)
    result = detect(path)
    if result is None:
        return None

    # Check for common combos like .tar.gz, .tar.bz2, .tar.xz, .tar.zst
    name = path.name.lower()
    combo_map = {
        ".tar.gz": FormatInfo("TAR.GZ", [".tar.gz"], "application/gzip"),
        ".tar.bz2": FormatInfo("TAR.BZ2", [".tar.bz2"], "application/x-bzip2"),
        ".tar.xz": FormatInfo("TAR.XZ", [".tar.xz"], "application/x-xz"),
        ".tar.zst": FormatInfo("TAR.ZST", [".tar.zst"], "application/zstd"),
        ".tgz": FormatInfo("TAR.GZ", [".tgz", ".tar.gz"], "application/gzip"),
        ".tbz2": FormatInfo("TAR.BZ2", [".tbz2", ".tar.bz2"], "application/x-bzip2"),
        ".txz": FormatInfo("TAR.XZ", [".txz", ".tar.xz"], "application/x-xz"),
    }

    for suffix, info in combo_map.items():
        if name.endswith(suffix):
            return info

    return result
