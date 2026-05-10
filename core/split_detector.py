"""Split/volume archive detection and grouping."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Optional


# Patterns for split archives, ordered by specificity
SPLIT_PATTERNS = [
    # name.part1.rar, name.part01.rar, name.part001.rar
    re.compile(r"^(?P<base>.+?)\.part(?P<num>\d+)\.(?P<ext>rar)$", re.IGNORECASE),
    # name.rar (first of name.rar + name.r00 + name.r01 ...)
    re.compile(r"^(?P<base>.+)\.rar$", re.IGNORECASE),
    # name.r00, name.r01 ... (must detect .rar first as primary)
    re.compile(r"^(?P<base>.+)\.r\d{2,}$", re.IGNORECASE),
    # name.zip.001, name.7z.001, name.tar.001 etc.
    re.compile(r"^(?P<base>.+)\.(?P<ext>zip|7z|rar|tgz|tar\.gz|tar\.bz2|tar\.xz|tar)\.(?P<num>\d{3,})$", re.IGNORECASE),
    # name.001, name.002 ... (generic, low priority)
    re.compile(r"^(?P<base>.+)\.(?P<num>\d{3,})$", re.IGNORECASE),
    # name.zip.001 -> .zip suffix pattern (same as above but keep)
    re.compile(r"^(?P<base>.+\.\w+)\.(?P<num>\d{3,})$", re.IGNORECASE),
    # 7z.001 pattern
    re.compile(r"^(?P<base>.+)\.7z\.(?P<num>\d+)$", re.IGNORECASE),
]


def _match_pattern(filename: str) -> Optional[tuple[str, re.Pattern, re.Match]]:
    """Try to match a filename against split volume patterns.

    Returns (base_name, pattern, match) or None.
    """
    for pat in SPLIT_PATTERNS:
        m = pat.match(filename)
        if m:
            return (m.group("base"), pat, m)
    return None


def is_split_archive(filepath: str | Path) -> bool:
    """Check if a file appears to be part of a split archive."""
    path = Path(filepath)
    name = path.name
    for pat in SPLIT_PATTERNS:
        if pat.match(name):
            return True
    return False


def find_volumes(filepath: str | Path) -> list[Path]:
    """Find all related split volumes for a given file.

    Scans the same directory for files matching the split pattern.
    Returns sorted list of volume paths.
    """
    path = Path(filepath).resolve()
    directory = path.parent
    name = path.name

    match_result = _match_pattern(name)
    if match_result is None:
        return [path]

    base, pat, match = match_result

    volumes = set()
    # Scan directory for matching files
    for f in directory.iterdir():
        if not f.is_file():
            continue
        m2 = pat.match(f.name)
        if m2 and m2.group("base") == base:
            volumes.add(f)

    if not volumes:
        volumes.add(path)

    # Sort volumes by number
    def _sort_key(p: Path) -> int:
        m = pat.match(p.name)
        if m:
            try:
                num_str = m.group("num")
                return int(num_str)
            except (IndexError, ValueError):
                pass
        # .rar files (first volume) get 0, .r00 is 0, .r01 is 1
        if re.match(r".+\.rar$", p.name, re.IGNORECASE):
            return 0
        rxx = re.match(r".+\.r(\d{2,})$", p.name, re.IGNORECASE)
        if rxx:
            return int(rxx.group(1))
        return 0

    return sorted(volumes, key=_sort_key)


def get_first_volume(filepath: str | Path) -> Path:
    """Get the first volume of a split archive (the one to pass to 7z)."""
    volumes = find_volumes(filepath)
    if not volumes:
        return Path(filepath)
    return volumes[0]


def get_part_number(filepath: str | Path) -> int:
    """Extract part number from a split archive filename. Returns 0 if not a split."""
    path = Path(filepath)
    for pat in SPLIT_PATTERNS:
        m = pat.match(path.name)
        if m:
            try:
                return int(m.group("num"))
            except (IndexError, ValueError):
                return 0
    return 0
