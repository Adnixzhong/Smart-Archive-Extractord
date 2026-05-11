"""Binary executable header detection — PE, ELF, Mach-O."""

from __future__ import annotations

from pathlib import Path

# Mach-O magic bytes (32/64 bit, both endiannesses)
_MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",  # 32-bit big-endian
    b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
    b"\xce\xfa\xed\xfe",  # 32-bit little-endian
    b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
)


def is_executable_binary(filepath: str | Path) -> bool:
    """Check whether a file has a known executable binary header.

    Detects PE (Windows), ELF (Linux), and Mach-O (macOS) formats
    by reading the first few bytes — no extension matching.
    """
    p = Path(filepath)
    if not p.is_file():
        return False
    try:
        with open(p, "rb") as f:
            header = f.read(4)
    except OSError:
        return False

    if len(header) < 2:
        return False

    # PE (Windows) — MZ
    if header[:2] == b"MZ":
        return True

    # ELF (Linux)
    if header[:4] == b"\x7fELF":
        return True

    # Mach-O (macOS)
    if header[:4] in _MACHO_MAGICS:
        return True

    return False
