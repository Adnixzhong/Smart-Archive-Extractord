"""Archive format signatures (magic bytes)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class FormatInfo:
    name: str          # e.g. "ZIP"
    extensions: list[str]  # e.g. [".zip"]
    mime: str          # e.g. "application/zip"


# Ordered from most specific / longest magic to avoid false matches
SIGNATURES: list[tuple[bytes, int, FormatInfo]] = [
    # 7-Zip
    (b"7z\xbc\xaf\x27\x1c", 0, FormatInfo("7Z", [".7z"], "application/x-7z-compressed")),

    # RAR v5
    (b"Rar!\x1a\x07\x01\x00", 0, FormatInfo("RAR5", [".rar"], "application/vnd.rar")),
    # RAR v4
    (b"Rar!\x1a\x07\x00", 0, FormatInfo("RAR4", [".rar"], "application/vnd.rar")),

    # ZIP (multiple possible headers)
    (b"PK\x03\x04", 0, FormatInfo("ZIP", [".zip"], "application/zip")),
    (b"PK\x05\x06", 0, FormatInfo("ZIP", [".zip"], "application/zip")),
    (b"PK\x07\x08", 0, FormatInfo("ZIP", [".zip"], "application/zip")),

    # GZIP
    (b"\x1f\x8b\x08", 0, FormatInfo("GZIP", [".gz", ".gzip"], "application/gzip")),

    # BZIP2
    (b"BZh", 0, FormatInfo("BZIP2", [".bz2", ".bzip2"], "application/x-bzip2")),

    # XZ
    (b"\xfd7zXZ\x00", 0, FormatInfo("XZ", [".xz"], "application/x-xz")),

    # Zstandard
    (b"\x28\xb5\x2f\xfd", 0, FormatInfo("ZST", [".zst", ".zstd"], "application/zstd")),

    # LZ4 frame
    (b"\x04\x22\x4d\x18", 0, FormatInfo("LZ4", [".lz4"], "application/x-lz4")),

    # CAB
    (b"MSCF", 0, FormatInfo("CAB", [".cab"], "application/vnd.ms-cab-compressed")),

    # ISO 9660 (CD001 at offset 32769, but also check at 34817 and 36865)
    # We'll handle ISO specially in detector since it's a deep offset

    # ARJ
    (b"\x60\xea", 0, FormatInfo("ARJ", [".arj"], "application/x-arj")),

    # LHA/LZH
    (b"\x1f\xa0", 0, FormatInfo("LZH", [".lzh", ".lha"], "application/x-lzh")),
    (b"\x1f\x9d", 0, FormatInfo("LZH", [".lzh", ".lha"], "application/x-lzh")),

    # TAR (detected by ustar at offset 257, handled specially)
    # We place TAR last as it's a fallback — many other formats may contain tar inside
]

# Tar detection: "ustar" at offset 257, or "ustar\x0000" / "ustar  \x00"
TAR_MAGIC_OFFSET = 257
TAR_MAGICS = [b"ustar\x00", b"ustar ", b"ustar"]

# ISO detection: "CD001" at various offsets
ISO_OFFSETS = [32769, 34817, 36865]
ISO_MAGIC = b"CD001"


def signature_size() -> int:
    """Max bytes needed to read for signature detection."""
    return max(len(sig) + offset for sig, offset, _ in SIGNATURES)
