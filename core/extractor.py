"""7-Zip extractor wrapper."""

from __future__ import annotations

import subprocess
import re
import os
import zipfile
from pathlib import Path
from typing import Optional, Callable

from . import subprocess_kwargs


_7Z_CACHE: Optional[Path] = None
_7Z_SEARCHED = False


def find_7z() -> Optional[Path]:
    """Locate 7z.exe on the system (cached)."""
    global _7Z_CACHE, _7Z_SEARCHED
    if _7Z_SEARCHED:
        return _7Z_CACHE
    _7Z_SEARCHED = True

    # Check PATH first
    for cmd in ["7z", "7z.exe", "7za", "7za.exe"]:
        try:
            result = subprocess.run(
                ["where", cmd] if os.name == "nt" else ["which", cmd],
                capture_output=True, text=True, timeout=5,
                **subprocess_kwargs(),
            )
            if result.returncode == 0:
                found = result.stdout.strip().split("\n")[0].strip()
                p = Path(found)
                if p.is_file():
                    _7Z_CACHE = p
                    return p
        except Exception:
            pass

    # Common install paths on Windows
    if os.name == "nt":
        candidates = [
            Path(r"C:\Program Files\7-Zip\7z.exe"),
            Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
            Path(r"C:\Program Files\7-Zip-Zstandard\7z.exe"),
            Path(os.path.expandvars(r"%ProgramFiles%\7-Zip\7z.exe")),
            Path(os.path.expandvars(r"%ProgramFiles(x86)%\7-Zip\7z.exe")),
            Path(os.path.expandvars(r"%ProgramFiles%\7-Zip-Zstandard\7z.exe")),
            Path(os.path.expandvars(r"%LOCALAPPDATA%\Programs\7-Zip\7z.exe")),
        ]
        for p in candidates:
            if p.is_file():
                _7Z_CACHE = p
                return p

    return None


class ExtractError(Exception):
    def __init__(self, message: str, password_wrong: bool = False):
        super().__init__(message)
        self.password_wrong = password_wrong


class ExtractionResult:
    def __init__(self, success: bool, output_dir: str, files_extracted: int = 0,
                 password: Optional[str] = None, error: Optional[str] = None):
        self.success = success
        self.output_dir = output_dir
        self.files_extracted = files_extracted
        self.password = password
        self.error = error

    @property
    def password_wrong(self) -> bool:
        return self.error == "Wrong password" or "Wrong password" in (self.error or "")


def extract(
    archive_path: str | Path,
    output_dir: str | Path,
    password: Optional[str] = None,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> ExtractionResult:
    """Extract an archive using 7z.

    Args:
        archive_path: Path to the archive file (first volume if split)
        output_dir: Directory to extract to
        password: Optional password for encrypted archives
        progress_callback: Called with (percent, status_line) during extraction
    """
    sz = find_7z()
    if sz is None:
        raise ExtractError("7-Zip not found. Please install 7-Zip and ensure 7z.exe is in PATH.")

    archive_path = Path(archive_path).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(sz), "x",
        str(archive_path),
        f"-o{output_dir}",
        "-y",  # assume yes on all queries
        "-bsp1",  # redirect progress to stdout
    ]

    if password:
        cmd.append(f"-p{password}")
    else:
        cmd.append("-p-")  # no password

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
                **subprocess_kwargs(),
        )
    except Exception as e:
        raise ExtractError(f"Failed to start 7z: {e}")

    output_lines: list[str] = []
    last_percent = 0

    if proc.stdout:
        for line in proc.stdout:
            line = line.rstrip("\n\r")
            output_lines.append(line)

            # Parse progress percentage
            pct_match = re.search(r"(\d+)%", line)
            if pct_match:
                last_percent = int(pct_match.group(1))
                if progress_callback:
                    progress_callback(last_percent, line)

            # Also detect "Everything is Ok" etc
            if progress_callback and ("Everything is Ok" in line or "Ok" in line):
                progress_callback(100, line)

    proc.wait()
    full_output = "\n".join(output_lines)

    # Check for password error
    if "Wrong password" in full_output or "Cannot open encrypted archive" in full_output:
        return ExtractionResult(
            success=False, output_dir=str(output_dir),
            password=password, error="Wrong password"
        )

    if "Can not open the file as archive" in full_output:
        return ExtractionResult(
            success=False, output_dir=str(output_dir),
            error="Cannot open file as archive"
        )

    if proc.returncode != 0:
        return ExtractionResult(
            success=False, output_dir=str(output_dir),
            error=f"7z exited with code {proc.returncode}"
        )

    # Count extracted files if possible
    files_count = 0
    for line in output_lines:
        if "Files:" in line and "Size:" in line:
            try:
                files_count = int(re.search(r"Files:\s*(\d+)", line).group(1))
            except Exception:
                pass

    if progress_callback:
        progress_callback(100, "Extraction complete")

    return ExtractionResult(
        success=True, output_dir=str(output_dir),
        files_extracted=files_count, password=password,
    )


def extract_with_password_list(
    archive_path: str | Path,
    output_dir: str | Path,
    passwords: list[str],
    progress_callback: Optional[Callable[[int, str], None]] = None,
    password_callback: Optional[Callable[[str], None]] = None,
) -> ExtractionResult:
    """Try extracting with a list of passwords, returning first success.

    Args:
        archive_path: Path to archive
        output_dir: Output directory
        passwords: List of passwords to try
        progress_callback: Called during extraction attempt
        password_callback: Called with the password currently being tried
    """
    for pwd in passwords:
        if password_callback:
            password_callback(pwd)

        try:
            result = extract(archive_path, output_dir, password=pwd, progress_callback=progress_callback)
            if result.success:
                return result
            if not result.password_wrong and result.error:
                # Non-password error (archive corrupt etc.) — don't keep trying
                return result
        except ExtractError as e:
            if not e.password_wrong:
                return ExtractionResult(success=False, output_dir=str(output_dir), error=str(e))

    return ExtractionResult(
        success=False, output_dir=str(output_dir),
        error="All passwords exhausted, none worked"
    )


def _7z_test_password(archive_path: Path, password: str) -> bool:
    """Test a password using 7z t (test mode, no disk writes)."""
    sz = find_7z()
    if sz is None:
        return False
    cmd = [
        str(sz), "t",
        str(archive_path),
        "-y",
        f"-p{password}",
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
                **subprocess_kwargs(),
        )
        output = proc.stdout.read() if proc.stdout else ""
        proc.wait()
        return "Everything is Ok" in output and "Wrong password" not in output
    except Exception:
        return False


def verify_password(archive_path: str | Path, password: str,
                    zip_file: zipfile.ZipFile | None = None) -> bool:
    """Quickly verify if a password is correct without writing files.

    Uses zipfile for ZIP (fast in-process), 7z t for other formats.
    Pass a pre-opened zipfile.ZipFile to reuse across multiple passwords.
    """
    path = Path(archive_path).resolve()
    if not path.is_file():
        return False
    if not password:
        return False

    lower = path.name.lower()

    # ZIP fast-path: use Python's built-in zipfile (no subprocess overhead).
    # Python's zipfile may not raise on wrong passwords for certain ZIP files
    # (ZipCrypto with weak CRC, non-standard encryption from third-party tools).
    # When zipfile accepts the password we always confirm with 7z test mode.
    if lower.endswith(".zip") or lower.endswith(".zip.001"):
        zip_ok = False

        # Use pre-opened zipfile if provided (per-thread cached for cracking)
        if zip_file is not None:
            try:
                zip_file.read(zip_file.namelist()[0],
                              pwd=password.encode("utf-8", errors="replace"))
                zip_ok = True
            except NotImplementedError:
                return _7z_test_password(path, password)
            except (RuntimeError, zipfile.BadZipFile):
                return False
            except Exception:
                return False
        else:
            try:
                with zipfile.ZipFile(path, "r") as z:
                    names = z.namelist()
                    if not names:
                        return False
                    z.read(names[0], pwd=password.encode("utf-8", errors="replace"))
                    zip_ok = True
            except NotImplementedError:
                return _7z_test_password(path, password)
            except (RuntimeError, zipfile.BadZipFile):
                return False
            except Exception:
                return False

        if zip_ok:
            return _7z_test_password(path, password)
        return False

    # All other formats: use 7z test mode (no disk writes)
    return _7z_test_password(path, password)


# Archive extensions to scan for in nested extraction
_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
                 ".zst", ".cab", ".iso", ".arj", ".lzh", ".lha",
                 ".tgz", ".tbz2", ".txz"}

# Specific split archive filename patterns (not too broad)
_SPLIT_PATTERNS_FOR_SCAN = [
    # .zip.001, .7z.001, .rar.001, .tar.001, .tgz.001, etc
    re.compile(r".+\.(zip|7z|rar|tgz|tar\.gz|tar\.bz2|tar\.xz|tar|iso)\.\d{3,}$"),
    # .r00, .r01 etc (RAR old-style volumes)
    re.compile(r".+\.r\d{2,}$"),
    # .part1.rar, .part01.rar
    re.compile(r".+\.part\d+\.rar$"),
    # Generic .001 when preceded by a known archive extension pattern
    re.compile(r".+\.\w+\.\d{3,}$"),
]


def scan_for_archives(directory: str | Path) -> list[Path]:
    """Scan a directory recursively for archive files.

    For split archives (e.g. .7z.001 / .r00 / .part1.rar),
    only the first volume is returned after verifying all parts
    exist in the same directory.
    Returns a list sorted by path.
    """
    from .split_detector import find_volumes, is_split_archive, get_first_volume

    directory = Path(directory)
    if not directory.is_dir():
        return []

    found: list[Path] = []
    seen = set()

    for f in directory.rglob("*"):
        if not f.is_file():
            continue
        if f.stat().st_size < 2:
            continue

        lower = f.name.lower()
        is_archive_ext = any(lower.endswith(ext) for ext in _ARCHIVE_EXTS)
        is_split_pattern = any(p.match(lower) for p in _SPLIT_PATTERNS_FOR_SCAN)

        if not is_archive_ext and not is_split_pattern:
            continue

        # For split archives, find all volumes and only register the first
        if is_split_archive(f):
            all_vols = find_volumes(f)
            if not all_vols:
                continue
            first = all_vols[0].resolve()
            if first not in seen:
                seen.add(first)
                # Also mark all other volumes as seen so they won't be processed
                for v in all_vols[1:]:
                    seen.add(v.resolve())
                found.append(first)
        else:
            resolved = f.resolve()
            if resolved not in seen:
                seen.add(resolved)
                found.append(resolved)

    return sorted(found)
