"""External tool detection and one-click download management.

Tools (hashcat, rar2john, 7z2john) are stored in:
  %APPDATA%\\Smart Archive Extractor\\tools\\

Note: 7z2john does NOT have a native Windows .exe. We download the
Python script (7z2john.py) from the John the Ripper repo instead.
"""

import os
import subprocess
import tempfile
import zipfile
import json
from pathlib import Path
from typing import Optional, Callable

# ---------------------------------------------------------------
#  Tool definitions
# ---------------------------------------------------------------

def _resolve_default_tools_dir() -> str:
    """Determine the default tools directory.
    Portable mode: if running as a bundled exe, use exe-adjacent 'tools' dir.
    Otherwise: %APPDATA%\\Smart Archive Extractor\\tools\\
    Can be overridden with SMART_AE_TOOLS_DIR env var.
    """
    # Check for portable mode — exe-adjacent tools dir
    exe_dir = None
    if getattr(os.sys, 'frozen', False):
        exe_dir = Path(os.environ.get("_MEIPASS", "")).parent
    else:
        try:
            exe_dir = Path(os.sys.argv[0]).resolve().parent
        except Exception:
            pass

    if exe_dir:
        portable = exe_dir / "tools"
        if portable.is_dir():
            return str(portable)

    # Default: APPDATA
    return str(Path(os.environ.get("APPDATA", "")) / "Smart Archive Extractor" / "tools")


TOOLS_DIR = Path(os.environ.get("SMART_AE_TOOLS_DIR") or
                  _resolve_default_tools_dir())

# hashcat releases: https://hashcat.net/hashcat/
# John the Ripper Windows binaries: https://www.openwall.com/john/
# 7z hash extraction is handled in pure Python (hash_extractor.py), no external tool needed.

TOOL_DEFS = {
    "hashcat": {
        "exe": "hashcat.exe",
        "url": "https://hashcat.net/files/hashcat-6.2.6.7z",
        "download_type": "archive",
        "archive_type": "7z",
        "archive_member": "hashcat-6.2.6/hashcat.exe",  # path inside archive
        "description": "GPU-accelerated password recovery (hashcat)",
    },
    "rar2john": {
        "exe": "rar2john.exe",
        "url": "https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip",
        "fallback_url": "https://github.com/openwall/john-packages/releases/download/jumbo-dev/win64-1.9.0-jumbo-1-dev.7z",
        "download_type": "archive",
        "archive_type": "zip",
        "archive_member": "run/rar2john.exe",  # path inside archive
        "description": "RAR hash extractor (John the Ripper)",
    },
}


def _subprocess_kwargs() -> dict:
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = si
    return kwargs


# ---------------------------------------------------------------
#  Detection
# ---------------------------------------------------------------

def find_tool(name: str) -> Optional[Path]:
    """Locate a tool executable. Checks bundled dir first, then PATH."""
    if name not in TOOL_DEFS:
        return None
    exe = TOOL_DEFS[name]["exe"]

    # Bundled tools directory (direct match)
    bundled = TOOLS_DIR / exe
    if bundled.is_file():
        # Validate: at least one non-.exe file in the dir (companion DLLs etc.)
        siblings = list(bundled.parent.iterdir())
        if len(siblings) >= 3 or any(not s.name.endswith(".exe") for s in siblings):
            return bundled

    # Search recursively (handles hashcat in subdir, John tools in run/, etc.)
    for candidate in sorted(TOOLS_DIR.rglob(exe), key=lambda p: p.parent == TOOLS_DIR):
        if candidate.is_file() and candidate != bundled:
            parent_files = list(candidate.parent.iterdir())
            if len(parent_files) >= 3:
                return candidate

    # Fallback: any match even if sparse
    for candidate in TOOLS_DIR.rglob(exe):
        if candidate.is_file():
            return candidate

    # PATH — only for .exe tools
    if exe.endswith(".exe"):
        try:
            result = subprocess.run(
                ["where", exe.replace(".exe", "")],
                capture_output=True, text=True, timeout=5,
                **_subprocess_kwargs(),
            )
            if result.returncode == 0:
                path = Path(result.stdout.strip().split("\n")[0].strip())
                if path.is_file():
                    return path
        except Exception:
            pass

    return None


def is_tool_available(name: str) -> bool:
    return find_tool(name) is not None


def get_tool_status() -> dict[str, bool]:
    """Return availability status for all known tools."""
    return {name: is_tool_available(name) for name in TOOL_DEFS}


def get_hashcat_path() -> Optional[Path]:
    return find_tool("hashcat")


def get_rar2john_path() -> Optional[Path]:
    return find_tool("rar2john")


# ---------------------------------------------------------------
#  Download
# ---------------------------------------------------------------

def _find_7z_for_extract() -> Optional[Path]:
    from .extractor import find_7z
    return find_7z()


def download_tool(
    name: str,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> tuple[bool, str]:
    """Download and install a tool into the bundled tools directory.

    Returns (success, message).
    progress_callback receives (percent, status_message).
    """
    if name not in TOOL_DEFS:
        msg = f"Unknown tool: {name}"
        if progress_callback:
            progress_callback(0, msg)
        return False, msg

    info = TOOL_DEFS[name]
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    download_type = info.get("download_type", "archive")

    if download_type == "script":
        return _download_script(name, info, progress_callback)
    else:
        return _download_archive(name, info, progress_callback)


def _download_script(
    name: str, info: dict,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> tuple[bool, str]:
    """Download a standalone script file directly."""
    if progress_callback:
        progress_callback(10, f"Downloading {name} script...")

    data, err = _download_file(info["url"], progress=None)
    if data is None:
        fallback = info.get("fallback_url", "")
        if fallback:
            if progress_callback:
                progress_callback(10, f"Primary failed, trying mirror...")
            data, err = _download_file(fallback, progress=None)
        if data is None:
            msg = f"Download failed: {err}"
            if progress_callback:
                progress_callback(0, msg)
            return False, msg

    if progress_callback:
        progress_callback(70, f"Saving {name}...")

    dest = TOOLS_DIR / info["exe"]
    try:
        dest.write_bytes(data)
        if progress_callback:
            progress_callback(100, f"{name} installed: {dest}")
        return True, f"Installed to {dest}"
    except OSError as e:
        msg = f"Failed to save: {e}"
        if progress_callback:
            progress_callback(0, msg)
        return False, msg


def _download_archive(
    name: str, info: dict,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> tuple[bool, str]:
    """Download an archive and extract the target executable."""
    url = info["url"]
    archive_type = info.get("archive_type", "7z")
    archive_member = info.get("archive_member", "")
    exe_name = info["exe"]

    if progress_callback:
        progress_callback(0, f"Downloading {name}...")

    # Download — try primary URL, then fallback
    data, err = _download_file(
        url,
        progress=lambda pct: (
            progress_callback(int(pct * 0.5), f"Downloading {name}... {pct:.0%}")
            if progress_callback else None
        ),
    )
    if data is None:
        fallback = info.get("fallback_url", "")
        if fallback:
            if progress_callback:
                progress_callback(0, f"Primary URL failed, trying mirror...")
            data, err = _download_file(
                fallback,
                progress=lambda pct: (
                    progress_callback(int(pct * 0.5), f"Downloading {name}... {pct:.0%}")
                    if progress_callback else None
                ),
            )
        if data is None:
            msg = f"Download failed: {err}"
            if progress_callback:
                progress_callback(0, msg)
            return False, msg

    if progress_callback:
        progress_callback(55, f"Extracting {name}...")

    # Extract and find the target exe
    try:
        ok, msg = _extract_and_find(data, archive_type, exe_name, archive_member)
        if ok:
            if progress_callback:
                progress_callback(100, f"{name} installed: {msg}")
            return True, msg
        else:
            if progress_callback:
                progress_callback(0, msg)
            return False, msg
    except Exception as e:
        msg = f"Extraction failed: {e}"
        if progress_callback:
            progress_callback(0, msg)
        return False, msg


def _copy_all_from_dir(src: Path, dst: Path):
    """Copy all files and dirs from src into dst, overwriting existing."""
    import shutil
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def _remove_dir(path: Path):
    """Remove a directory tree, ignoring errors."""
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def _extract_and_find(
    data: bytes, archive_type: str, exe_name: str, archive_member: str,
) -> tuple[bool, str]:
    """Extract an archive and find the target executable within it.
    Returns (success, path_or_error).
    """
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    # Write archive data to temp file
    suffix = ".7z" if archive_type == "7z" else ".zip"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        if archive_type == "7z":
            sz = _find_7z_for_extract()
            if sz is None:
                return False, "7-Zip not found (needed to extract download)"
            subprocess.run(
                [str(sz), "x", tmp_path, f"-o{TOOLS_DIR}", "-y", "-aoa"],
                capture_output=True, text=True, timeout=120,
                **_subprocess_kwargs(),
            )
        elif archive_type == "zip":
            with zipfile.ZipFile(tmp_path, "r") as z:
                # If we know the member path, extract just that file
                if archive_member:
                    try:
                        z.extract(archive_member, TOOLS_DIR)
                    except KeyError:
                        # Member not found by exact path — try matching by name
                        for name_in_zip in z.namelist():
                            if name_in_zip.endswith("/" + exe_name) or name_in_zip == exe_name:
                                z.extract(name_in_zip, TOOLS_DIR)
                                break
                        else:
                            # Last resort: extract all and search
                            z.extractall(TOOLS_DIR)
                else:
                    z.extractall(TOOLS_DIR)
        else:
            return False, f"Unsupported archive type: {archive_type}"
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # Find the installed tool
    # Check direct path first
    direct = TOOLS_DIR / exe_name
    if direct.is_file():
        return True, str(direct)

    # Search recursively
    for candidate in sorted(TOOLS_DIR.rglob(exe_name),
                            key=lambda p: p.parent == TOOLS_DIR):
        if candidate.is_file() and candidate.parent != TOOLS_DIR:
            # Copy ALL companion files from the same directory (DLLs etc.)
            _copy_all_from_dir(candidate.parent, TOOLS_DIR)
            _remove_dir(candidate.parent)  # clean up subdirectory
            return True, str(direct)

    # If archive_member and directory was created, the exe might be in a subdir
    # For hashcat specifically: hashcat-6.2.6/hashcat.exe
    if archive_member and "/" in archive_member:
        subdir_exe = TOOLS_DIR / archive_member
        if subdir_exe.is_file():
            _copy_all_from_dir(subdir_exe.parent, TOOLS_DIR)
            _remove_dir(subdir_exe.parent)
            return True, str(direct)

    return False, f"{exe_name} not found in downloaded archive"


# ---------------------------------------------------------------
#  HTTP download with proxy support
# ---------------------------------------------------------------

def _download_file(
    url: str,
    progress: Callable[[float], None] | None = None,
) -> tuple[Optional[bytes], str]:
    """Download a file into memory. Returns (data, error_message).

    Uses system proxy settings automatically on Windows.
    """
    import urllib.request
    import urllib.error
    import ssl

    ctx = ssl.create_default_context()

    try:
        # Build opener with system proxy + SSL context support
        proxy_handler = urllib.request.ProxyHandler()
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(proxy_handler, https_handler)
        req = urllib.request.Request(url, headers={"User-Agent": "SmartArchiveExtractor/1.0"})

        with opener.open(req, timeout=120) as resp:
            # Handle redirects
            final_url = resp.geturl()
            total_raw = resp.headers.get("Content-Length")
            total = int(total_raw) if total_raw else 0
            chunks = []
            downloaded = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                downloaded += len(chunk)
                if total and progress:
                    progress(downloaded / total)
            return b"".join(chunks), ""

    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return None, f"Connection error: {e.reason}"
    except ssl.SSLError as e:
        return None, f"SSL error: {e}"
    except OSError as e:
        return None, f"Network error: {e}"
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------
#  GitHub API — resolve latest release download URL
# ---------------------------------------------------------------

def _get_github_latest_asset(repo: str, name_pattern: str) -> Optional[str]:
    """Query GitHub API for the latest release asset URL matching name_pattern.
    e.g. repo='openwall/john-packages', name_pattern='win64'
    Returns the browser_download_url or None.
    """
    import urllib.request
    import urllib.error
    import ssl

    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(
            api_url,
            headers={
                "User-Agent": "SmartArchiveExtractor/1.0",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            release = json.loads(resp.read())
        for asset in release.get("assets", []):
            name = asset.get("name", "")
            if name_pattern in name.lower():
                return asset.get("browser_download_url")
    except Exception:
        pass
    return None
