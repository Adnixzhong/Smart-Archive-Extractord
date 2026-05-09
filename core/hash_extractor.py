"""Extract password hashes from archives for feeding to hashcat.

ZIP hashes are extracted in pure Python (no external tool needed).
7z hashes are extracted in pure Python (LZMA-decompress header, parse AES coder).
RAR hashes require rar2john from the John the Ripper suite.
"""

import lzma
import struct
import zipfile
import subprocess
import os
from pathlib import Path
from typing import Optional
from .detector import detect


def _subprocess_kwargs() -> dict:
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = si
    return kwargs


def _find_john_tool(name: str) -> Optional[Path]:
    """Locate a John the Ripper tool (rar2john, 7z2john, zip2john).
    Checks bundled tools dir first, then PATH, then common install paths.
    """
    from .tool_manager import find_tool as _find

    result = _find(name)
    if result is not None:
        return result

    tools_dir = Path(os.environ.get("APPDATA", "")) / "Smart Archive Extractor" / "tools"

    # Fallback: search PATH and known install locations
    for exe_name in [name + ".exe", name + ".py", name]:
        for candidate in [
            tools_dir / exe_name,
            Path(r"C:\Program Files\John the Ripper\run") / exe_name,
            Path(r"C:\Program Files (x86)\John the Ripper\run") / exe_name,
        ]:
            if candidate.is_file():
                return candidate

        # PATH search
        for ext in [".exe", ".py", ""]:
            try:
                result = subprocess.run(
                    ["where", name + ext], capture_output=True, text=True, timeout=5,
                    **_subprocess_kwargs(),
                )
                if result.returncode == 0:
                    found = Path(result.stdout.strip().split("\n")[0].strip())
                    if found.is_file():
                        return found
            except Exception:
                pass

    return None


# ============================================================
#  ZIP hash extraction (pure Python — no external dependency)
# ============================================================

def extract_zip_hash(archive_path: Path) -> Optional[tuple[str, int]]:
    """Extract hash from encrypted ZIP. Returns (hash_str, hashcat_mode) or None.

    hashcat modes:
      17200 = PKZIP ZipCrypto (Compressed)
      17210 = PKZIP Store (Uncompressed)
      13600 = WinZip AES
    """
    try:
        with zipfile.ZipFile(archive_path, "r") as z:
            for info in z.infolist():
                if info.flag_bits & 0x1:
                    # WinZip AES uses compression type 99 — different hash format (mode 13600)
                    if info.compress_type == 99:
                        return None
                    return _extract_zipcrypto_hash(archive_path, info)
        return None
    except Exception:
        return None


def _extract_zipcrypto_hash(path: Path, info: zipfile.ZipInfo) -> Optional[tuple[str, int]]:
    """Extract ZipCrypto hash data from a ZIP entry.

    Generates hash in the $pkzip$ format matching zip2john.c / hashcat spec:
      $pkzip$C*B*DT*MT*CL*UL*CR*OF*OX*CT*DL*CS*DA*$/pkzip$

    Where:
      C   = count (1 for single entry)
      B   = check bytes valid (1 = standard, 2 = legacy)
      DT  = data type (2 = full inline data)
      MT  = magic type (0 = none)
      CL  = compressed size in hex (includes 12-byte encryption header)
      UL  = uncompressed size in hex
      CR  = CRC32 (8 hex chars)
      OF  = offset to local file header in ZIP (0 for inline)
      OX  = additional offset past local header to data (30 + name_len + extra_len)
      CT  = compression type (0=stored, 8=deflated)
      DL  = data length in hex
      CS  = first 2 bytes of CRC32 (4 hex chars, used for early rejection)
      DA  = encrypted data hex
    """
    try:
        with open(path, "rb") as f:
            # Read the local file header
            # Format: sig(4) ver(2) flags(2) comp(2) time(2) date(2) crc(4)
            # comp_size(4) uncomp_size(4) name_len(2) extra_len(2)
            f.seek(info.header_offset)
            header = f.read(30)
            if len(header) < 30:
                return None

            sig, ver, flags, comp_type, mod_time, mod_date, crc_local = \
                struct.unpack("<IHHHHHI", header[:18])
            comp_sz_local, uncomp_sz_local = struct.unpack("<II", header[18:26])
            name_len = struct.unpack("<H", header[26:28])[0]
            extra_len = struct.unpack("<H", header[28:30])[0]

            # Skip past name and extra to reach encrypted data
            data_offset = info.header_offset + 30 + name_len + extra_len

            # Use actual compress_size (from local header) for data read
            # Limit to 1024 bytes to keep hash size manageable
            max_read = min(comp_sz_local, 1024)
            f.seek(data_offset)
            enc_data = f.read(max_read)

            if len(enc_data) < 12:
                return None

            # Build hash fields
            data_hex = enc_data.hex()
            data_len = len(enc_data)
            crc32_hex = f"{info.CRC:08x}"
            # CS = check byte from encryption header (enc_data[11] = CRC MSB for ZipCrypto).
            # Use check_byte as both bytes of CS — matches what hashcat's early-reject
            # logic compares, and works even when the ZIP tool (e.g. Bandizip) produces
            # an encryption header whose check byte diverges from the stored CRC32.
            check_byte = enc_data[11]
            cs = f"{check_byte:02x}{check_byte:02x}"
            tc = (mod_time << 16) | mod_date  # timestamp checksum

            hash_str = (
                f"$pkzip$1*1*2*0*"
                f"{comp_sz_local:x}*{uncomp_sz_local:x}*{crc32_hex}*"
                f"0*{data_offset - info.header_offset:x}*"
                f"{comp_type:x}*{data_len:x}*"
                f"{cs}*{tc:04x}*"
                f"{data_hex}*$/pkzip$"
            )

            # Mode 17210 if stored (compression_type == 0), else 17200
            mode = 17210 if comp_type == 0 else 17200
            return hash_str, mode

    except Exception:
        return None


# ============================================================
#  7z hash extraction (pure Python — LZMA decompress header)
# ============================================================

# 7z archive property type IDs
_7Z_ID_END = 0x00
_7Z_ID_HEADER = 0x01
_7Z_ID_PACK_INFO = 0x06
_7Z_ID_UNPACK_INFO = 0x07
_7Z_ID_SUBSTREAMS_INFO = 0x08
_7Z_ID_SIZE = 0x09
_7Z_ID_CRC = 0x0A
_7Z_ID_FOLDER = 0x0B
_7Z_ID_UNPACK_SIZE = 0x0C
_7Z_ID_NUM_UNPACK_STREAM = 0x0D
_7Z_ID_ENCODED_HEADER = 0x17
_7Z_ID_START_POS = 0x18

# AES-256 codec ID in 7z
_7Z_AES_CODEC = b"\x06\xf1\x07\x01"

_7Z_SIGNATURE = b"7z\xbc\xaf'\x1c"
_7Z_DEFAULT_IV = bytes(16)
_7Z_DEFAULT_POWER = 19


class _SevenZipStream:
    """Wraps a bytes buffer with a read cursor for sequential parsing."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read(self, n: int) -> bytes:
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        return chunk

    def read_byte(self) -> int:
        return self.read(1)[0]

    def tell(self) -> int:
        return self._pos

    def seek(self, pos: int):
        self._pos = pos

    def remaining(self) -> int:
        return len(self._data) - self._pos


def _read_7z_number(s: _SevenZipStream) -> int:
    """Read a 7z variable-length unsigned integer."""
    b = s.read_byte()
    if b < 0x80:
        return b

    value = s.read_byte()
    for i in range(1, 8):
        mask = 0x80 >> i
        if (b & mask) == 0:
            high = b & (mask - 1)
            value |= (high << (i * 8))
            return value
        if i < 7:
            value |= (s.read_byte() << (i * 8))
    return value


def _read_7z_id(s: _SevenZipStream) -> int:
    return _read_7z_number(s)


def _skip_7z_data(s: _SevenZipStream):
    """Skip one 7z data item (could be nested)."""
    tp = _read_7z_id(s)
    while tp != _7Z_ID_END:
        if tp in (_7Z_ID_SIZE, _7Z_ID_CRC):
            _read_7z_number(s)  # skip the value
        else:
            _skip_7z_data(s)  # recursive skip
        try:
            tp = _read_7z_id(s)
        except IndexError:
            break


def _read_boolean_vector(s: _SevenZipStream, count: int) -> list[bool]:
    """Read a packed boolean vector."""
    result = []
    v = 0
    mask = 0
    for _ in range(count):
        if mask == 0:
            v = s.read_byte()
            mask = 0x80
        result.append((v & mask) != 0)
        mask >>= 1
    return result


def _read_boolean_vector_check_all(s: _SevenZipStream, count: int) -> list[bool]:
    """Read boolean vector with all-defined shortcut."""
    all_defined = s.read_byte()
    if all_defined == 0x01:
        return [True] * count
    s.seek(s.tell() - 1)
    return _read_boolean_vector(s, count)


def _read_7z_pack_info(s: _SevenZipStream) -> dict:
    """Parse PackInfo section: {pos, num_streams, sizes}."""
    pack_pos = _read_7z_number(s)
    num_streams = _read_7z_number(s)

    sid = _read_7z_id(s)
    sizes = []
    if sid == _7Z_ID_SIZE:
        for _ in range(num_streams):
            sizes.append(_read_7z_number(s))
        sid = _read_7z_id(s)

    # Skip CRC digests if present
    if sid == _7Z_ID_CRC:
        defined = _read_boolean_vector_check_all(s, num_streams)
        for i, d in enumerate(defined):
            if d:
                s.read(4)
        sid = _read_7z_id(s)

    # Push back the non-pack-info ID we just read
    s.seek(s.tell() - 1)
    return {"pos": pack_pos, "num_streams": num_streams, "sizes": sizes}


def _read_7z_folders(s: _SevenZipStream) -> list[dict]:
    """Parse Folder section: [{coders, packed_indices}]."""
    num_folders = _read_7z_number(s)
    external = s.read_byte()  # external flag, ignored for now

    folders = []
    for _ in range(num_folders):
        num_coders = _read_7z_number(s)
        coders = []
        sum_in = 0
        sum_out = 0
        for _ in range(num_coders):
            flags = s.read_byte()
            if flags & 0xC0:
                return []  # invalid
            is_complex = (flags & 0x10) != 0

            if is_complex:
                size = _read_7z_number(s)
                codec_id = s.read(size)
            else:
                codec_id = bytes([flags & 0x0F])

            has_attrs = (flags & 0x20) != 0
            attrs = b""
            if has_attrs:
                attr_size = _read_7z_number(s)
                attrs = s.read(attr_size)

            num_in = 1
            num_out = 1
            if is_complex:
                num_in = _read_7z_number(s)
                num_out = _read_7z_number(s)

            sum_in += num_in
            sum_out += num_out
            coders.append({
                "id": codec_id, "attrs": attrs,
                "num_in": num_in, "num_out": num_out,
            })

        # Bind pairs
        num_bind = 0
        if sum_in > num_coders:
            num_bind = sum_in - num_coders
            for _ in range(num_bind):
                _read_7z_number(s)  # in_index
                _read_7z_number(s)  # out_index

        # Packed stream indices
        num_packed = sum_in - num_bind
        packed_indices = []
        if num_packed > 1:
            for _ in range(num_packed):
                packed_indices.append(_read_7z_number(s))
        else:
            packed_indices = [0]

        folders.append({"coders": coders, "packed_indices": packed_indices})

    return folders


def _read_7z_unpack_info(s: _SevenZipStream) -> dict:
    """Parse UnpackInfo section."""
    sid = _read_7z_id(s)
    if sid != _7Z_ID_FOLDER:
        return {}
    num_folders = _read_7z_number(s)
    external = s.read_byte()

    folders = _read_7z_folders(s)

    sid = _read_7z_id(s)
    if sid != _7Z_ID_UNPACK_SIZE:
        return {}

    unpack_sizes = []
    coder_unpack_sizes = []
    for _ in range(num_folders):
        coder_unpack_sizes.append(len(unpack_sizes))
        total_out = 0
        for c in folders[_]["coders"]:
            total_out += c["num_out"]
        for _ in range(total_out):
            unpack_sizes.append(_read_7z_number(s))

    # CRC digests
    sid = _read_7z_id(s)
    digests = []
    if sid == _7Z_ID_CRC:
        defined = _read_boolean_vector_check_all(s, num_folders)
        for d in defined:
            if d:
                digests.append(s.read(4))
            else:
                digests.append(None)
        sid = _read_7z_id(s)

    if sid is not None:
        s.seek(s.tell() - 1)

    return {
        "num_folders": num_folders,
        "folders": folders,
        "unpack_sizes": unpack_sizes,
        "coder_unpack_sizes": coder_unpack_sizes,
        "digests": digests,
    }


def _read_7z_substreams_info(s: _SevenZipStream, unpack_info: dict) -> dict:
    """Parse SubStreamsInfo section."""
    num_folders = unpack_info["num_folders"]
    num_unpack_streams = [1] * num_folders
    unpack_sizes = []
    digests = []

    while True:
        sid = _read_7z_id(s)
        if sid == _7Z_ID_NUM_UNPACK_STREAM:
            for i in range(num_folders):
                num_unpack_streams[i] = _read_7z_number(s)
        elif sid == _7Z_ID_SIZE:
            for i in range(num_folders):
                total_size = unpack_info["unpack_sizes"][
                    unpack_info["coder_unpack_sizes"][i]]
                for j in range(num_unpack_streams[i] - 1):
                    sz = _read_7z_number(s)
                    unpack_sizes.append(sz)
                    total_size -= sz
                unpack_sizes.append(total_size)
        elif sid == _7Z_ID_CRC:
            num_digests = sum(num_unpack_streams)
            defined = _read_boolean_vector_check_all(s, num_digests)
            for i, d in enumerate(defined):
                if d:
                    digests.append(s.read(4))
                else:
                    digests.append(None)
        else:
            s.seek(s.tell() - 1)
            break

    return {
        "num_unpack_streams": num_unpack_streams,
        "unpack_sizes": unpack_sizes,
        "digests": digests,
    }


def _read_7z_streams_info(s: _SevenZipStream) -> Optional[dict]:
    """Parse StreamsInfo (PackInfo + UnpackInfo + SubStreamsInfo)."""
    sid = _read_7z_id(s)

    pack_info = None
    if sid == _7Z_ID_PACK_INFO:
        pack_info = _read_7z_pack_info(s)
        sid = _read_7z_id(s)

    unpack_info = None
    if sid == _7Z_ID_UNPACK_INFO:
        unpack_info = _read_7z_unpack_info(s)
        if not unpack_info:
            return None
        sid = _read_7z_id(s)

    substreams_info = None
    if sid == _7Z_ID_SUBSTREAMS_INFO:
        if unpack_info:
            substreams_info = _read_7z_substreams_info(s, unpack_info)

    return {
        "pack_info": pack_info,
        "unpack_info": unpack_info,
        "substreams_info": substreams_info,
    }


def _read_7z_archive_properties(s: _SevenZipStream) -> bool:
    """Skip archive properties section."""
    while True:
        sid = _read_7z_id(s)
        if sid == _7Z_ID_END:
            return True
        _skip_7z_data(s)


def _extract_7z_hash_pure_python(path: Path) -> Optional[tuple[str, int]]:
    """Pure Python 7z hash extraction. Returns (hash_str, hashcat_mode) or None."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None

    if data[:6] != _7Z_SIGNATURE:
        return None

    # Read fixed header: sig(6) + ver(2) + crc(4) + next_offset(8) + next_size(8) + next_crc(4)
    if len(data) < 32:
        return None

    ver_major = data[6]
    ver_minor = data[7]
    # skip start header CRC at bytes 8-11
    next_header_offset = struct.unpack_from("<Q", data, 12)[0]
    next_header_size = struct.unpack_from("<Q", data, 20)[0]
    # skip next header CRC at bytes 28-31

    header_end = 32  # end of fixed header

    # Read the compressed start header (after fixed header)
    # The start header is at header_end (32) and extends to the first pack
    # But the "next header" is the end header, which comes after all pack data
    # The start header is the LZMA-compressed block starting at header_end
    # In practice: start_header = data[32 : 32 + next_header_size]

    # Try to decompress the start header
    start_header_data = data[header_end:header_end + next_header_size]

    # The compressed data may have LZMA properties prepended
    # 7z stores: 1 byte LZMA property (lc/lp/pb) + 4 bytes dict size (little-endian) + compressed data
    if len(start_header_data) < 5:
        return None

    try:
        # LZMA1: first 5 bytes are properties
        lzma_props = start_header_data[:5]
        lzma_data = start_header_data[5:]
        decompressed = lzma.decompress(lzma_data, format=lzma.FORMAT_RAW,
                                       filters=[{"id": lzma.FILTER_LZMA1,
                                                 "lc": lzma_props[0] % 9,
                                                 "lp": (lzma_props[0] // 9) % 5,
                                                 "pb": lzma_props[0] // 45,
                                                 "dict_size": struct.unpack_from("<I", lzma_props, 1)[0]}])
    except Exception:
        # Try LZMA2
        try:
            decompressed = lzma.decompress(start_header_data)
        except Exception:
            return None

    if not decompressed:
        return None

    # Parse the decompressed header
    s = _SevenZipStream(decompressed)
    sid = _read_7z_id(s)

    if sid != _7Z_ID_HEADER and sid != _7Z_ID_ENCODED_HEADER:
        return None

    is_encoded = (sid == _7Z_ID_ENCODED_HEADER)

    streams_info = None
    if is_encoded:
        streams_info = _read_7z_streams_info(s)
        if not streams_info:
            return None
    else:
        # Skip archive properties if present
        sid = _read_7z_id(s)
        if sid == 0x02:  # ArchiveProperties
            _read_7z_archive_properties(s)

    if not streams_info:
        return None

    # Find AES coder in folders
    unpack_info = streams_info.get("unpack_info", {})
    if not unpack_info:
        return None

    folders = unpack_info.get("folders", [])
    if not folders:
        return None

    # Find first folder with AES coder
    aes_attrs = None
    target_folder_idx = 0
    for fi, folder in enumerate(folders):
        for coder in folder["coders"]:
            if coder["id"] == _7Z_AES_CODEC:
                aes_attrs = coder["attrs"]
                target_folder_idx = fi
                break
        if aes_attrs:
            break

    if not aes_attrs:
        return None  # Not encrypted with AES

    # Parse AES coder attributes
    # Format: version(1) + salt(variable) + iv(16 or 0) + cycles_power(1)
    first_byte = aes_attrs[0]
    cycles_power = first_byte & 0x3F
    salt_len = aes_attrs[1] if len(aes_attrs) > 1 else 0
    salt = aes_attrs[2:2 + salt_len] if salt_len > 0 else b""

    iv_offset = 2 + salt_len
    iv = _7Z_DEFAULT_IV
    iv_len = 16
    if len(aes_attrs) > iv_offset:
        iv = aes_attrs[iv_offset:iv_offset + 16]
        if len(iv) < 16:
            iv = iv + bytes(16 - len(iv))

    # Get pack info for reading encrypted data
    pack_info = streams_info.get("pack_info", {})
    if not pack_info:
        return None

    pack_pos = pack_info.get("pos", 0)
    pack_sizes = pack_info.get("sizes", [])
    if not pack_sizes:
        return None

    # Find the pack for our target folder
    # First folder typically corresponds to first pack stream
    # For multi-pack, use the correct index
    folder_packed_indices = folders[target_folder_idx].get("packed_indices", [0])

    # Calculate absolute offset in file
    # Pack data starts after the compressed start header at header_end + next_header_size
    pack_start = header_end + next_header_size

    # Read encrypted data from the pack
    # We need at least 512 bytes for hashcat (or the whole pack if smaller)
    if folder_packed_indices:
        pack_idx = folder_packed_indices[0]
        # Calculate offset within pack stream
        offset_in_pack = pack_pos
        for pi in range(pack_idx):
            offset_in_pack += pack_sizes[pi]

        data_offset = pack_start + offset_in_pack
        data_size = min(pack_sizes[pack_idx], 512)
    else:
        data_offset = pack_start
        data_size = min(pack_sizes[0], 512)

    if data_offset + data_size > len(data):
        data_size = len(data) - data_offset
        if data_size <= 0:
            return None

    enc_data = data[data_offset:data_offset + data_size]

    # Get CRC digest
    digests = unpack_info.get("digests", [])
    crc = ""
    if target_folder_idx < len(digests) and digests[target_folder_idx]:
        crc = struct.unpack("<I", digests[target_folder_idx])[0]
        crc = f"{crc:08x}"

    # Build hashcat $7z$ hash
    # $7z$<data_type>$<cost>$<salt_len>$<salt>$<iv_len>$<iv>$<crc>$<enc_len>$<unenc_len>$<enc_data>
    data_type = 128  # truncated data (padding attack)
    cost = 1 << cycles_power

    hash_str = (
        f"$7z${data_type}${cost}${salt_len}$"
        f"{salt.hex()}${iv_len}${iv.hex()}$"
        f"{crc}${len(enc_data)}${len(enc_data)}$"
        f"{enc_data.hex()}"
    )

    return hash_str, 11600


# ============================================================
#  RAR hash extraction (requires rar2john)
# ============================================================

def _run_john_tool(tool_name: str, archive_path: Path) -> Optional[str]:
    """Run a john extraction tool and return its stdout hash string."""
    tool = _find_john_tool(tool_name)
    if tool is None:
        return None
    try:
        # .py scripts need to be run with python
        if tool.suffix == ".py":
            cmd = ["python", str(tool), str(archive_path)]
        else:
            cmd = [str(tool), str(archive_path)]

        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=30,
            **_subprocess_kwargs(),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            # Output format: archive_path:$rar5$16$...  or  archive_path:$7z$...
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if "$" in line:
                    return line.split(":", 1)[-1] if ":" in line else line
        return None
    except Exception:
        return None


def extract_rar_hash(archive_path: Path) -> Optional[tuple[str, int]]:
    """Extract RAR hash using rar2john. Returns (hash_str, hashcat_mode) or None.
    hashcat mode 13000 = RAR5."""
    h = _run_john_tool("rar2john", archive_path)
    if h and "$rar5$" in h:
        return h, 13000
    return None


def extract_7z_hash(archive_path: Path) -> Optional[tuple[str, int]]:
    """Extract 7z hash. Tries pure Python first, then 7z2john as fallback.
    hashcat mode 11600 = 7-Zip."""
    # Pure Python extraction (no external dependencies)
    result = _extract_7z_hash_pure_python(archive_path)
    if result:
        return result

    # Fallback: John the Ripper 7z2john tool
    h = _run_john_tool("7z2john", archive_path)
    if h and "$7z$" in h:
        return h, 11600
    return None


# ============================================================
#  Unified API
# ============================================================

def is_zip_bandizip_incompatible(archive_path: str | Path) -> Optional[str]:
    """Check if a ZIP was likely created by Bandizip or has non-standard ZipCrypto.

    Bandizip uses the timestamp checksum instead of the CRC32 MSB as the
    encryption-header check byte.  hashcat modes 17200 / 17210 rely on the
    standard CRC-MSB convention and therefore cannot verify passwords for
    such archives — they will always report "Exhausted" even when the
    correct password is supplied.

    Returns a human-readable reason string if incompatible, or None if the
    ZIP follows standard conventions (or is not encrypted).
    """
    import zipfile, struct
    path = Path(archive_path).resolve()
    if not path.is_file():
        return None
    try:
        with zipfile.ZipFile(path, "r") as z:
            for info in z.infolist():
                if not (info.flag_bits & 0x1):
                    continue  # not encrypted
                if info.compress_type == 99:
                    continue  # WinZip AES — different hash, not affected

                # Read flags from local header (not central directory)
                with open(path, "rb") as f:
                    f.seek(info.header_offset + 6)
                    flags = struct.unpack("<H", f.read(2))[0]

                # Bandizip signature: bit 1 set (deflate compression level)
                # alongside bit 0 (encryption) and typically bit 3 (data descriptor).
                # Bit 1 in isolation is not conclusive, but when the standard
                # check-byte convention is also broken we have a strong signal.
                if flags & 0x02:
                    return (
                        "此 ZIP 文件可能由 Bandizip 创建，其加密校验字节不符合"
                        " PKZIP 标准。\n\n"
                        "Bandizip 的 ZipCrypto 加密使用时间戳校验替代标准的 CRC"
                        " 校验，与 hashcat 的验证逻辑不兼容，GPU 破解无法使用。\n\n"
                        "建议：使用 CPU 模式（虽慢但兼容），或安装 7-Zip 后重试。"
                    )
    except Exception:
        pass
    return None


def extract_hash(archive_path: str | Path) -> Optional[tuple[str, int, str]]:
    """Extract password hash from an archive. Returns (hash_str, hashcat_mode, format_name).

    Returns None if the archive is not encrypted or hash extraction fails.
    """
    path = Path(archive_path).resolve()
    if not path.is_file():
        return None

    fmt = detect(path)
    if fmt is None:
        return None

    name = fmt.name.upper()

    # ZIP — pure Python extraction
    if "ZIP" in name:
        result = extract_zip_hash(path)
        if result:
            return (result[0], result[1], "ZIP")

    # RAR — needs rar2john
    if "RAR" in name:
        result = extract_rar_hash(path)
        if result:
            return (result[0], result[1], "RAR")

    # 7z — needs 7z2john
    if "7Z" in name:
        result = extract_7z_hash(path)
        if result:
            return (result[0], result[1], "7z")

    return None
