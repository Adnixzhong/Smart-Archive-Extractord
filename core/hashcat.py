"""hashcat subprocess wrapper — GPU-accelerated password cracking.

Manages hashcat lifecycle: launch, parse --status output, cancel.
Integrates with CrackConfig for attack configuration.
"""

import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable

from .tool_manager import find_tool as _find_tool, get_hashcat_path


def _subprocess_kwargs() -> dict:
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return kwargs


# ---------------------------------------------------------------
#  Config
# ---------------------------------------------------------------

@dataclass
class HashcatConfig:
    """Configuration for a hashcat attack."""
    attack_type: str = "bruteforce"      # bruteforce | dictionary | mask
    charset: str = ""                     # charset for bruteforce/mask (-1 custom)
    min_length: int = 1
    max_length: int = 6
    mask_pattern: str = ""               # hashcat mask (?a, ?d, ?l, etc.)
    dictionary_path: str = ""            # wordlist for dictionary attack
    rules_file: str = ""                 # hashcat rule file
    hashcat_mode: int = 0                # hashcat hash type mode number
    hash_str: str = ""                   # the hash string

    # GPU / hardware
    device: int = 0                      # GPU device ID (-d)
    workload_profile: int = 2            # -w 2 = default, 3 = high, 4 = nightmare
    optimise_kernel: bool = True         # -O flag
    force: bool = False                  # --force (for unsupported devices)


# ---------------------------------------------------------------
#  Hashcat status parser
# ---------------------------------------------------------------

# hashcat --status --status-timer=1 output looks like:
#   Time.Started...: Thu Jan 01 00:00:00 2026 (0 secs)
#   Time.Estimated...: Thu Jan 01 01:00:00 2026 (3600 secs)
#   Recovered........: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts
#   Progress.........: 12345678/98765432 (12.50%)
#   Speed.#1.........:    1234.5 kH/s (1.23ms) @ Accel:64 Loops:256 Thr:1024 Vec:1
#   HWMon.Dev.#1.....: Temp: 65c Fan: 45% Core:1800MHz Mem:7000MHz Bus:16
#   Candidates.#1....: $HEX[61626364313233]


def parse_hashcat_status(line: str) -> Optional[dict]:
    """Parse a hashcat status line into a dict of key -> value.

    Returns None if the line doesn't contain recognizable status info.
    """
    line = line.strip()
    if not line:
        return None

    # Match "Key...: Value" format
    m = re.match(r"^([A-Za-z.#0-9]+)\.+:\s*(.*)", line)
    if not m:
        return None

    key = m.group(1).strip().rstrip(".")
    value = m.group(2).strip()

    # Parse numeric values
    result = {"_raw_key": key, "_raw_value": value}

    if key == "Progress":
        pm = re.search(r"(\d+)/(\d+)\s+\((\d+\.?\d*)%\)", value)
        if pm:
            result["progress_done"] = int(pm.group(1))
            result["progress_total"] = int(pm.group(2))
            result["progress_pct"] = float(pm.group(3))

    elif key.startswith("Speed"):
        sm = re.search(r"([\d.]+)\s*([kMG]?)H/s", value)
        if sm:
            speed = float(sm.group(1))
            unit = sm.group(2)
            if unit == "k":
                speed *= 1000
            elif unit == "M":
                speed *= 1_000_000
            elif unit == "G":
                speed *= 1_000_000_000
            result["speed_hs"] = speed

    elif key.startswith("HWMon"):
        # Extract temperature, fan, clock speeds
        tm = re.search(r"Temp[.:\s]*(\d+)c", value, re.IGNORECASE)
        if tm:
            result["gpu_temp"] = int(tm.group(1))
        fm = re.search(r"Fan[.:\s]*(\d+)%", value, re.IGNORECASE)
        if fm:
            result["gpu_fan"] = int(fm.group(1))

    elif key == "Time.Estimated":
        # Parse estimated time
        em = re.search(r"(\d+)\s*secs?", value)
        if em:
            result["eta_seconds"] = int(em.group(1))
        # Format: "Thu Jan 01 01:00:00 2026 (3600 secs)"
        tm2 = re.search(r"\((\d+)\s*secs?\)", value)
        if tm2:
            result["eta_seconds"] = int(tm2.group(1))

    elif key == "Time.Started":
        sm2 = re.search(r"\((\d+)\s*secs?\)", value)
        if sm2:
            result["elapsed_seconds"] = int(sm2.group(1))

    elif key == "Recovered":
        rm = re.search(r"(\d+)/(\d+)\s+\((\d+\.?\d*)%\)", value)
        if rm:
            result["recovered"] = int(rm.group(1))
            result["recovered_total"] = int(rm.group(2))
            result["recovered_pct"] = float(rm.group(3))

    elif key.startswith("Candidates"):
        # Candidates.#1....: $HEX[61626364313233]
        result["candidate"] = value

    return result


# ---------------------------------------------------------------
#  Hashcat session
# ---------------------------------------------------------------


class HashcatSession:
    """Manages a hashcat process with real-time status parsing."""

    def __init__(
        self,
        config: HashcatConfig,
        *,
        hash_file: Optional[Path] = None,
        pot_file: Optional[Path] = None,
        on_status: Optional[Callable[[dict], None]] = None,
        on_cracked: Optional[Callable[[str], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ):
        self._config = config
        self._hash_file = hash_file
        self._pot_file = pot_file
        self._on_status = on_status
        self._on_cracked = on_cracked
        self._on_log = on_log

        self._proc: subprocess.Popen | None = None
        self._cancel_flag = threading.Event()
        self._status_thread: threading.Thread | None = None
        self._found_password: Optional[str] = None
        self._error: str = ""

    # ---------- public ----------

    @property
    def found_password(self) -> Optional[str]:
        return self._found_password

    @property
    def error_message(self) -> str:
        return self._error

    def cancel(self):
        self._cancel_flag.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            # If still running after 2s, force kill
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def run(self) -> Optional[str]:
        """Run hashcat. Returns the cracked password or None."""
        hc = get_hashcat_path()
        if hc is None:
            self._log("hashcat not found")
            return None

        # Write hash to a temp file
        if self._hash_file:
            hash_path = self._hash_file
        else:
            import tempfile
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".hash", delete=False,
                encoding="utf-8",
            )
            tmp.write(self._config.hash_str + "\n")
            tmp.close()
            hash_path = Path(tmp.name)
            self._log(f"哈希内容: {self._config.hash_str[:200]}...")

        try:
            cmd = self._build_cmd(hc, hash_path)
            self._log(f"hashcat: {' '.join(cmd)}")

            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=str(hc.parent),  # hashcat needs ./OpenCL/ relative to its exe dir
                **_subprocess_kwargs(),
            )

            # Read stdout line by line in a thread, stderr in parallel
            stderr_lines = []
            def _read_stderr():
                if self._proc and self._proc.stderr:
                    for line in self._proc.stderr:
                        stderr_lines.append(line.rstrip("\n\r"))

            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stderr_thread.start()

            if self._proc.stdout:
                for line in self._proc.stdout:
                    line = line.rstrip("\n\r")
                    self._log(line)

                    # Detect error conditions
                    self._check_error(line)

                    # Check for cracked password
                    if ":" in line and not line.startswith(("Time", "Speed", "Progress",
                                                             "HWMon", "Candidates", "Recovered",
                                                             "Status", "Guess", "Session",
                                                             "Hash", "Dictionary", "Rules",
                                                             "Applicable", "Optimized", "Watchdog",
                                                             "Started", "Stopped", "Restore",
                                                             "ATTENTION", "The wordlist", "Approaching",
                                                             "INFO", "WARN", "ADL", "nvml",
                                                             "clCreate", "clBuild", "OpenCL",
                                                             "Device", "Backend", "Hashes",
                                                             "Minimum", "Maximum")):
                        # Potential cracked line: hash:password
                        parts = line.split(":", 1)
                        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                            if self._is_hash_match(parts[0]):
                                password = parts[1].strip()
                                self._found_password = password
                                if self._on_cracked:
                                    self._on_cracked(password)
                                break

                    # Parse status lines
                    status = parse_hashcat_status(line)
                    if status and self._on_status:
                        self._on_status(status)

            self._proc.wait()
            stderr_thread.join(timeout=2)

            # Also check stderr for error patterns
            for line in stderr_lines:
                self._check_error(line)

            # Append hash to format-related errors for debugging
            if self._error and "哈希格式" in self._error:
                h = self._config.hash_str
                self._error += f"\n\n生成的哈希:\n{h[:300]}{'...' if len(h) > 300 else ''}"

            if self._proc.returncode != 0 and not self._error and not self._found_password:
                rc = self._proc.returncode
                if rc == 1:
                    # Exhausted — all candidates tried, no match. Not an error.
                    pass
                elif rc == 2:
                    # Aborted by user
                    pass
                elif rc == 4294967295 or rc == -1:
                    self._error = (
                        "hashcat 启动失败 — 可能原因:\n"
                        "- 缺少 OpenCL 运行时 (需安装显卡驱动或 OpenCL SDK)\n"
                        "- 缺少 Visual C++ Redistributable\n"
                        "- 程序依赖库不完整"
                    )
                elif rc == 3:
                    self._error = "hashcat 运行错误 (code 3) — 请检查上方日志"
                else:
                    self._error = f"hashcat 异常退出 (code {rc})"
                # Append stderr if available
                if stderr_lines:
                    self._error += "\n\nstderr:\n" + "\n".join(stderr_lines[:10])

        except Exception as e:
            self._log(f"hashcat error: {e}")
        finally:
            # Clean up temp hash file
            if not self._hash_file and hash_path.is_file():
                try:
                    hash_path.unlink()
                except OSError:
                    pass

        return self._found_password

    def _build_cmd(self, hc: Path, hash_path: Path) -> list[str]:
        cfg = self._config
        cmd = [
            str(hc),
            "-m", str(cfg.hashcat_mode),
            str(hash_path),
            "--status",
            "--status-timer=1",
            "--machine-readable",
            "-w", str(cfg.workload_profile),
        ]

        if cfg.force:
            cmd.append("--force")
        if cfg.optimise_kernel:
            cmd.append("-O")

        # Attack mode
        if cfg.attack_type == "bruteforce":
            cmd.append("-a3")
            if cfg.charset:
                # Build hashcat mask from charset and lengths
                # Convert charset to hashcat custom charset (-1)
                cmd.extend(["-1", cfg.charset])
                # For each length: generate mask
                if cfg.min_length == cfg.max_length:
                    cmd.append("?1" * cfg.min_length)
                else:
                    # Use --increment
                    cmd.append("--increment")
                    cmd.extend(["--increment-min", str(cfg.min_length)])
                    cmd.extend(["--increment-max", str(cfg.max_length)])
                    cmd.append("?1" * cfg.max_length)

        elif cfg.attack_type == "dictionary":
            cmd.append("-a0")
            if cfg.dictionary_path:
                cmd.append(cfg.dictionary_path)
            if cfg.rules_file:
                cmd.extend(["-r", cfg.rules_file])

        elif cfg.attack_type == "mask":
            cmd.append("-a3")
            if cfg.mask_pattern:
                # Convert user mask (? -> hashcat mask chars ?a or custom)
                # Replace '?' with ?1 if custom charset, else ?a
                mask = cfg.mask_pattern
                if cfg.charset:
                    cmd.extend(["-1", cfg.charset])
                    mask = mask.replace("?", "?1")
                else:
                    mask = mask.replace("?", "?a")
                cmd.append(mask)

        # Device selection — only when explicitly configured
        if cfg.device > 0:
            cmd.extend(["-d", str(cfg.device)])

        return cmd

    _NVML_ADL_PREFIXES = ("nvml", "ADL", "NVML")

    _ERROR_PATTERNS = [
        ("No hashes loaded", "没有哈希被加载 — 哈希格式可能不正确"),
        ("No devices found/left", "未找到 GPU 设备 — 请检查显卡驱动和 OpenCL 支持"),
        ("Invalid device_id", "指定的 GPU 设备不存在 — 请检查设备编号"),
        ("Line-length exception", "哈希格式错误 (Line-length exception)"),
        ("Separator unmatched", "哈希格式错误 (Separator unmatched)"),
        ("Hash-encoding", "哈希编码不支持"),
        ("Hashfile", "哈希文件错误"),
        ("clGetDeviceIDs", "OpenCL 错误: 无法获取设备 (clGetDeviceIDs)"),
        ("clCreateContext", "OpenCL 错误: 无法创建上下文 (clCreateContext)"),
        ("No OpenCL", "未检测到 OpenCL 设备 — 需安装显卡驱动或 OpenCL 运行时"),
        ("No compatible devices", "未找到兼容设备"),
        ("Token length exception", "哈希格式错误 (Token length)"),
        ("Hash '", "哈希格式可能不正确"),
    ]

    def _check_error(self, line: str):
        """Detect hashcat error conditions from output lines.

        NVML/ADL hardware-monitoring warnings (fan speed, temp, etc.) are
        intentionally skipped — they don't affect cracking and hashcat will
        still use the GPU for compute.
        """
        if self._error:
            return

        low = line.strip().lower()
        if low.startswith(self._NVML_ADL_PREFIXES):
            return

        for pattern, msg in self._ERROR_PATTERNS:
            if pattern in line:
                self._error = msg
                return

    def _is_hash_match(self, s: str) -> bool:
        """Check if a string looks like a hash (hex or base64)."""
        return bool(re.match(r'^[\$a-fA-F0-9]{16,}$', s))

    def _log(self, msg: str):
        if self._on_log:
            self._on_log(msg)


# ---------------------------------------------------------------
#  Convenience
# ---------------------------------------------------------------

def is_hashcat_available() -> bool:
    return get_hashcat_path() is not None


def detect_hashcat() -> Optional[Path]:
    return get_hashcat_path()
