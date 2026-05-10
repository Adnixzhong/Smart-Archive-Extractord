"""Password cracking engine — brute force, dictionary, mask, and rule-based."""

from __future__ import annotations

import itertools
import json
import time
import threading
import multiprocessing as mp
import queue
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Callable


# ============================================================
#  Character set presets
# ============================================================

CHARSET_PRESETS = {
    "数字 (0-9)": "0123456789",
    "小写字母 (a-z)": "abcdefghijklmnopqrstuvwxyz",
    "大写字母 (A-Z)": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "数字 + 小写": "0123456789abcdefghijklmnopqrstuvwxyz",
    "数字 + 大小写": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "常用符号": "!@#$%^&*()_+-=[]{}|;:',.<>?/~`",
}

# Leet substitution table
LEET_TABLE = {
    "a": ["4", "@"],
    "b": ["8"],
    "c": ["(", "{", "["],
    "e": ["3"],
    "g": ["9", "6"],
    "i": ["1", "!"],
    "l": ["1", "|"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7", "+"],
    "z": ["2"],
}

# Common number suffixes
COMMON_NUMBERS = ["0", "1", "12", "123", "1234", "12345", "123456",
                  "00", "01", "10", "11", "22", "33", "42", "69", "88", "99",
                  "111", "222", "333", "444", "555", "666", "777", "888", "999", "000"]
COMMON_YEARS = [str(y) for y in range(1970, 2031)]
COMMON_SYMBOLS = ["!", "@", "#", "$", "%", "&", "*", "?", "_", "-", "."]


# ============================================================
#  Config
# ============================================================

@dataclass
class CrackConfig:
    attack_type: str = "bruteforce"  # "bruteforce" | "dictionary" | "mask"
    charset: str = CHARSET_PRESETS["数字 (0-9)"]
    min_length: int = 1
    max_length: int = 6
    mask_pattern: str = ""
    dictionary_path: str = ""
    rules: list[str] = field(default_factory=lambda: ["lowercase", "uppercase"])
    append_mask: str = ""
    prepend_mask: str = ""
    threads: int = 4
    time_limit_minutes: int = 0


# ============================================================
#  Password generators
# ============================================================

class PasswordGenerator(ABC):
    """Abstract base for password generators."""

    @abstractmethod
    def next_batch(self, n: int) -> list[str]:
        """Return up to n passwords. Empty list = exhausted."""
        ...

    @abstractmethod
    def total_estimate(self) -> int:
        """Return total number of passwords (or 0 if unknown)."""
        ...

    @abstractmethod
    def save_state(self) -> dict:
        """Serialize current position to a dict for resume."""
        ...

    @abstractmethod
    def load_state(self, state: dict):
        """Restore position from a saved state dict."""
        ...


class BruteForceGenerator(PasswordGenerator):
    """Generate all combinations of `charset` within [min_len, max_len].

    Supports `offset` / `stride` for parallel instances — each instance
    produces every Nth password starting from `offset`.
    """

    def __init__(self, charset: str, min_len: int = 1, max_len: int = 6,
                 offset: int = 0, stride: int = 1):
        self._charset = charset
        self._chars = list(charset)
        self._charset_len = len(charset)
        self._min_len = min_len
        self._max_len = max_len
        self._offset = offset
        self._stride = stride
        self._current_len = min_len
        self._k = 0
        self._powers = [1]
        for _ in range(1, max_len + 1):
            self._powers.append(self._powers[-1] * self._charset_len)

    def total_estimate(self) -> int:
        total = 0
        for L in range(self._min_len, self._max_len + 1):
            total += self._powers[L]
        return total // self._stride + 1

    def next_batch(self, n: int) -> list[str]:
        batch = []
        chars = self._chars
        charset_len = self._charset_len
        powers = self._powers
        while len(batch) < n and self._current_len <= self._max_len:
            L = self._current_len
            limit = powers[L]
            global_idx = self._offset + self._k * self._stride
            if global_idx >= limit:
                self._current_len += 1
                self._k = 0
                continue
            idx = global_idx
            result = []
            for _ in range(L):
                result.append(chars[idx % charset_len])
                idx //= charset_len
            batch.append("".join(reversed(result)))
            self._k += 1
        return batch

    def save_state(self) -> dict:
        return {
            "charset": self._charset, "min_len": self._min_len,
            "max_len": self._max_len, "current_len": self._current_len,
            "k": self._k,
        }

    def load_state(self, state: dict):
        self._charset = state["charset"]
        self._min_len = state["min_len"]
        self._max_len = state["max_len"]
        self._current_len = state["current_len"]
        self._k = state["k"]


class DictionaryGenerator(PasswordGenerator):
    """Stream passwords from a wordlist file line-by-line (memory-efficient)."""

    def __init__(self, filepath: str):
        self._filepath = Path(filepath)
        self._fh = None

    def total_estimate(self) -> int:
        try:
            count = 0
            with open(self._filepath, "r", encoding="utf-8", errors="replace") as f:
                for _ in f:
                    count += 1
            return count
        except Exception:
            return 0

    def next_batch(self, n: int) -> list[str]:
        if self._fh is None:
            self._fh = open(self._filepath, "r", encoding="utf-8", errors="replace")
        batch = []
        while len(batch) < n:
            line = self._fh.readline()
            if not line:
                self._fh.close()
                self._fh = None
                break
            pwd = line.strip()
            if pwd:
                batch.append(pwd)
        return batch

    def save_state(self) -> dict:
        offset = self._fh.tell() if self._fh else 0
        return {"filepath": str(self._filepath), "offset": offset}

    def load_state(self, state: dict):
        self._filepath = Path(state["filepath"])
        if state.get("offset", 0) > 0:
            self._fh = open(self._filepath, "r", encoding="utf-8", errors="replace")
            self._fh.seek(state["offset"])


class MaskGenerator(PasswordGenerator):
    """Generate passwords matching a mask. '?' is replaced by charset chars."""

    def __init__(self, pattern: str, charset: str):
        self._pattern = pattern
        self._charset = charset
        self._chars = list(charset)
        self._charset_len = len(charset)
        self._num_wildcards = pattern.count("?")
        if self._num_wildcards > 12:
            raise ValueError(
                f"掩码中的 ? 占位符过多 ({self._num_wildcards})，最多支持 12 个以避免组合爆炸"
            )
        self._total = self._charset_len ** self._num_wildcards
        self._idx = 0

    def total_estimate(self) -> int:
        return self._total

    def next_batch(self, n: int) -> list[str]:
        batch = []
        chars = self._chars
        charset_len = self._charset_len
        pattern = self._pattern
        num_wild = self._num_wildcards
        while len(batch) < n and self._idx < self._total:
            idx = self._idx
            self._idx += 1
            # Convert index to base-N substitution chars
            subs = []
            for _ in range(num_wild):
                subs.append(chars[idx % charset_len])
                idx //= charset_len
            subs.reverse()
            # Build result
            result = []
            wi = 0
            for ch in pattern:
                if ch == "?":
                    result.append(subs[wi])
                    wi += 1
                else:
                    result.append(ch)
            batch.append("".join(result))
        return batch

    def save_state(self) -> dict:
        return {"pattern": self._pattern, "charset": self._charset, "idx": self._idx}

    def load_state(self, state: dict):
        self._pattern = state["pattern"]
        self._charset = state["charset"]
        self._idx = state["idx"]
        self._num_wildcards = self._pattern.count("?")
        self._total = len(self._charset) ** self._num_wildcards


class RuleBasedGenerator(PasswordGenerator):
    """Apply transformation rules to base words (from dictionary or inline list)."""

    _NUM_SUFFIXES = COMMON_NUMBERS + COMMON_YEARS
    _SYM_SUFFIXES = COMMON_SYMBOLS

    def __init__(self, base_words: list[str], rules: list[str]):
        self._words = base_words
        self._rules = rules
        self._word_idx = 0
        self._cache: list[str] = []
        self._cache_pos = 0

    def total_estimate(self) -> int:
        est = 0
        for rule in self._rules:
            if rule == "leet":
                est += 5
            elif rule in ("append_numbers", "prepend_numbers"):
                est += len(self._NUM_SUFFIXES)
            elif rule in ("append_symbols", "prepend_symbols"):
                est += len(self._SYM_SUFFIXES)
            else:
                est += 1
        return len(self._words) * est

    def _apply_rules(self, word: str) -> list[str]:
        results = set()
        if "lowercase" in self._rules:
            results.add(word.lower())
        if "uppercase" in self._rules:
            results.add(word.upper())
        if "capitalize" in self._rules:
            results.add(word.capitalize())
        if "leet" in self._rules:
            self._leet_expand(word, 0, "", results)
        if "append_numbers" in self._rules:
            for n in self._NUM_SUFFIXES:
                results.add(word + n)
        if "prepend_numbers" in self._rules:
            for n in self._NUM_SUFFIXES:
                results.add(n + word)
        if "append_symbols" in self._rules:
            for s in self._SYM_SUFFIXES:
                results.add(word + s)
        if "prepend_symbols" in self._rules:
            for s in self._SYM_SUFFIXES:
                results.add(s + word)
        if "reverse" in self._rules:
            results.add(word[::-1])
        if "double" in self._rules:
            results.add(word + word)
        return list(results)

    def _leet_expand(self, word: str, pos: int, current: str, results: set):
        if pos >= len(word):
            if current != word:
                results.add(current)
            return
        ch = word[pos].lower()
        if ch in LEET_TABLE:
            for sub in LEET_TABLE[ch]:
                self._leet_expand(word, pos + 1, current + sub, results)
        self._leet_expand(word, pos + 1, current + word[pos], results)

    def next_batch(self, n: int) -> list[str]:
        batch = []
        while len(batch) < n:
            remaining = len(self._cache) - self._cache_pos
            take = min(n - len(batch), remaining)
            if take > 0:
                batch.extend(self._cache[self._cache_pos:self._cache_pos + take])
                self._cache_pos += take
                continue
            if self._word_idx >= len(self._words):
                break
            word = self._words[self._word_idx]
            self._word_idx += 1
            self._cache = self._apply_rules(word)
            self._cache_pos = 0
        return batch

    def save_state(self) -> dict:
        return {
            "words": self._words, "rules": self._rules,
            "word_idx": self._word_idx, "cache_pos": self._cache_pos,
        }

    def load_state(self, state: dict):
        self._words = state["words"]
        self._rules = state["rules"]
        self._word_idx = state["word_idx"]
        self._cache_pos = state["cache_pos"]
        self._cache = []
        if self._word_idx < len(self._words):
            self._cache = self._apply_rules(self._words[self._word_idx])


class HybridGenerator(PasswordGenerator):
    """Combine dictionary words with mask patterns (append or prepend)."""

    def __init__(self, words: list[str], mask_pattern: str, charset: str,
                 position: str = "append"):
        self._words = words
        self._pattern = mask_pattern
        self._charset = charset
        self._chars = list(charset)
        self._charset_len = len(charset)
        self._position = position
        self._num_wildcards = mask_pattern.count("?")
        if self._num_wildcards > 12:
            raise ValueError(
                f"掩码中的 ? 占位符过多 ({self._num_wildcards})，最多支持 12 个以避免组合爆炸"
            )
        self._mask_total = self._charset_len ** self._num_wildcards if self._num_wildcards else 0
        self._word_idx = 0
        self._mask_idx = 0

    def total_estimate(self) -> int:
        return len(self._words) * max(self._mask_total, 1)

    def _idx_to_mask(self, idx: int) -> str:
        chars = self._chars
        charset_len = self._charset_len
        subs = []
        for _ in range(self._num_wildcards):
            subs.append(chars[idx % charset_len])
            idx //= charset_len
        subs.reverse()
        result = []
        wi = 0
        for ch in self._pattern:
            if ch == "?":
                result.append(subs[wi])
                wi += 1
            else:
                result.append(ch)
        return "".join(result)

    def next_batch(self, n: int) -> list[str]:
        batch = []
        while len(batch) < n and self._word_idx < len(self._words):
            word = self._words[self._word_idx]
            if self._mask_total == 0:
                batch.append(word)
                self._word_idx += 1
                continue
            remaining = self._mask_total - self._mask_idx
            take = min(n - len(batch), remaining)
            for i in range(take):
                m = self._idx_to_mask(self._mask_idx + i)
                batch.append(word + m if self._position == "append" else m + word)
            self._mask_idx += take
            if self._mask_idx >= self._mask_total:
                self._mask_idx = 0
                self._word_idx += 1
        return batch

    def save_state(self) -> dict:
        return {
            "words": self._words, "pattern": self._pattern,
            "charset": self._charset, "position": self._position,
            "word_idx": self._word_idx, "mask_idx": self._mask_idx,
        }

    def load_state(self, state: dict):
        self._words = state["words"]
        self._pattern = state["pattern"]
        self._charset = state["charset"]
        self._position = state["position"]
        self._word_idx = state["word_idx"]
        self._mask_idx = state["mask_idx"]
        self._num_wildcards = self._pattern.count("?")
        self._charset_len = len(self._charset)
        self._mask_total = self._charset_len ** self._num_wildcards if self._num_wildcards else 0


# ============================================================
#  Factory
# ============================================================

def create_generator(config: CrackConfig) -> PasswordGenerator:
    """Create a PasswordGenerator from a CrackConfig."""
    if config.attack_type == "bruteforce":
        return BruteForceGenerator(
            charset=config.charset,
            min_len=config.min_length,
            max_len=config.max_length,
        )
    elif config.attack_type == "dictionary":
        if not config.dictionary_path:
            raise ValueError("Dictionary attack requires a wordlist file path")
        words = _load_dict_words(config.dictionary_path)
        # Hybrid: dictionary + mask
        if config.append_mask:
            return HybridGenerator(words, config.append_mask, config.charset, "append")
        if config.prepend_mask:
            return HybridGenerator(words, config.prepend_mask, config.charset, "prepend")
        # Dictionary with rules
        if config.rules:
            return RuleBasedGenerator(words, config.rules)
        return DictionaryGenerator(config.dictionary_path)
    elif config.attack_type == "mask":
        if not config.mask_pattern:
            raise ValueError("Mask attack requires a pattern (e.g. ???2024)")
        return MaskGenerator(config.mask_pattern, config.charset)
    else:
        raise ValueError(f"Unknown attack type: {config.attack_type}")


def _load_dict_words(filepath: str | Path) -> list[str]:
    """Load words from a dictionary file into memory (deduplicated)."""
    words = []
    seen = set()
    with open(Path(filepath), "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if w and w not in seen:
                seen.add(w)
                words.append(w)
    return words


# ============================================================
#  Password verifier helpers
# ============================================================

def _try_zip_read(zf_obj, first_name: str, password: str) -> bool:
    """Fast password check using an already-open ZipFile.

    When zipfile accepts the password we confirm with 7z test mode to
    rule out false positives from non-standard ZIP encryption headers.
    Skips directory entries (which are never encrypted).
    """
    # Find first non-directory entry
    name_to_read = first_name
    if first_name.endswith("/"):
        for n in zf_obj.namelist():
            if not n.endswith("/"):
                name_to_read = n
                break
        else:
            return False
    try:
        zf_obj.read(name_to_read, pwd=password.encode("utf-8", errors="replace"))
    except Exception:
        return False
    from .extractor import _7z_test_password as _test7z
    return _test7z(zf_obj.filename, password)


# ------------------------------------------------------------
#  Multiprocessing ZIP worker (module-level, picklable on Windows)
# ------------------------------------------------------------

def _zip_mp_worker(
    archive_path_str: str,
    charset: str,
    min_len: int,
    max_len: int,
    offset: int,
    stride: int,
    batch_size: int,
    cancel_val: "mp.synchronize.SynchronizedBase",
    attempts_val: "mp.synchronize.SynchronizedBase",
    result_queue: "mp.Queue",
    seven_zip_path: str,
):
    """Multiprocessing worker for ZIP bruteforce.

    Each worker owns an independent BruteForceGenerator slice (offset/stride)
    so no IPC is needed for candidate generation.  zipfile.read() serves as a
    fast pre-filter; on success the password is confirmed with 7z test mode
    inside this process before reporting to the parent.
    """
    import zipfile
    import subprocess as sp
    from . import subprocess_kwargs

    try:
        z = zipfile.ZipFile(archive_path_str, "r")
        # Pick first non-directory entry
        first_name = ""
        for n in z.namelist():
            if not n.endswith("/"):
                first_name = n
                break
        if not first_name:
            return
    except Exception:
        return

    gen = BruteForceGenerator(
        charset=charset, min_len=min_len, max_len=max_len,
        offset=offset, stride=stride,
    )

    try:
        while cancel_val.value == 0:
            batch = gen.next_batch(batch_size)
            if not batch:
                break

            for pwd in batch:
                if cancel_val.value != 0:
                    break
                # Fast check: zipfile in-process
                try:
                    z.read(first_name, pwd=pwd.encode("utf-8", "replace"))
                except Exception:
                    continue

                # zipfile accepted — confirm with 7z to rule out false positives
                try:
                    r = sp.run(
                        [seven_zip_path, "t", archive_path_str, "-y", f"-p{pwd}"],
                        capture_output=True, text=True, timeout=30,
                        **subprocess_kwargs(),
                    )
                    if "Everything is Ok" in r.stdout and "Wrong password" not in r.stdout:
                        result_queue.put(pwd)
                        return
                except Exception:
                    pass
                # False positive, continue searching

            attempts_val.value += len(batch)
    finally:
        try:
            z.close()
        except Exception:
            pass


# ============================================================
#  Crack session
# ============================================================

class CrackSession:
    """Manages a password cracking attack.

    Architecture:
      - ZIP bruteforce → multiprocessing (offset/stride shards, GIL-free)
      - Everything else → producer-consumer queue with threading
      - All ZIP verification goes through zipfile fast-check → 7z confirm
      - All non-ZIP verification uses 7z test mode directly
    """

    def __init__(
        self,
        configs: list[CrackConfig],
        archive_path: str | Path,
        *,
        state_file: str | None = None,
        on_found: Callable[[str], None] | None = None,
        on_progress: Callable[[dict], None] | None = None,
        on_log: Callable[[str], None] | None = None,
    ):
        self._configs = configs
        self._archive_path = Path(archive_path)
        self._state_file = state_file
        self._on_found = on_found
        self._on_progress = on_progress
        self._on_log = on_log

        self._cancel_flag = threading.Event()
        self._found_password: str | None = None
        self._found_lock = threading.Lock()
        self._total_attempts = 0
        self._attempts_lock = threading.Lock()
        self._start_time = 0.0

    # ---------- public API ----------

    @property
    def found_password(self) -> str | None:
        with self._found_lock:
            return self._found_password

    @property
    def attempts(self) -> int:
        return self._total_attempts

    @property
    def speed(self) -> float:
        elapsed = time.time() - self._start_time
        return self._total_attempts / elapsed if elapsed > 0 else 0

    def cancel(self):
        self._cancel_flag.set()

    def run(self) -> str | None:
        self._start_time = time.time()

        lower = self._archive_path.name.lower()
        is_zip = lower.endswith(".zip") or lower.endswith(".zip.001")

        for ci, config in enumerate(self._configs):
            if self._cancel_flag.is_set():
                break

            self._log(f"[攻击 {ci + 1}/{len(self._configs)}] 类型: {config.attack_type}")

            try:
                gen = create_generator(config)
            except ValueError as e:
                self._log(f"  配置错误: {e}")
                continue

            total = gen.total_estimate()
            if total:
                self._log(f"  预计尝试: {total:,}")

            num_workers = max(1, config.threads)

            # ZIP bruteforce: multiprocessing to bypass GIL
            if is_zip and config.attack_type == "bruteforce":
                found = self._run_zip_mp(config, num_workers)
            else:
                found = self._run_with_queue(gen, num_workers, is_zip)

            if found:
                with self._found_lock:
                    self._found_password = found
                if self._on_found:
                    self._on_found(found)
                self._log(f"  ✓ 找到密码: {found}")
                return found

            if self._cancel_flag.is_set():
                self._log("  已取消")
                return None

            elapsed = time.time() - self._start_time
            if config.time_limit_minutes and elapsed > config.time_limit_minutes * 60:
                self._log("  时间限制已到")
                return None

            self._log(f"  未找到密码 (耗时 {elapsed:.1f}s)")

        return None

    # ---------- Queue-based threading (non-ZIP, or ZIP non-bruteforce) ----------

    def _run_with_queue(self, gen: PasswordGenerator, num_workers: int,
                        is_zip: bool) -> str | None:
        """Producer-consumer: 1 producer feeds batches, N consumers verify.

        For ZIP: each consumer pre-opens a ZipFile for fast pre-check, then
        confirms with 7z.  For non-ZIP: each consumer uses 7z test mode.
        """
        from .extractor import verify_password

        batch_size = 200 if isinstance(gen, BruteForceGenerator) else 1
        q: queue.Queue = queue.Queue(maxsize=num_workers * 4)
        num_active = num_workers

        # --- producer ---
        def _produce():
            nonlocal num_active
            try:
                while not self._cancel_flag.is_set():
                    batch = gen.next_batch(batch_size)
                    if not batch:
                        break
                    q.put(batch)
            finally:
                for _ in range(num_workers):
                    q.put(None)

        # --- consumer ---
        def _consume(worker_id: int):
            nonlocal num_active
            import zipfile as zf_mod

            zf = None
            first_name = ""
            if is_zip:
                try:
                    zf = zf_mod.ZipFile(str(self._archive_path), "r")
                    for n in zf.namelist():
                        if not n.endswith("/"):
                            first_name = n
                            break
                except Exception:
                    pass

            try:
                while not self._cancel_flag.is_set():
                    if self._found_password is not None:
                        return

                    try:
                        batch = q.get(timeout=0.3)
                    except queue.Empty:
                        continue

                    if batch is None:
                        break

                    for pwd in batch:
                        if self._cancel_flag.is_set() or self._found_password is not None:
                            return

                        ok = False
                        try:
                            if zf is not None and first_name:
                                ok = _try_zip_read(zf, first_name, pwd)
                            else:
                                ok = verify_password(str(self._archive_path), pwd)
                        except Exception:
                            ok = False

                        if ok:
                            with self._found_lock:
                                if self._found_password is None:
                                    self._found_password = pwd
                            self._cancel_flag.set()
                            return

                    with self._attempts_lock:
                        self._total_attempts += len(batch)

                    if self._total_attempts % 500 == 0:
                        last = batch[-1] if batch else ""
                        self._progress({"current_password": last})

            finally:
                if zf:
                    try:
                        zf.close()
                    except Exception:
                        pass

        # Launch workers
        workers = []
        for i in range(num_workers):
            t = threading.Thread(target=_consume, args=(i,), daemon=True)
            t.start()
            workers.append(t)

        producer = threading.Thread(target=_produce, daemon=True)
        producer.start()

        producer.join()
        for t in workers:
            t.join()

        return self._found_password

    # ---------- Multiprocessing ZIP bruteforce ----------

    def _run_zip_mp(self, config: CrackConfig, num_workers: int) -> str | None:
        """ZIP bruteforce across processes — each core decrypts independently.

        Workers use zipfile as a fast pre-filter and confirm candidates with 7z
        inside the worker process (no false positives reach the parent).
        """
        from .extractor import find_7z

        sz = find_7z()
        if sz is None:
            self._log("  7-Zip 未找到，回退到线程模式")
            return self._run_with_queue(
                BruteForceGenerator(config.charset, config.min_length, config.max_length),
                num_workers, True,
            )

        batch_size = 200
        num_procs = min(num_workers, mp.cpu_count() or 4)

        cancel_val = mp.Value("i", 0)
        attempts_val = mp.Value("Q", 0)
        result_queue = mp.Queue()

        procs = []
        for i in range(num_procs):
            p = mp.Process(
                target=_zip_mp_worker,
                args=(
                    str(self._archive_path),
                    config.charset,
                    config.min_length,
                    config.max_length,
                    i,
                    num_procs,
                    batch_size,
                    cancel_val,
                    attempts_val,
                    result_queue,
                    str(sz),
                ),
                daemon=True,
            )
            p.start()
            procs.append(p)

        total_est = sum(
            BruteForceGenerator(config.charset, config.min_length, config.max_length,
                                offset=i, stride=num_procs).total_estimate()
            for i in range(num_procs)
        )
        self._log(f"  {num_procs} 进程并行, 预计 {total_est:,} 次")

        last_attempts = 0
        last_time = time.time()

        try:
            while any(p.is_alive() for p in procs):
                if self._cancel_flag.is_set():
                    cancel_val.value = 1
                    break

                # Check for results (already 7z-confirmed by worker)
                try:
                    pwd = result_queue.get_nowait()
                    cancel_val.value = 1
                    return pwd
                except Exception:
                    pass

                current = attempts_val.value
                with self._attempts_lock:
                    self._total_attempts = current

                now = time.time()
                if now - last_time >= 1.0:
                    speed = (current - last_attempts) / max(now - last_time, 0.001)
                    self._progress({
                        "current_password": f"{num_procs} 进程并行",
                        "speed": speed,
                    })
                    last_attempts = current
                    last_time = now

                time.sleep(0.1)

            # Drain any remaining results
            while not result_queue.empty():
                try:
                    pwd = result_queue.get_nowait()
                    cancel_val.value = 1
                    return pwd
                except Exception:
                    break

        finally:
            cancel_val.value = 1
            for p in procs:
                if p.is_alive():
                    p.terminate()
                p.join(timeout=3)
            result_queue.close()
            result_queue.join_thread()

        return None

    # ---------- session persistence ----------

    def save_session(self):
        if not self._state_file:
            return
        state = {
            "archive_path": str(self._archive_path),
            "configs": [asdict(c) for c in self._configs],
            "total_attempts": self._total_attempts,
            "timestamp": time.time(),
        }
        with open(self._state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

    @staticmethod
    def has_saved_session(state_file: str) -> bool:
        return Path(state_file).is_file()

    # ---------- internal helpers ----------

    def _log(self, msg: str):
        if self._on_log:
            self._on_log(msg)

    def _progress(self, info: dict):
        info["total_attempts"] = self._total_attempts
        info["total_estimate"] = getattr(self, "_total_estimate", 0)
        info["speed"] = self.speed
        info["elapsed"] = time.time() - self._start_time
        if self._on_progress:
            self._on_progress(info)
