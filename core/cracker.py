"""Password cracking engine — brute force, dictionary, mask, and rule-based."""

import itertools
import json
import time
import threading
import multiprocessing as mp
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
    attack_type: str = "bruteforce"  # "bruteforce" | "dictionary" | "mask" | "rule"
    charset: str = CHARSET_PRESETS["数字 (0-9)"]
    min_length: int = 1
    max_length: int = 6
    mask_pattern: str = ""          # e.g. "???2024"
    dictionary_path: str = ""       # path to wordlist file
    rules: list[str] = field(default_factory=lambda: ["lowercase", "uppercase"])
    append_mask: str = ""           # dictionary + mask hybrid: append mask pattern
    prepend_mask: str = ""          # dictionary + mask hybrid: prepend mask pattern
    threads: int = 4
    time_limit_minutes: int = 0     # 0 = unlimited


# ============================================================
#  Password generators (iterators with save/resume)
# ============================================================

class PasswordGenerator(ABC):
    """Abstract base for password generators. Each is an iterator that yields str."""

    @abstractmethod
    def __iter__(self):
        ...

    @abstractmethod
    def __next__(self) -> str:
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
    produces every Nth password starting from `offset`. No lock needed.
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
        self._k = 0  # local count (how many passwords produced)
        # Precompute powers
        self._powers = [1]
        for _ in range(1, max_len + 1):
            self._powers.append(self._powers[-1] * self._charset_len)
        self._current_limit = self._powers[min_len]

    def total_estimate(self) -> int:
        total = 0
        for L in range(self._min_len, self._max_len + 1):
            total += self._powers[L]
        return total // self._stride + 1

    def __iter__(self):
        return self

    def __next__(self) -> str:
        if self._current_len > self._max_len:
            raise StopIteration

        global_idx = self._offset + self._k * self._stride
        self._k += 1

        # Advance length if this generator has passed the limit for current length
        while self._current_len <= self._max_len and global_idx >= self._current_limit:
            self._current_len += 1
            if self._current_len <= self._max_len:
                self._current_limit += self._powers[self._current_len]
                # Reset offset within new length
                self._k = 0
                global_idx = self._offset

        if self._current_len > self._max_len:
            raise StopIteration

        return self._idx_to_str(global_idx, self._current_len)

    def _idx_to_str(self, idx: int, L: int) -> str:
        """Convert a numeric index to a base-N password string."""
        chars = self._chars
        charset_len = self._charset_len
        result = []
        for _ in range(L):
            result.append(chars[idx % charset_len])
            idx //= charset_len
        return "".join(reversed(result))

    def next_batch(self, n: int) -> list[str]:
        """Return up to n passwords for this generator."""
        batch = []
        chars = self._chars
        charset_len = self._charset_len
        while len(batch) < n and self._current_len <= self._max_len:
            L = self._current_len
            global_idx = self._offset + self._k * self._stride
            if global_idx >= self._current_limit:
                self._current_len += 1
                self._k = 0
                if self._current_len <= self._max_len:
                    self._current_limit += self._powers[self._current_len]
                continue
            # Build one password
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
            "charset": self._charset,
            "min_len": self._min_len,
            "max_len": self._max_len,
            "current_len": self._current_len,
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
        self._offset = 0
        self._fh = None
        self._started = False
        self._total_lines: Optional[int] = None

    def total_estimate(self) -> int:
        if self._total_lines is not None:
            return self._total_lines
        try:
            # Quick count (may be slow for huge files)
            count = 0
            with open(self._filepath, "r", encoding="utf-8", errors="replace") as f:
                for _ in f:
                    count += 1
            self._total_lines = count
            return count
        except Exception:
            return 0

    def __iter__(self):
        self._fh = open(self._filepath, "r", encoding="utf-8", errors="replace")
        if self._offset > 0:
            self._fh.seek(self._offset)
        return self

    def __next__(self) -> str:
        if self._fh is None:
            raise StopIteration
        while True:
            line = self._fh.readline()
            if not line:
                self._fh.close()
                self._fh = None
                raise StopIteration
            pwd = line.strip()
            if pwd:
                self._offset = self._fh.tell()
                return pwd

    def save_state(self) -> dict:
        return {
            "filepath": str(self._filepath),
            "offset": self._offset,
        }

    def load_state(self, state: dict):
        self._filepath = Path(state["filepath"])
        self._offset = state["offset"]


class MaskGenerator(PasswordGenerator):
    """Generate passwords matching a mask. '?' is replaced by charset chars."""

    def __init__(self, pattern: str, charset: str):
        self._pattern = pattern
        self._charset = charset
        self._num_wildcards = pattern.count("?")
        self._idx = 0
        self._started = False

    def total_estimate(self) -> int:
        return len(self._charset) ** self._num_wildcards

    def __iter__(self):
        return self

    def __next__(self) -> str:
        if self._idx >= len(self._charset) ** self._num_wildcards:
            raise StopIteration

        # Convert index to base-N substitution
        idx = self._idx
        self._idx += 1
        chars = []
        remaining = idx
        for _ in range(self._num_wildcards):
            chars.append(self._charset[remaining % len(self._charset)])
            remaining //= len(self._charset)
        chars.reverse()

        # Build result
        result = []
        wild_idx = 0
        for ch in self._pattern:
            if ch == "?":
                result.append(chars[wild_idx])
                wild_idx += 1
            else:
                result.append(ch)
        return "".join(result)

    def save_state(self) -> dict:
        return {
            "pattern": self._pattern,
            "charset": self._charset,
            "idx": self._idx,
        }

    def load_state(self, state: dict):
        self._pattern = state["pattern"]
        self._charset = state["charset"]
        self._idx = state["idx"]
        self._num_wildcards = self._pattern.count("?")


class RuleBasedGenerator(PasswordGenerator):
    """Apply transformation rules to base words (from dictionary or inline list)."""

    # Pre-compute number/symbol suffixes for speed
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
                est += 5  # average leet variations
            elif rule in ("append_numbers", "prepend_numbers"):
                est += len(self._NUM_SUFFIXES)
            elif rule in ("append_symbols", "prepend_symbols"):
                est += len(self._SYM_SUFFIXES)
            else:
                est += 1
        return len(self._words) * est

    def _apply_rules(self, word: str) -> list[str]:
        results = set()
        # Case rules (fast — no loops)
        if "lowercase" in self._rules:
            results.add(word.lower())
        if "uppercase" in self._rules:
            results.add(word.upper())
        if "capitalize" in self._rules:
            results.add(word.capitalize())
        # Leet (recursive expansion)
        if "leet" in self._rules:
            self._leet_expand(word, 0, "", results)
        # Number suffixes
        if "append_numbers" in self._rules:
            for n in self._NUM_SUFFIXES:
                results.add(word + n)
        if "prepend_numbers" in self._rules:
            for n in self._NUM_SUFFIXES:
                results.add(n + word)
        # Symbol suffixes
        if "append_symbols" in self._rules:
            for s in self._SYM_SUFFIXES:
                results.add(word + s)
        if "prepend_symbols" in self._rules:
            for s in self._SYM_SUFFIXES:
                results.add(s + word)
        # Misc
        if "reverse" in self._rules:
            results.add(word[::-1])
        if "double" in self._rules:
            results.add(word + word)
        results.discard(word)
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

    def __iter__(self):
        return self

    def __next__(self) -> str:
        while self._cache_pos >= len(self._cache):
            if self._word_idx >= len(self._words):
                raise StopIteration
            word = self._words[self._word_idx]
            self._word_idx += 1
            self._cache = self._apply_rules(word)
            self._cache_pos = 0
            if self._cache:
                break
        pwd = self._cache[self._cache_pos]
        self._cache_pos += 1
        return pwd

    def next_batch(self, n: int) -> list[str]:
        batch = []
        while len(batch) < n:
            # Drain cache first
            remaining = len(self._cache) - self._cache_pos
            take = min(n - len(batch), remaining)
            if take > 0:
                batch.extend(self._cache[self._cache_pos:self._cache_pos + take])
                self._cache_pos += take
                continue
            # Refill cache from next word
            if self._word_idx >= len(self._words):
                break
            word = self._words[self._word_idx]
            self._word_idx += 1
            self._cache = self._apply_rules(word)
            self._cache_pos = 0
        return batch

    def save_state(self) -> dict:
        return {
            "words": self._words,
            "rules": self._rules,
            "word_idx": self._word_idx,
            "cache_pos": self._cache_pos,
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
    """Combine dictionary words with mask patterns (append or prepend).

    Yields word+mask or mask+word for every dictionary word and every
    mask combination.  The mask '?' characters are substituted from
    *charset* (not "any character").
    """

    def __init__(self, words: list[str], mask_pattern: str, charset: str,
                 position: str = "append"):
        self._words = words
        self._pattern = mask_pattern
        self._charset = charset
        self._position = position  # "append" or "prepend"
        self._num_wildcards = mask_pattern.count("?")
        self._charset_len = len(charset)
        self._mask_total = self._charset_len ** self._num_wildcards if self._num_wildcards else 0

        self._word_idx = 0
        self._mask_idx = 0

    def total_estimate(self) -> int:
        return len(self._words) * max(self._mask_total, 1)

    def __iter__(self):
        return self

    def __next__(self) -> str:
        while self._word_idx < len(self._words):
            word = self._words[self._word_idx]
            if self._mask_total == 0:
                self._word_idx += 1
                return word
            if self._mask_idx < self._mask_total:
                mask_str = self._idx_to_mask(self._mask_idx)
                self._mask_idx += 1
                if self._position == "append":
                    return word + mask_str
                else:
                    return mask_str + word
            self._mask_idx = 0
            self._word_idx += 1
        raise StopIteration

    def _idx_to_mask(self, idx: int) -> str:
        chars = []
        for _ in range(self._num_wildcards):
            chars.append(self._charset[idx % self._charset_len])
            idx //= self._charset_len
        chars.reverse()
        result = []
        wild_idx = 0
        for ch in self._pattern:
            if ch == "?":
                result.append(chars[wild_idx])
                wild_idx += 1
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
            base = self._mask_idx
            for i in range(take):
                m = self._idx_to_mask(base + i)
                batch.append(word + m if self._position == "append" else m + word)
            self._mask_idx += take
            if self._mask_idx >= self._mask_total:
                self._mask_idx = 0
                self._word_idx += 1
        return batch

    def save_state(self) -> dict:
        return {
            "words": self._words,
            "pattern": self._pattern,
            "charset": self._charset,
            "position": self._position,
            "word_idx": self._word_idx,
            "mask_idx": self._mask_idx,
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
        if config.rules:
            # Load words from file and apply rules
            words = _load_dict_words(config.dictionary_path)
            return RuleBasedGenerator(words, config.rules)
        return DictionaryGenerator(config.dictionary_path)
    elif config.attack_type == "mask":
        if not config.mask_pattern:
            raise ValueError("Mask attack requires a pattern (e.g. ???2024)")
        return MaskGenerator(config.mask_pattern, config.charset)
    else:
        raise ValueError(f"Unknown attack type: {config.attack_type}")


def _load_dict_words(filepath: str | Path) -> list[str]:
    """Load words from a dictionary file into memory."""
    words = []
    with open(Path(filepath), "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if w and w not in words:
                words.append(w)
    return words


def _try_zip_read(zf_obj, first_name: str, password: str) -> bool:
    """Fast password check on an already-open ZipFile with cached first filename."""
    try:
        zf_obj.read(first_name, pwd=password.encode("utf-8", errors="replace"))
        return True
    except Exception:
        return False


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
):
    """Multiprocessing worker for ZIP bruteforce.  Each worker owns an
    independent BruteForceGenerator slice (offset / stride) so no IPC is
    needed for candidate generation – only the final result and progress
    counters cross process boundaries."""
    import zipfile

    archive_path = Path(archive_path_str)
    try:
        z = zipfile.ZipFile(archive_path, "r")
        first_name = z.namelist()[0]
    except Exception:
        return

    gen = BruteForceGenerator(
        charset=charset,
        min_len=min_len,
        max_len=max_len,
        offset=offset,
        stride=stride,
    )

    try:
        while cancel_val.value == 0:
            batch = gen.next_batch(batch_size)
            if not batch:
                break

            for pwd in batch:
                if cancel_val.value != 0:
                    break
                try:
                    z.read(first_name, pwd=pwd.encode("utf-8", "replace"))
                    result_queue.put(pwd)
                    return
                except Exception:
                    pass

            attempts_val.value += len(batch)
    finally:
        try:
            z.close()
        except Exception:
            pass


# ============================================================
#  Crack session (parallel password verification)
# ============================================================

class CrackSession:
    """Manages a password cracking attack with parallel workers."""

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
        self._total_estimate = 0  # total passwords for current config
        self._start_time = 0.0
        self._current_config_idx = 0

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
        """Attempts per second."""
        elapsed = time.time() - self._start_time
        if elapsed <= 0:
            return 0
        return self._total_attempts / elapsed

    def cancel(self):
        self._cancel_flag.set()

    # ── Multiprocessing ZIP bruteforce ──────────────────────

    def _run_zip_bruteforce_mp(self, config: CrackConfig, num_workers: int) -> str | None:
        """Run ZIP bruteforce across *processes* so each core can decrypt
        independently (threading is serialised by the GIL for ZipCrypto)."""
        batch_size = 200

        cancel_val = mp.Value("i", 0)       # 0 = running, 1 = stop
        attempts_val = mp.Value("Q", 0)     # unsigned long long
        result_queue = mp.Queue()

        num_procs = min(num_workers, mp.cpu_count() or 4)
        total_est = sum(
            BruteForceGenerator(
                config.charset, config.min_length, config.max_length,
                offset=i, stride=num_procs,
            ).total_estimate()
            for i in range(num_procs)
        )
        self._total_estimate = total_est
        if total_est:
            self._log(f"  预计尝试数量: {total_est:,} ({num_procs} 进程并行)")

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
                ),
                daemon=True,
            )
            p.start()
            procs.append(p)

        poll_interval = 0.2
        last_attempts = 0
        last_time = time.time()

        try:
            while any(p.is_alive() for p in procs):
                if self._cancel_flag.is_set():
                    cancel_val.value = 1
                    break

                try:
                    pwd = result_queue.get_nowait()
                    cancel_val.value = 1
                    return pwd
                except Exception:
                    pass

                current = attempts_val.value
                self._total_attempts = current
                now = time.time()
                if now - last_time >= 1.0:
                    speed = (current - last_attempts) / (now - last_time)
                    self._progress({"current_password": f"{num_procs} 进程并行"})
                    last_attempts = current
                    last_time = now

                time.sleep(poll_interval)

            while not result_queue.empty():
                try:
                    pwd = result_queue.get_nowait()
                    if pwd:
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

    # ── Main entry ──────────────────────────────────────────

    def run(self) -> str | None:
        self._start_time = time.time()
        from .extractor import verify_password

        lower = self._archive_path.name.lower()
        is_zip = lower.endswith(".zip") or lower.endswith(".zip.001")

        for ci, config in enumerate(self._configs):
            if self._cancel_flag.is_set():
                break
            self._current_config_idx = ci
            self._log(f"[攻击 {ci + 1}/{len(self._configs)}] 类型: {config.attack_type}")

            num_workers = max(1, config.threads)

            # ── ZIP bruteforce: multiprocessing (no GIL) ──────────
            if is_zip and config.attack_type == "bruteforce":
                found = self._run_zip_bruteforce_mp(config, num_workers)
                if found:
                    self._found_password = found
                    self._log(f"  ✓ 找到密码: {found}")
                    return found
                if self._cancel_flag.is_set():
                    self._log("  已取消")
                    break
                elapsed = time.time() - self._start_time
                if config.time_limit_minutes and elapsed > config.time_limit_minutes * 60:
                    self._log("  时间限制已到")
                    break
                self._log(f"  未找到密码 (耗时 {elapsed:.1f}s)")
                continue

            # ── ZIP dictionary / mask: threading (acceptable for small wordlists) ──
            # ── Non-ZIP (RAR/7z): threading (subprocess releases GIL)      ──

            # Build per-thread generators (each thread owns its generator, no lock)
            if config.attack_type == "bruteforce":
                gens = [BruteForceGenerator(
                    charset=config.charset,
                    min_len=config.min_length,
                    max_len=config.max_length,
                    offset=i, stride=num_workers,
                ) for i in range(num_workers)]
                total_est = sum(g.total_estimate() for g in gens)
                self._total_estimate = total_est
                if total_est:
                    self._log(f"  预计尝试数量: {total_est:,} ({num_workers} 线程分片)")
            else:
                # ── Dictionary + mask hybrid ────────────────────
                if config.attack_type == "dictionary" and (config.append_mask or config.prepend_mask):
                    words = _load_dict_words(config.dictionary_path)
                    self._log(f"  字典加载: {len(words)} 个词")
                    if config.append_mask:
                        self._log(f"  末尾追加掩码: {config.append_mask}")
                        base_gen = HybridGenerator(words, config.append_mask, config.charset, "append")
                    else:
                        self._log(f"  开头追加掩码: {config.prepend_mask}")
                        base_gen = HybridGenerator(words, config.prepend_mask, config.charset, "prepend")
                else:
                    try:
                        base_gen = create_generator(config)
                    except ValueError as e:
                        self._log(f"  ✗ 配置错误: {e}")
                        continue
                total_est = base_gen.total_estimate()
                self._total_estimate = total_est
                if total_est:
                    self._log(f"  预计尝试数量: {total_est:,}")
                gens = [base_gen]
                if num_workers > 1:
                    for _ in range(1, num_workers):
                        if config.attack_type == "dictionary" and (config.append_mask or config.prepend_mask):
                            words = _load_dict_words(config.dictionary_path)
                            if config.append_mask:
                                gens.append(HybridGenerator(words, config.append_mask, config.charset, "append"))
                            else:
                                gens.append(HybridGenerator(words, config.prepend_mask, config.charset, "prepend"))
                        else:
                            gens.append(create_generator(config))

            # Build per-thread verifier: for ZIP, use closure to skip all overhead
            _zip_handles = []
            if is_zip:
                import zipfile as zf
                verifiers = []
                for _ in range(num_workers):
                    try:
                        z = zf.ZipFile(self._archive_path, "r")
                        _zip_handles.append(z)
                        first_name = z.namelist()[0]
                        verifiers.append(lambda p, zf=z, fn=first_name: _try_zip_read(zf, fn, p))
                    except Exception:
                        verifiers.append(lambda p, vp=verify_password, ap=self._archive_path: vp(ap, p))
                self._log(f"  ZIP 已预加载 ({num_workers} 线程), 文件名缓存")
            else:
                verifiers = [lambda p, vp=verify_password, ap=self._archive_path: vp(ap, p)
                            for _ in range(num_workers)]

            batch_size = 200 if config.attack_type == "bruteforce" else 1

            # Launch workers — each with its own generator, no lock needed
            workers = []
            for i in range(num_workers):
                t = threading.Thread(
                    target=self._worker,
                    args=(verifiers[i], gens[i], batch_size),
                    daemon=True,
                )
                t.start()
                workers.append(t)

            for t in workers:
                t.join()

            # Close zipfile handles
            if is_zip:
                for z in _zip_handles:
                    try:
                        z.close()
                    except Exception:
                        pass

            if self._found_password:
                self._log(f"  ✓ 找到密码: {self._found_password}")
                return self._found_password

            if self._cancel_flag.is_set():
                self._log("  已取消")
                break

            elapsed = time.time() - self._start_time
            if config.time_limit_minutes and elapsed > config.time_limit_minutes * 60:
                self._log("  时间限制已到")
                break

            self._log(f"  未找到密码 (耗时 {elapsed:.1f}s)")

        return None

    def save_session(self):
        """Save crack session state to JSON for later resume."""
        if not self._state_file:
            return
        state = {
            "archive_path": str(self._archive_path),
            "configs": [asdict(c) for c in self._configs],
            "current_config_idx": self._current_config_idx,
            "total_attempts": self._total_attempts,
            "timestamp": time.time(),
        }
        with open(self._state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

    @staticmethod
    def has_saved_session(state_file: str) -> bool:
        return Path(state_file).is_file()

    # ---------- internals ----------

    def _log(self, msg: str):
        if self._on_log:
            self._on_log(msg)

    def _progress(self, info: dict):
        info["total_attempts"] = self._total_attempts
        info["total_estimate"] = self._total_estimate
        info["speed"] = self.speed
        info["elapsed"] = time.time() - self._start_time
        if self._on_progress:
            self._on_progress(info)

    def _worker(self, verify_fn, gen, batch_size: int = 1):
        """Worker thread: owns its generator, no lock needed."""
        use_batch = batch_size > 1 and hasattr(gen, "next_batch")

        while not self._cancel_flag.is_set():
            if self._found_password is not None:
                return

            if use_batch:
                batch = gen.next_batch(batch_size)
                if not batch:
                    return
            else:
                try:
                    pwd = next(iter(gen))
                    batch = [pwd]
                except StopIteration:
                    return

            for pwd in batch:
                if self._cancel_flag.is_set() or self._found_password is not None:
                    return

                try:
                    ok = verify_fn(pwd)
                except Exception:
                    ok = False

                if ok:
                    with self._found_lock:
                        self._found_password = pwd
                    if self._on_found:
                        self._on_found(pwd)
                    self._cancel_flag.set()
                    return

            self._total_attempts += len(batch)
            attempts = self._total_attempts

            if attempts % 500 == 0:
                self._progress({"current_password": batch[-1] if batch else ""})
            if self._state_file and attempts % 5000 == 0:
                self.save_session()
