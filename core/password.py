"""Password dictionary management for archive cracking."""

from pathlib import Path


class PasswordManager:
    def __init__(self):
        self._passwords: list[str] = []
        self._persist_path: Path | None = None

    def set_persistence(self, filepath: str | Path):
        """Set the file path used for auto-save/load."""
        self._persist_path = Path(filepath)

    @property
    def persist_path(self) -> Path | None:
        return self._persist_path

    def load(self, filepath: str | Path = None) -> int:
        """Load passwords from a text file (one per line). Returns count loaded."""
        path = Path(filepath) if filepath else self._persist_path
        if path is None or not path.is_file():
            return 0
        loaded = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                pwd = line.strip()
                if pwd and pwd not in loaded:
                    loaded.append(pwd)
        self._passwords = loaded
        return len(loaded)

    def save(self, filepath: str | Path = None) -> int:
        """Save passwords to a text file. Returns count written."""
        path = Path(filepath) if filepath else self._persist_path
        if path is None:
            return 0
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for p in self._passwords:
                f.write(p + "\n")
        return len(self._passwords)

    def _auto_save(self):
        if self._persist_path:
            self.save()

    def get_all_passwords(self) -> list[str]:
        return list(self._passwords)

    @property
    def total_count(self) -> int:
        return len(self._passwords)

    @property
    def custom_count(self) -> int:
        return len(self._passwords)

    def add(self, password: str) -> bool:
        pwd = password.strip()
        if not pwd:
            return False
        if pwd in self._passwords:
            return False
        self._passwords.append(pwd)
        self._auto_save()
        return True

    def add_multiple(self, text: str) -> int:
        """Parse multi-line text, add all non-empty lines. Returns count added."""
        added = 0
        for line in text.strip().splitlines():
            pwd = line.strip()
            if pwd and pwd not in self._passwords:
                self._passwords.append(pwd)
                added += 1
        if added:
            self._auto_save()
        return added

    def remove(self, password: str) -> bool:
        if password in self._passwords:
            self._passwords.remove(password)
            self._auto_save()
            return True
        return False

    def clear(self):
        self._passwords.clear()
        self._auto_save()
