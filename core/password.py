"""Password dictionary management for archive cracking."""

from pathlib import Path
from typing import Optional

# Built-in common passwords — most frequently used ones first
BUILTIN_PASSWORDS: list[str] = [
    # Top common passwords
    "", "password", "123456", "12345678", "123456789", "1234567890",
    "1234", "12345", "1234567", "qwerty", "qwerty123", "abc123",
    "admin", "root", "test", "guest", "user", "pass",
    "111111", "000000", "888888", "666666", "555555",
    "iloveyou", "monkey", "dragon", "master", "letmein",
    "starwars", "princess", "sunshine", "football", "baseball",
    "welcome", "shadow", "michael", "superman", "batman",
    "trustno1", "password1", "password123", "p@ssword", "p@ssw0rd",
    "P@ssw0rd", "Passw0rd", "Password", "Password123",
    "admin123", "admin@123", "root123", "root@123",
    # Chinese common
    "123456789", "woaini", "woaiwojia", "nihao",
    "5201314", "1314520", "88888888",
    # Numeric patterns
    "123123", "121212", "112233", "654321", "0987654321",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1q2w3e4r", "1qaz2wsx", "qazwsx", "qweasd",
    "zaqxsw", "xsw2",
    # Dates
    "20000101", "19900101", "19880101", "20010101",
    "20001212", "20200101", "20100101", "20110101",
    "20120101", "20130101", "20140101", "20150101",
    "20160101", "20170101", "20180101", "20190101",
    "20200101", "20210101", "20220101", "20230101",
    "20240101", "20250101", "20260101",
    # Common words
    "chocolate", "dolphin", "elephant", "guitar",
    "hunter", "icecream", "jordan", "killer",
    "liverpool", "marvel", "naruto", "orange",
    "pokemon", "rainbow", "samsung", "thomas",
    "united", "victory", "william", "xavier",
    "yellow", "zombie",
    # Work/office
    "work", "office", "company", "project", "document",
    "excel", "word", "pdf", "archive", "backup",
    "data", "files", "secret", "private", "confidential",
    "topsecret", "internal",
    # Extra common
    "temp", "tmp", "test123", "demo", "sample", "example",
    "default", "changeme", "forgot", "reset",
    "abc", "abcd", "abcde", "abcdef",
    "qwerty1", "qwerty12", "qwerty12345",
    "asdfgh", "asdfghj", "asdfghjk",
    "1q2w3e", "1q2w3e4r5t", "1q2w3e4r5t6y",
    "zxcvbn", "zxcvbnm1", "zxcvbnm12",
    "passw0rd", "p455w0rd", "p@55w0rd",
    "l0ve", "l0v3", "n00b", "h4x0r",
    "flower", "dragon1", "master1",
    "michael1", "thomas1", "jennifer1",
    "jessica1", "amanda1", "andrew1",
    "joshua1", "matthew1", "daniel1",
    "soccer", "hockey", "tennis", "golf",
    "swimming", "cricket", "basketball",
    "friday", "saturday", "sunday", "monday",
    "summer", "winter", "spring", "autumn",
    "hello", "hi", "hey", "yo", "ok", "yes", "no",
    "good", "bad", "cool", "nice", "love", "hate",
    "fire", "water", "earth", "wind", "light", "dark",
    "night", "morning", "evening",
    "alpha", "beta", "gamma", "delta", "omega",
    "coffee", "tea", "beer", "wine", "pizza",
    "cat", "dog", "bird", "fish", "horse", "tiger",
    "lion", "bear", "wolf", "eagle", "snake",
    "red", "blue", "green", "black", "white", "gray",
    "gold", "silver", "bronze",
    "mercedes", "bmw", "audi", "honda", "toyota", "ford",
    "apple", "google", "microsoft", "amazon", "facebook",
    "samsung1", "iphone", "android", "windows", "linux",
    "ubuntu", "debian", "centos",
    "chrome", "firefox", "safari", "opera",
    "router", "switch", "server", "client", "proxy",
    "jack", "jim", "john", "bob", "tom", "sam", "david",
    "mike", "chris", "kevin", "jason", "eric", "alex",
    "steve", "mark", "paul", "ryan", "scott", "james",
    "robert", "william", "richard", "joseph", "charles",
]


class PasswordManager:
    def __init__(self):
        self._builtin = BUILTIN_PASSWORDS.copy()
        self._custom: list[str] = []

    def load_custom(self, filepath: str | Path) -> int:
        """Load passwords from a text file (one per line). Returns count loaded."""
        path = Path(filepath)
        if not path.is_file():
            return 0

        loaded = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                pwd = line.strip()
                if pwd and pwd not in loaded:
                    loaded.append(pwd)

        self._custom = loaded
        return len(loaded)

    def get_all_passwords(self) -> list[str]:
        """Get the combined password list (custom first, then built-in)."""
        seen = set()
        result = []
        for p in self._custom + self._builtin:
            if p not in seen:
                seen.add(p)
                result.append(p)
        return result

    @property
    def total_count(self) -> int:
        return len(self._custom) + len(self._builtin)

    @property
    def builtin_count(self) -> int:
        return len(self._builtin)

    @property
    def custom_count(self) -> int:
        return len(self._custom)

    def add(self, password: str) -> bool:
        """Add a password to the custom list. Returns True if added, False if duplicate."""
        pwd = password.strip()
        if not pwd:
            return False
        if pwd in self._custom or pwd in self._builtin:
            return False
        self._custom.append(pwd)
        return True

    def remove(self, password: str) -> bool:
        """Remove a password from the custom list. Returns True if removed."""
        if password in self._custom:
            self._custom.remove(password)
            return True
        return False

    def clear_custom(self):
        """Clear all custom passwords."""
        self._custom.clear()

    def save_custom(self, filepath: str | Path) -> int:
        """Save custom passwords to a text file. Returns count written."""
        with open(filepath, "w", encoding="utf-8") as f:
            for p in self._custom:
                f.write(p + "\n")
        return len(self._custom)


def save_builtin_passwords(filepath: str | Path) -> None:
    """Save the built-in password list to a file (for user reference/customization)."""
    with open(filepath, "w", encoding="utf-8") as f:
        for p in BUILTIN_PASSWORDS:
            if p == "":
                f.write("(empty password)\n")
            else:
                f.write(p + "\n")
