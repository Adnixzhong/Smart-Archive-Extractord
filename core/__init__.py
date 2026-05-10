"""Core package — shared utilities for all subprocess operations."""

import os
import subprocess


def subprocess_kwargs() -> dict:
    """Return kwargs to hide console windows on Windows."""
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = si
    return kwargs
