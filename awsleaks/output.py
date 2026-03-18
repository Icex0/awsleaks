"""Centralized colored output. Works on Unix and Windows (PowerShell/cmd)."""

import os
import sys


def _supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return True


# ANSI codes — work in modern terminals including PowerShell 5.1+ and Windows Terminal
_USE_COLOR = _supports_color()

# Enable ANSI on Windows cmd.exe
if _USE_COLOR and sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

_RED = "\033[91m" if _USE_COLOR else ""
_GREEN = "\033[92m" if _USE_COLOR else ""
_CYAN = "\033[96m" if _USE_COLOR else ""
_RESET = "\033[0m" if _USE_COLOR else ""


def info(msg):
    """[+] message in green."""
    print(f"  {_GREEN}[+]{_RESET} {msg}")


def warn(msg):
    """[!] message in red."""
    print(f"  {_RED}[!]{_RESET} {msg}")


def none(msg):
    """[-] message (no special color)."""
    print(f"  [-] {msg}")


def detail(msg):
    """Indented detail line."""
    print(f"      {msg}")


def header(msg):
    """--- section --- in cyan."""
    print(f"\n{_CYAN}--- {msg} ---{_RESET}")


def region_header(region):
    """Region separator."""
    line = "─" * 50
    print(f"\n{line}")
    print(f"  Region: {region}")
    print(f"{line}")


def banner(msg):
    """Major section banner."""
    print(f"\n{'=' * 50}")
    print(f"  {msg}")
    print(f"{'=' * 50}")


def status(msg):
    """[+] status in green (left-aligned, no indent)."""
    print(f"{_GREEN}[+]{_RESET} {msg}")


def error(msg):
    """[!] error in red (left-aligned, no indent)."""
    print(f"{_RED}[!]{_RESET} {msg}")
