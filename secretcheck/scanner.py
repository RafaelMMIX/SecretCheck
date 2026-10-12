"""Scan local project files for common secret patterns.

The public API exposes lightweight helpers that inspect individual lines,
individual files, or a whole directory tree while ignoring common generated
folders such as .git and __pycache__.
"""

import re
from pathlib import Path


SECRET_PATTERNS = {
    "api_key": re.compile(
        r"""(?i)\bapi[_-]?key\b\s*[:=]\s*['"][^'"]+['"]"""
    ),
    "password": re.compile(
        r"""(?i)\bpassword\b\s*[:=]\s*['"][^'"]+['"]"""
    ),
    "token": re.compile(
        r"""(?i)\b(?:access[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*['"][^'"]+['"]"""
    ),
}


def scan_line(line: str) -> list[str]:
    """Return the secret categories detected in a single line.

    This is intentionally conservative: it only recognizes common assignment
    patterns and ignores environment variable access or other non-literal values.
    """
    findings = []

    for secret_type, pattern in SECRET_PATTERNS.items():
        if pattern.search(line):
            findings.append(secret_type)

    return findings


def scan_file(file_path: Path) -> list[dict]:
    """Read a file and report suspicious secret assignments.

    Binary files and invalid UTF-8 content are ignored gracefully so that a scan
    can continue without crashing on unrelated files in the project tree.
    """
    findings = []

    try:
        with file_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                secret_types = scan_line(line)
                if secret_types:
                    for secret_type in secret_types:
                        findings.append(
                            {
                                "file": str(file_path),
                                "line": line_number,
                                "type": secret_type,
                            }
                        )
    except (UnicodeDecodeError, OSError):
        return []

    return findings


IGNORED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
}


def scan_directory(directory: Path) -> list[dict]:
    """Scan every file under a directory tree and return suspicious findings.

    The starting path must exist and be a directory. This makes failures clear
    and avoids confusing stack traces when a user passes a missing folder.
    """
    directory = Path(directory)

    if not directory.exists():
        raise FileNotFoundError(f"Scan directory does not exist: {directory}")

    if not directory.is_dir():
        raise NotADirectoryError(f"Starting path is not a directory: {directory}")

    findings = []

    for path in directory.rglob("*"):
        if not path.is_file():
            continue

        # Ignore generated or version-control folders that usually do not contain
        # project source files worth reviewing.
        if any(ignored_dir in path.parts for ignored_dir in IGNORED_DIRS):
            continue

        findings.extend(scan_file(path))

    return findings
