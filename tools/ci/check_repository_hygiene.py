"""Fail CI when repository content crosses AEGIS confidentiality boundaries."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SELF = Path(__file__).resolve()
MAX_FILE_BYTES = 10 * 1024 * 1024

EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "exports",
    "htmlcov",
    "licenses",
    "logs",
    "private",
    "release",
    "secrets",
}
FORBIDDEN_SUFFIXES = {
    ".aegis-license",
    ".db",
    ".jks",
    ".key",
    ".keystore",
    ".p8",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".whl",
    ".zip",
}
FORBIDDEN_NAMES = {".env", "aegis.db", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}
SECRET_PATTERNS = {
    "private-key marker": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"(?:ghp|github_pat)_[A-Za-z0-9_]{20,}"),
    "AWS access-key identifier": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "Google API key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "API credential": re.compile(rb"sk-[A-Za-z0-9_-]{32,}"),
}
ASSISTANT_BRAND_MARKERS = (
    b"chat" + b"gpt",
    b"co" + b"dex",
    b"open" + b"ai",
)


def candidate_files() -> list[Path]:
    """Use the Git index in CI and a conservative filesystem fallback locally."""

    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]

    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.parts[0] == "data" and relative.name != ".gitkeep":
            continue
        files.append(path)
    return sorted(files)


def main() -> int:
    failures: list[str] = []
    files = candidate_files()

    for path in files:
        relative = path.relative_to(ROOT)
        lower_name = path.name.lower()
        lower_suffix = path.suffix.lower()

        if lower_name in FORBIDDEN_NAMES or lower_suffix in FORBIDDEN_SUFFIXES:
            failures.append(f"forbidden repository artifact: {relative}")
            continue
        if any(part in {"licenses", "private", "secrets"} for part in relative.parts):
            failures.append(f"forbidden sensitive directory: {relative}")
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            failures.append(f"file exceeds {MAX_FILE_BYTES} bytes: {relative} ({size})")
            continue
        if path.resolve() == SELF or size == 0:
            continue

        content = path.read_bytes()
        lowered_content = content.lower()
        if content.startswith(b"SQLite format 3\x00"):
            failures.append(f"SQLite runtime database detected: {relative}")
        if any(marker in lowered_content for marker in ASSISTANT_BRAND_MARKERS):
            failures.append(f"automated-assistant attribution detected: {relative}")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                failures.append(f"{label} detected: {relative}")

    history = subprocess.run(
        ["git", "-C", str(ROOT), "log", "-50", "--format=%B%x00"],
        check=False,
        capture_output=True,
    )
    if history.returncode == 0:
        lowered_history = history.stdout.lower()
        if any(marker in lowered_history for marker in ASSISTANT_BRAND_MARKERS):
            failures.append("automated-assistant attribution detected in commit history")

    if failures:
        print("AEGIS repository hygiene FAILED")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"AEGIS repository hygiene PASS ({len(files)} files inspected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
