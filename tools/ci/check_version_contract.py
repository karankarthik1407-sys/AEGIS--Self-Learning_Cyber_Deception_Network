"""Verify that Python, Windows packaging and release metadata agree."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(pattern: str, content: str, source: str) -> str:
    match = re.search(pattern, content, flags=re.MULTILINE)
    if not match:
        raise AssertionError(f"version declaration missing or malformed in {source}")
    return match.group(1)


def main() -> int:
    pyproject_version = require(
        r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"$',
        read("pyproject.toml"),
        "pyproject.toml",
    )
    version_source = read("aegis/version.py")
    product_version = require(
        r'^PRODUCT_VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"$',
        version_source,
        "aegis/version.py",
    )
    if pyproject_version != product_version:
        raise AssertionError(
            f"pyproject version {pyproject_version} != product version {product_version}"
        )

    major, minor, patch = (int(part) for part in product_version.split("."))
    expected_tuple = f"({major}, {minor}, {patch}, 0)"
    if expected_tuple not in version_source:
        raise AssertionError(f"PRODUCT_VERSION_TUPLE must be {expected_tuple}")
    if f'AEGIS/{major}.{minor}' not in version_source:
        raise AssertionError("SERVER_VERSION does not match product major/minor")

    exact_files = {
        "BUILD_AEGIS_EXE.bat": product_version,
        "START_AEGIS.bat": product_version,
        "install/Install-AEGIS.ps1": product_version,
        "packaging/windows/Build-AEGIS-Desktop.ps1": product_version,
        "packaging/windows/Install-AEGIS-Desktop.ps1": product_version,
        ".github/workflows/windows-desktop-release.yml": product_version,
    }
    windows_version = f"{product_version}.0"
    exact_files.update(
        {
            "packaging/windows/version_info.txt": windows_version,
            "packaging/windows/node_version_info.txt": windows_version,
        }
    )
    for relative, expected in exact_files.items():
        if expected not in read(relative):
            raise AssertionError(f"{relative} does not declare {expected}")

    if f"## {product_version} " not in read("CHANGELOG.md"):
        raise AssertionError("CHANGELOG.md has no current-version entry")
    if f"version: {product_version}" not in read("CITATION.cff"):
        raise AssertionError("CITATION.cff does not match the product version")

    print(f"AEGIS version contract PASS ({product_version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
