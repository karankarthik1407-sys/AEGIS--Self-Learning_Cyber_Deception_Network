"""Static, dependency-free contract checks for the bundled desktop UI."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HTML = (ROOT / "web/index.html").read_text(encoding="utf-8")
JS = (ROOT / "web/app.js").read_text(encoding="utf-8")
CSS = (ROOT / "web/styles.css").read_text(encoding="utf-8")


def main() -> int:
    failures: list[str] = []

    ids = re.findall(r'\bid=["\']([^"\']+)["\']', HTML)
    duplicates = sorted(item for item, count in Counter(ids).items() if count > 1)
    if duplicates:
        failures.append(f"duplicate HTML ids: {', '.join(duplicates)}")

    jquery_ids = set(re.findall(r'\$\(\s*["\']#([^"\']+)["\']\s*\)', JS))
    dom_ids = set(re.findall(r'getElementById\(\s*["\']([^"\']+)["\']\s*\)', JS))
    referenced_ids = jquery_ids | dom_ids
    missing_ids = sorted(referenced_ids - set(ids))
    if missing_ids:
        failures.append(f"JavaScript references missing HTML ids: {', '.join(missing_ids)}")

    nav_workspaces = set(re.findall(r'\bdata-workspace=["\']([^"\']+)["\']', HTML))
    section_workspaces = set(re.findall(r'\bid=["\']workspace-([^"\']+)["\']', HTML))
    if nav_workspaces != section_workspaces:
        failures.append(
            "workspace navigation mismatch: "
            f"nav-only={sorted(nav_workspaces - section_workspaces)}, "
            f"section-only={sorted(section_workspaces - nav_workspaces)}"
        )
    if len(nav_workspaces) != 16:
        failures.append(f"expected 16 v1.2 workspaces, found {len(nav_workspaces)}")

    if CSS.count("{") != CSS.count("}"):
        failures.append("CSS brace count is unbalanced")
    if re.search(r'(?:src|href)=["\']https?://', HTML, flags=re.IGNORECASE):
        failures.append("desktop UI contains an external HTTP dependency")

    if failures:
        print("AEGIS UI contract FAILED")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(
        "AEGIS UI contract PASS "
        f"({len(ids)} ids, {len(referenced_ids)} JS selectors, "
        f"{len(nav_workspaces)} workspaces)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
